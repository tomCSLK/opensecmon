//! Settings pages of the notifications: the instant mail (`/settings/alerts`) and the daily report
//! (`/settings/report`, with a preview and "send now").

use askama::Template;
use axum::Form;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::alerts::{self, compose};
use crate::audit::{Action, Changes, Kind as AuditKind};
use crate::error::Result;
use crate::i18n::Lang;
use crate::sources::now_ms;
use crate::storage::alerts::{self as store, Settings};
use crate::storage::mail as mail_store;
use crate::storage::matches::{self, Confidence};
use crate::web::audit::{self, Object};
use crate::web::auth::{CsrfForm, CurrentUser};
use crate::web::{AppState, FlashQuery, Layout, flash_message, time_html};

const MAX_URL: usize = 200;

/// Checks and normalises the address of the interface: `http(s)://host[:port][/path]`, without a trailing
/// slash; empty stays empty.
pub fn check_public_url(text: &str) -> std::result::Result<String, &'static str> {
    const ERROR: &str = "alerts-error-url";
    let text = text.trim();
    if text.is_empty() {
        return Ok(String::new());
    }
    if text.chars().count() > MAX_URL {
        return Err(ERROR);
    }
    let lower = text.to_ascii_lowercase();
    let (scheme, rest) = if lower.starts_with("https://") {
        ("https", &text[8..])
    } else if lower.starts_with("http://") {
        ("http", &text[7..])
    } else {
        return Err(ERROR);
    };
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => {
            let port: u16 = p.parse().map_err(|_| ERROR)?;
            if port == 0 {
                return Err(ERROR);
            }
            (h, Some(port))
        }
        _ => (authority, None),
    };
    let host = crate::host::validate_host(host).map_err(|_| ERROR)?;
    let path_ok = path
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~' | '/'));
    if !path_ok {
        return Err(ERROR);
    }
    let path = path.trim_end_matches('/');
    let mut out = format!("{scheme}://{host}");
    if let Some(port) = port {
        out.push_str(&format!(":{port}"));
    }
    if !path.is_empty() {
        out.push('/');
        out.push_str(path);
    }
    Ok(out)
}

/// A number as typed (comma or point as decimal separator).
fn number(text: &str) -> Option<f64> {
    text.trim()
        .replace(',', ".")
        .parse::<f64>()
        .ok()
        .filter(|n| n.is_finite())
}

fn yes_no(b: bool) -> &'static str {
    if b { "audit-yes" } else { "audit-no" }
}

/// A threshold as the protocol shows it: the value, or "–" when it is off.
fn threshold(on: bool, value: impl ToString) -> String {
    if on {
        value.to_string()
    } else {
        "–".to_owned()
    }
}

// ---------------------------------------------------------------------------------------------------
// Instant mail

struct ConfidenceOption {
    value: &'static str,
    label: String,
    selected: bool,
}

/// The form as shown (numbers as typed after an error).
struct AlertForm {
    instant: bool,
    on_kev: bool,
    prio_on: bool,
    prio_min: String,
    cvss_on: bool,
    cvss_min: String,
    epss_on: bool,
    epss_min: String,
    bundle: bool,
    once_per_vuln: bool,
    public_url: String,
}

impl AlertForm {
    fn of(t: Lang, s: &Settings) -> Self {
        Self {
            instant: s.instant,
            on_kev: s.on_kev,
            prio_on: s.prio_on,
            prio_min: s.prio_min.to_string(),
            cvss_on: s.cvss_on,
            cvss_min: t.decimal(s.cvss_min, 1),
            epss_on: s.epss_on,
            epss_min: t.decimal(s.epss_min, 1),
            bundle: s.bundle,
            once_per_vuln: s.once_per_vuln,
            public_url: s.public_url.clone(),
        }
    }
}

#[derive(Template)]
#[template(path = "alert_settings.html")]
struct AlertsTemplate {
    t: Lang,
    layout: Layout,
    form: AlertForm,
    confidences: Vec<ConfidenceOption>,
    url_example: String,
    mail_enabled: bool,
    last: Option<String>,
    waiting: usize,
    retry: Option<String>,
    flash: Option<String>,
    error: Option<String>,
}

/// An example address from the address this page was opened under.
fn url_example(headers: &HeaderMap, secure: bool) -> String {
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .filter(|h| {
            h.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | ':' | '[' | ']'))
        })
        .unwrap_or("secmon.example.org");
    format!("{}://{host}", if secure { "https" } else { "http" })
}

async fn render_alerts(
    state: &AppState,
    user: &CurrentUser,
    headers: &HeaderMap,
    form: AlertForm,
    confidence: Confidence,
    flash: Option<String>,
    error: Option<String>,
) -> Result<String> {
    let t = user.lang;
    let settings = store::settings(&state.pool).await?;
    let st = store::state(&state.pool).await?;
    let mail_enabled = mail_store::get_view(&state.pool).await?.enabled;
    let waiting = if mail_enabled && settings.instant {
        matches::unalerted(&state.pool)
            .await?
            .iter()
            .filter(|r| !alerts::reasons(&settings, r).is_empty())
            .count()
    } else {
        0
    };
    let now = now_ms();
    let page = AlertsTemplate {
        t,
        layout: user.layout(),
        form,
        confidences: [Confidence::High, Confidence::Medium, Confidence::Low]
            .into_iter()
            .map(|c| ConfidenceOption {
                value: c.as_str(),
                label: t.get(c.label_id()),
                selected: c == confidence,
            })
            .collect(),
        url_example: url_example(headers, state.cookie_secure),
        mail_enabled,
        last: st.last_alert_ms.map(time_html),
        waiting,
        retry: (st.alert_failures > 0 && st.alert_retry_ms > now)
            .then(|| time_html(st.alert_retry_ms)),
        flash,
        error,
    };
    Ok(page.render()?)
}

pub async fn alerts_page(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Query(query): Query<FlashQuery>,
) -> Result<Html<String>> {
    let s = store::settings(&state.pool).await?;
    let flash = flash_message(user.lang, query.msg.as_deref());
    let form = AlertForm::of(user.lang, &s);
    Ok(Html(
        render_alerts(&state, &user, &headers, form, s.min_confidence, flash, None).await?,
    ))
}

#[derive(Deserialize)]
pub struct AlertsInput {
    csrf_token: String,
    instant: Option<String>,
    on_kev: Option<String>,
    prio_on: Option<String>,
    #[serde(default)]
    prio_min: String,
    cvss_on: Option<String>,
    #[serde(default)]
    cvss_min: String,
    epss_on: Option<String>,
    #[serde(default)]
    epss_min: String,
    #[serde(default)]
    min_confidence: String,
    bundle: Option<String>,
    once_per_vuln: Option<String>,
    #[serde(default)]
    public_url: String,
}

impl AlertsInput {
    fn form(&self) -> AlertForm {
        AlertForm {
            instant: self.instant.is_some(),
            on_kev: self.on_kev.is_some(),
            prio_on: self.prio_on.is_some(),
            prio_min: self.prio_min.clone(),
            cvss_on: self.cvss_on.is_some(),
            cvss_min: self.cvss_min.clone(),
            epss_on: self.epss_on.is_some(),
            epss_min: self.epss_min.clone(),
            bundle: self.bundle.is_some(),
            once_per_vuln: self.once_per_vuln.is_some(),
            public_url: self.public_url.clone(),
        }
    }

    fn confidence(&self) -> Confidence {
        Confidence::parse(&self.min_confidence)
    }

    /// The new settings on top of `current` (the report part stays).
    fn apply(&self, current: &Settings) -> std::result::Result<Settings, &'static str> {
        let prio_min = self
            .prio_min
            .trim()
            .parse::<i64>()
            .ok()
            .filter(|p| (0..=100).contains(p))
            .ok_or("alerts-error-prio")?;
        let cvss_min = number(&self.cvss_min)
            .filter(|c| (0.0..=10.0).contains(c))
            .ok_or("alerts-error-cvss")?;
        let epss_min = number(&self.epss_min)
            .filter(|e| (0.0..=100.0).contains(e))
            .ok_or("alerts-error-epss")?;
        Ok(Settings {
            instant: self.instant.is_some(),
            on_kev: self.on_kev.is_some(),
            prio_on: self.prio_on.is_some(),
            prio_min,
            cvss_on: self.cvss_on.is_some(),
            cvss_min: (cvss_min * 10.0).round() / 10.0,
            epss_on: self.epss_on.is_some(),
            epss_min: (epss_min * 10.0).round() / 10.0,
            min_confidence: self.confidence(),
            bundle: self.bundle.is_some(),
            once_per_vuln: self.once_per_vuln.is_some(),
            public_url: check_public_url(&self.public_url)?,
            ..current.clone()
        })
    }
}

fn alert_changes(old: &Settings, new: &Settings) -> Changes {
    Changes::new()
        .label(
            "audit-field-enabled",
            yes_no(old.instant),
            yes_no(new.instant),
        )
        .label(
            "audit-field-alert-kev",
            yes_no(old.on_kev),
            yes_no(new.on_kev),
        )
        .field(
            "audit-field-alert-prio",
            threshold(old.prio_on, old.prio_min),
            threshold(new.prio_on, new.prio_min),
        )
        .field(
            "audit-field-alert-cvss",
            threshold(old.cvss_on, old.cvss_min),
            threshold(new.cvss_on, new.cvss_min),
        )
        .field(
            "audit-field-alert-epss",
            threshold(old.epss_on, old.epss_min),
            threshold(new.epss_on, new.epss_min),
        )
        .label(
            "audit-field-confidence",
            old.min_confidence.label_id(),
            new.min_confidence.label_id(),
        )
        .label(
            "audit-field-alert-bundle",
            yes_no(old.bundle),
            yes_no(new.bundle),
        )
        .label(
            "audit-field-alert-once",
            yes_no(old.once_per_vuln),
            yes_no(new.once_per_vuln),
        )
        .field("audit-field-url", &old.public_url, &new.public_url)
}

pub async fn alerts_save(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Form(input): Form<AlertsInput>,
) -> Result<Response> {
    user.verify_csrf(&input.csrf_token)?;
    let before = store::settings(&state.pool).await?;
    match input.apply(&before) {
        Ok(after) => {
            store::save(&state.pool, &after, now_ms()).await?;
            audit::record(
                &state,
                &user,
                Action::Changed,
                Object {
                    kind: AuditKind::Alerts,
                    id: None,
                    name: "",
                },
                alert_changes(&before, &after),
            )
            .await;
            Ok(Redirect::to("/settings/alerts?msg=alerts_saved").into_response())
        }
        Err(id) => {
            let error = Some(user.lang.get(id));
            let html = render_alerts(
                &state,
                &user,
                &headers,
                input.form(),
                input.confidence(),
                None,
                error,
            )
            .await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, Html(html)).into_response())
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// Daily report

struct ReportForm {
    report: bool,
    time: String,
    new: bool,
    open: bool,
    sources: bool,
    due: bool,
    skip_empty: bool,
}

impl ReportForm {
    fn of(s: &Settings) -> Self {
        Self {
            report: s.report,
            time: format!("{:02}:{:02}", s.report_minute / 60, s.report_minute % 60),
            new: s.report_new,
            open: s.report_open,
            sources: s.report_sources,
            due: s.report_due,
            skip_empty: s.report_skip_empty,
        }
    }
}

/// The report as it would go out now.
struct Preview {
    subject: String,
    body: String,
    to: String,
    /// Empty and "skip empty" is on.
    skipped: bool,
}

/// Result of "send now", shown on the page.
enum SendOutcome {
    Sent(String),
    Failed(String),
}

#[derive(Template)]
#[template(path = "report_settings.html")]
struct ReportTemplate {
    t: Lang,
    layout: Layout,
    form: ReportForm,
    zone: String,
    mail_enabled: bool,
    next: Option<String>,
    last: Option<String>,
    preview: Preview,
    flash: Option<String>,
    error: Option<String>,
    sent_ok: Option<String>,
    sent_error: Option<String>,
}

async fn render_report(
    state: &AppState,
    user: &CurrentUser,
    form: ReportForm,
    flash: Option<String>,
    error: Option<String>,
    outcome: Option<SendOutcome>,
) -> Result<String> {
    let t = user.lang;
    let settings = store::settings(&state.pool).await?;
    let st = store::state(&state.pool).await?;
    let config = mail_store::load_config(&state.pool, &state.secrets).await?;
    let now = now_ms();
    let data = alerts::build_report(
        &state.pool,
        &settings,
        config.language,
        now,
        st.last_report_ms,
    )
    .await?;
    let links =
        compose::Links((!settings.public_url.is_empty()).then_some(settings.public_url.as_str()));
    let mail = compose::report(config.language, &state.time_zone, &data, &links);
    let to = if config.recipients.is_empty() {
        t.get("report-preview-no-recipients")
    } else {
        t.get1(
            "report-preview-to",
            "recipients",
            config.recipients.join(", "),
        )
    };
    let (sent_ok, sent_error) = match outcome {
        Some(SendOutcome::Sent(m)) => (Some(m), None),
        Some(SendOutcome::Failed(m)) => (None, Some(m)),
        None => (None, None),
    };
    let page = ReportTemplate {
        t,
        layout: user.layout(),
        form,
        zone: state.time_zone_name.clone(),
        mail_enabled: config.enabled,
        next: (config.enabled && settings.report).then(|| {
            time_html(alerts::next_slot_ms(
                &state.time_zone,
                now,
                settings.report_minute,
            ))
        }),
        last: st.last_report_ms.map(time_html),
        preview: Preview {
            subject: mail.subject,
            body: mail.body,
            to,
            skipped: settings.report_skip_empty && data.is_empty(),
        },
        flash,
        error,
        sent_ok,
        sent_error,
    };
    Ok(page.render()?)
}

pub async fn report_page(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<FlashQuery>,
) -> Result<Html<String>> {
    let s = store::settings(&state.pool).await?;
    let flash = flash_message(user.lang, query.msg.as_deref());
    Ok(Html(
        render_report(&state, &user, ReportForm::of(&s), flash, None, None).await?,
    ))
}

#[derive(Deserialize)]
pub struct ReportInput {
    csrf_token: String,
    report: Option<String>,
    #[serde(default)]
    time: String,
    report_new: Option<String>,
    report_open: Option<String>,
    report_sources: Option<String>,
    report_due: Option<String>,
    report_skip_empty: Option<String>,
}

/// `HH:MM` as minutes after midnight.
fn parse_time(text: &str) -> Option<i64> {
    let (h, m) = text.trim().split_once(':')?;
    let (h, m) = (h.parse::<i64>().ok()?, m.parse::<i64>().ok()?);
    ((0..24).contains(&h) && (0..60).contains(&m) && text.trim().len() <= 5).then_some(h * 60 + m)
}

impl ReportInput {
    fn form(&self) -> ReportForm {
        ReportForm {
            report: self.report.is_some(),
            time: self.time.chars().take(8).collect(),
            new: self.report_new.is_some(),
            open: self.report_open.is_some(),
            sources: self.report_sources.is_some(),
            due: self.report_due.is_some(),
            skip_empty: self.report_skip_empty.is_some(),
        }
    }

    fn apply(&self, current: &Settings) -> std::result::Result<Settings, &'static str> {
        Ok(Settings {
            report: self.report.is_some(),
            report_minute: parse_time(&self.time).ok_or("report-error-time")?,
            report_new: self.report_new.is_some(),
            report_open: self.report_open.is_some(),
            report_sources: self.report_sources.is_some(),
            report_due: self.report_due.is_some(),
            report_skip_empty: self.report_skip_empty.is_some(),
            ..current.clone()
        })
    }
}

fn report_changes(old: &Settings, new: &Settings) -> Changes {
    let time = |s: &Settings| format!("{:02}:{:02}", s.report_minute / 60, s.report_minute % 60);
    Changes::new()
        .label(
            "audit-field-enabled",
            yes_no(old.report),
            yes_no(new.report),
        )
        .field("audit-field-report-time", time(old), time(new))
        .label(
            "audit-field-report-new",
            yes_no(old.report_new),
            yes_no(new.report_new),
        )
        .label(
            "audit-field-report-open",
            yes_no(old.report_open),
            yes_no(new.report_open),
        )
        .label(
            "audit-field-report-sources",
            yes_no(old.report_sources),
            yes_no(new.report_sources),
        )
        .label(
            "audit-field-report-due",
            yes_no(old.report_due),
            yes_no(new.report_due),
        )
        .label(
            "audit-field-report-skip",
            yes_no(old.report_skip_empty),
            yes_no(new.report_skip_empty),
        )
}

pub async fn report_save(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(input): Form<ReportInput>,
) -> Result<Response> {
    user.verify_csrf(&input.csrf_token)?;
    let before = store::settings(&state.pool).await?;
    match input.apply(&before) {
        Ok(after) => {
            store::save(&state.pool, &after, now_ms()).await?;
            audit::record(
                &state,
                &user,
                Action::Changed,
                Object {
                    kind: AuditKind::Report,
                    id: None,
                    name: "",
                },
                report_changes(&before, &after),
            )
            .await;
            Ok(Redirect::to("/settings/report?msg=report_saved").into_response())
        }
        Err(id) => {
            let error = Some(user.lang.get(id));
            let html = render_report(&state, &user, input.form(), None, error, None).await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, Html(html)).into_response())
        }
    }
}

/// "Send now": the report as of now, with the stored settings.
pub async fn report_send(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(form): Form<CsrfForm>,
) -> Result<Html<String>> {
    user.verify_csrf(&form.csrf_token)?;
    let outcome =
        alerts::send_report_now(&state.pool, &state.secrets, &state.time_zone, now_ms()).await?;
    tracing::info!(user = %user.username, ok = outcome.is_ok(), "daily report sent by hand");
    let outcome = match outcome {
        Ok(to) => SendOutcome::Sent(user.lang.get1("report-sent", "recipients", to.join(", "))),
        Err(message) => SendOutcome::Failed(user.lang.msg(&message)),
    };
    let s = store::settings(&state.pool).await?;
    Ok(Html(
        render_report(&state, &user, ReportForm::of(&s), None, None, Some(outcome)).await?,
    ))
}

#[cfg(test)]
mod tests;
