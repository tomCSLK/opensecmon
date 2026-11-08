//! The page "Sources" (docs/entwurf/quellen.html): the state of every source, "fetch now", switching a
//! source on and off and its interval. While a source runs, `static/sources.js` refreshes the table.

use askama::Template;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};

use crate::audit::{Action, Changes, Kind};
use crate::error::{Error, Result};
use crate::i18n::Lang;
use crate::sources::{SourceId, now_ms};
use crate::storage::sources::{self as store, SourceState};
use crate::web::audit::{Object, record};
use crate::web::auth::CurrentUser;
use crate::web::{AppState, FlashQuery, Layout, flash_message, time_html};

/// How a source is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    Running,
    Off,
    Failed,
    /// Never fetched yet.
    Waiting,
    /// The last success is long ago (three intervals and an hour).
    Stale,
    Ok,
}

impl Health {
    pub fn of(state: &SourceState, running: bool, now: i64) -> Self {
        if running {
            Self::Running
        } else if !state.enabled {
            Self::Off
        } else if state.failures > 0 {
            Self::Failed
        } else if let Some(success) = state.last_success_ms {
            if now - success > (3 * state.interval_secs + 3600) * 1000 {
                Self::Stale
            } else {
                Self::Ok
            }
        } else {
            Self::Waiting
        }
    }

    /// CSS class of the state (`.state.*`).
    pub fn class(self) -> &'static str {
        match self {
            Self::Running => "run",
            Self::Off | Self::Waiting => "off",
            Self::Failed => "err",
            Self::Stale => "warn",
            Self::Ok => "ok",
        }
    }

    pub fn icon(self) -> &'static str {
        match self {
            Self::Running => "refresh",
            Self::Off => "pause-circle",
            Self::Waiting => "clock",
            Self::Failed => "x-circle",
            Self::Stale => "alert",
            Self::Ok => "check-circle",
        }
    }

    pub fn label_id(self) -> &'static str {
        match self {
            Self::Running => "sources-state-running",
            Self::Off => "sources-state-off",
            Self::Waiting => "sources-state-waiting",
            Self::Failed => "sources-state-failed",
            Self::Stale => "sources-state-stale",
            Self::Ok => "sources-state-ok",
        }
    }
}

pub struct IntervalChoice {
    pub secs: i64,
    pub label: String,
    pub current: bool,
}

pub struct SourceRow {
    pub id: &'static str,
    pub label: String,
    pub health: &'static str,
    pub health_icon: &'static str,
    pub health_label: String,
    pub progress: Option<String>,
    pub last_run: Option<String>,
    pub duration: String,
    pub new: String,
    pub changed: String,
    pub next_run: Option<String>,
    pub interval: String,
    pub intervals: Vec<IntervalChoice>,
    pub enabled: bool,
    pub error: Option<String>,
    pub data_state: Option<String>,
    pub notice: String,
    /// A note on the last run although it succeeded (documents skipped …).
    pub warning: Option<String>,
    /// A page to manage what the source loads (the vendors of "Vendor CSAF").
    pub manage: Option<&'static str>,
    /// The details row starts open (after an error).
    pub open: bool,
}

#[derive(Template)]
#[template(path = "sources.html")]
struct SourcesTemplate {
    t: Lang,
    layout: Layout,
    rows: Vec<SourceRow>,
    scheduled: bool,
    running: bool,
    flash: Option<String>,
    error: Option<String>,
}

/// A duration in milliseconds, short: `850 ms`, `12 s`, `3 min 4 s`, `1 h 2 min`.
pub fn duration(ms: i64) -> String {
    let secs = ms / 1000;
    match secs {
        _ if ms < 1000 => format!("{ms} ms"),
        0..60 => format!("{secs} s"),
        60..3600 => format!("{} min {} s", secs / 60, secs % 60),
        _ => format!("{} h {} min", secs / 3600, (secs % 3600) / 60),
    }
}

/// An interval in seconds: `1 h`, `6 h`, `daily`.
pub fn interval_label(t: Lang, secs: i64) -> String {
    if secs == 86_400 {
        t.get("sources-interval-daily")
    } else if secs % 3600 == 0 {
        t.get1("sources-interval-hours", "hours", secs / 3600)
    } else {
        t.get1("sources-interval-minutes", "minutes", secs / 60)
    }
}

fn row(t: Lang, id: SourceId, s: &SourceState, state: &AppState, now: i64) -> SourceRow {
    let running = state.sources.running().filter(|r| r.source == id);
    let health = Health::of(s, running.is_some(), now);
    let number = |n: Option<i64>| n.map_or_else(|| "–".to_owned(), |n| t.number(n));
    SourceRow {
        id: id.as_str(),
        label: t.get(id.label_id()),
        health: health.class(),
        health_icon: health.icon(),
        health_label: t.get(health.label_id()),
        progress: running.map(|r| {
            t.get1(
                "sources-progress",
                "count",
                t.number(i64::try_from(r.processed).unwrap_or(i64::MAX)),
            )
        }),
        last_run: s.last_finished_ms.map(time_html),
        duration: s.last_duration_ms.map_or_else(|| "–".to_owned(), duration),
        new: number(s.last_new),
        changed: number(s.last_changed),
        next_run: (s.enabled && state.sources.scheduled() && running.is_none())
            .then(|| time_html(s.next_run_ms.max(now))),
        interval: interval_label(t, s.interval_secs),
        intervals: id
            .intervals()
            .into_iter()
            .map(|secs| IntervalChoice {
                secs,
                label: interval_label(t, secs),
                current: secs == s.interval_secs,
            })
            .collect(),
        enabled: s.enabled,
        error: s
            .last_error
            .clone()
            .filter(|_| s.failures > 0 && running.is_none()),
        data_state: s.version.as_ref().map(|version| {
            t.get2(
                id.state_id(),
                "version",
                version.clone(),
                "count",
                t.number(s.item_count.unwrap_or(0)),
            )
        }),
        notice: t.get(id.notice_id()),
        warning: s
            .last_warning
            .clone()
            .filter(|_| s.failures == 0 && running.is_none()),
        manage: (id == SourceId::Vendor).then_some("/sources/vendors"),
        open: health == Health::Failed,
    }
}

async fn render(
    state: &AppState,
    user: &CurrentUser,
    flash: Option<String>,
    error: Option<String>,
) -> Result<Html<String>> {
    let t = user.lang;
    let now = now_ms();
    let states = store::all(&state.pool).await?;
    let rows = SourceId::ALL
        .iter()
        .filter_map(|&id| {
            states
                .iter()
                .find(|s| s.source == id.as_str())
                .map(|s| row(t, id, s, state, now))
        })
        .collect();
    Ok(Html(
        SourcesTemplate {
            t,
            layout: user.layout().at("sources"),
            rows,
            scheduled: state.sources.scheduled(),
            running: state.sources.running().is_some(),
            flash,
            error,
        }
        .render()?,
    ))
}

pub async fn page(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<FlashQuery>,
) -> Result<Html<String>> {
    let flash = flash_message(user.lang, query.msg.as_deref());
    let error = match query.msg.as_deref() {
        Some("source_off") => Some(user.lang.get("sources-run-off")),
        _ => None,
    };
    render(&state, &user, flash, error).await
}

#[derive(serde::Deserialize)]
pub struct CsrfForm {
    csrf_token: String,
}

#[derive(serde::Deserialize)]
pub struct SettingsForm {
    csrf_token: String,
    enabled: Option<String>,
    interval_secs: String,
}

fn source(id: &str) -> Result<SourceId> {
    SourceId::parse(id).ok_or(Error::NotFound)
}

/// Switches a source on or off and sets its interval.
pub async fn save(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Form(form): Form<SettingsForm>,
) -> Result<Response> {
    user.verify_csrf(&form.csrf_token)?;
    let id = source(&id)?;
    let before = store::get(&state.pool, id.as_str())
        .await?
        .ok_or(Error::NotFound)?;
    let interval = form
        .interval_secs
        .trim()
        .parse::<i64>()
        .ok()
        .filter(|secs| id.intervals().contains(secs))
        .ok_or_else(|| Error::Invalid(crate::i18n::Msg::new("sources-interval-invalid")))?;
    let enabled = form.enabled.is_some();
    store::configure(&state.pool, id.as_str(), enabled, interval).await?;
    let t = user.lang;
    let yes_no = |b: bool| if b { "audit-yes" } else { "audit-no" };
    let label = t.get(id.label_id());
    record(
        &state,
        &user,
        Action::Changed,
        Object {
            kind: Kind::Source,
            id: None,
            name: &label,
        },
        Changes::new()
            .label(
                "audit-field-enabled",
                yes_no(before.enabled),
                yes_no(enabled),
            )
            .field(
                "audit-field-interval",
                interval_label(t, before.interval_secs),
                interval_label(t, interval),
            ),
    )
    .await;
    state.sources.wake();
    state.sources.refresh_status().await;
    Ok(Redirect::to("/sources?msg=source_saved").into_response())
}

/// Fetches one source now (it must be switched on).
pub async fn run(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Result<Response> {
    user.verify_csrf(&form.csrf_token)?;
    let id = source(&id)?;
    let s = store::get(&state.pool, id.as_str())
        .await?
        .ok_or(Error::NotFound)?;
    if !s.enabled {
        return Ok(Redirect::to("/sources?msg=source_off").into_response());
    }
    state.sources.run_now(id).await?;
    Ok(Redirect::to("/sources?msg=source_started").into_response())
}

/// Fetches every switched-on source now (one after another).
pub async fn run_all(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(form): Form<CsrfForm>,
) -> Result<Response> {
    user.verify_csrf(&form.csrf_token)?;
    for s in store::all(&state.pool).await? {
        if let (true, Some(id)) = (s.enabled, SourceId::parse(&s.source)) {
            state.sources.run_now(id).await?;
        }
    }
    Ok(Redirect::to("/sources?msg=sources_started").into_response())
}

// Used in sources.html: "sources-warning" "sources-vendors-manage".
// Ids of `Health::label_id`, spelled out for the catalog check: "sources-state-running" "sources-state-off"
// "sources-state-waiting" "sources-state-failed" "sources-state-stale" "sources-state-ok"

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::testutil::*;
    use axum::http::StatusCode;

    #[test]
    fn durations_and_intervals_are_short() {
        assert_eq!(duration(850), "850 ms");
        assert_eq!(duration(12_400), "12 s");
        assert_eq!(duration(184_000), "3 min 4 s");
        assert_eq!(duration(3_720_000), "1 h 2 min");
        assert_eq!(interval_label(Lang::De, 3600), "1 h");
        assert_eq!(interval_label(Lang::De, 86_400), "täglich");
        assert_eq!(interval_label(Lang::En, 1800), "30 min");
    }

    #[test]
    fn every_state_has_a_label() {
        for h in [
            Health::Running,
            Health::Off,
            Health::Failed,
            Health::Waiting,
            Health::Stale,
            Health::Ok,
        ] {
            for lang in Lang::ALL {
                assert_ne!(lang.get(h.label_id()), h.label_id());
            }
        }
    }

    #[tokio::test]
    async fn sources_are_switched_and_fetched_from_the_page() {
        let h = harness(true).await;
        let (session, csrf) = login(&h, "anna").await;
        let reply = send(&h.app, get("/sources", Some(&session))).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert!(reply.body.contains("CISA KEV"), "{}", reply.body);
        assert!(reply.body.contains("Noch nie abgerufen"));

        let form = format!("csrf_token={csrf}&interval_secs=43200");
        let reply = send(&h.app, post("/sources/kev", Some(&session), &form)).await;
        assert_eq!(reply.location(), "/sources?msg=source_saved");
        let s = store::get(&h.state.pool, "kev").await.unwrap().unwrap();
        assert_eq!((s.enabled, s.interval_secs), (false, 43_200));
        let audit = send(&h.app, get("/settings/audit", Some(&session))).await;
        assert!(audit.body.contains("Aktiv: ja → nein"), "{}", audit.body);

        let reply = send(
            &h.app,
            post(
                "/sources/kev/run",
                Some(&session),
                &format!("csrf_token={csrf}"),
            ),
        )
        .await;
        assert_eq!(reply.location(), "/sources?msg=source_off");
        let reply = send(
            &h.app,
            post(
                "/sources/epss/run",
                Some(&session),
                &format!("csrf_token={csrf}"),
            ),
        )
        .await;
        assert_eq!(reply.location(), "/sources?msg=source_started");
        let s = store::get(&h.state.pool, "epss").await.unwrap().unwrap();
        assert_eq!(s.next_run_ms, crate::storage::sources::REQUESTED);

        let bad = send(
            &h.app,
            post(
                "/sources/epss",
                Some(&session),
                &format!("csrf_token={csrf}&interval_secs=60&enabled=1"),
            ),
        )
        .await;
        assert_eq!(bad.status, StatusCode::UNPROCESSABLE_ENTITY);
        let forged = send(
            &h.app,
            post("/sources/run", Some(&session), "csrf_token=wrong"),
        )
        .await;
        assert_eq!(forged.status, StatusCode::FORBIDDEN);
        let unknown = send(
            &h.app,
            post(
                "/sources/nope/run",
                Some(&session),
                &format!("csrf_token={csrf}"),
            ),
        )
        .await;
        assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    }
}
