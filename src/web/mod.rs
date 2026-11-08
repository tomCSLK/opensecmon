//! Web layer: axum router, shared state and handlers.

mod account;
pub mod advisories;
pub mod agent_api;
pub mod alert_settings;
pub mod asset_pages;
mod assets;
pub mod audit;
pub mod auth;
pub mod computers;
pub mod csv_export;
pub mod csv_import;
pub mod cves;
mod distro_view;
mod error_page;
pub mod hosts;
#[cfg(test)]
mod import_tests;
pub mod inbox;
pub mod mail_settings;
pub mod onm_import;
mod origin;
pub mod pages;
pub mod prio_settings;
pub mod retention;
pub mod situation;
pub mod sources;
#[cfg(test)]
pub(crate) mod testutil;
pub mod unassigned;
pub mod vendors;

use axum::Router;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::routing::{get, post};
use sqlx::SqlitePool;
use tower_http::compression::CompressionLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use crate::config::Config;
use crate::crypto::SecretBox;
use crate::i18n::Lang;
use crate::storage;

/// Password checks that may run at the same time (see [`AppState::check_password`]).
pub(crate) const PASSWORD_CHECKS: usize = 4;
/// How long a password check waits for a free slot before the request is turned away.
const PASSWORD_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub secrets: Arc<SecretBox>,
    pub cookie_secure: bool,
    pub session_ttl_secs: i64,
    /// Sign-out after this time without activity (`None`: off).
    pub session_idle_secs: Option<i64>,
    pub login_throttle: Arc<crate::auth::throttle::LoginThrottle>,
    /// Slots for password checks, see [`AppState::check_password`].
    password_checks: Arc<tokio::sync::Semaphore>,
    pub client_ip_header: Option<crate::auth::throttle::ClientIpHeader>,
    /// Host names the interface may be opened under (`Host` header); empty: any.
    pub allowed_hosts: Arc<[String]>,
    /// The data sources (state, "fetch now"); the scheduler itself is started by `serve`.
    pub sources: crate::sources::Sources,
    /// Time zone of the daily report and of the times in mails.
    pub time_zone: jiff::tz::TimeZone,
    /// Its name as the settings show it.
    pub time_zone_name: String,
    /// `retention_audit_days` of the configuration (the page "Retention" may override it).
    pub audit_days: i64,
    /// Networks computers may use the agent API from (`agent_networks`).
    pub agent_networks: Arc<[crate::agent::Network]>,
    /// The certificate of the built-in HTTPS for the page "Add computer" (`None` without built-in HTTPS).
    pub tls_certificate: Option<Arc<crate::tls::PublicCertificate>>,
    /// When each computer last reported (agent API).
    pub agent_pace: Arc<crate::agent::Pace>,
    /// The packages of opensecagent that came with opensecmon (read at start).
    pub agent_packages: Arc<crate::agent_packages::Catalog>,
}

impl AppState {
    pub fn new(pool: SqlitePool, config: &Config, secrets: Arc<SecretBox>) -> Self {
        let sources = crate::sources::Sources::new(
            pool.clone(),
            config.download_dir(),
            crate::sources::Endpoints::default(),
            config.fetch_sources,
        );
        let time_zone = config.zone();
        Self {
            pool,
            secrets,
            sources,
            time_zone: time_zone.clone(),
            time_zone_name: time_zone.iana_name().unwrap_or("UTC").to_owned(),
            audit_days: i64::from(config.retention_audit_days),
            agent_networks: config.agent_networks().into(),
            tls_certificate: config
                .tls_files()
                .and_then(|(cert, _)| crate::tls::public_certificate(cert))
                .map(Arc::new),
            agent_pace: Arc::default(),
            agent_packages: Arc::new(crate::agent_packages::Catalog::load(
                &config.agent_packages_dir(),
            )),
            cookie_secure: config.cookie_secure,
            login_throttle: Arc::default(),
            password_checks: Arc::new(tokio::sync::Semaphore::new(PASSWORD_CHECKS)),
            client_ip_header: config.client_ip_header,
            allowed_hosts: config
                .allowed_hosts
                .iter()
                .map(|h| h.to_ascii_lowercase())
                .collect(),
            session_ttl_secs: i64::try_from(config.session_ttl_hours.saturating_mul(3600))
                .unwrap_or(i64::MAX),
            session_idle_secs: (config.session_idle_minutes > 0)
                .then(|| i64::try_from(config.session_idle_minutes.saturating_mul(60)).ok())
                .flatten(),
        }
    }

    /// Verifies a password against an Argon2 hash on the blocking pool, at most [`PASSWORD_CHECKS`] at a
    /// time: each check takes about 19 MiB, and sign-in attempts need no account, so without a limit a
    /// burst of them (200 at once took 2.4 GB) could exhaust the memory of the host. `None` when no slot
    /// became free within [`PASSWORD_WAIT`]. The slot stays taken until the check is done, even if
    /// the client gives up earlier.
    pub async fn check_password(
        &self,
        hash: String,
        password: String,
    ) -> crate::error::Result<Option<bool>> {
        let slot = Arc::clone(&self.password_checks).acquire_owned();
        let Ok(Ok(slot)) = tokio::time::timeout(PASSWORD_WAIT, slot).await else {
            return Ok(None);
        };
        let verified = tokio::task::spawn_blocking(move || {
            let _slot = slot;
            crate::auth::verify_password(&hash, &password)
        })
        .await
        .map_err(|e| crate::error::Error::Internal(format!("password check task failed: {e}")))?;
        Ok(Some(verified))
    }
}

/// Largest form of the CSV import (the file is at most 1 MiB; URL encoding makes it longer).
const CSV_BODY_LIMIT: usize = 4 * 1024 * 1024;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(inbox::page))
        .route("/inbox", post(inbox::act))
        .route("/inbox.csv", get(inbox::export))
        .route("/situation", get(situation::page))
        .route("/assets", get(asset_pages::list))
        .route(
            "/assets/new",
            get(asset_pages::new_form).post(asset_pages::create),
        )
        .route("/assets/suggest", get(asset_pages::suggest))
        .route("/assets/preview", get(asset_pages::preview_fragment))
        .route(
            "/assets/watchlist",
            get(asset_pages::watchlist).post(asset_pages::add_watch),
        )
        .route(
            "/assets/watchlist/{id}/delete",
            post(asset_pages::delete_watch),
        )
        .route(
            "/assets/{id}",
            get(asset_pages::edit_form).post(asset_pages::update),
        )
        .route("/assets/{id}/delete", post(asset_pages::delete))
        .route("/assets/hosts", get(hosts::list))
        .route("/assets/hosts/new", get(hosts::new_form).post(hosts::create))
        .route("/assets/hosts/{id}", post(hosts::update))
        .route("/assets/hosts/{id}/edit", get(hosts::edit_form))
        .route("/assets/hosts/{id}/setup", get(hosts::setup))
        .route("/assets/hosts/{id}/connect", post(hosts::connect))
        .route("/assets/hosts/{id}/confirm", post(hosts::confirm))
        .route("/assets/hosts/{id}/run", post(hosts::run))
        .route("/assets/hosts/{id}/enabled", post(hosts::set_enabled))
        .route("/assets/hosts/{id}/pro", post(hosts::set_pro))
        .route("/assets/hosts/{id}/delete", post(hosts::delete))
        .route("/assets/unassigned", get(unassigned::page))
        .route(
            "/assets/unassigned/assign",
            get(unassigned::assign_form).post(unassigned::assign),
        )
        .route("/assets/unassigned/ignore", post(unassigned::ignore))
        .route(
            "/assets/unassigned/rules/{id}/delete",
            post(unassigned::delete_rule),
        )
        .route("/assets/computers", get(computers::list))
        .route(
            "/assets/computers/new",
            get(computers::new_form).post(computers::create),
        )
        .route("/assets/computers/opensecmon.pem", get(computers::certificate))
        .route("/assets/computers/opensecmon-agent.sh", get(computers::script))
        .route(
            "/assets/computers/opensecmon-agent.ps1",
            get(computers::windows_script),
        )
        .route(
            "/assets/computers/{id}",
            get(computers::page).post(computers::rename),
        )
        .route("/assets/computers/{id}/code", post(computers::new_code))
        .route("/assets/computers/{id}/update", post(computers::update))
        .route(
            "/assets/computers/{id}/update/cancel",
            post(computers::cancel_update),
        )
        .route("/assets/computers/update-all", post(computers::update_all))
        .route("/assets/computers/agent/{file}", get(computers::agent_package))
        .route("/assets/computers/{id}/pro", post(computers::set_pro))
        .route("/assets/computers/{id}/revoke", post(computers::revoke))
        .route("/assets/computers/{id}/delete", post(computers::delete))
        .route(
            "/api/v1/agent/enroll",
            post(agent_api::enroll).layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route("/api/v1/agent/status", get(agent_api::status))
        .route("/api/v1/agent/packages/{file}", get(agent_api::package))
        .route(
            "/api/v1/agent/report",
            post(agent_api::report).layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .route("/assets/opennetmon", get(onm_import::page))
        .route("/assets/opennetmon/settings", post(onm_import::save))
        .route("/assets/opennetmon/run", post(onm_import::run))
        .route("/assets/opennetmon/{id}/take", post(onm_import::take))
        .route("/assets/opennetmon/{id}/state", post(onm_import::set_state))
        .route(
            "/assets/csv",
            get(csv_import::page)
                .post(csv_import::submit)
                .layer(axum::extract::DefaultBodyLimit::max(CSV_BODY_LIMIT)),
        )
        .route("/cves", get(cves::list))
        .route("/cves.csv", get(cves::export))
        .route("/cves/{id}", get(cves::page))
        .route("/advisories", get(advisories::list))
        .route("/advisories/{seq}", get(advisories::page))
        .route("/sources", get(sources::page))
        .route("/sources/run", post(sources::run_all))
        .route("/sources/vendors", get(vendors::page).post(vendors::add))
        .route("/sources/vendors/lister", post(vendors::load_lister))
        .route("/sources/vendors/{id}", post(vendors::save))
        .route("/sources/vendors/{id}/delete", post(vendors::delete))
        .route("/sources/{id}", post(sources::save))
        .route("/sources/{id}/run", post(sources::run))
        .route("/login", get(auth::login_form).post(auth::login_submit))
        .route("/logout", post(auth::logout))
        .route(
            "/session",
            get(auth::session_state).post(auth::session_active),
        )
        .route("/settings", get(pages::settings))
        .route(
            "/settings/mail",
            get(mail_settings::show).post(mail_settings::save),
        )
        .route("/settings/mail/test", post(mail_settings::send_test))
        .route(
            "/settings/alerts",
            get(alert_settings::alerts_page).post(alert_settings::alerts_save),
        )
        .route(
            "/settings/report",
            get(alert_settings::report_page).post(alert_settings::report_save),
        )
        .route("/settings/report/send", post(alert_settings::report_send))
        .route(
            "/settings/retention",
            get(retention::page).post(retention::save),
        )
        .route("/settings/retention/vacuum", post(retention::vacuum))
        .route(
            "/settings/priority",
            get(prio_settings::page).post(prio_settings::save),
        )
        .route("/settings/account", get(account::show))
        .route("/settings/account/password", post(account::change_password))
        .route("/settings/account/language", post(account::set_language))
        .route("/settings/audit", get(audit::page))
        .route("/healthz", get(healthz))
        .route("/static/{*path}", get(assets::serve))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            error_page::render,
        ))
        .layer(security_header(header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .layer(security_header(header::X_FRAME_OPTIONS, "DENY"))
        .layer(security_header(header::REFERRER_POLICY, "same-origin"))
        .layer(security_header(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'",
        ))
        // Pages show advisories, assets and forms of signed-in users: never keep them in a cache, so they
        // cannot be shown again (e.g. with the back button) after signing out. Static files set their
        // own `no-cache` with an ETag.
        .layer(security_header(header::CACHE_CONTROL, "no-store"))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            origin::check,
        ))
        .layer(axum::middleware::from_fn(request_language))
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Runs every request in the browser's language; signed-in users switch it to their own (see `CurrentUser`).
async fn request_language(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let lang = auth::browser_language(request.headers());
    crate::i18n::scope(lang, next.run(request)).await
}

fn security_header(name: HeaderName, value: &'static str) -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::if_not_present(name, HeaderValue::from_static(value))
}

/// An entry of the language selection; `code` is empty for "follow the browser".
pub struct LanguageOption {
    pub code: &'static str,
    pub label: String,
    pub selected: bool,
}

/// The choices for a user's language: the browser's first, then every language by its own name.
pub fn language_options(t: Lang, chosen: Option<Lang>) -> Vec<LanguageOption> {
    let mut options = vec![LanguageOption {
        code: "",
        label: t.get("language-browser"),
        selected: chosen.is_none(),
    }];
    options.extend(Lang::ALL.into_iter().map(|lang| LanguageOption {
        code: lang.code(),
        label: lang.native_name().to_owned(),
        selected: chosen == Some(lang),
    }));
    options
}

/// A submitted language choice: empty for "follow the browser".
pub fn parse_language_choice(code: &str) -> crate::error::Result<Option<Lang>> {
    if code.is_empty() {
        return Ok(None);
    }
    Lang::parse(code)
        .map(Some)
        .ok_or_else(|| crate::error::Error::invalid(crate::i18n::Msg::new("language-invalid")))
}

/// How a user's language choice is shown in lists.
pub fn language_label(t: Lang, chosen: Option<Lang>) -> String {
    chosen.map_or_else(|| t.get("language-browser"), |l| l.native_name().to_owned())
}

/// `?msg=` of a page that shows a [`flash_message`].
#[derive(serde::Deserialize)]
pub struct FlashQuery {
    pub msg: Option<String>,
}

/// Message shown after a successful action (`?msg=` is mapped to fixed texts, never echoed).
pub fn flash_message(t: Lang, key: Option<&str>) -> Option<String> {
    let id = match key? {
        "account_password_saved" => "flash-account-password-saved",
        "mail_saved" => "flash-mail-saved",
        "language_saved" => "flash-language-saved",
        "source_saved" => "flash-source-saved",
        "source_started" => "flash-source-started",
        "sources_started" => "flash-sources-started",
        "provider_added" => "flash-provider-added",
        "provider_saved" => "flash-provider-saved",
        "provider_deleted" => "flash-provider-deleted",
        "lister_loaded" => "flash-lister-loaded",
        "asset_added" => "flash-asset-added",
        "asset_saved" => "flash-asset-saved",
        "asset_deleted" => "flash-asset-deleted",
        "watch_added" => "flash-watch-added",
        "watch_deleted" => "flash-watch-deleted",
        "triage_done" => "flash-triage-done",
        "triage_later" => "flash-triage-later",
        "triage_ignored" => "flash-triage-ignored",
        "triage_reopened" => "flash-triage-reopened",
        "host_saved" => "flash-host-saved",
        "host_read" => "flash-host-read",
        "host_deleted" => "flash-host-deleted",
        "computer_saved" => "flash-computer-saved",
        "computer_code" => "flash-computer-code",
        "computer_update" => "flash-computer-update",
        "computer_update_cancelled" => "flash-computer-update-cancelled",
        "computer_revoked" => "flash-computer-revoked",
        "computer_deleted" => "flash-computer-deleted",
        "item_assigned" => "flash-item-assigned",
        "item_ignored" => "flash-item-ignored",
        "rule_deleted" => "flash-rule-deleted",
        "onm_saved" => "flash-onm-saved",
        "onm_read" => "flash-onm-read",
        "device_taken" => "flash-device-taken",
        "csv_imported" => "flash-csv-imported",
        "alerts_saved" => "alerts-saved",
        "report_saved" => "report-saved",
        "prio_saved" => "prio-saved",
        "retention_saved" => "retention-saved",
        "vacuum_started" => "retention-vacuum-started",
        _ => return None,
    };
    Some(t.get(id))
}

/// Civil date and time of Unix milliseconds in UTC: `(year, month, day, hour, minute, second)`.
fn civil_utc(ms: i64) -> (i64, i64, i64, i64, i64, i64) {
    let secs = ms.div_euclid(1000);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day, rem / 3_600, (rem % 3_600) / 60, rem % 60)
}

/// Formats Unix milliseconds as `2026-10-15 19:32:10 UTC` (plain text, e.g. for e-mails).
pub fn format_utc(ms: i64) -> String {
    let (y, mo, d, h, mi, s) = civil_utc(ms);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02} UTC")
}

/// A timestamp for HTML pages: `<time>` with the exact instant in `datetime` and the UTC text as content.
/// `static/time.js` rewrites it into the browser's time zone; without JavaScript the UTC text stays.
/// The result contains only digits and fixed text, so it may be rendered with `|safe`.
pub fn time_html(ms: i64) -> String {
    let (y, mo, d, h, mi, s) = civil_utc(ms);
    format!(
        "<time class=\"ts\" datetime=\"{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z\">{}</time>",
        format_utc(ms)
    )
}

/// Unix milliseconds as an ISO timestamp in UTC (`2026-11-07T14:02:11Z`), e.g. for JSON.
pub fn iso_utc(ms: i64) -> String {
    let (y, mo, d, h, mi, s) = civil_utc(ms);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Like [`time_html`] for an ISO timestamp as SQLite writes it (`2026-10-16T18:30:00.123Z`).
/// Anything that is not a plain timestamp is reduced to its digits and separators, so the result
/// is always safe to render with `|safe`.
pub fn iso_time_html(iso: &str) -> String {
    let clean: String = iso
        .chars()
        .filter(|c| c.is_ascii_digit() || matches!(c, '-' | ':' | 'T' | 'Z' | '.'))
        .take(32)
        .collect();
    let text = clean.replace('T', " ").trim_end_matches('Z').to_owned();
    let text = text.split('.').next().unwrap_or_default().to_owned();
    format!("<time class=\"ts\" datetime=\"{clean}\">{text} UTC</time>")
}

/// Where this program's source code is offered to its users (AGPL-3.0, section 13); `repository` in Cargo.toml.
pub const SOURCE_URL: &str = env!("CARGO_PKG_REPOSITORY");
/// Program version shown next to the source link.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Data every logged-in page needs for the frame (navigation, user menu, sign-out form).
pub struct Layout {
    pub username: String,
    pub csrf_token: String,
    /// Seconds until the sign-out without activity (`None`: no limit); read by `static/session.js`.
    pub session_left: Option<i64>,
    /// The entry of the main navigation for this page (`""`: none, e.g. the settings).
    pub active: &'static str,
    /// The state of the sources, shown in the top bar.
    pub sources: crate::sources::Status,
    /// Vulnerabilities with open matches (the count beside "Inbox").
    pub open: i64,
}

/// The state of the sources in the top bar: a coloured dot and a short text.
pub struct StatusChip {
    /// `ok`, `warn`, `err`, `run` or `off`.
    pub class: &'static str,
    pub text: String,
    /// End of the last run (a `<time>` element, safe to render).
    pub checked: Option<String>,
}

/// An entry of the main navigation.
pub struct NavItem {
    pub href: &'static str,
    pub icon: &'static str,
    /// Text in the top bar.
    pub label: String,
    /// Shorter text in the bottom bar of narrow screens.
    pub short: String,
    pub current: bool,
    /// A count beside the entry (open matches of the inbox), 0: none.
    pub count: i64,
}

/// The main navigation: `(key, path, icon, label, short label)`.
const NAV: [(&str, &str, &str, &str, &str); 5] = [
    ("inbox", "/", "inbox", "nav-inbox", "nav-inbox"),
    (
        "situation",
        "/situation",
        "activity",
        "nav-situation",
        "nav-situation",
    ),
    ("assets", "/assets", "server", "nav-assets", "nav-assets"),
    ("cves", "/cves", "list", "nav-cves", "nav-cves-short"),
    ("sources", "/sources", "rss", "nav-sources", "nav-sources"),
];

impl Layout {
    /// The layout for the page `active` (a key of the main navigation).
    pub fn at(mut self, active: &'static str) -> Self {
        self.active = active;
        self
    }

    /// The state of the sources for the top bar (`None` until it has been read once).
    pub fn status_chip(&self, t: Lang) -> Option<StatusChip> {
        let s = self.sources;
        if !s.known {
            return None;
        }
        // `short`: static/time.js shows only the time of day for today.
        let checked = s
            .checked_ms
            .map(|ms| time_html(ms).replacen("class=\"ts\"", "class=\"ts short\"", 1));
        let (class, text) = if let Some(source) = s.running {
            (
                "run",
                t.get1("status-running", "source", t.get(source.label_id())),
            )
        } else if s.failing > 0 {
            ("err", t.get1("status-failing", "count", s.failing))
        } else if checked.is_none() {
            ("off", t.get("status-never"))
        } else {
            ("ok", t.get("status-ok"))
        };
        Some(StatusChip {
            class,
            text,
            checked,
        })
    }

    pub fn nav(&self, t: Lang) -> Vec<NavItem> {
        NAV.iter()
            .map(|&(key, href, icon, label, short)| NavItem {
                href,
                icon,
                label: t.get(label),
                short: t.get(short),
                current: key == self.active,
                count: if key == "inbox" { self.open } else { 0 },
            })
            .collect()
    }
}

/// Unauthenticated health check; exposes no internal details.
async fn healthz(State(state): State<AppState>) -> (StatusCode, &'static str) {
    match storage::ping(&state.pool).await {
        Ok(()) => (StatusCode::OK, "ok"),
        Err(e) => {
            tracing::warn!(error = %e, "health check failed");
            (StatusCode::SERVICE_UNAVAILABLE, "unavailable")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn test_state() -> (AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pool = storage::connect(&dir.path().join("t.db")).await.unwrap();
        storage::migrate(&pool).await.unwrap();
        let secrets = Arc::new(SecretBox::from_key([1u8; 32]));
        (AppState::new(pool, &Config::default(), secrets), dir)
    }

    async fn get_path(app: Router, path: &str) -> (StatusCode, String) {
        let response = app
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[test]
    fn utc_timestamps_are_formatted() {
        assert_eq!(format_utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_utc(951_782_400_000), "2000-02-29 00:00:00 UTC");
        assert_eq!(format_utc(1_781_551_930_000), "2026-06-15 19:32:10 UTC");
        assert_eq!(format_utc(-1_000), "1969-12-31 23:59:59 UTC");
    }

    #[test]
    fn html_timestamps_carry_the_instant_and_a_utc_fallback() {
        assert_eq!(
            time_html(1_781_551_930_000),
            "<time class=\"ts\" datetime=\"2026-06-15T19:32:10Z\">2026-06-15 19:32:10 UTC</time>"
        );
        assert!(time_html(0).contains("datetime=\"1970-01-01T00:00:00Z\""));
    }

    #[test]
    fn iso_timestamps_are_rendered_safely() {
        assert_eq!(
            iso_time_html("2026-10-16T18:30:00.123Z"),
            "<time class=\"ts\" datetime=\"2026-10-16T18:30:00.123Z\">2026-10-16 18:30:00 UTC</time>"
        );
        assert!(!iso_time_html("\"><script>alert(1)</script>").contains("script"));
    }

    #[tokio::test]
    async fn healthz_is_ok_without_auth() {
        let (state, _dir) = test_state().await;
        let (status, body) = get_path(router(state), "/healthz").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "ok");
    }

    #[tokio::test]
    async fn healthz_reports_unavailable_when_db_is_closed() {
        let (state, _dir) = test_state().await;
        state.pool.close().await;
        let (status, body) = get_path(router(state), "/healthz").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, "unavailable");
    }

    #[tokio::test]
    async fn unknown_path_is_404() {
        let (state, _dir) = test_state().await;
        let (status, _) = get_path(router(state), "/nope").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn responses_carry_security_headers() {
        let (state, _dir) = test_state().await;
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let h = response.headers();
        assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(h[header::X_FRAME_OPTIONS], "DENY");
        let csp = h[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
        for directive in [
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "object-src 'none'",
        ] {
            assert!(csp.contains(directive), "{csp}");
        }
        assert_eq!(h[header::CACHE_CONTROL], "no-store");
    }

    #[test]
    fn the_navigation_marks_the_current_page() {
        let layout = Layout {
            username: "anna".to_owned(),
            csrf_token: String::new(),
            session_left: None,
            active: "",
            sources: crate::sources::Status::default(),
            open: 3,
        }
        .at("cves");
        let nav = layout.nav(Lang::De);
        assert_eq!(nav.len(), 5);
        let current: Vec<_> = nav.iter().filter(|n| n.current).map(|n| n.href).collect();
        assert_eq!(current, ["/cves"]);
        let counts: Vec<_> = nav.iter().map(|n| n.count).collect();
        assert_eq!(counts, [3, 0, 0, 0, 0], "only the inbox counts");
        assert_eq!(
            (nav[3].label.as_str(), nav[3].short.as_str()),
            ("Alle CVEs", "CVEs")
        );
    }
}
