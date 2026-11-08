//! Settings page "Retention" (`/settings/retention`): how long the audit log and closed matches stay, the size
//! of the database by area and "compact the database" (`/settings/retention/vacuum`).

use askama::Template;
use axum::Form;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::audit::{Action, Changes, Kind as AuditKind};
use crate::error::Result;
use crate::i18n::Lang;
use crate::sources::now_ms;
use crate::storage::retention::{self as store, Settings};
use crate::web::audit::{self, Object};
use crate::web::auth::CurrentUser;
use crate::web::{AppState, FlashQuery, Layout, flash_message, time_html};

const AUDIT_CHOICES: [i64; 5] = [90, 180, 365, 730, 1825];
const CLOSED_CHOICES: [i64; 4] = [90, 365, 730, 0];

/// A size in bytes as shown ("1,8 GB", "520 MB").
pub fn size_text(t: Lang, bytes: i64) -> String {
    const MB: f64 = 1_000_000.0;
    let b = bytes.max(0) as f64;
    if b >= 1_000.0 * MB {
        format!("{} GB", t.decimal(b / (1_000.0 * MB), 1))
    } else if b >= 10.0 * MB {
        format!("{} MB", t.decimal(b / MB, 0))
    } else if b >= MB {
        format!("{} MB", t.decimal(b / MB, 1))
    } else {
        format!("{} KB", t.decimal(b / 1_000.0, 0))
    }
}

/// A period of days as shown ("90 Tage", "2 Jahre"); 0 = keep.
fn period_text(t: Lang, days: i64) -> String {
    if days == 0 {
        t.get("retention-keep")
    } else if days % 365 == 0 {
        t.get1("retention-years", "count", days / 365)
    } else {
        t.get1("retention-days", "count", days)
    }
}

struct Choice {
    value: String,
    label: String,
    selected: bool,
}

fn choices(t: Lang, list: &[i64], current: i64) -> Vec<Choice> {
    let mut days: Vec<i64> = list.to_vec();
    if !days.contains(&current) {
        days.push(current);
    }
    days.into_iter()
        .map(|d| Choice {
            value: d.to_string(),
            label: period_text(t, d),
            selected: d == current,
        })
        .collect()
}

struct AreaRow {
    label: String,
    size: String,
    /// Share of the measured total in percent (bar width, 0–100).
    share: i64,
}

#[derive(Template)]
#[template(path = "retention.html")]
struct RetentionTemplate {
    t: Lang,
    layout: Layout,
    audit: Vec<Choice>,
    closed: Vec<Choice>,
    config_days: String,
    total: String,
    free: String,
    has_free: bool,
    areas: Vec<AreaRow>,
    measured: Option<String>,
    running: Option<String>,
    last_done: Option<String>,
    last_freed: String,
    last_error: Option<String>,
    flash: Option<String>,
    error: Option<String>,
}

async fn render(
    state: &AppState,
    user: &CurrentUser,
    flash: Option<String>,
    error: Option<String>,
) -> Result<String> {
    let t = user.lang;
    let s = store::settings(&state.pool).await?;
    let size = store::file_size(&state.pool).await?;
    let a = store::areas(&state.pool).await?;
    let v = store::vacuum_state(&state.pool).await?;
    let measured_total = a.size_cves + a.size_advisories + a.size_distros + a.size_own;
    let areas = [
        ("retention-area-cves", a.size_cves),
        ("retention-area-advisories", a.size_advisories),
        ("retention-area-distros", a.size_distros),
        ("retention-area-own", a.size_own),
    ]
    .into_iter()
    .map(|(id, bytes)| AreaRow {
        label: t.get(id),
        size: size_text(t, bytes),
        share: if measured_total > 0 {
            (bytes * 100 / measured_total).clamp(0, 100)
        } else {
            0
        },
    })
    .collect();
    let mut audit = vec![Choice {
        value: String::new(),
        label: t.get1(
            "retention-audit-config",
            "period",
            period_text(t, state.audit_days),
        ),
        selected: s.audit_days.is_none(),
    }];
    audit.extend(
        choices(t, &AUDIT_CHOICES, s.audit_days.unwrap_or(-1))
            .into_iter()
            .filter(|c| c.value != "-1"),
    );
    let running = v.running();
    let page = RetentionTemplate {
        t,
        layout: user.layout(),
        audit,
        closed: choices(t, &CLOSED_CHOICES, s.closed_days),
        config_days: period_text(t, state.audit_days),
        total: size_text(t, size.total),
        free: size_text(t, size.free),
        has_free: size.free >= 1_000_000,
        areas,
        measured: a.sizes_ms.filter(|_| measured_total > 0).map(time_html),
        running: running.then(|| time_html(v.vacuum_started_ms.unwrap_or_default())),
        last_done: v
            .vacuum_done_ms
            .filter(|_| !running && v.vacuum_error.is_empty())
            .map(time_html),
        last_freed: size_text(t, v.vacuum_freed),
        last_error: (!running && !v.vacuum_error.is_empty()).then(|| {
            if v.vacuum_error == "interrupted" {
                t.get("retention-vacuum-interrupted")
            } else {
                v.vacuum_error.clone()
            }
        }),
        flash,
        error,
    };
    Ok(page.render()?)
}

pub async fn page(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<FlashQuery>,
) -> Result<Html<String>> {
    let flash = flash_message(user.lang, query.msg.as_deref());
    Ok(Html(render(&state, &user, flash, None).await?))
}

#[derive(Deserialize)]
pub struct RetentionInput {
    csrf_token: String,
    #[serde(default)]
    audit_days: String,
    #[serde(default)]
    closed_days: String,
}

impl RetentionInput {
    fn settings(&self) -> std::result::Result<Settings, &'static str> {
        let audit_days = match self.audit_days.trim() {
            "" => None,
            text => Some(
                text.parse::<i64>()
                    .ok()
                    // Not below the shortest choice: one request must not wipe the log.
                    .filter(|d| (AUDIT_CHOICES[0]..=36_500).contains(d))
                    .ok_or("retention-error")?,
            ),
        };
        let closed_days = self
            .closed_days
            .trim()
            .parse::<i64>()
            .ok()
            .filter(|d| (0..=36_500).contains(d))
            .ok_or("retention-error")?;
        Ok(Settings {
            audit_days,
            closed_days,
        })
    }
}

pub async fn save(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(input): Form<RetentionInput>,
) -> Result<Response> {
    user.verify_csrf(&input.csrf_token)?;
    let t = user.lang;
    let before = store::settings(&state.pool).await?;
    match input.settings() {
        Ok(after) => {
            store::save(&state.pool, &after).await?;
            let audit_text = |s: &Settings| match s.audit_days {
                Some(d) => period_text(t, d),
                None => t.get1(
                    "retention-audit-config",
                    "period",
                    period_text(t, state.audit_days),
                ),
            };
            audit::record(
                &state,
                &user,
                Action::Changed,
                Object {
                    kind: AuditKind::Retention,
                    id: None,
                    name: "",
                },
                Changes::new()
                    .field(
                        "audit-field-retention-audit",
                        audit_text(&before),
                        audit_text(&after),
                    )
                    .field(
                        "audit-field-retention-closed",
                        period_text(t, before.closed_days),
                        period_text(t, after.closed_days),
                    ),
            )
            .await;
            Ok(Redirect::to("/settings/retention?msg=retention_saved").into_response())
        }
        Err(id) => {
            let html = render(&state, &user, None, Some(t.get(id))).await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, Html(html)).into_response())
        }
    }
}

#[derive(Deserialize)]
pub struct VacuumInput {
    csrf_token: String,
}

pub async fn vacuum(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(input): Form<VacuumInput>,
) -> Result<Response> {
    user.verify_csrf(&input.csrf_token)?;
    if store::begin_vacuum(&state.pool, now_ms()).await? {
        audit::record(
            &state,
            &user,
            Action::Changed,
            Object {
                kind: AuditKind::Retention,
                id: None,
                name: "",
            },
            Changes::new().label(
                "audit-field-vacuum",
                "audit-vacuum-idle",
                "audit-vacuum-started",
            ),
        )
        .await;
        store::spawn_vacuum(state.pool.clone());
    }
    Ok(Redirect::to("/settings/retention?msg=vacuum_started").into_response())
}

#[cfg(test)]
mod tests;
