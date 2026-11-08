//! The CSV import (`/assets/csv`): the text of a file (pasted, or read into the field by
//! `static/inventory.js`), a preview per row (new, changes an asset, unchanged, error), then "take over".
//! Only assets entered by hand or by CSV are changed; assets that follow a host or a device are left to
//! their source. All values are shown escaped.

use askama::Template;
use axum::Form;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};

use crate::audit::{Action, Changes, Kind as AuditKind};
use crate::error::Result;
use crate::i18n::Lang;
use crate::inventory::csv::{self, EXAMPLE, MAX_BYTES, MAX_ROWS, RowState};
use crate::matching;
use crate::sources::now_ms;
use crate::storage::assets;
use crate::web::asset_pages::{Tab, tabs};
use crate::web::audit::{Object, record};
use crate::web::auth::CurrentUser;
use crate::web::{AppState, Layout, flash_message};

/// Rows listed in the preview (the counts cover all).
const PREVIEW_ROWS: usize = 300;

pub struct CsvRow {
    pub line: usize,
    /// `ok` (new), `warn` (changes), `off` (unchanged) or `err`.
    pub class: &'static str,
    pub icon: &'static str,
    pub state: String,
    pub kind: String,
    pub name: String,
    pub version: String,
    pub host: String,
    pub error: String,
    pub asset_id: Option<i64>,
}

pub struct Preview {
    pub rows: Vec<CsvRow>,
    pub summary: String,
    pub more: String,
    pub importable: usize,
}

#[derive(Template)]
#[template(path = "csv_import.html")]
struct PageTemplate {
    t: Lang,
    layout: Layout,
    tabs: Vec<Tab>,
    text: String,
    example: &'static str,
    max_bytes: usize,
    rules: String,
    preview: Option<Preview>,
    flash: Option<String>,
    error: Option<String>,
}

async fn render(
    state: &AppState,
    user: &CurrentUser,
    text: String,
    preview: Option<Preview>,
    flash: Option<String>,
    error: Option<String>,
) -> Result<Response> {
    let t = user.lang;
    let html = PageTemplate {
        t,
        layout: user.layout().at("assets"),
        tabs: tabs(state, t, "csv").await?,
        text,
        example: EXAMPLE,
        max_bytes: MAX_BYTES,
        rules: t.get1("csv-rules", "count", MAX_ROWS),
        preview,
        flash,
        error,
    }
    .render()?;
    Ok(Html(html).into_response())
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct MsgParams {
    msg: Option<String>,
}

/// The empty page.
pub async fn page(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(params): Query<MsgParams>,
) -> Result<Response> {
    let flash = flash_message(user.lang, params.msg.as_deref());
    render(&state, &user, String::new(), None, flash, None).await
}

#[derive(serde::Deserialize)]
pub struct CsvForm {
    csrf_token: String,
    #[serde(default)]
    text: String,
    /// "import": take the rows over; else the preview.
    #[serde(default)]
    action: String,
}

fn preview_of(t: Lang, parsed: &csv::Parsed) -> Preview {
    let count = |f: fn(&RowState) -> bool| parsed.count(f);
    let new = count(|s| *s == RowState::New);
    let update = count(|s| matches!(s, RowState::Update(_)));
    let same = count(|s| matches!(s, RowState::Same(_)));
    let errors = count(|s| matches!(s, RowState::Error(_)));
    let rows = parsed
        .rows
        .iter()
        .take(PREVIEW_ROWS)
        .map(|r| {
            let (class, icon, state, error, asset_id) = match &r.state {
                RowState::New => ("ok", "plus", t.get("csv-state-new"), String::new(), None),
                RowState::Update(id) => (
                    "warn",
                    "refresh",
                    t.get("csv-state-update"),
                    String::new(),
                    Some(*id),
                ),
                RowState::Same(id) => (
                    "off",
                    "check",
                    t.get("csv-state-same"),
                    String::new(),
                    Some(*id),
                ),
                RowState::Error(id) => {
                    ("err", "x-circle", t.get("csv-state-error"), t.get(id), None)
                }
            };
            let (kind, name) = match &r.checked {
                Some(c) => (t.get(c.kind.label_id()), c.as_asset(0, 0).display_name()),
                None => (
                    r.input.kind.clone(),
                    format!("{} {}", r.input.vendor_name, r.input.product_name)
                        .trim()
                        .to_owned(),
                ),
            };
            CsvRow {
                line: r.line,
                class,
                icon,
                state,
                kind,
                name,
                version: r.input.version.clone(),
                host: r.input.host.clone(),
                error,
                asset_id,
            }
        })
        .collect();
    Preview {
        rows,
        summary: t.fmt(
            "csv-summary",
            &[
                ("new", new.into()),
                ("update", update.into()),
                ("same", same.into()),
                ("errors", errors.into()),
            ],
        ),
        more: if parsed.rows.len() > PREVIEW_ROWS {
            t.get1("csv-more", "count", parsed.rows.len() - PREVIEW_ROWS)
        } else {
            String::new()
        },
        importable: new + update,
    }
}

/// Shows the preview, or takes the rows over.
pub async fn submit(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(f): Form<CsvForm>,
) -> Result<Response> {
    user.verify_csrf(&f.csrf_token)?;
    let t = user.lang;
    let existing = assets::all(&state.pool).await?;
    let parsed = match csv::parse(&f.text, &existing) {
        Ok(p) => p,
        Err(id) => {
            let text = if f.text.len() > MAX_BYTES {
                String::new()
            } else {
                f.text
            };
            return render(&state, &user, text, None, None, Some(t.get(id))).await;
        }
    };
    if f.action != "import" {
        let preview = preview_of(t, &parsed);
        return render(&state, &user, f.text, Some(preview), None, None).await;
    }
    let now = now_ms();
    let mut tx = state.pool.begin().await?;
    let mut changed = Vec::new();
    let (mut added, mut updated) = (0usize, 0usize);
    for r in &parsed.rows {
        let Some(c) = &r.checked else { continue };
        match r.state {
            RowState::New => {
                changed.push(assets::add_from(&mut *tx, c, "csv", "", now).await?);
                added += 1;
            }
            RowState::Update(id) => {
                assets::update(&mut *tx, id, c, now).await?;
                changed.push(id);
                updated += 1;
            }
            RowState::Same(_) | RowState::Error(_) => {}
        }
    }
    tx.commit().await?;
    record(
        &state,
        &user,
        Action::Created,
        Object {
            kind: AuditKind::CsvImport,
            id: None,
            name: "CSV",
        },
        Changes::new()
            .value("audit-field-csv-new", added)
            .value("audit-field-csv-changed", updated),
    )
    .await;
    matching::match_assets(&state.pool, &changed, now_ms()).await?;
    Ok(Redirect::to("/assets?msg=csv_imported").into_response())
}
