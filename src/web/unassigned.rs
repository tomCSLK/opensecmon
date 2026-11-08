//! The page "Unassigned" under "Assets" (`/assets/unassigned`): the programs, store apps, snaps and Flatpaks that
//! computers report and no rule turns into an asset, each once with the computers that have it. Assigning one to a
//! product (with the suggestions and the preview of the asset form) or ignoring it makes a rule that applies to all
//! computers at once; the rules are listed below and can be removed.

use askama::Template;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};

use crate::audit::{Action, Changes, Kind as AuditKind};
use crate::error::{Error, Result};
use crate::i18n::Lang;
use crate::inventory::items::{self, ItemType, Resolution, Rule};
use crate::sources::now_ms;
use crate::storage::assets::Input;
use crate::storage::items as store;
use crate::web::asset_pages::{PreviewView, Tab, preview, tabs};
use crate::web::audit::{Object, record};
use crate::web::auth::CurrentUser;
use crate::web::{AppState, Layout, flash_message};

/// Versions and computers shown per entry before "and N more".
const SHOWN: usize = 3;

pub struct EntryView {
    pub type_label: String,
    pub item_type: &'static str,
    pub key: String,
    pub name: String,
    pub publisher: String,
    pub versions: String,
    pub computers: String,
    pub count: usize,
    pub user_scope: bool,
}

pub struct RuleView {
    pub id: i64,
    pub type_label: String,
    pub key: String,
    /// "Vendor Product", or "" when ignored.
    pub product: String,
    pub computers: usize,
}

/// A list shortened to its first entries: "a, b, c and 2 more".
fn shortened(t: Lang, list: &[String]) -> String {
    let mut text = list
        .iter()
        .take(SHOWN)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if list.len() > SHOWN {
        text.push(' ');
        text.push_str(&t.get1("unassigned-more", "count", list.len() - SHOWN));
    }
    text
}

fn entry_view(t: Lang, g: &store::Group) -> EntryView {
    EntryView {
        type_label: t.get(g.item_type.label_id()),
        item_type: g.item_type.as_str(),
        key: g.key.clone(),
        name: g.name.clone(),
        publisher: g.publisher.clone(),
        versions: shortened(t, &g.versions),
        computers: shortened(t, &g.computers),
        count: g.origins.len(),
        user_scope: g.user_scope,
    }
}

#[derive(Template)]
#[template(path = "unassigned.html")]
struct ListTemplate {
    t: Lang,
    layout: Layout,
    tabs: Vec<Tab>,
    entries: Vec<EntryView>,
    rules: Vec<RuleView>,
    /// Entries the built-in rules assign and ignore.
    built_in: String,
    flash: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct ListParams {
    msg: Option<String>,
}

pub async fn page(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(params): Query<ListParams>,
) -> Result<Response> {
    let t = user.lang;
    let groups = store::groups(&state.pool).await?;
    let mut entries: Vec<&store::Group> = groups
        .iter()
        .filter(|g| g.resolution == Resolution::Unassigned)
        .collect();
    entries.sort_by(|a, b| {
        b.origins
            .len()
            .cmp(&a.origins.len())
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    let (mut assigned, mut ignored) = (0, 0);
    for g in &groups {
        if g.source == items::Source::BuiltIn {
            match g.resolution {
                Resolution::Asset { .. } => assigned += 1,
                Resolution::Ignore => ignored += 1,
                Resolution::Unassigned => {}
            }
        }
    }
    let rules = store::list_rules(&state.pool).await?;
    let html = ListTemplate {
        t,
        layout: user.layout().at("assets"),
        tabs: tabs(&state, t, "unassigned").await?,
        entries: entries.into_iter().map(|g| entry_view(t, g)).collect(),
        rules: rules
            .iter()
            .map(|r| RuleView {
                id: r.id,
                type_label: t.get(r.item_type.label_id()),
                key: r.key.clone(),
                product: match &r.resolution {
                    Resolution::Asset {
                        vendor_name,
                        product_name,
                    } => format!("{vendor_name} {product_name}").trim().to_owned(),
                    _ => String::new(),
                },
                computers: groups
                    .iter()
                    .find(|g| g.item_type == r.item_type && g.key == r.key)
                    .map_or(0, |g| g.origins.len()),
            })
            .collect(),
        built_in: if assigned + ignored > 0 {
            t.get2(
                "unassigned-built-in",
                "assigned",
                assigned,
                "ignored",
                ignored,
            )
        } else {
            String::new()
        },
        flash: flash_message(t, params.msg.as_deref()),
        error: None,
    }
    .render()?;
    Ok(Html(html).into_response())
}

/// The fields of the form "Assign" as sent (and as shown again).
#[derive(Debug, Default, Clone, serde::Deserialize)]
pub struct AssignForm {
    #[serde(default)]
    csrf_token: String,
    #[serde(default, rename = "type")]
    item_type: String,
    #[serde(default)]
    key: String,
    #[serde(default)]
    vendor_name: String,
    #[serde(default)]
    product_name: String,
    /// A version of the entry, for the preview.
    #[serde(default)]
    version: String,
    /// "preview": show the matches instead of saving.
    #[serde(default)]
    action: String,
}

#[derive(Template)]
#[template(path = "unassigned_assign.html")]
struct AssignTemplate {
    t: Lang,
    layout: Layout,
    tabs: Vec<Tab>,
    entry: EntryView,
    f: AssignForm,
    preview: Option<PreviewView>,
    error: Option<String>,
    flash: Option<String>,
}

fn item_type(s: &str) -> Result<ItemType> {
    ItemType::parse_sent(s).ok_or(Error::NotFound)
}

async fn render_assign(
    state: &AppState,
    user: &CurrentUser,
    g: &store::Group,
    f: AssignForm,
    preview: Option<PreviewView>,
    error: Option<String>,
) -> Result<Response> {
    let t = user.lang;
    let html = AssignTemplate {
        t,
        layout: user.layout().at("assets"),
        tabs: tabs(state, t, "unassigned").await?,
        entry: entry_view(t, g),
        f,
        preview,
        error,
        flash: None,
    }
    .render()?;
    Ok(Html(html).into_response())
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct AssignParams {
    #[serde(rename = "type")]
    item_type: String,
    key: String,
}

/// The form to assign an entry, with a proposal from its publisher and name.
pub async fn assign_form(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(p): Query<AssignParams>,
) -> Result<Response> {
    let item_type = item_type(&p.item_type)?;
    let g = store::group(&state.pool, item_type, &p.key)
        .await?
        .ok_or(Error::NotFound)?;
    let (vendor_name, product_name) = match &g.resolution {
        Resolution::Asset {
            vendor_name,
            product_name,
        } => (vendor_name.clone(), product_name.clone()),
        _ => (g.publisher.clone(), items::product_proposal(&g.name)),
    };
    let f = AssignForm {
        item_type: item_type.as_str().to_owned(),
        key: g.key.clone(),
        vendor_name,
        product_name,
        version: g
            .versions
            .last()
            .map(|v| items::item_version(item_type, &g.name, v))
            .unwrap_or_default(),
        ..AssignForm::default()
    };
    render_assign(&state, &user, &g, f, None, None).await
}

fn rule_changes(item_type: ItemType, key: &str, resolution: &Resolution) -> Changes {
    let changes = Changes::new()
        .value("audit-field-item-type", item_type.as_str())
        .value("audit-field-item-key", key);
    match resolution {
        Resolution::Asset {
            vendor_name,
            product_name,
        } => changes
            .value("audit-field-vendor", vendor_name)
            .value("audit-field-product", product_name),
        _ => changes.value_label("audit-field-item-action", "unassigned-rule-ignored"),
    }
}

/// Sets a rule, applies it to the computers that have the entry and matches what changed.
async fn apply_rule(
    state: &AppState,
    user: &CurrentUser,
    item_type: ItemType,
    key: &str,
    resolution: Resolution,
) -> Result<()> {
    let now = now_ms();
    let id = store::set_rule(&state.pool, item_type, key, &resolution, now).await?;
    record(
        state,
        user,
        Action::Changed,
        Object::new(AuditKind::ItemRule, id, key),
        rule_changes(item_type, key, &resolution),
    )
    .await;
    let origins = store::origins_with(&state.pool, item_type, key).await?;
    let changed = store::resync(&state.pool, &origins, now).await?;
    crate::inventory::runner::match_in_background(state.pool.clone(), changed, key.to_owned());
    Ok(())
}

pub async fn assign(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(f): Form<AssignForm>,
) -> Result<Response> {
    user.verify_csrf(&f.csrf_token)?;
    let t = user.lang;
    let item_type = item_type(&f.item_type)?;
    let g = store::group(&state.pool, item_type, &f.key)
        .await?
        .ok_or(Error::NotFound)?;
    let checked = Input {
        kind: "software".into(),
        vendor_name: f.vendor_name.clone(),
        product_name: f.product_name.clone(),
        version: items::clean_version(&f.version),
        ..Default::default()
    }
    .check();
    let checked = match checked {
        Ok(c) => c,
        Err(id) => {
            let error = Some(t.get(id));
            return render_assign(&state, &user, &g, f, None, error).await;
        }
    };
    if f.action == "preview" {
        let view = preview(&state, t, &checked, now_ms()).await?;
        return render_assign(&state, &user, &g, f, Some(view), None).await;
    }
    apply_rule(
        &state,
        &user,
        item_type,
        &g.key,
        Resolution::Asset {
            vendor_name: checked.vendor_name,
            product_name: checked.product_name,
        },
    )
    .await?;
    Ok(Redirect::to("/assets/unassigned?msg=item_assigned").into_response())
}

#[derive(serde::Deserialize)]
pub struct IgnoreForm {
    csrf_token: String,
    #[serde(rename = "type")]
    item_type: String,
    key: String,
}

pub async fn ignore(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(f): Form<IgnoreForm>,
) -> Result<Response> {
    user.verify_csrf(&f.csrf_token)?;
    let item_type = item_type(&f.item_type)?;
    let g = store::group(&state.pool, item_type, &f.key)
        .await?
        .ok_or(Error::NotFound)?;
    apply_rule(&state, &user, item_type, &g.key, Resolution::Ignore).await?;
    Ok(Redirect::to("/assets/unassigned?msg=item_ignored").into_response())
}

#[derive(serde::Deserialize)]
pub struct CsrfForm {
    csrf_token: String,
}

/// Removes a rule: its entries are unassigned again (or follow a built-in rule), their assets go.
pub async fn delete_rule(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Response> {
    user.verify_csrf(&form.csrf_token)?;
    let Rule {
        item_type,
        key,
        resolution,
        ..
    } = store::delete_rule(&state.pool, id)
        .await?
        .ok_or(Error::NotFound)?;
    record(
        &state,
        &user,
        Action::Deleted,
        Object::new(AuditKind::ItemRule, id, &key),
        rule_changes(item_type, &key, &resolution),
    )
    .await;
    let origins = store::origins_with(&state.pool, item_type, &key).await?;
    let changed = store::resync(&state.pool, &origins, now_ms()).await?;
    crate::inventory::runner::match_in_background(state.pool.clone(), changed, key);
    Ok(Redirect::to("/assets/unassigned?msg=rule_deleted").into_response())
}

/// Texts that only templates use, for the catalog check: "unassigned-title" "unassigned-text" "unassigned-none"
/// "unassigned-col-entry" "unassigned-col-versions" "unassigned-col-computers" "unassigned-assign"
/// "unassigned-ignore" "unassigned-user-scope" "unassigned-rules" "unassigned-rules-text" "unassigned-rules-none"
/// "unassigned-rule-ignored" "unassigned-rule-delete" "unassigned-assign-title" "unassigned-assign-text"
/// "unassigned-save" "unassigned-back" "unassigned-entry" "unassigned-publisher"
#[cfg(test)]
mod tests;
