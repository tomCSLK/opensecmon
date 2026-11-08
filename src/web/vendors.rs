//! The page "Vendor CSAF" (`/sources/vendors`): the CSAF providers of vendors the source "Vendor CSAF" loads.
//! A provider is added from the BSI's list of providers or by the URL of its provider-metadata.json; per
//! provider the distributions to load (large VEX directories start switched off) and the first day of
//! documents can be set.

use askama::Template;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};

use crate::audit::{Action, Changes, Kind};
use crate::csaf::{DistKind, https_url};
use crate::error::{Error, Result};
use crate::i18n::Lang;
use crate::sources::csaf::{fetch_lister, fetch_metadata};
use crate::sources::{SourceId, now_ms};
use crate::storage::advisories::{self as store, NewProvider, Provider};
use crate::web::audit::{Object, record};
use crate::web::auth::CurrentUser;
use crate::web::{AppState, FlashQuery, Layout, flash_message, time_html};

pub struct DistView {
    pub url: String,
    pub kind: &'static str,
    pub label: String,
    pub on: bool,
}

pub struct ProviderView {
    pub id: i64,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub since: String,
    pub documents: String,
    pub checked: Option<String>,
    pub error: Option<String>,
    pub dists: Vec<DistView>,
}

pub struct ListedView {
    pub url: String,
    pub label: String,
}

#[derive(Template)]
#[template(path = "vendors.html")]
struct VendorsTemplate {
    t: Lang,
    layout: Layout,
    providers: Vec<ProviderView>,
    listed: Vec<ListedView>,
    lister_loaded: Option<String>,
    default_since: String,
    today: String,
    flash: Option<String>,
    error: Option<String>,
}

/// The default first day of a new provider: 1 January of last year (large providers publish tens of
/// thousands of documents going back to 2001).
fn default_since() -> String {
    let year = jiff::Zoned::now().year() - 1;
    format!("{year:04}-01-01")
}

/// A distribution that starts switched off: VEX directories have one document per CVE.
fn heavy(url: &str) -> bool {
    url.to_ascii_lowercase().contains("vex")
}

fn view(t: Lang, p: Provider) -> ProviderView {
    let skip = p.skip();
    let dists = p
        .distributions()
        .into_iter()
        .map(|d| DistView {
            on: !skip.contains(&d.url),
            kind: match d.kind {
                DistKind::Rolie => "ROLIE",
                DistKind::Directory => "Directory",
            },
            label: match (d.kind, d.summary.is_empty()) {
                (DistKind::Rolie, false) => format!("{} (TLP:{})", d.summary, d.tlp),
                (DistKind::Rolie, true) => format!("TLP:{}", d.tlp),
                (DistKind::Directory, _) => t.get("vendors-dist-directory"),
            },
            url: d.url,
        })
        .collect();
    ProviderView {
        id: p.id,
        name: if p.name.is_empty() {
            p.url.clone()
        } else {
            p.name.clone()
        },
        url: p.url,
        enabled: p.enabled,
        since: p.since,
        documents: t.number(p.documents),
        checked: p.checked_ms.map(time_html),
        error: p.last_error,
        dists,
    }
}

async fn render(
    state: &AppState,
    user: &CurrentUser,
    flash: Option<String>,
    error: Option<String>,
) -> Result<Html<String>> {
    let t = user.lang;
    let providers: Vec<Provider> = store::providers(&state.pool, "vendor").await?;
    let added: Vec<String> = providers.iter().map(|p| p.url.clone()).collect();
    let (listed, loaded) = store::lister(&state.pool).await?;
    Ok(Html(
        VendorsTemplate {
            t,
            layout: user.layout().at("sources"),
            providers: providers.into_iter().map(|p| view(t, p)).collect(),
            listed: listed
                .into_iter()
                .filter(|l| !added.contains(&l.url))
                .map(|l| ListedView {
                    label: if l.role.is_empty() {
                        l.name
                    } else {
                        format!("{} ({})", l.name, l.role.trim_start_matches("csaf_"))
                    },
                    url: l.url,
                })
                .collect(),
            lister_loaded: loaded.map(time_html),
            default_since: default_since(),
            today: jiff::Zoned::now().date().to_string(),
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
    render(&state, &user, flash, None).await
}

/// A day `YYYY-MM-DD` not in the future, or empty (everything).
fn since(text: &str) -> Result<String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(String::new());
    }
    let today = jiff::Zoned::now().date();
    match text.parse::<jiff::civil::Date>() {
        Ok(d) if d.year() >= 1990 && d <= today => Ok(d.to_string()),
        _ => Err(Error::Invalid(crate::i18n::Msg::new(
            "vendors-since-invalid",
        ))),
    }
}

/// The page again with an error (the form is not stored).
async fn refused(state: &AppState, user: &CurrentUser, text: String) -> Result<Response> {
    let mut reply = render(state, user, None, Some(text)).await?.into_response();
    *reply.status_mut() = axum::http::StatusCode::UNPROCESSABLE_ENTITY;
    Ok(reply)
}

#[derive(serde::Deserialize)]
pub struct AddForm {
    csrf_token: String,
    #[serde(default)]
    listed: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    since: String,
}

/// Adds a provider: reads its metadata first, so a wrong URL is refused right away.
pub async fn add(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(form): Form<AddForm>,
) -> Result<Response> {
    user.verify_csrf(&form.csrf_token)?;
    let t = user.lang;
    let given = if form.url.trim().is_empty() {
        form.listed.trim()
    } else {
        form.url.trim()
    };
    let Some(url) = https_url(given) else {
        return refused(&state, &user, t.get("vendors-url-invalid")).await;
    };
    let since = match since(&form.since) {
        Ok(s) => s,
        Err(_) => return refused(&state, &user, t.get("vendors-since-invalid")).await,
    };
    if store::provider_by_url(&state.pool, &url).await?.is_some() {
        return refused(&state, &user, t.get("vendors-exists")).await;
    }
    let meta = match fetch_metadata(&url).await {
        Ok(m) => m,
        Err(e) => {
            let text = t.get1("vendors-metadata-failed", "error", format!("{e:#}"));
            return refused(&state, &user, text).await;
        }
    };
    let skip: Vec<String> = meta
        .distributions
        .iter()
        .filter(|d| heavy(&d.url))
        .map(|d| d.url.clone())
        .collect();
    let name = if meta.name.is_empty() {
        url.clone()
    } else {
        meta.name.clone()
    };
    let id = store::add_provider(
        &state.pool,
        &NewProvider {
            url: &url,
            name: &name,
            since: &since,
            skip: &skip,
            distributions: &meta.distributions,
            now_ms: now_ms(),
        },
    )
    .await?;
    record(
        &state,
        &user,
        Action::Created,
        Object::new(Kind::Provider, id, &name),
        Changes::new()
            .value("audit-field-url", &url)
            .value("audit-field-since", &since),
    )
    .await;
    if crate::storage::sources::get(&state.pool, SourceId::Vendor.as_str())
        .await?
        .is_some_and(|s| s.enabled)
    {
        state.sources.run_now(SourceId::Vendor).await?;
    }
    Ok(Redirect::to("/sources/vendors?msg=provider_added").into_response())
}

/// Saves enabled, the first day and the distributions to load (`dist` once per distribution switched on).
pub async fn save(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
    Form(fields): Form<Vec<(String, String)>>,
) -> Result<Response> {
    let field = |name: &str| {
        fields
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    user.verify_csrf(field("csrf_token").unwrap_or_default())?;
    let before = store::provider(&state.pool, id)
        .await?
        .filter(|p| p.source == "vendor")
        .ok_or(Error::NotFound)?;
    let since = since(field("since").unwrap_or_default())?;
    let enabled = field("enabled").is_some();
    let on: Vec<&str> = fields
        .iter()
        .filter(|(k, _)| k == "dist")
        .map(|(_, v)| v.as_str())
        .collect();
    let dists = before.distributions();
    let skip: Vec<String> = dists
        .iter()
        .filter(|d| !on.contains(&d.url.as_str()))
        .map(|d| d.url.clone())
        .collect();
    store::configure_provider(&state.pool, id, enabled, &since, &skip).await?;
    let yes_no = |b: bool| if b { "audit-yes" } else { "audit-no" };
    let loaded = |skip: &[String]| dists.iter().filter(|d| !skip.contains(&d.url)).count();
    record(
        &state,
        &user,
        Action::Changed,
        Object::new(Kind::Provider, id, &before.name),
        Changes::new()
            .label(
                "audit-field-enabled",
                yes_no(before.enabled),
                yes_no(enabled),
            )
            .field("audit-field-since", &before.since, &since)
            .field(
                "audit-field-distributions",
                loaded(&before.skip()),
                loaded(&skip),
            ),
    )
    .await;
    Ok(Redirect::to("/sources/vendors?msg=provider_saved").into_response())
}

#[derive(serde::Deserialize)]
pub struct CsrfForm {
    csrf_token: String,
}

/// Removes a provider with its advisories.
pub async fn delete(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Response> {
    user.verify_csrf(&form.csrf_token)?;
    let p = store::provider(&state.pool, id)
        .await?
        .filter(|p| p.source == "vendor")
        .ok_or(Error::NotFound)?;
    store::delete_provider(&state.pool, id).await?;
    record(
        &state,
        &user,
        Action::Deleted,
        Object::new(Kind::Provider, id, &p.name),
        Changes::new().value("audit-field-url", &p.url),
    )
    .await;
    Ok(Redirect::to("/sources/vendors?msg=provider_deleted").into_response())
}

/// Loads the BSI's list of providers again.
pub async fn load_lister(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(form): Form<CsrfForm>,
) -> Result<Response> {
    user.verify_csrf(&form.csrf_token)?;
    let url = state.sources.endpoints().csaf_lister.clone();
    match fetch_lister(&url).await {
        Ok(listed) => {
            store::replace_lister(&state.pool, &listed, now_ms()).await?;
            Ok(Redirect::to("/sources/vendors?msg=lister_loaded").into_response())
        }
        Err(e) => {
            let text = user
                .lang
                .get1("vendors-lister-failed", "error", format!("{e:#}"));
            refused(&state, &user, text).await
        }
    }
}

/// Texts that only templates use, for the catalog check: "vendors-title" "vendors-subtitle" "vendors-back"
/// "vendors-add" "vendors-add-help" "vendors-listed" "vendors-listed-choose" "vendors-listed-empty"
/// "vendors-lister-load" "vendors-lister-loaded" "vendors-own-url" "vendors-own-url-help" "vendors-since"
/// "vendors-since-help" "vendors-add-submit" "vendors-none" "vendors-documents" "vendors-checked"
/// "vendors-never" "vendors-dists" "vendors-dists-help" "vendors-delete" "vendors-save" "vendors-enabled"
/// "vendors-heavy-note"
#[cfg(test)]
mod tests {
    use super::*;
    use crate::csaf::Distribution;
    use crate::web::testutil::*;
    use axum::http::StatusCode;

    #[test]
    fn days_and_heavy_distributions() {
        assert_eq!(since(" 2025-01-01 ").unwrap(), "2025-01-01");
        assert_eq!(since("").unwrap(), "");
        assert!(since("2999-01-01").is_err());
        assert!(since("gestern").is_err());
        assert!(heavy("https://security.access.redhat.com/data/csaf/v2/vex"));
        assert!(!heavy(
            "https://security.access.redhat.com/data/csaf/v2/advisories"
        ));
        assert!(default_since().ends_with("-01-01"));
    }

    #[tokio::test]
    async fn providers_are_listed_configured_and_removed() {
        let h = harness(true).await;
        let (session, csrf) = login(&h, "anna").await;
        let page = send(&h.app, get("/sources/vendors", Some(&session))).await;
        assert_eq!(page.status, StatusCode::OK);
        assert!(page.body.contains("Noch kein Anbieter"), "{}", page.body);

        let bad = send(
            &h.app,
            post(
                "/sources/vendors",
                Some(&session),
                &format!("csrf_token={csrf}&url=http%3A%2F%2Fexample.org%2Fpm.json"),
            ),
        )
        .await;
        assert!(bad.body.contains("HTTPS"), "{}", bad.body);

        let dists = [
            Distribution {
                kind: DistKind::Directory,
                url: "https://v.example/csaf/advisories".into(),
                tlp: String::new(),
                summary: String::new(),
            },
            Distribution {
                kind: DistKind::Directory,
                url: "https://v.example/csaf/vex".into(),
                tlp: String::new(),
                summary: String::new(),
            },
        ];
        let id = store::add_provider(
            &h.state.pool,
            &NewProvider {
                url: "https://v.example/pm.json",
                name: "<b>Vendor</b>",
                since: "2025-01-01",
                skip: &["https://v.example/csaf/vex".to_owned()],
                distributions: &dists,
                now_ms: 1,
            },
        )
        .await
        .unwrap();
        let page = send(&h.app, get("/sources/vendors", Some(&session))).await;
        assert!(!page.body.contains("<b>Vendor</b>"), "names are escaped");
        assert!(page.body.contains("https://v.example/csaf/vex"));

        let exists = send(
            &h.app,
            post(
                "/sources/vendors",
                Some(&session),
                &format!("csrf_token={csrf}&url=https%3A%2F%2Fv.example%2Fpm.json"),
            ),
        )
        .await;
        assert!(exists.body.contains("schon"), "{}", exists.body);

        let form =
            format!("csrf_token={csrf}&since=2024-06-01&dist=https%3A%2F%2Fv.example%2Fcsaf%2Fvex");
        let saved = send(
            &h.app,
            post(&format!("/sources/vendors/{id}"), Some(&session), &form),
        )
        .await;
        assert_eq!(saved.location(), "/sources/vendors?msg=provider_saved");
        let p = store::provider(&h.state.pool, id).await.unwrap().unwrap();
        assert!(!p.enabled);
        assert_eq!(p.since, "2024-06-01");
        assert_eq!(p.skip(), ["https://v.example/csaf/advisories"]);
        let audit = send(&h.app, get("/settings/audit", Some(&session))).await;
        assert!(audit.body.contains("CSAF-Anbieter"), "{}", audit.body);

        let bad_day = send(
            &h.app,
            post(
                &format!("/sources/vendors/{id}"),
                Some(&session),
                &format!("csrf_token={csrf}&since=morgen"),
            ),
        )
        .await;
        assert_eq!(bad_day.status, StatusCode::UNPROCESSABLE_ENTITY);

        let deleted = send(
            &h.app,
            post(
                &format!("/sources/vendors/{id}/delete"),
                Some(&session),
                &format!("csrf_token={csrf}"),
            ),
        )
        .await;
        assert_eq!(deleted.location(), "/sources/vendors?msg=provider_deleted");
        assert!(store::provider(&h.state.pool, id).await.unwrap().is_none());
        let bsi = store::bsi_provider(&h.state.pool, "https://bsi.example/pm.json")
            .await
            .unwrap();
        let refused = send(
            &h.app,
            post(
                &format!("/sources/vendors/{}/delete", bsi.id),
                Some(&session),
                &format!("csrf_token={csrf}"),
            ),
        )
        .await;
        assert_eq!(refused.status, StatusCode::NOT_FOUND, "BSI is not a vendor");
        let forged = send(
            &h.app,
            post(
                "/sources/vendors/lister",
                Some(&session),
                "csrf_token=wrong",
            ),
        )
        .await;
        assert_eq!(forged.status, StatusCode::FORBIDDEN);
    }
}
