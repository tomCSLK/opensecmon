//! The import from opennetmon (`/assets/opennetmon`): its address and token, the devices it reported with the
//! product the rules suggest, and per device "take over" (becomes an asset that follows the device),
//! "change" (the asset form, filled with the suggestion) or "skip".
//!
//! Names, addresses and `sysDescr` come from opennetmon and are escaped; the token is stored encrypted and
//! never shown again.

use askama::Template;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};

use crate::audit::{Action, Changes, Kind as AuditKind};
use crate::crypto::Secret;
use crate::error::{Error, Result};
use crate::i18n::Lang;
use crate::inventory::opennetmon::{self, PATH};
use crate::matching;
use crate::sources::now_ms;
use crate::storage::assets::{self, Input};
use crate::storage::inventory::{self, OnmDevice};
use crate::web::asset_pages::{Tab, tabs};
use crate::web::audit::{Object, record};
use crate::web::auth::CurrentUser;
use crate::web::hosts::error_text;
use crate::web::{AppState, Layout, flash_message, time_html};

/// The reference of the asset that follows device `id`.
pub fn origin_ref(id: i64) -> String {
    format!("onm:{id}")
}

pub struct DeviceRow {
    pub id: i64,
    pub name: String,
    pub address: String,
    pub sys_descr: String,
    pub suggestion: String,
    pub rule: String,
    /// `ok` (sure), `warn` (to check) or `err` (not recognised).
    pub sure: &'static str,
    pub sure_icon: &'static str,
    pub sure_text: String,
    /// `new`, `taken` or `skipped`.
    pub state: String,
    pub asset_id: Option<i64>,
    pub can_take: bool,
    /// No longer reported by opennetmon.
    pub gone: bool,
    /// A host of the same name or address is read over SSH.
    pub via_ssh: bool,
}

fn row(t: Lang, d: &OnmDevice, last_ms: Option<i64>, ssh: &[(String, String)]) -> DeviceRow {
    let recognised = !d.rule.is_empty() && !d.product_name.is_empty();
    let (sure, sure_icon, sure_text) = if !recognised {
        ("err", "x-circle", t.get("onm-sure-none"))
    } else if d.sure {
        ("ok", "check-circle", t.get("onm-sure-yes"))
    } else {
        ("warn", "alert", t.get("onm-sure-check"))
    };
    let suggestion = if recognised {
        let version = if d.version.is_empty() {
            t.get("onm-version-unknown")
        } else {
            d.version.clone()
        };
        format!("{} · {} · {version}", d.vendor_name, d.product_name)
    } else {
        String::new()
    };
    let name = d.name.to_lowercase();
    let address = d.address.to_lowercase();
    let taken_ok = d.state == "taken" && d.asset_id.is_some();
    DeviceRow {
        id: d.id,
        name: d.name.clone(),
        address: d.address.clone(),
        sys_descr: d.sys_descr.clone(),
        suggestion,
        rule: t.get(opennetmon::rule_label_id(&d.rule)),
        sure,
        sure_icon,
        sure_text,
        state: if d.state == "taken" && !taken_ok {
            "new".to_owned()
        } else {
            d.state.clone()
        },
        asset_id: d.asset_id,
        can_take: recognised,
        gone: last_ms.is_some_and(|last| d.seen_ms < last),
        via_ssh: ssh
            .iter()
            .any(|(n, a)| *n == name || (!address.is_empty() && *a == address)),
    }
}

#[derive(Template)]
#[template(path = "onm_import.html")]
struct PageTemplate {
    t: Lang,
    layout: Layout,
    tabs: Vec<Tab>,
    url: String,
    /// Fingerprint of opennetmon's certificate, as entered or stored.
    cert: String,
    path: &'static str,
    has_token: bool,
    last: Option<String>,
    onm_error: Option<String>,
    devices: Vec<DeviceRow>,
    counts: String,
    flash: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct MsgParams {
    msg: Option<String>,
}

/// What the form held when it is shown again with an error.
struct Entered {
    url: String,
    cert: String,
}

async fn render(
    state: &AppState,
    user: &CurrentUser,
    entered: Option<Entered>,
    flash: Option<String>,
    error: Option<String>,
) -> Result<Response> {
    let t = user.lang;
    let settings = inventory::onm_settings(&state.pool).await?;
    let ssh: Vec<(String, String)> = inventory::hosts(&state.pool)
        .await?
        .into_iter()
        .map(|h| (h.name.to_lowercase(), h.address.to_lowercase()))
        .collect();
    let devices: Vec<DeviceRow> = inventory::onm_devices(&state.pool)
        .await?
        .iter()
        .map(|d| row(t, d, settings.last_ms, &ssh))
        .collect();
    let taken = devices.iter().filter(|d| d.state == "taken").count();
    let entered = entered.unwrap_or(Entered {
        url: settings.url,
        cert: settings.cert_sha256,
    });
    let html = PageTemplate {
        t,
        layout: user.layout().at("assets"),
        tabs: tabs(state, t, "opennetmon").await?,
        url: entered.url,
        cert: entered.cert,
        path: PATH,
        has_token: settings.has_token,
        last: settings.last_ms.map(time_html),
        onm_error: (!settings.error.is_empty()).then(|| error_text(t, &settings.error)),
        counts: t.get2("onm-counts", "count", devices.len(), "taken", taken),
        devices,
        flash,
        error,
    }
    .render()?;
    Ok(Html(html).into_response())
}

/// The page.
pub async fn page(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(params): Query<MsgParams>,
) -> Result<Response> {
    let flash = flash_message(user.lang, params.msg.as_deref());
    render(&state, &user, None, flash, None).await
}

#[derive(serde::Deserialize)]
pub struct SettingsForm {
    csrf_token: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    token: String,
    /// SHA-256 fingerprint of a self-signed certificate.
    #[serde(default)]
    cert: String,
    /// "remove": forget address, fingerprint and token.
    #[serde(default)]
    action: String,
}

/// Saves the address and (if given) a new token, or removes both.
pub async fn save(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(f): Form<SettingsForm>,
) -> Result<Response> {
    user.verify_csrf(&f.csrf_token)?;
    let t = user.lang;
    let before = inventory::onm_settings(&state.pool).await?;
    let object = Object {
        kind: AuditKind::Opennetmon,
        id: None,
        name: "opennetmon",
    };
    if f.action == "remove" {
        inventory::save_onm(&state.pool, &state.secrets, "", "", None).await?;
        record(
            &state,
            &user,
            Action::Changed,
            object,
            Changes::new()
                .field("audit-field-url", &before.url, "")
                .field("audit-field-cert-fingerprint", &before.cert_sha256, "")
                .secret("audit-field-token", before.has_token),
        )
        .await;
        return Ok(Redirect::to("/assets/opennetmon?msg=onm_saved").into_response());
    }
    let again = |url: String, cert: String| Some(Entered { url, cert });
    let cert_entered: String = f.cert.chars().take(300).collect();
    let url = match opennetmon::check_url(&f.url) {
        Ok(u) => u,
        Err(id) => {
            let error = Some(t.get(id));
            return render(&state, &user, again(f.url, cert_entered), None, error).await;
        }
    };
    let cert = match opennetmon::check_pin(&url, &cert_entered) {
        Ok(c) => c,
        Err(id) => {
            let error = Some(t.get(id));
            return render(&state, &user, again(url, cert_entered), None, error).await;
        }
    };
    let token = f.token.trim();
    if token.chars().count() > 500 || token.chars().any(char::is_control) {
        let error = Some(t.get("onm-error-token-format"));
        return render(&state, &user, again(url, cert), None, error).await;
    }
    if token.is_empty() && !before.has_token {
        let error = Some(t.get("onm-error-no-token"));
        return render(&state, &user, again(url, cert), None, error).await;
    }
    // The stored token only goes to the address and the certificate it was entered for.
    if token.is_empty() && (url != before.url || cert != before.cert_sha256) {
        let error = Some(t.get("onm-error-token-again"));
        return render(&state, &user, again(url, cert), None, error).await;
    }
    let token = (!token.is_empty()).then(|| Secret::new(token));
    inventory::save_onm(&state.pool, &state.secrets, &url, &cert, token.as_ref()).await?;
    record(
        &state,
        &user,
        Action::Changed,
        object,
        Changes::new()
            .field("audit-field-url", &before.url, &url)
            .field("audit-field-cert-fingerprint", &before.cert_sha256, &cert)
            .secret("audit-field-token", token.is_some()),
    )
    .await;
    Ok(Redirect::to("/assets/opennetmon?msg=onm_saved").into_response())
}

#[derive(serde::Deserialize)]
pub struct CsrfForm {
    csrf_token: String,
}

/// Reads opennetmon now.
pub async fn run(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(form): Form<CsrfForm>,
) -> Result<Response> {
    user.verify_csrf(&form.csrf_token)?;
    let to = match opennetmon::read(&state.pool, &state.secrets).await? {
        Ok(_) => "/assets/opennetmon?msg=onm_read",
        Err(_) => "/assets/opennetmon",
    };
    Ok(Redirect::to(to).into_response())
}

/// The suggestion of a device as the input of the asset form.
pub fn input_of(d: &OnmDevice) -> Input {
    Input {
        kind: d.kind.clone(),
        vendor_name: d.vendor_name.clone(),
        product_name: d.product_name.clone(),
        version: d.version.clone(),
        host: d.name.clone(),
        ..Input::default()
    }
}

/// Takes the suggestion over: an asset that follows the device.
pub async fn take(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Response> {
    user.verify_csrf(&form.csrf_token)?;
    let d = inventory::onm_device(&state.pool, id)
        .await?
        .ok_or(Error::NotFound)?;
    if d.state == "taken" && d.asset_id.is_some() {
        return Ok(Redirect::to("/assets/opennetmon").into_response());
    }
    let Ok(checked) = input_of(&d).check() else {
        // Nothing usable suggested: the form shows what is missing.
        return Ok(Redirect::to(&format!("/assets/new?onm={id}")).into_response());
    };
    let now = now_ms();
    let asset_id =
        assets::add_from(&state.pool, &checked, "opennetmon", &origin_ref(id), now).await?;
    inventory::set_onm_state(&state.pool, id, "taken", Some(asset_id)).await?;
    record(
        &state,
        &user,
        Action::Created,
        Object::new(
            AuditKind::Asset,
            asset_id,
            &checked.as_asset(asset_id, now).display_name(),
        ),
        Changes::new()
            .value("audit-field-version", &checked.version)
            .value("audit-field-asset-host", &checked.host)
            .value_label("audit-field-origin", "audit-origin-opennetmon"),
    )
    .await;
    matching::match_asset(&state.pool, asset_id, now_ms()).await?;
    Ok(Redirect::to("/assets/opennetmon?msg=device_taken").into_response())
}

#[derive(serde::Deserialize)]
pub struct StateForm {
    csrf_token: String,
    /// `skipped` or `new`.
    state: String,
}

/// Skips a device, or takes it back into the list.
pub async fn set_state(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<StateForm>,
) -> Result<Response> {
    user.verify_csrf(&form.csrf_token)?;
    let d = inventory::onm_device(&state.pool, id)
        .await?
        .ok_or(Error::NotFound)?;
    let new = match form.state.as_str() {
        "skipped" => "skipped",
        "new" => "new",
        _ => return Err(Error::NotFound),
    };
    if d.state == "taken" && d.asset_id.is_some() {
        return Ok(Redirect::to("/assets/opennetmon").into_response());
    }
    inventory::set_onm_state(&state.pool, id, new, None).await?;
    Ok(Redirect::to("/assets/opennetmon").into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rule_has_a_text() {
        for lang in Lang::ALL {
            for rule in opennetmon::RULES {
                let id = opennetmon::rule_label_id(rule);
                assert_ne!(lang.get(id), id, "{id} missing in {lang:?}");
            }
        }
    }
}
