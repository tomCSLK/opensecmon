//! Settings page of the priority (`/settings/priority`): the weights of CVSS and EPSS, the floor of CISA KEV and
//! what a medium or low confidence takes off. Saving brings every CVE priority to the new weights in the
//! background (`storage::prio::spawn_recompute`).

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
use crate::storage::cve_list::Band;
use crate::storage::prio::{self, Weights};
use crate::web::audit::{self, Object};
use crate::web::auth::CurrentUser;
use crate::web::{AppState, FlashQuery, Layout, flash_message};

/// A weight as shown: whole numbers without decimals ("7", not "7,0").
pub fn weight_text(t: Lang, w: f64) -> String {
    if w.fract() == 0.0 {
        format!("{w:.0}")
    } else {
        t.decimal(w, 1)
    }
}

/// A number as typed (comma or point as decimal separator).
fn number(text: &str) -> Option<f64> {
    text.trim()
        .replace(',', ".")
        .parse::<f64>()
        .ok()
        .filter(|n| n.is_finite())
}

fn whole(text: &str) -> Option<i64> {
    text.trim()
        .parse::<i64>()
        .ok()
        .filter(|n| (0..=100).contains(n))
}

/// The form as shown (numbers as typed after an error).
struct PrioForm {
    cvss_weight: String,
    epss_weight: String,
    kev_floor: String,
    penalty_medium: String,
    penalty_low: String,
    penalty_unimportant: String,
    penalty_minor: String,
}

impl PrioForm {
    fn of(t: Lang, w: &Weights) -> Self {
        Self {
            cvss_weight: weight_text(t, w.cvss_weight),
            epss_weight: weight_text(t, w.epss_weight),
            kev_floor: w.kev_floor.to_string(),
            penalty_medium: w.penalty_medium.to_string(),
            penalty_low: w.penalty_low.to_string(),
            penalty_unimportant: w.penalty_unimportant.to_string(),
            penalty_minor: w.penalty_minor.to_string(),
        }
    }
}

/// One band of the priority (fixed thresholds).
struct BandRow {
    band: &'static str,
    label: String,
    range: String,
}

/// An example CVE with the current weights.
struct Example {
    cvss: String,
    epss: String,
    kev: bool,
    prio: i64,
    band: &'static str,
}

#[derive(Template)]
#[template(path = "prio_settings.html")]
struct PrioTemplate {
    t: Lang,
    layout: Layout,
    form: PrioForm,
    defaults: PrioForm,
    pending: bool,
    bands: Vec<BandRow>,
    examples: Vec<Example>,
    flash: Option<String>,
    error: Option<String>,
}

fn bands(t: Lang) -> Vec<BandRow> {
    [
        (Band::Crit, "85–100"),
        (Band::High, "65–84"),
        (Band::Med, "45–64"),
        (Band::Low, "0–44"),
    ]
    .into_iter()
    .map(|(b, range)| BandRow {
        band: b.as_str(),
        label: t.get(b.label_id()),
        range: range.to_owned(),
    })
    .collect()
}

fn examples(t: Lang, w: &Weights) -> Vec<Example> {
    [
        (9.8, 0.97, false),
        (7.5, 0.50, false),
        (5.3, 0.10, false),
        (6.5, 0.30, true),
    ]
    .into_iter()
    .map(|(cvss, pct, kev)| {
        let prio = w.cve_prio(Some(cvss), Some(pct), kev);
        Example {
            cvss: t.decimal(cvss, 1),
            epss: format!("{} %", t.decimal(pct * 100.0, 0)),
            kev,
            prio,
            band: Band::of_prio(prio).as_str(),
        }
    })
    .collect()
}

async fn render(
    state: &AppState,
    user: &CurrentUser,
    form: PrioForm,
    flash: Option<String>,
    error: Option<String>,
) -> Result<String> {
    let t = user.lang;
    let w = prio::load(&state.pool).await?;
    let page = PrioTemplate {
        t,
        layout: user.layout(),
        form,
        defaults: PrioForm::of(t, &Weights::default()),
        pending: prio::pending(&state.pool).await?,
        bands: bands(t),
        examples: examples(t, &w),
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
    let w = prio::load(&state.pool).await?;
    let flash = flash_message(user.lang, query.msg.as_deref());
    let form = PrioForm::of(user.lang, &w);
    Ok(Html(render(&state, &user, form, flash, None).await?))
}

#[derive(Deserialize)]
pub struct PrioInput {
    csrf_token: String,
    #[serde(default)]
    cvss_weight: String,
    #[serde(default)]
    epss_weight: String,
    #[serde(default)]
    kev_floor: String,
    #[serde(default)]
    penalty_medium: String,
    #[serde(default)]
    penalty_low: String,
    #[serde(default)]
    penalty_unimportant: String,
    #[serde(default)]
    penalty_minor: String,
    /// "Back to the defaults" instead of the typed values.
    reset: Option<String>,
}

impl PrioInput {
    fn form(&self) -> PrioForm {
        PrioForm {
            cvss_weight: self.cvss_weight.clone(),
            epss_weight: self.epss_weight.clone(),
            kev_floor: self.kev_floor.clone(),
            penalty_medium: self.penalty_medium.clone(),
            penalty_low: self.penalty_low.clone(),
            penalty_unimportant: self.penalty_unimportant.clone(),
            penalty_minor: self.penalty_minor.clone(),
        }
    }

    fn weights(&self) -> std::result::Result<Weights, &'static str> {
        if self.reset.is_some() {
            return Ok(Weights::default());
        }
        let cvss_weight = number(&self.cvss_weight)
            .filter(|w| (0.0..=10.0).contains(w))
            .ok_or("prio-error-cvss")?;
        let epss_weight = number(&self.epss_weight)
            .filter(|w| (0.0..=100.0).contains(w))
            .ok_or("prio-error-epss")?;
        let kev_floor = whole(&self.kev_floor).ok_or("prio-error-kev")?;
        let penalty_medium = whole(&self.penalty_medium).ok_or("prio-error-penalty")?;
        let penalty_low = whole(&self.penalty_low).ok_or("prio-error-penalty")?;
        if penalty_low < penalty_medium {
            return Err("prio-error-order");
        }
        let penalty_unimportant = whole(&self.penalty_unimportant).ok_or("prio-error-penalty")?;
        let penalty_minor = whole(&self.penalty_minor).ok_or("prio-error-penalty")?;
        if penalty_unimportant < penalty_minor {
            return Err("prio-error-rating-order");
        }
        Ok(Weights {
            cvss_weight: (cvss_weight * 10.0).round() / 10.0,
            epss_weight: (epss_weight * 10.0).round() / 10.0,
            kev_floor,
            penalty_medium,
            penalty_low,
            penalty_unimportant,
            penalty_minor,
        })
    }
}

fn changes(t: Lang, old: &Weights, new: &Weights) -> Changes {
    Changes::new()
        .field(
            "audit-field-prio-cvss",
            weight_text(t, old.cvss_weight),
            weight_text(t, new.cvss_weight),
        )
        .field(
            "audit-field-prio-epss",
            weight_text(t, old.epss_weight),
            weight_text(t, new.epss_weight),
        )
        .field(
            "audit-field-prio-kev",
            old.kev_floor.to_string(),
            new.kev_floor.to_string(),
        )
        .field(
            "audit-field-prio-medium",
            old.penalty_medium.to_string(),
            new.penalty_medium.to_string(),
        )
        .field(
            "audit-field-prio-low",
            old.penalty_low.to_string(),
            new.penalty_low.to_string(),
        )
        .field(
            "audit-field-prio-unimportant",
            old.penalty_unimportant.to_string(),
            new.penalty_unimportant.to_string(),
        )
        .field(
            "audit-field-prio-minor",
            old.penalty_minor.to_string(),
            new.penalty_minor.to_string(),
        )
}

pub async fn save(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(input): Form<PrioInput>,
) -> Result<Response> {
    user.verify_csrf(&input.csrf_token)?;
    let before = prio::load(&state.pool).await?;
    match input.weights() {
        Ok(after) => {
            if after != before {
                prio::save(&state.pool, &after, now_ms()).await?;
                audit::record(
                    &state,
                    &user,
                    Action::Changed,
                    Object {
                        kind: AuditKind::Priority,
                        id: None,
                        name: "",
                    },
                    changes(user.lang, &before, &after),
                )
                .await;
                prio::spawn_recompute(state.pool.clone());
            }
            Ok(Redirect::to("/settings/priority?msg=prio_saved").into_response())
        }
        Err(id) => {
            let error = Some(user.lang.get(id));
            let html = render(&state, &user, input.form(), None, error).await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, Html(html)).into_response())
        }
    }
}

#[cfg(test)]
mod tests;
