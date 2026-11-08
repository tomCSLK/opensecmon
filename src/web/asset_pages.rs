//! The page "Assets" (`/assets`): the own software and hardware by host, the form to add or change an
//! asset (with suggestions while typing and a preview of the matches), and the watchlist.
//!
//! Every form works without JavaScript (the preview is then a button); `static/assets.js` shows only the
//! fields of the chosen kind, fills the suggestions and refreshes the preview while typing.

use std::collections::BTreeMap;

use askama::Template;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::{Html, IntoResponse, Redirect, Response};

use crate::audit::{Action, Changes, Kind as AuditKind};
use crate::error::{Error, Result};
use crate::i18n::Lang;
use crate::matching;
use crate::sources::now_ms;
use crate::storage::assets::{self, Asset, Checked, Distro, Input, Kind, Suggestion};
use crate::storage::cve_list::Band;
use crate::storage::inventory;
use crate::storage::matches::{self, Found};
use crate::web::audit::{Object, record};
use crate::web::auth::CurrentUser;
use crate::web::{AppState, Layout, flash_message, time_html};

/// Releases offered in the form (any other can be typed).
const RELEASES: [&str; 9] = [
    "11", "12", "13", "14", "20.04", "22.04", "24.04", "25.10", "26.04",
];
/// Matches listed in the preview.
const PREVIEW_ROWS: usize = 8;

pub struct AssetRow {
    pub id: i64,
    pub name: String,
    pub icon: &'static str,
    pub kind: String,
    pub version: String,
    pub detail: String,
    pub open: i64,
    pub prio: i64,
    pub band: &'static str,
    /// Matches below this priority are muted (0: none).
    pub min_prio: i64,
    /// Why the asset is not matched (a kernel of Raspberry Pi OS), or empty.
    pub no_source: String,
}

pub struct GroupView {
    /// Number of the group, for folding it.
    pub key: usize,
    pub host: String,
    pub named: bool,
    pub count: String,
    /// Different vulnerabilities with open matches (two packages often share one).
    pub open: usize,
    pub vulns: std::collections::HashSet<String>,
    pub prio: i64,
    pub band: &'static str,
    pub rows: Vec<AssetRow>,
    /// System of a host read over SSH (from the host: escaped) and its last reading.
    pub sub: String,
    pub sub_time: Option<String>,
    /// Packages of an SSH host without open matches, not listed.
    pub hidden: usize,
    pub hidden_text: String,
}

pub struct Tab {
    pub href: &'static str,
    pub icon: &'static str,
    pub label: String,
    pub count: i64,
    pub current: bool,
}

#[derive(Template)]
#[template(path = "assets.html")]
struct ListTemplate {
    t: Lang,
    layout: Layout,
    tabs: Vec<Tab>,
    groups: Vec<GroupView>,
    total: usize,
    shown: usize,
    q: String,
    kind: String,
    open_only: bool,
    host: String,
    kinds: Vec<(&'static str, String)>,
    flash: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct ListParams {
    q: Option<String>,
    kind: Option<String>,
    open: Option<String>,
    /// Only this host, with all its packages.
    host: Option<String>,
    msg: Option<String>,
}

/// The areas of the page "Assets" with their counts; `current` is the one shown.
pub(crate) async fn tabs(state: &AppState, t: Lang, current: &str) -> Result<Vec<Tab>> {
    let (assets, watches, hosts, computers, devices): (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM assets), (SELECT COUNT(*) FROM watchlist),
                (SELECT COUNT(*) FROM ssh_hosts), (SELECT COUNT(*) FROM agent_devices),
                (SELECT COUNT(*) FROM onm_devices WHERE state = 'new')",
    )
    .fetch_one(&state.pool)
    .await?;
    let tab = |href, icon, label: &str, count, key| Tab {
        href,
        icon,
        label: t.get(label),
        count,
        current: current == key,
    };
    Ok(vec![
        tab("/assets", "server", "assets-tab-assets", assets, "assets"),
        tab(
            "/assets/watchlist",
            "tag",
            "assets-tab-watchlist",
            watches,
            "watchlist",
        ),
        tab(
            "/assets/hosts",
            "terminal",
            "assets-tab-hosts",
            hosts,
            "hosts",
        ),
        tab(
            "/assets/computers",
            "cpu",
            "assets-tab-computers",
            computers,
            "computers",
        ),
        tab(
            "/assets/unassigned",
            "package",
            "assets-tab-unassigned",
            crate::storage::items::unassigned_counts(&state.pool)
                .await?
                .0 as i64,
            "unassigned",
        ),
        tab(
            "/assets/opennetmon",
            "network",
            "assets-tab-opennetmon",
            devices,
            "opennetmon",
        ),
        tab("/assets/csv", "upload", "assets-tab-csv", -1, "csv"),
    ])
}

/// The id of the text that names where an asset comes from (`None`: entered by hand).
pub(crate) fn origin_label_id(origin: &str) -> Option<&'static str> {
    match origin {
        "ssh" => Some("asset-origin-ssh"),
        "agent" => Some("asset-origin-agent"),
        "opennetmon" => Some("asset-origin-opennetmon"),
        "csv" => Some("asset-origin-csv"),
        _ => None,
    }
}

/// The kind as shown in the list: "Package · Ubuntu 24.04 · SSH", "Software".
fn kind_text(t: Lang, a: &Asset) -> String {
    let mut parts = vec![t.get(a.kind().label_id())];
    let release = a.release_label();
    if !release.is_empty() {
        parts.push(release);
    }
    if let Some(id) = origin_label_id(&a.origin) {
        parts.push(t.get(id));
    }
    parts.join(" · ")
}

/// The list of assets, grouped by host.
pub async fn list(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(params): Query<ListParams>,
) -> Result<Html<String>> {
    let t = user.lang;
    let all = assets::all(&state.pool).await?;
    let open = matches::open_per_asset(&state.pool).await?;
    let q: String = params
        .q
        .as_deref()
        .unwrap_or_default()
        .trim()
        .chars()
        .take(100)
        .collect();
    let needle = q.to_lowercase();
    let kind = params
        .kind
        .as_deref()
        .and_then(Kind::parse)
        .map(Kind::as_str)
        .unwrap_or_default()
        .to_owned();
    let open_only = params.open.as_deref().is_some_and(|v| v == "1");
    let host: String = params
        .host
        .as_deref()
        .unwrap_or_default()
        .trim()
        .chars()
        .take(100)
        .collect();
    let host_key = host.to_lowercase();
    // Hosts read over SSH and computers that report: their packages without open matches are only counted (a
    // host has a thousand).
    let (_, unassigned) = crate::storage::items::unassigned_counts(&state.pool).await?;
    // Software no rule assigns is not an asset yet: it must not look like a host without matches.
    let unassigned_suffix = |origin_ref: String| match unassigned.get(&origin_ref) {
        Some(n) if *n > 0 => format!(" · {}", t.get1("computers-unassigned", "count", *n)),
        _ => String::new(),
    };
    let mut ssh: std::collections::HashMap<String, (String, Option<String>)> =
        inventory::hosts(&state.pool)
            .await?
            .into_iter()
            .map(|h| {
                let sub = format!(
                    "{} · {}{}",
                    h.os_name,
                    t.get("asset-origin-ssh"),
                    unassigned_suffix(h.origin_ref())
                );
                (h.name.to_lowercase(), (sub, h.last_ok_ms.map(time_html)))
            })
            .collect();
    for d in crate::storage::agents::devices(&state.pool).await? {
        if d.last_report_ms.is_some() {
            let sub = format!(
                "{} · {}{}",
                d.os_name,
                t.get("asset-origin-agent"),
                unassigned_suffix(d.origin_ref())
            );
            ssh.insert(
                d.name.to_lowercase(),
                (sub, d.last_report_ms.map(time_html)),
            );
        }
    }
    let fold = needle.is_empty() && host.is_empty() && !open_only;
    let mut groups: BTreeMap<(bool, String), GroupView> = BTreeMap::new();
    let mut shown = 0;
    for a in &all {
        if !host.is_empty() && a.host.to_lowercase() != host_key {
            continue;
        }
        let (n, prio) = open.get(&a.id).map_or((0, 0), |o| (o.count, o.prio));
        let text = format!(
            "{} {} {} {} {}",
            a.vendor_name, a.product_name, a.version, a.host, a.cpe
        )
        .to_lowercase();
        if (!needle.is_empty() && !text.contains(&needle))
            || (!kind.is_empty() && a.kind != kind)
            || (open_only && n == 0)
        {
            continue;
        }
        let key = (a.host.is_empty(), a.host.to_lowercase());
        let g = groups.entry(key).or_insert_with(|| GroupView {
            key: 0,
            host: if a.host.is_empty() {
                t.get("assets-no-host")
            } else {
                a.host.clone()
            },
            named: !a.host.is_empty(),
            count: String::new(),
            open: 0,
            vulns: Default::default(),
            prio: 0,
            band: "low",
            rows: Vec::new(),
            sub: ssh
                .get(&a.host.to_lowercase())
                .map(|s| s.0.clone())
                .unwrap_or_default(),
            sub_time: ssh.get(&a.host.to_lowercase()).and_then(|s| s.1.clone()),
            hidden: 0,
            hidden_text: String::new(),
        });
        if let Some(o) = open.get(&a.id) {
            g.vulns.extend(o.vulns.iter().cloned());
        }
        g.prio = g.prio.max(prio);
        // A package without a data source stays visible, it must not look like a package without matches.
        let pi_kernel = a.pi_kernel();
        if fold && matches!(a.origin.as_str(), "ssh" | "agent") && n == 0 && !pi_kernel {
            g.hidden += 1;
            continue;
        }
        shown += 1;
        g.rows.push(AssetRow {
            id: a.id,
            name: a.display_name(),
            icon: a.kind().icon(),
            kind: kind_text(t, a),
            version: a.version.clone(),
            detail: if a.cpe.is_empty() {
                a.note.clone()
            } else {
                a.cpe.clone()
            },
            open: n,
            prio,
            band: Band::of_prio(prio).as_str(),
            min_prio: a.min_prio,
            no_source: if pi_kernel {
                t.get("asset-no-source-pi")
            } else {
                String::new()
            },
        });
    }
    let groups: Vec<GroupView> = groups
        .into_values()
        .enumerate()
        .map(|(key, mut g)| {
            g.key = key;
            g.open = g.vulns.len();
            g.count = t.get1("assets-group-count", "count", g.rows.len() + g.hidden);
            if g.hidden > 0 {
                g.hidden_text = t.get1("assets-hidden", "count", g.hidden);
            }
            g.band = Band::of_prio(g.prio).as_str();
            g
        })
        .collect();
    let html = ListTemplate {
        t,
        layout: user.layout().at("assets"),
        tabs: tabs(&state, t, "assets").await?,
        groups,
        total: all.len(),
        shown,
        q,
        kind,
        open_only,
        host,
        kinds: Kind::ALL
            .iter()
            .map(|k| (k.as_str(), t.get(k.label_id())))
            .collect(),
        flash: flash_message(t, params.msg.as_deref()),
        error: None,
    }
    .render()?;
    Ok(Html(html))
}

/// The fields of the form as sent (and as shown again).
#[derive(Debug, Default, Clone, serde::Deserialize)]
pub struct AssetForm {
    #[serde(default)]
    csrf_token: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    vendor_name: String,
    #[serde(default)]
    product_name: String,
    #[serde(default)]
    package: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    cpe: String,
    #[serde(default)]
    distro: String,
    #[serde(default)]
    release: String,
    #[serde(default)]
    pro: Option<String>,
    #[serde(default)]
    note: String,
    /// Priority from which the matches show (empty or 0: all).
    #[serde(default)]
    min_prio: String,
    /// "preview": show the matches instead of saving.
    #[serde(default)]
    action: String,
    /// The asset being changed (preview of a stored asset).
    #[serde(default)]
    id: Option<i64>,
    /// A new asset for this opennetmon device (it then follows the device).
    #[serde(default)]
    onm: Option<i64>,
}

impl AssetForm {
    fn input(&self) -> Input {
        let package = self.kind == "package";
        Input {
            kind: self.kind.clone(),
            vendor_name: if package {
                String::new()
            } else {
                self.vendor_name.clone()
            },
            product_name: if package {
                self.package.clone()
            } else {
                self.product_name.clone()
            },
            version: self.version.clone(),
            host: self.host.clone(),
            cpe: if package {
                String::new()
            } else {
                self.cpe.clone()
            },
            distro: self.distro.clone(),
            release: self.release.clone(),
            pro: self.pro.as_deref().is_some_and(|v| !v.is_empty()),
            note: self.note.clone(),
        }
    }

    fn of(a: &Asset) -> Self {
        let package = a.kind() == Kind::Package;
        Self {
            kind: a.kind.clone(),
            vendor_name: if package {
                String::new()
            } else {
                a.vendor_name.clone()
            },
            product_name: if package {
                String::new()
            } else {
                a.product_name.clone()
            },
            package: if package {
                a.product_name.clone()
            } else {
                String::new()
            },
            version: a.version.clone(),
            host: a.host.clone(),
            cpe: a.cpe.clone(),
            distro: a.distro.clone(),
            release: a.release.clone(),
            pro: a.pro.then(|| "1".to_owned()),
            note: a.note.clone(),
            min_prio: if a.min_prio > 0 {
                a.min_prio.to_string()
            } else {
                String::new()
            },
            id: Some(a.id),
            ..Self::default()
        }
    }
}

pub struct PreviewItem {
    pub vuln: String,
    pub href: String,
    pub title: String,
    pub prio: i64,
    pub band: &'static str,
    pub confidence: String,
    pub confidence_class: &'static str,
}

pub struct PreviewView {
    pub text: String,
    pub class: &'static str,
    pub items: Vec<PreviewItem>,
    pub more: String,
}

#[derive(Template)]
#[template(path = "asset_form.html")]
struct FormTemplate {
    t: Lang,
    layout: Layout,
    tabs: Vec<Tab>,
    f: AssetForm,
    id: Option<i64>,
    title: String,
    action: String,
    hosts: Vec<String>,
    releases: &'static [&'static str],
    preview: Option<PreviewView>,
    error: Option<String>,
    flash: Option<String>,
    matched: Option<String>,
    /// Where the asset comes from, if not from this form (it may be overwritten).
    origin_note: Option<String>,
    /// A package of an SSH host or computer: its Ubuntu Pro follows the host, set on this page.
    pro_from: Option<String>,
    /// Why the stored asset is not matched, or nothing.
    no_source: Option<String>,
}

#[derive(Template)]
#[template(path = "asset_preview.html")]
struct PreviewTemplate {
    preview: PreviewView,
}

/// The CSS class of a confidence (the names of the drafts).
pub(crate) fn conf_class(c: matches::Confidence) -> &'static str {
    match c {
        matches::Confidence::High => "conf-hoch",
        matches::Confidence::Medium => "conf-mittel",
        matches::Confidence::Low => "conf-niedrig",
    }
}

/// The link of a vulnerability: the CVE page, the advisory page, or the inbox.
pub(crate) fn vuln_href(vuln: &str) -> String {
    if let Some(seq) = vuln.strip_prefix("adv:") {
        format!("/advisories/{seq}")
    } else if vuln.starts_with("osv:") {
        format!("/?view=all&sel={}", crate::web::cves::encode(vuln))
    } else {
        format!("/cves/{vuln}")
    }
}

/// The id shown for a vulnerability ("CVE-2026-1", "WID-SEC-2026-7", "USN-9000-1").
pub(crate) fn vuln_label(vuln: &str, evidence: &str) -> String {
    if let Some(id) = vuln.strip_prefix("osv:") {
        id.to_owned()
    } else if vuln.starts_with("adv:") {
        evidence
            .split(',')
            .next()
            .filter(|e| !e.is_empty())
            .unwrap_or(vuln)
            .to_owned()
    } else {
        vuln.to_owned()
    }
}

/// What the matching would find for the asset in the form.
pub(crate) async fn preview(
    state: &AppState,
    t: Lang,
    checked: &Checked,
    created_ms: i64,
) -> Result<PreviewView> {
    let asset = checked.as_asset(0, created_ms);
    if asset.pi_kernel() {
        return Ok(PreviewView {
            text: t.get("asset-no-source-pi-note"),
            class: "info",
            items: Vec::new(),
            more: String::new(),
        });
    }
    let found = matching::find(&state.pool, &asset).await?;
    // Priorities as the inbox shows them.
    let weights = crate::storage::prio::load(&state.pool).await?;
    let mut items: Vec<(i64, &Found)> = Vec::new();
    for f in &found {
        let base: Option<(i64, bool)> =
            sqlx::query_as("SELECT prio, kev_added IS NOT NULL FROM cves WHERE id = ?")
                .bind(&f.vuln)
                .fetch_optional(&state.pool)
                .await?;
        let (base, kev) = base.unwrap_or((f.base_prio, false));
        items.push((weights.match_prio(base, kev, f.confidence, f.rating), f));
    }
    items.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.vuln.cmp(&a.1.vuln)));
    let count = items.len();
    let (text, class) = if count == 0 {
        (t.get("asset-preview-none"), "info")
    } else {
        (t.get1("asset-preview-count", "count", count), "warn")
    };
    let more = if count > PREVIEW_ROWS {
        t.get1("asset-preview-more", "count", count - PREVIEW_ROWS)
    } else {
        String::new()
    };
    Ok(PreviewView {
        text,
        class,
        items: items
            .into_iter()
            .take(PREVIEW_ROWS)
            .map(|(prio, f)| PreviewItem {
                vuln: vuln_label(&f.vuln, &f.evidence.join(",")),
                href: vuln_href(&f.vuln),
                title: f.title.clone(),
                prio,
                band: Band::of_prio(prio).as_str(),
                confidence: t.get(f.confidence.label_id()),
                confidence_class: conf_class(f.confidence),
            })
            .collect(),
        more,
    })
}

async fn render_form(
    state: &AppState,
    user: &CurrentUser,
    f: AssetForm,
    preview: Option<PreviewView>,
    error: Option<String>,
    flash: Option<String>,
) -> Result<Response> {
    let t = user.lang;
    let id = f.id;
    let stored = match id {
        Some(id) => assets::get(&state.pool, id).await?,
        None => None,
    };
    let origin_note = match (&stored, f.onm) {
        (Some(a), _) if a.origin == "ssh" => Some(t.get("asset-origin-ssh-note")),
        (Some(a), _) if a.origin == "agent" => Some(t.get("asset-origin-agent-note")),
        (Some(a), _) if a.origin == "opennetmon" => Some(t.get("asset-origin-onm-note")),
        (None, Some(onm)) => inventory::onm_device(&state.pool, onm)
            .await?
            .map(|d| t.get1("asset-origin-onm-new", "device", d.name)),
        _ => None,
    };
    let html = FormTemplate {
        t,
        layout: user.layout().at("assets"),
        tabs: tabs(state, t, "assets").await?,
        title: match &stored {
            Some(a) => a.display_name(),
            None => t.get("asset-new-title"),
        },
        action: match id {
            Some(id) => format!("/assets/{id}"),
            None => "/assets/new".to_owned(),
        },
        pro_from: stored.as_ref().and_then(|a| {
            let (kind, id) = a.origin_ref.split_once(':')?;
            match kind {
                "ssh" if a.origin == "ssh" => Some(format!("/assets/hosts/{id}/edit")),
                "agent" if a.origin == "agent" => Some(format!("/assets/computers/{id}")),
                _ => None,
            }
        }),
        no_source: stored
            .as_ref()
            .filter(|a| a.pi_kernel())
            .map(|_| t.get("asset-no-source-pi-note")),
        matched: stored.and_then(|a| a.matched_ms).map(time_html),
        origin_note,
        id,
        f,
        hosts: assets::hosts(&state.pool).await?,
        releases: &RELEASES,
        preview,
        error,
        flash,
    }
    .render()?;
    Ok(Html(html).into_response())
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct NewParams {
    host: Option<String>,
    /// Fill the form with the suggestion for this opennetmon device.
    onm: Option<i64>,
}

/// The empty form.
pub async fn new_form(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(params): Query<NewParams>,
) -> Result<Response> {
    let mut f = AssetForm {
        kind: "software".to_owned(),
        distro: "ubuntu".to_owned(),
        host: params.host.unwrap_or_default().chars().take(100).collect(),
        ..AssetForm::default()
    };
    if let Some(onm) = params.onm
        && let Some(d) = inventory::onm_device(&state.pool, onm).await?
    {
        let input = crate::web::onm_import::input_of(&d);
        f.kind = if input.kind.is_empty() {
            "hardware".to_owned()
        } else {
            input.kind
        };
        f.vendor_name = input.vendor_name;
        f.product_name = input.product_name;
        f.version = input.version;
        f.host = input.host;
        f.onm = Some(onm);
    }
    render_form(&state, &user, f, None, None, None).await
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct EditParams {
    msg: Option<String>,
}

/// The form of a stored asset.
pub async fn edit_form(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
    Query(params): Query<EditParams>,
) -> Result<Response> {
    let a = assets::get(&state.pool, id).await?.ok_or(Error::NotFound)?;
    let flash = flash_message(user.lang, params.msg.as_deref());
    render_form(&state, &user, AssetForm::of(&a), None, None, flash).await
}

/// The changes of an asset for the audit log (`old`: `None` for a new asset).
fn changes(old: Option<&Asset>, new: &Checked) -> Changes {
    let pro = |p: bool| if p { "Pro" } else { "" };
    let new_asset = new.as_asset(0, 0);
    let text = |f: fn(&Asset) -> String| old.map(f).unwrap_or_default();
    Changes::new()
        .field(
            "audit-field-asset-kind",
            text(|a| a.kind.clone()),
            new.kind.as_str(),
        )
        .field(
            "audit-field-vendor",
            text(|a| a.vendor_name.clone()),
            &new.vendor_name,
        )
        .field(
            "audit-field-product",
            text(|a| a.product_name.clone()),
            &new.product_name,
        )
        .field(
            "audit-field-version",
            text(|a| a.version.clone()),
            &new.version,
        )
        .field(
            "audit-field-release",
            text(Asset::release_label),
            new_asset.release_label(),
        )
        .field(
            "audit-field-pro",
            pro(old.is_some_and(|a| a.pro)),
            pro(new.pro),
        )
        .field(
            "audit-field-asset-host",
            text(|a| a.host.clone()),
            &new.host,
        )
        .field("audit-field-cpe", text(|a| a.cpe.clone()), &new.cpe)
        .field("audit-field-note", text(|a| a.note.clone()), &new.note)
}

/// Saves a new asset (or shows the preview), then matches it.
pub async fn create(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(mut f): Form<AssetForm>,
) -> Result<Response> {
    user.verify_csrf(&f.csrf_token)?;
    f.id = None;
    save(&state, &user, f, None).await
}

/// Saves a changed asset (or shows the preview), then matches it again.
pub async fn update(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
    Form(mut f): Form<AssetForm>,
) -> Result<Response> {
    user.verify_csrf(&f.csrf_token)?;
    let old = assets::get(&state.pool, id).await?.ok_or(Error::NotFound)?;
    f.id = Some(id);
    save(&state, &user, f, Some(old)).await
}

async fn save(
    state: &AppState,
    user: &CurrentUser,
    f: AssetForm,
    old: Option<Asset>,
) -> Result<Response> {
    let t = user.lang;
    let checked = match f.input().check() {
        Ok(c) => c,
        Err(id) => return render_form(state, user, f, None, Some(t.get(id)), None).await,
    };
    let min_prio = match f.min_prio.trim() {
        "" => 0,
        text => match text.parse::<i64>().ok().filter(|p| (0..=100).contains(p)) {
            Some(p) => p,
            None => {
                let error = Some(t.get("asset-error-min-prio"));
                return render_form(state, user, f, None, error, None).await;
            }
        },
    };
    let now = now_ms();
    if f.action == "preview" {
        let created = old.as_ref().map_or(now, |a| a.created_ms);
        let p = preview(state, t, &checked, created).await?;
        return render_form(state, user, f, Some(p), None, None).await;
    }
    let device = match (&old, f.onm) {
        (None, Some(onm)) => inventory::onm_device(&state.pool, onm)
            .await?
            .filter(|d| !(d.state == "taken" && d.asset_id.is_some())),
        _ => None,
    };
    let (id, action) = match (&old, &device) {
        (Some(a), _) => {
            assets::update(&state.pool, a.id, &checked, now).await?;
            (a.id, Action::Changed)
        }
        (None, Some(d)) => {
            let origin_ref = crate::web::onm_import::origin_ref(d.id);
            let id =
                assets::add_from(&state.pool, &checked, "opennetmon", &origin_ref, now).await?;
            inventory::set_onm_state(&state.pool, d.id, "taken", Some(id)).await?;
            (id, Action::Created)
        }
        (None, None) => (
            assets::add(&state.pool, &checked, now).await?,
            Action::Created,
        ),
    };
    assets::set_min_prio(&state.pool, id, min_prio).await?;
    let old_min = old.as_ref().map_or(0, |a| a.min_prio);
    let show = |p: i64| if p > 0 { p.to_string() } else { String::new() };
    record(
        state,
        user,
        action,
        Object::new(
            AuditKind::Asset,
            id,
            &checked.as_asset(id, now).display_name(),
        ),
        changes(old.as_ref(), &checked).field(
            "audit-field-min-prio",
            show(old_min),
            show(min_prio),
        ),
    )
    .await;
    matching::match_asset(&state.pool, id, now_ms()).await?;
    if device.is_some() {
        return Ok(Redirect::to("/assets/opennetmon?msg=device_taken").into_response());
    }
    let msg = if old.is_some() {
        "asset_saved"
    } else {
        "asset_added"
    };
    Ok(Redirect::to(&format!("/assets?msg={msg}")).into_response())
}

#[derive(serde::Deserialize)]
pub struct CsrfForm {
    csrf_token: String,
}

/// Removes an asset with its matches.
pub async fn delete(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Response> {
    user.verify_csrf(&form.csrf_token)?;
    let a = assets::delete(&state.pool, id)
        .await?
        .ok_or(Error::NotFound)?;
    record(
        &state,
        &user,
        Action::Deleted,
        Object::new(AuditKind::Asset, id, &a.display_name()),
        Changes::new()
            .value("audit-field-version", &a.version)
            .value("audit-field-asset-host", &a.host),
    )
    .await;
    Ok(Redirect::to("/assets?msg=asset_deleted").into_response())
}

/// The preview as a fragment, for `static/assets.js` (the form's own button renders the whole page).
pub async fn preview_fragment(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(form): Query<AssetForm>,
) -> Result<Response> {
    let t = user.lang;
    let preview = match form.input().check() {
        Ok(checked) => {
            let created = match form.id {
                Some(id) => assets::get(&state.pool, id)
                    .await?
                    .map_or_else(now_ms, |a| a.created_ms),
                None => now_ms(),
            };
            preview(&state, t, &checked, created).await?
        }
        Err(id) => PreviewView {
            text: t.get(id),
            class: "info",
            items: Vec::new(),
            more: String::new(),
        },
    };
    Ok(Html(PreviewTemplate { preview }.render()?).into_response())
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct SuggestParams {
    field: Option<String>,
    q: Option<String>,
    vendor: Option<String>,
    distro: Option<String>,
    release: Option<String>,
}

/// Suggestions while typing, as JSON (`[{"name": …, "hint": …}]`).
pub async fn suggest(
    State(state): State<AppState>,
    _user: CurrentUser,
    Query(p): Query<SuggestParams>,
) -> Result<Response> {
    let q: String = p.q.unwrap_or_default().chars().take(100).collect();
    let list: Vec<Suggestion> = match p.field.as_deref() {
        Some("vendor") => assets::suggest_vendors(&state.pool, &q).await?,
        Some("product") => {
            let vendor: String = p.vendor.unwrap_or_default().chars().take(200).collect();
            assets::suggest_products(&state.pool, &vendor, &q).await?
        }
        Some("package") => match p.distro.as_deref().and_then(Distro::parse) {
            Some(d) => {
                let release: String = p.release.unwrap_or_default().chars().take(10).collect();
                assets::suggest_packages(&state.pool, d, release.trim(), &q).await?
            }
            None => Vec::new(),
        },
        _ => Vec::new(),
    };
    let body = serde_json::to_string(&list).map_err(|e| Error::Internal(e.to_string()))?;
    Ok(([(header::CONTENT_TYPE, "application/json")], body).into_response())
}

// ---------------------------------------------------------------------------------------------------
// Watchlist

pub struct WatchView {
    pub id: i64,
    pub keyword: String,
    pub open: i64,
    pub since: String,
}

#[derive(Template)]
#[template(path = "watchlist.html")]
struct WatchTemplate {
    t: Lang,
    layout: Layout,
    tabs: Vec<Tab>,
    watches: Vec<WatchView>,
    keyword: String,
    flash: Option<String>,
    error: Option<String>,
}

async fn render_watchlist(
    state: &AppState,
    user: &CurrentUser,
    keyword: String,
    flash: Option<String>,
    error: Option<String>,
) -> Result<Response> {
    let t = user.lang;
    let watches = assets::watches(&state.pool).await?;
    let open = matches::open_per_watch(&state.pool).await?;
    let html = WatchTemplate {
        t,
        layout: user.layout().at("assets"),
        tabs: tabs(state, t, "watchlist").await?,
        watches: watches
            .iter()
            .map(|w| WatchView {
                id: w.id,
                keyword: w.keyword.clone(),
                open: open.get(&w.id).copied().unwrap_or(0),
                since: crate::web::cves::date(t, Some(w.since_ms)),
            })
            .collect(),
        keyword,
        flash,
        error,
    }
    .render()?;
    Ok(Html(html).into_response())
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct WatchParams {
    msg: Option<String>,
}

pub async fn watchlist(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(params): Query<WatchParams>,
) -> Result<Response> {
    let flash = flash_message(user.lang, params.msg.as_deref());
    render_watchlist(&state, &user, String::new(), flash, None).await
}

#[derive(serde::Deserialize)]
pub struct WatchForm {
    csrf_token: String,
    #[serde(default)]
    keyword: String,
}

pub async fn add_watch(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(form): Form<WatchForm>,
) -> Result<Response> {
    user.verify_csrf(&form.csrf_token)?;
    let t = user.lang;
    let keyword = match assets::check_keyword(&form.keyword) {
        Ok(k) => k,
        Err(id) => {
            return render_watchlist(&state, &user, form.keyword, None, Some(t.get(id))).await;
        }
    };
    let now = now_ms();
    let Some(id) = assets::add_watch(&state.pool, &keyword, now).await? else {
        let error = t.get("watch-error-exists");
        return render_watchlist(&state, &user, keyword, None, Some(error)).await;
    };
    record(
        &state,
        &user,
        Action::Created,
        Object::new(AuditKind::Watch, id, &keyword),
        Changes::new(),
    )
    .await;
    matching::match_watch(&state.pool, id, now).await?;
    Ok(Redirect::to("/assets/watchlist?msg=watch_added").into_response())
}

pub async fn delete_watch(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Response> {
    user.verify_csrf(&form.csrf_token)?;
    let w = assets::delete_watch(&state.pool, id)
        .await?
        .ok_or(Error::NotFound)?;
    record(
        &state,
        &user,
        Action::Deleted,
        Object::new(AuditKind::Watch, id, &w.keyword),
        Changes::new(),
    )
    .await;
    Ok(Redirect::to("/assets/watchlist?msg=watch_deleted").into_response())
}

/// Texts that only templates use, for the catalog check: "asset-back" "asset-cancel" "asset-cpe"
/// "asset-cpe-help" "asset-delete" "asset-delete-help" "asset-distro" "asset-fields-package"
/// "asset-fields-product" "asset-host" "asset-host-help" "asset-kind" "asset-kind-package-help"
/// "asset-matched" "asset-note" "asset-package" "asset-package-help" "asset-preview" "asset-preview-hint"
/// "asset-preview-title" "asset-pro" "asset-pro-help" "asset-product" "asset-release" "asset-release-help"
/// "asset-save" "asset-vendor" "asset-vendor-help" "asset-version" "asset-version-help" "assets-add"
/// "assets-add-here" "assets-areas" "assets-col-asset" "assets-col-detail" "assets-col-kind"
/// "assets-col-open" "assets-col-version" "assets-filter" "assets-kind-any" "assets-none-filtered"
/// "assets-none-text" "assets-none-title" "assets-open-count" "assets-open-none" "assets-open-only"
/// "assets-search" "assets-search-placeholder" "assets-shown" "assets-subtitle" "assets-title"
/// "assets-toggle" "watch-add" "watch-add-help" "watch-delete" "watch-keyword" "watch-none" "watch-open"
/// "watch-since" "watch-text" "watch-title"
#[cfg(test)]
mod tests {
    use crate::web::testutil::*;
    use axum::http::StatusCode;

    async fn post_form(h: &Harness, session: &str, path: &str, fields: &[(&str, &str)]) -> Reply {
        let form: Vec<String> = fields
            .iter()
            .map(|(k, v)| format!("{k}={}", crate::web::cves::encode(v)))
            .collect();
        send(&h.app, post(path, Some(session), &form.join("&"))).await
    }

    #[tokio::test]
    async fn assets_are_added_changed_and_removed() {
        let h = harness(true).await;
        let (session, csrf) = login(&h, "anna").await;
        let reply = send(&h.app, get("/assets", Some(&session))).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert!(reply.body.contains("Noch keine Assets"));

        // Invalid: shown again with the message and the entered values.
        let reply = post_form(
            &h,
            &session,
            "/assets/new",
            &[
                ("csrf_token", &csrf),
                ("kind", "package"),
                ("distro", "ubuntu"),
                ("release", "noble"),
                ("package", "openssh"),
                ("version", "1:9.6p1-3ubuntu13.4"),
            ],
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        assert!(reply.body.contains("Release"), "{}", reply.body);
        assert!(reply.body.contains("value=\"openssh\""));

        let reply = post_form(
            &h,
            &session,
            "/assets/new",
            &[
                ("csrf_token", &csrf),
                ("kind", "package"),
                ("distro", "ubuntu"),
                ("release", "24.04"),
                ("package", "openssh"),
                ("version", "1:9.6p1-3ubuntu13.4"),
                ("host", "<server01>"),
            ],
        )
        .await;
        assert_eq!(reply.location(), "/assets?msg=asset_added");
        let reply = send(&h.app, get("/assets", Some(&session))).await;
        assert!(
            reply.body.contains("server01") && !reply.body.contains("<server01>"),
            "escaped host"
        );
        assert!(reply.body.contains("Ubuntu 24.04"));
        let id: i64 = sqlx::query_scalar("SELECT id FROM assets")
            .fetch_one(&h.state.pool)
            .await
            .unwrap();

        // Preview without saving.
        let reply = post_form(
            &h,
            &session,
            &format!("/assets/{id}"),
            &[
                ("csrf_token", &csrf),
                ("kind", "software"),
                ("vendor_name", "OpenBSD"),
                ("product_name", "OpenSSH"),
                ("version", "9.6p1"),
                ("action", "preview"),
            ],
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        assert!(reply.body.contains("keine bekannte Meldung"));
        let kind: String = sqlx::query_scalar("SELECT kind FROM assets")
            .fetch_one(&h.state.pool)
            .await
            .unwrap();
        assert_eq!(kind, "package", "the preview saves nothing");

        let reply = send(&h.app, get(&format!("/assets/{id}"), Some(&session))).await;
        assert!(reply.body.contains("value=\"1:9.6p1-3ubuntu13.4\""));

        let reply = post_form(
            &h,
            &session,
            &format!("/assets/{id}/delete"),
            &[("csrf_token", &csrf)],
        )
        .await;
        assert_eq!(reply.location(), "/assets?msg=asset_deleted");
        let reply = send(&h.app, get(&format!("/assets/{id}"), Some(&session))).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND);
        let audit: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE kind = 'asset'")
            .fetch_one(&h.state.pool)
            .await
            .unwrap();
        assert_eq!(audit, 2);
    }

    #[tokio::test]
    async fn changes_need_the_csrf_token() {
        let h = harness(true).await;
        let (session, _) = login(&h, "anna").await;
        let reply = post_form(
            &h,
            &session,
            "/assets/new",
            &[
                ("csrf_token", "wrong"),
                ("kind", "software"),
                ("product_name", "X"),
            ],
        )
        .await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        let reply = post_form(
            &h,
            &session,
            "/assets/watchlist",
            &[("csrf_token", "wrong"), ("keyword", "Zigbee")],
        )
        .await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn the_watchlist_takes_keywords_once() {
        let h = harness(true).await;
        let (session, csrf) = login(&h, "anna").await;
        let reply = post_form(
            &h,
            &session,
            "/assets/watchlist",
            &[("csrf_token", &csrf), ("keyword", "Huawei 5G CPE")],
        )
        .await;
        assert_eq!(reply.location(), "/assets/watchlist?msg=watch_added");
        let reply = post_form(
            &h,
            &session,
            "/assets/watchlist",
            &[("csrf_token", &csrf), ("keyword", "Huawei  5G CPE")],
        )
        .await;
        assert!(
            reply.body.contains("schon auf der Watchlist"),
            "{}",
            reply.body
        );
        let reply = post_form(
            &h,
            &session,
            "/assets/watchlist",
            &[("csrf_token", &csrf), ("keyword", "<b>")],
        )
        .await;
        assert!(reply.body.contains("mindestens drei"));
        let reply = send(&h.app, get("/assets/watchlist", Some(&session))).await;
        assert!(reply.body.contains("Huawei 5G CPE"));
    }

    #[tokio::test]
    async fn suggestions_and_preview_answer_scripts() {
        let h = harness(true).await;
        let (session, _) = login(&h, "anna").await;
        let reply = send(
            &h.app,
            get("/assets/suggest?field=vendor&q=op", Some(&session)),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.body, "[]");
        let reply = send(
            &h.app,
            get(
                "/assets/preview?kind=software&product_name=Widget&version=1.0",
                Some(&session),
            ),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        assert!(reply.body.contains("keine bekannte Meldung"));
        assert!(!reply.body.contains("<html"), "a fragment");
    }
}
