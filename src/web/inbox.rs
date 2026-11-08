//! The inbox (`/`): the matches of the own assets and the watchlist, one row per vulnerability, with views,
//! filters and the detail of the chosen one; and the triage (`POST /inbox`): done, later, ignore, reopen.
//!
//! Everything is rendered on the server: views, filters and the selection are links, the actions are forms
//! (`static/inbox.js` adds keys and swaps the detail without a reload). Titles, names and versions come from
//! the sources and the user and are escaped by the templates.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use askama::Template;
use axum::Form;
use axum::extract::{Query, State};
use axum::http::Uri;
use axum::response::{Html, IntoResponse, Redirect, Response};

use crate::error::{Error, Result};
use crate::i18n::Lang;
use crate::sources::now_ms;
use crate::storage::advisory_list;
use crate::storage::assets::Kind;
use crate::storage::cve_list::{self, Band};
use crate::storage::matches::{self, Change, Confidence, Method, Row, State as MatchState};
use crate::web::asset_pages::{conf_class, vuln_href, vuln_label};
use crate::web::auth::CurrentUser;
use crate::web::cves::encode;
use crate::web::{AppState, Layout, flash_message};

/// Rows shown at most; more are counted below the list.
const MAX_ROWS: usize = 300;
const DAY_MS: i64 = 86_400_000;
/// Reasons offered for "ignore" (stored as the key).
const REASONS: [&str; 4] = ["unused", "lan", "false", "other"];
const MAX_NOTE: usize = 1000;

// ---------------------------------------------------------------------------------------------------
// Parameters

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum View {
    Open,
    Critical,
    New,
    Later,
    Done,
    Ignored,
}

impl View {
    const ALL: [Self; 6] = [
        Self::Open,
        Self::Critical,
        Self::New,
        Self::Later,
        Self::Done,
        Self::Ignored,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Critical => "critical",
            Self::New => "new",
            Self::Later => "later",
            Self::Done => "done",
            Self::Ignored => "ignored",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }

    fn label_id(self) -> &'static str {
        match self {
            Self::Open => "inbox-view-open",
            Self::Critical => "inbox-view-critical",
            Self::New => "inbox-view-new",
            Self::Later => "inbox-view-later",
            Self::Done => "inbox-view-done",
            Self::Ignored => "inbox-view-ignored",
        }
    }

    fn icon(self) -> &'static str {
        match self {
            Self::Open => "inbox",
            Self::Critical => "flame",
            Self::New => "star",
            Self::Later => "clock",
            Self::Done => "check-circle",
            Self::Ignored => "eye-off",
        }
    }

    fn states(self) -> &'static [MatchState] {
        match self {
            Self::Open | Self::Critical | Self::New => &[MatchState::New, MatchState::Seen],
            Self::Later => &[MatchState::Later],
            Self::Done => &[MatchState::Done],
            Self::Ignored => &[MatchState::Ignored],
        }
    }
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct Params {
    view: Option<String>,
    sev: Option<String>,
    kev: Option<String>,
    fix: Option<String>,
    conf: Option<String>,
    kind: Option<String>,
    host: Option<String>,
    asset: Option<i64>,
    watch: Option<i64>,
    sort: Option<String>,
    sel: Option<String>,
    msg: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sort {
    Prio,
    New,
    Host,
}

impl Sort {
    fn as_str(self) -> &'static str {
        match self {
            Self::Prio => "prio",
            Self::New => "new",
            Self::Host => "host",
        }
    }
}

/// The filters of the list, checked.
#[derive(Debug, Clone, PartialEq)]
struct Filter {
    view: View,
    sev: Option<Band>,
    kev: bool,
    /// Only matches whose fix is announced (a newer version fixes them; apt need not offer it yet).
    fix: bool,
    conf: Option<Confidence>,
    /// `package`, `software`, `hardware` or `watch`.
    kind: Option<&'static str>,
    host: Option<String>,
    asset: Option<i64>,
    watch: Option<i64>,
    sort: Sort,
}

const KINDS: [&str; 4] = ["package", "software", "hardware", "watch"];

impl Params {
    fn filter(&self) -> Filter {
        Filter {
            view: self
                .view
                .as_deref()
                .and_then(View::parse)
                .unwrap_or(View::Open),
            sev: self
                .sev
                .as_deref()
                .and_then(Band::parse)
                .filter(|b| *b != Band::None),
            kev: self.kev.as_deref() == Some("1"),
            fix: self.fix.as_deref() == Some("1"),
            conf: self.conf.as_deref().and_then(|c| match c {
                "high" => Some(Confidence::High),
                "medium" => Some(Confidence::Medium),
                "low" => Some(Confidence::Low),
                _ => None,
            }),
            kind: self
                .kind
                .as_deref()
                .and_then(|k| KINDS.into_iter().find(|x| *x == k)),
            host: self
                .host
                .as_deref()
                .map(|h| h.chars().take(100).collect::<String>())
                .filter(|h| !h.is_empty()),
            asset: self.asset,
            watch: self.watch,
            sort: match self.sort.as_deref() {
                Some("new") => Sort::New,
                Some("host") => Sort::Host,
                _ => Sort::Prio,
            },
        }
    }

    fn selected(&self) -> Option<String> {
        self.sel
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty() && s.len() <= 200)
            .map(str::to_owned)
    }
}

impl Filter {
    /// The query string of the list (only what differs from the defaults), without the selection.
    fn query(&self) -> String {
        let mut parts = Vec::new();
        if self.view != View::Open {
            parts.push(format!("view={}", self.view.as_str()));
        }
        if let Some(b) = self.sev {
            parts.push(format!("sev={}", b.as_str()));
        }
        if self.kev {
            parts.push("kev=1".to_owned());
        }
        if self.fix {
            parts.push("fix=1".to_owned());
        }
        if let Some(c) = self.conf {
            parts.push(format!("conf={}", c.as_str()));
        }
        if let Some(k) = self.kind {
            parts.push(format!("kind={k}"));
        }
        if let Some(h) = &self.host {
            parts.push(format!("host={}", encode(h)));
        }
        if let Some(a) = self.asset {
            parts.push(format!("asset={a}"));
        }
        if let Some(w) = self.watch {
            parts.push(format!("watch={w}"));
        }
        if self.sort != Sort::Prio {
            parts.push(format!("sort={}", self.sort.as_str()));
        }
        parts.join("&")
    }

    fn href(&self, sel: Option<&str>) -> String {
        let mut q = self.query();
        if let Some(sel) = sel {
            if !q.is_empty() {
                q.push('&');
            }
            q.push_str(&format!("sel={}", encode(sel)));
        }
        if q.is_empty() {
            "/".to_owned()
        } else {
            format!("/?{q}")
        }
    }

    /// Whether a match passes the filters on single matches (all but severity and KEV).
    fn row_passes(&self, r: &Row, skip: Group) -> bool {
        (skip == Group::Conf || self.conf.is_none_or(|c| r.confidence() == c))
            && (skip == Group::Fix || !self.fix || !r.fixed.is_empty())
            && (skip == Group::Kind || self.kind.is_none_or(|k| kind_of(r) == k))
            && (skip == Group::Host
                || self
                    .host
                    .as_deref()
                    .is_none_or(|h| r.host.as_deref() == Some(h)))
            && self.asset.is_none_or(|a| r.asset_id == Some(a))
            && self.watch.is_none_or(|w| r.watch_id == Some(w))
            // Muted matches only show when the list is filtered by their asset.
            && (!r.muted() || self.asset.is_some())
    }

    fn item_passes(&self, item: &Item, skip: Group) -> bool {
        (skip == Group::Sev || self.sev.is_none_or(|b| Band::of_prio(item.prio) == b))
            && (skip == Group::Kev || !self.kev || item.kev)
    }
}

/// A group of the filter column (the counts of a group ignore its own filter).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Group {
    None,
    Sev,
    Kev,
    Fix,
    Conf,
    Kind,
    Host,
}

fn kind_of(r: &Row) -> &'static str {
    if r.watch_id.is_some() {
        return "watch";
    }
    r.kind
        .as_deref()
        .and_then(Kind::parse)
        .map_or("software", Kind::as_str)
}

// ---------------------------------------------------------------------------------------------------
// Items: the matches of one vulnerability

/// One vulnerability with its matches that passed the filters.
struct Item<'a> {
    vuln: &'a str,
    rows: Vec<&'a Row>,
    prio: i64,
    kev: bool,
    first_seen_ms: i64,
}

/// Groups the matches by vulnerability, keeping those that pass the filters.
fn items<'a>(rows: &'a [Row], f: &Filter, skip: Group, now: i64) -> Vec<Item<'a>> {
    let mut by_vuln: BTreeMap<&str, Item<'a>> = BTreeMap::new();
    for r in rows {
        if !f.view.states().contains(&r.state()) || !f.row_passes(r, skip) {
            continue;
        }
        let item = by_vuln.entry(r.vuln.as_str()).or_insert_with(|| Item {
            vuln: r.vuln.as_str(),
            rows: Vec::new(),
            prio: 0,
            kev: false,
            first_seen_ms: i64::MAX,
        });
        item.prio = item.prio.max(r.prio());
        item.kev |= r.kev;
        item.first_seen_ms = item.first_seen_ms.min(r.first_seen_ms);
        item.rows.push(r);
    }
    by_vuln
        .into_values()
        .filter(|i| match f.view {
            View::Critical => Band::of_prio(i.prio) == Band::Crit || i.kev,
            View::New => i.first_seen_ms >= now - DAY_MS,
            _ => true,
        })
        .filter(|i| f.item_passes(i, skip))
        .collect()
}

// ---------------------------------------------------------------------------------------------------
// Views for the templates

pub struct ViewRow {
    pub href: String,
    pub icon: &'static str,
    pub label: String,
    pub count: usize,
    pub current: bool,
}

pub struct FacetRow {
    pub href: String,
    pub label: String,
    /// Icon of a band (`crit` …) or empty.
    pub band: &'static str,
    pub count: usize,
    pub on: bool,
}

pub struct FacetGroup {
    pub title: String,
    pub reset: Option<String>,
    pub rows: Vec<FacetRow>,
}

pub struct ListRow {
    pub vuln: String,
    pub label: String,
    pub href: String,
    pub title: String,
    pub prio: i64,
    pub band: &'static str,
    pub prio_title: String,
    pub kev: bool,
    pub unread: bool,
    pub state: &'static str,
    pub state_icon: &'static str,
    pub state_text: String,
    pub age: String,
    pub icon: &'static str,
    pub asset: String,
    pub more_assets: String,
    pub selected: bool,
}

pub struct Chip {
    pub label: String,
    pub href: String,
}

/// An own asset (or keyword) a vulnerability affects, for the detail.
pub struct OwnRow {
    pub name: String,
    pub href: String,
    pub host: String,
    pub icon: &'static str,
    pub installed: String,
    pub fixed: String,
    pub confidence: String,
    pub conf_class: &'static str,
    pub method: String,
    pub evidence: String,
    /// How Debian or Ubuntu rate the match and what it takes off, empty without a rating.
    pub rating: String,
    pub state: String,
    pub state_class: &'static str,
    pub note: String,
    /// When the match was found (a `<time>` element, safe to render).
    pub found: String,
    /// When the instant mail about it went out (a `<time>` element), empty if none did.
    pub mailed: String,
}

/// The triage of a vulnerability: the forms of the detail.
pub struct Actions {
    pub vuln: String,
    /// `open`, `later`, `done` or `ignored`.
    pub state: &'static str,
    pub state_text: String,
    pub back: String,
    pub next: String,
    pub reasons: Vec<(&'static str, String)>,
    /// The open matches `(id, label)` that "ignore" can be limited to (two or more).
    pub choices: Vec<(i64, String)>,
    pub source_href: String,
}

/// "Betrifft": the own assets of a vulnerability, with the triage when shown in the inbox.
pub struct OwnBox {
    pub rows: Vec<OwnRow>,
    pub actions: Option<Actions>,
    /// Link into the inbox (pages outside the inbox).
    pub inbox_href: Option<String>,
}

fn state_text(t: Lang, r: &Row) -> (String, &'static str) {
    match r.state() {
        MatchState::New => (t.get("match-state-new"), "warn"),
        MatchState::Seen => (t.get("match-state-seen"), "warn"),
        MatchState::Later => (
            t.get1(
                "match-state-later",
                "date",
                crate::web::cves::date(t, r.until_ms),
            ),
            "off",
        ),
        MatchState::Done if r.auto => (t.get("match-state-resolved"), "ok"),
        MatchState::Done => (t.get("match-state-done"), "ok"),
        MatchState::Ignored => (t.get("match-state-ignored"), "off"),
    }
}

fn reason_text(t: Lang, key: &str) -> String {
    match key {
        "unused" => t.get("triage-reason-unused"),
        "lan" => t.get("triage-reason-lan"),
        "false" => t.get("triage-reason-false"),
        "other" => t.get("triage-reason-other"),
        other => other.to_owned(),
    }
}

/// The name of the asset (or keyword) of a match.
fn subject_name(t: Lang, r: &Row) -> String {
    if let Some(k) = &r.keyword {
        return t.get1("inbox-keyword", "keyword", k.as_str());
    }
    let vendor = r.vendor_name.as_deref().unwrap_or_default();
    let product = r.product_name.as_deref().unwrap_or_default();
    if r.kind.as_deref() == Some("package")
        || vendor.is_empty()
        || product.to_lowercase().starts_with(&vendor.to_lowercase())
    {
        product.to_owned()
    } else {
        format!("{vendor} {product}")
    }
}

/// "Debian rates it: unimportant (−30 points)", empty without a rating.
pub(crate) fn rating_text(t: Lang, r: &Row) -> String {
    let Some(id) = r.rating().label_id() else {
        return String::new();
    };
    let distro = r
        .distro
        .as_deref()
        .and_then(crate::storage::assets::Distro::parse)
        .map_or("", |d| d.name());
    t.fmt(
        "own-rating",
        &[
            ("distro", distro.into()),
            ("rating", t.get(id).into()),
            ("points", r.rating_penalty.into()),
        ],
    )
}

fn subject_icon(r: &Row) -> &'static str {
    match kind_of(r) {
        "watch" => "tag",
        k => Kind::parse(k).map_or("package", Kind::icon),
    }
}

/// The own assets of a vulnerability; `None` if none is affected.
pub(crate) async fn own_box(
    pool: &sqlx::SqlitePool,
    t: Lang,
    vuln: &str,
    triage: Option<(String, String)>,
) -> Result<Option<OwnBox>> {
    let rows = matches::for_vuln(pool, vuln).await?;
    if rows.is_empty() {
        return Ok(None);
    }
    let own = rows
        .iter()
        .map(|r| {
            let (state, state_class) = state_text(t, r);
            let mut note = String::new();
            if r.state() == MatchState::Ignored && !r.reason.is_empty() {
                note = reason_text(t, &r.reason);
            }
            if !r.note.is_empty() {
                if !note.is_empty() {
                    note.push_str(" · ");
                }
                note.push_str(&r.note);
            }
            let release = match (r.distro.as_deref(), r.release.as_deref()) {
                (Some(d), Some(rel)) if !d.is_empty() => {
                    let name = crate::storage::assets::Distro::parse(d).map_or(d, |d| d.name());
                    let pro = if r.pro == Some(true) { " · Pro" } else { "" };
                    format!("{name} {rel}{pro}")
                }
                _ => String::new(),
            };
            let host = r.host.clone().unwrap_or_default();
            OwnRow {
                name: subject_name(t, r),
                href: match (r.asset_id, r.watch_id) {
                    (Some(a), _) => format!("/assets/{a}"),
                    _ => "/assets/watchlist".to_owned(),
                },
                host: [host, release]
                    .into_iter()
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join(" · "),
                icon: subject_icon(r),
                installed: r.version.clone().unwrap_or_default(),
                fixed: r.fixed.clone(),
                confidence: t.get(r.confidence().label_id()),
                conf_class: conf_class(r.confidence()),
                method: t.get(Method::parse(&r.method).label_id()),
                evidence: r.evidence.replace(',', ", "),
                rating: rating_text(t, r),
                state,
                state_class,
                note,
                found: crate::web::time_html(r.first_seen_ms),
                mailed: match (r.alert.as_str(), r.alert_ms) {
                    ("sent", Some(ms)) => crate::web::time_html(ms),
                    _ => String::new(),
                },
            }
        })
        .collect();
    let actions = triage.map(|(back, next)| {
        let open: Vec<&Row> = rows
            .iter()
            .filter(|r| {
                matches!(
                    r.state(),
                    MatchState::New | MatchState::Seen | MatchState::Later
                )
            })
            .collect();
        let (state, state_text) = if rows.iter().any(|r| r.state().is_open()) {
            ("open", String::new())
        } else if let Some(r) = rows.iter().find(|r| r.state() == MatchState::Later) {
            ("later", state_text(t, r).0)
        } else if rows.iter().any(|r| r.state() == MatchState::Done) {
            ("done", t.get("match-state-done"))
        } else {
            let reason = rows
                .iter()
                .find(|r| !r.reason.is_empty())
                .map(|r| reason_text(t, &r.reason))
                .unwrap_or_default();
            let text = if reason.is_empty() {
                t.get("match-state-ignored")
            } else {
                format!("{}: {reason}", t.get("match-state-ignored"))
            };
            ("ignored", text)
        };
        Actions {
            vuln: vuln.to_owned(),
            state,
            state_text,
            back,
            next,
            reasons: REASONS.iter().map(|&k| (k, reason_text(t, k))).collect(),
            choices: if open.len() > 1 {
                open.iter()
                    .map(|r| {
                        let host = r.host.as_deref().unwrap_or_default();
                        let name = subject_name(t, r);
                        let label = if host.is_empty() {
                            name
                        } else {
                            format!("{name} · {host}")
                        };
                        (r.id, label)
                    })
                    .collect()
            } else {
                Vec::new()
            },
            source_href: source_link(vuln, &rows),
        }
    });
    Ok(Some(OwnBox {
        rows: own,
        inbox_href: actions.is_none().then(|| format!("/?sel={}", encode(vuln))),
        actions,
    }))
}

/// The page of the vulnerability at its source (for the key `o`).
fn source_link(vuln: &str, rows: &[Row]) -> String {
    if let Some(id) = vuln.strip_prefix("osv:") {
        return format!("https://osv.dev/vulnerability/{}", encode(id));
    }
    if vuln.starts_with("adv:") {
        return vuln_href(vuln);
    }
    let _ = rows;
    format!("https://www.cve.org/CVERecord?id={}", encode(vuln))
}

// ---------------------------------------------------------------------------------------------------
// The page

/// The detail of the selected vulnerability, by its kind.
pub enum DetailKind {
    Cve(Box<crate::web::cves::DetailView>),
    Advisory(Box<crate::web::advisories::DetailView>),
    Simple(Box<SimpleDetail>),
}

/// A vulnerability without its own record here (OSV): what the matches know.
pub struct SimpleDetail {
    pub label: String,
    pub title: String,
    pub prio: i64,
    pub band: &'static str,
    pub link: String,
    pub back_href: String,
    pub own: Option<OwnBox>,
}

#[derive(Template)]
#[template(path = "inbox.html")]
struct InboxTemplate {
    t: Lang,
    layout: Layout,
    views: Vec<ViewRow>,
    groups: Vec<FacetGroup>,
    chips: Vec<Chip>,
    clear_href: String,
    rows: Vec<ListRow>,
    more: String,
    title: String,
    count: String,
    sorts: Vec<(&'static str, String, bool)>,
    hidden: Vec<(&'static str, String)>,
    /// The CSV of the filtered list.
    export_href: String,
    back: String,
    detail: Option<DetailKind>,
    sheet_open: bool,
    flash: Option<String>,
    error: Option<String>,
    reasons: Vec<(&'static str, String)>,
    /// No asset and no keyword yet: the hints for the start.
    no_assets: bool,
    all_done: bool,
    checked: Option<String>,
    /// Muted matches: what is hidden (or shown with the asset filter) and where to change it.
    muted: Option<(String, String)>,
}

/// The note about muted matches (below the priority from which their asset shows matches): without an asset
/// filter how many are hidden, with one that they show.
fn muted_note(t: Lang, rows: &[Row], f: &Filter) -> Option<(String, String)> {
    let muted: Vec<&Row> = rows
        .iter()
        .filter(|r| r.muted() && f.view.states().contains(&r.state()))
        .collect();
    let mut assets: Vec<i64> = muted.iter().filter_map(|r| r.asset_id).collect();
    assets.sort_unstable();
    assets.dedup();
    if let Some(a) = f.asset {
        let min = rows
            .iter()
            .find(|r| r.asset_id == Some(a) && r.min_prio > 0)?
            .min_prio;
        return Some((
            t.get1("inbox-muted-shown", "prio", min),
            format!("/assets/{a}"),
        ));
    }
    if muted.is_empty() {
        return None;
    }
    let mut vulns: Vec<&str> = muted.iter().map(|r| r.vuln.as_str()).collect();
    vulns.sort_unstable();
    vulns.dedup();
    let href = match assets.as_slice() {
        [one] => format!("/?view={}&asset={one}", f.view.as_str()),
        _ => "/assets".to_owned(),
    };
    Some((
        t.fmt(
            "inbox-muted",
            &[
                ("count", vulns.len().into()),
                ("shown", t.number(vulns.len() as i64).into()),
                ("assets", assets.len().into()),
            ],
        ),
        href,
    ))
}

/// The inbox.
pub async fn page(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(params): Query<Params>,
) -> Result<Response> {
    let t = user.lang;
    let now = now_ms();
    // Both only write markers; while the database is being compacted the page still shows (the housekeeping
    // wakes postponed matches as well, the next opening marks as seen).
    matches::wake_later_for_page(&state.pool, now).await;
    let f = params.filter();
    let explicit = params.selected();
    if let Some(sel) = &explicit
        && let Err(e) = matches::mark_seen(&state.pool, sel, now).await
    {
        tracing::warn!(error = %e, "marking a match as seen failed");
    }
    let all_states = [
        MatchState::New,
        MatchState::Seen,
        MatchState::Later,
        MatchState::Done,
        MatchState::Ignored,
    ];
    let rows = matches::rows(&state.pool, &all_states).await?;

    let mut list = items(&rows, &f, Group::None, now);
    sort_items(&mut list, f.sort);

    let shown = explicit
        .clone()
        .or_else(|| list.first().map(|i| i.vuln.to_owned()));
    let position = shown
        .as_deref()
        .and_then(|s| list.iter().position(|i| i.vuln == s));
    let next = position
        .and_then(|p| {
            list.get(p + 1)
                .or_else(|| p.checked_sub(1).and_then(|q| list.get(q)))
        })
        .map(|i| i.vuln.to_owned())
        .unwrap_or_default();

    let list_rows: Vec<ListRow> = list
        .iter()
        .take(MAX_ROWS)
        .map(|i| list_row(t, &f, i, shown.as_deref(), now))
        .collect();
    let more = if list.len() > MAX_ROWS {
        t.get1("inbox-more", "count", list.len() - MAX_ROWS)
    } else {
        String::new()
    };

    let detail = match &shown {
        Some(vuln) => {
            detail(
                &state,
                t,
                vuln,
                &rows,
                f.href(None),
                (f.query(), next.clone()),
            )
            .await?
        }
        None => None,
    };

    let asset_count: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM assets) + (SELECT COUNT(*) FROM watchlist)",
    )
    .fetch_one(&state.pool)
    .await?;
    let layout = user.layout().at("inbox");
    let checked = layout.sources.checked_ms.map(crate::web::time_html);
    let unfiltered = f.sev.is_none()
        && !f.kev
        && !f.fix
        && f.conf.is_none()
        && f.kind.is_none()
        && f.host.is_none()
        && f.asset.is_none()
        && f.watch.is_none();

    let html = InboxTemplate {
        t,
        layout,
        views: View::ALL
            .iter()
            .map(|&v| {
                let vf = Filter {
                    view: v,
                    ..f.clone()
                };
                ViewRow {
                    href: vf.href(None),
                    icon: v.icon(),
                    label: t.get(v.label_id()),
                    count: items(&rows, &vf, Group::None, now).len(),
                    current: v == f.view,
                }
            })
            .collect(),
        groups: facets(t, &rows, &f, now),
        chips: chips(t, &f, &rows),
        clear_href: Filter {
            view: f.view,
            sort: f.sort,
            ..Filter::cleared()
        }
        .href(None),
        title: t.get(f.view.label_id()),
        count: t.get1("inbox-count", "count", list.len()),
        sorts: [Sort::Prio, Sort::New, Sort::Host]
            .iter()
            .map(|&s| {
                (
                    s.as_str(),
                    t.get(match s {
                        Sort::Prio => "inbox-sort-prio",
                        Sort::New => "inbox-sort-new",
                        Sort::Host => "inbox-sort-host",
                    }),
                    s == f.sort,
                )
            })
            .collect(),
        hidden: hidden_fields(&f),
        export_href: {
            let q = f.query();
            if q.is_empty() {
                "/inbox.csv".to_owned()
            } else {
                format!("/inbox.csv?{q}")
            }
        },
        back: f.query(),
        rows: list_rows,
        more,
        detail,
        sheet_open: explicit.is_some(),
        flash: flash_message(t, params.msg.as_deref()),
        error: None,
        reasons: REASONS.iter().map(|&k| (k, reason_text(t, k))).collect(),
        no_assets: asset_count == 0,
        all_done: list.is_empty() && f.view == View::Open && unfiltered,
        checked,
        muted: muted_note(t, &rows, &f),
    }
    .render()?;
    Ok(Html(html).into_response())
}

impl Filter {
    fn cleared() -> Self {
        Self {
            view: View::Open,
            sev: None,
            kev: false,
            fix: false,
            conf: None,
            kind: None,
            host: None,
            asset: None,
            watch: None,
            sort: Sort::Prio,
        }
    }
}

fn sort_items(list: &mut [Item], sort: Sort) {
    match sort {
        Sort::Prio => list.sort_by(|a, b| b.prio.cmp(&a.prio).then_with(|| b.vuln.cmp(a.vuln))),
        Sort::New => list.sort_by(|a, b| {
            b.first_seen_ms
                .cmp(&a.first_seen_ms)
                .then_with(|| b.prio.cmp(&a.prio))
        }),
        Sort::Host => list.sort_by(|a, b| {
            first_host(a)
                .cmp(&first_host(b))
                .then_with(|| b.prio.cmp(&a.prio))
        }),
    }
}

/// The list with its filters as CSV: one line per match (asset), in the order of the list.
pub async fn export(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(params): Query<Params>,
) -> Result<Response> {
    use crate::web::csv_export::{self, Csv};
    let t = user.lang;
    let now = now_ms();
    matches::wake_later_for_page(&state.pool, now).await;
    let f = params.filter();
    let rows = matches::rows(
        &state.pool,
        &[
            MatchState::New,
            MatchState::Seen,
            MatchState::Later,
            MatchState::Done,
            MatchState::Ignored,
        ],
    )
    .await?;
    let mut list = items(&rows, &f, Group::None, now);
    sort_items(&mut list, f.sort);
    let tz = &state.time_zone;
    let mut csv = Csv::new(t);
    csv.line(
        &[
            "export-vuln",
            "export-title",
            "export-prio",
            "export-band",
            "export-kev",
            "export-match-state",
            "export-asset",
            "export-host",
            "export-release",
            "export-installed",
            "export-fixed",
            "export-confidence",
            "export-method",
            "export-found",
            "export-mailed",
        ]
        .map(|id| csv.text(&t.get(id))),
    );
    let mut lines = 0;
    'items: for i in &list {
        for r in &i.rows {
            if lines >= csv_export::MAX_ROWS {
                break 'items;
            }
            lines += 1;
            let band = Band::of_prio(r.prio());
            let release = match (r.distro.as_deref(), r.release.as_deref()) {
                (Some(d), Some(rel)) if !d.is_empty() => {
                    let name = crate::storage::assets::Distro::parse(d).map_or(d, |d| d.name());
                    let pro = if r.pro == Some(true) { " Pro" } else { "" };
                    format!("{name} {rel}{pro}")
                }
                _ => String::new(),
            };
            csv.line(&[
                csv.text(&vuln_label(&r.vuln, &r.evidence)),
                csv.text(&r.title),
                r.prio().to_string(),
                csv.text(&t.get(band.label_id())),
                csv.text(&t.get(if r.kev { "export-yes" } else { "export-no" })),
                csv.text(&state_text(t, r).0),
                csv.text(&subject_name(t, r)),
                csv.text(r.host.as_deref().unwrap_or_default()),
                csv.text(&release),
                csv.text(r.version.as_deref().unwrap_or_default()),
                csv.text(&r.fixed),
                csv.text(&t.get(r.confidence().label_id())),
                csv.text(&t.get(Method::parse(&r.method).label_id())),
                csv_export::minute(tz, Some(r.first_seen_ms)),
                if r.alert == "sent" {
                    csv_export::minute(tz, r.alert_ms)
                } else {
                    String::new()
                },
            ]);
        }
    }
    Ok(csv.into_response("inbox", &csv_export::day(tz, Some(now))))
}

fn first_host(i: &Item) -> String {
    i.rows
        .iter()
        .filter_map(|r| r.host.as_deref())
        .filter(|h| !h.is_empty())
        .min()
        .unwrap_or("\u{10ffff}")
        .to_lowercase()
}

fn list_row(t: Lang, f: &Filter, i: &Item, shown: Option<&str>, now: i64) -> ListRow {
    let first = i.rows[0];
    let band = Band::of_prio(i.prio);
    let state = i
        .rows
        .iter()
        .map(|r| r.state())
        .min_by_key(|s| match s {
            MatchState::New => 0,
            MatchState::Seen => 1,
            MatchState::Later => 2,
            MatchState::Done => 3,
            MatchState::Ignored => 4,
        })
        .unwrap_or(MatchState::Seen);
    let (state_icon, state_text) = match state {
        MatchState::Later => (
            "clock",
            t.get1(
                "inbox-until",
                "date",
                crate::web::cves::date(t, i.rows.iter().filter_map(|r| r.until_ms).min()),
            ),
        ),
        MatchState::Done => ("check", t.get("match-state-done")),
        MatchState::Ignored => ("eye-off", t.get("match-state-ignored")),
        _ => ("", String::new()),
    };
    let subjects: BTreeSet<String> = i.rows.iter().map(|r| subject_name(t, r)).collect();
    let hosts: BTreeSet<&str> = i
        .rows
        .iter()
        .filter_map(|r| r.host.as_deref())
        .filter(|h| !h.is_empty())
        .collect();
    let name = subjects.iter().next().cloned().unwrap_or_default();
    let mut asset = name;
    if !hosts.is_empty() {
        asset.push_str(" · ");
        asset.push_str(&hosts.into_iter().collect::<Vec<_>>().join(", "));
    } else if let Some(v) = first.version.as_deref().filter(|v| !v.is_empty()) {
        asset.push_str(" · ");
        asset.push_str(v);
    }
    ListRow {
        vuln: i.vuln.to_owned(),
        label: vuln_label(i.vuln, &first.evidence),
        href: f.href(Some(i.vuln)),
        title: if first.title.is_empty() {
            t.get("cve-no-title")
        } else {
            first.title.clone()
        },
        prio: i.prio,
        band: band.as_str(),
        prio_title: t.fmt(
            "cve-prio-title",
            &[
                ("prio", i.prio.into()),
                ("band", t.get(band.label_id()).into()),
            ],
        ),
        kev: i.kev,
        unread: i.rows.iter().any(|r| r.state() == MatchState::New),
        state: state.as_str(),
        state_icon,
        state_text,
        age: age(t, now - i.first_seen_ms),
        icon: subject_icon(first),
        asset,
        more_assets: if i.rows.len() > 1 {
            t.get1("inbox-assets", "count", i.rows.len())
        } else {
            String::new()
        },
        selected: shown == Some(i.vuln),
    }
}

/// "today", "3 d", "5 wk." – how long a match has been known.
fn age(t: Lang, ms: i64) -> String {
    let days = ms.max(0) / DAY_MS;
    match days {
        0 => t.get("inbox-age-today"),
        1..=13 => t.get1("inbox-age-days", "count", days),
        _ => t.get1("inbox-age-weeks", "count", days / 7),
    }
}

fn facets(t: Lang, rows: &[Row], f: &Filter, now: i64) -> Vec<FacetGroup> {
    let mut groups = Vec::new();
    // Severity (band of the priority).
    let base = items(rows, f, Group::Sev, now);
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for i in &base {
        *counts.entry(Band::of_prio(i.prio).as_str()).or_default() += 1;
    }
    let sev_rows = [Band::Crit, Band::High, Band::Med, Band::Low]
        .iter()
        .map(|&b| {
            let on = f.sev == Some(b);
            FacetRow {
                href: Filter {
                    sev: if on { None } else { Some(b) },
                    ..f.clone()
                }
                .href(None),
                label: t.get(b.label_id()),
                band: b.as_str(),
                count: counts.get(b.as_str()).copied().unwrap_or(0),
                on,
            }
        })
        .collect();
    groups.push(group(t, "inbox-group-sev", f, Group::Sev, sev_rows));

    let kev_count = items(rows, f, Group::Kev, now)
        .iter()
        .filter(|i| i.kev)
        .count();
    groups.push(group(
        t,
        "inbox-group-kev",
        f,
        Group::Kev,
        vec![FacetRow {
            href: Filter {
                kev: !f.kev,
                ..f.clone()
            }
            .href(None),
            label: t.get("inbox-kev-only"),
            band: "",
            count: kev_count,
            on: f.kev,
        }],
    ));

    let fix_count = items(rows, f, Group::Fix, now)
        .iter()
        .filter(|i| i.rows.iter().any(|r| !r.fixed.is_empty()))
        .count();
    groups.push(group(
        t,
        "inbox-group-fix",
        f,
        Group::Fix,
        vec![FacetRow {
            href: Filter {
                fix: !f.fix,
                ..f.clone()
            }
            .href(None),
            label: t.get("inbox-fix-only"),
            band: "",
            count: fix_count,
            on: f.fix,
        }],
    ));

    let base = items(rows, f, Group::Conf, now);
    let conf_rows = [Confidence::High, Confidence::Medium, Confidence::Low]
        .iter()
        .map(|&c| {
            let on = f.conf == Some(c);
            FacetRow {
                href: Filter {
                    conf: if on { None } else { Some(c) },
                    ..f.clone()
                }
                .href(None),
                label: t.get(c.label_id()),
                band: "",
                count: base
                    .iter()
                    .filter(|i| i.rows.iter().any(|r| r.confidence() == c))
                    .count(),
                on,
            }
        })
        .collect();
    groups.push(group(t, "inbox-group-conf", f, Group::Conf, conf_rows));

    let base = items(rows, f, Group::Kind, now);
    let kind_rows = KINDS
        .iter()
        .map(|&k| {
            let on = f.kind == Some(k);
            FacetRow {
                href: Filter {
                    kind: if on { None } else { Some(k) },
                    ..f.clone()
                }
                .href(None),
                label: match k {
                    "watch" => t.get("inbox-kind-watch"),
                    k => Kind::parse(k).map_or_else(String::new, |k| t.get(k.label_id())),
                },
                band: "",
                count: base
                    .iter()
                    .filter(|i| i.rows.iter().any(|r| kind_of(r) == k))
                    .count(),
                on,
            }
        })
        .collect();
    groups.push(group(t, "inbox-group-kind", f, Group::Kind, kind_rows));

    let base = items(rows, f, Group::Host, now);
    let mut hosts: BTreeMap<String, usize> = BTreeMap::new();
    for i in &base {
        let set: BTreeSet<&str> = i
            .rows
            .iter()
            .filter_map(|r| r.host.as_deref())
            .filter(|h| !h.is_empty())
            .collect();
        for h in set {
            *hosts.entry(h.to_owned()).or_default() += 1;
        }
    }
    if let Some(h) = &f.host {
        hosts.entry(h.clone()).or_default();
    }
    let host_rows = hosts
        .into_iter()
        .map(|(h, count)| {
            let on = f.host.as_deref() == Some(h.as_str());
            FacetRow {
                href: Filter {
                    host: if on { None } else { Some(h.clone()) },
                    ..f.clone()
                }
                .href(None),
                label: h,
                band: "",
                count,
                on,
            }
        })
        .collect();
    groups.push(group(t, "inbox-group-host", f, Group::Host, host_rows));
    groups.retain(|g| !g.rows.is_empty());
    groups
}

fn group(t: Lang, title: &str, f: &Filter, g: Group, rows: Vec<FacetRow>) -> FacetGroup {
    let rows: Vec<FacetRow> = rows.into_iter().filter(|r| r.count > 0 || r.on).collect();
    let active = rows.iter().any(|r| r.on);
    FacetGroup {
        title: t.get(title),
        reset: active.then(|| {
            let mut c = f.clone();
            match g {
                Group::Sev => c.sev = None,
                Group::Kev => c.kev = false,
                Group::Fix => c.fix = false,
                Group::Conf => c.conf = None,
                Group::Kind => c.kind = None,
                Group::Host => c.host = None,
                Group::None => {}
            }
            c.href(None)
        }),
        rows,
    }
}

/// The active filters as chips with a link that removes them.
fn chips(t: Lang, f: &Filter, rows: &[Row]) -> Vec<Chip> {
    let mut out = Vec::new();
    let without = |change: &dyn Fn(&mut Filter)| {
        let mut c = f.clone();
        change(&mut c);
        c.href(None)
    };
    if let Some(b) = f.sev {
        out.push(Chip {
            label: format!("{}: {}", t.get("inbox-group-sev"), t.get(b.label_id())),
            href: without(&|c| c.sev = None),
        });
    }
    if f.kev {
        out.push(Chip {
            label: t.get("inbox-kev-only"),
            href: without(&|c| c.kev = false),
        });
    }
    if f.fix {
        out.push(Chip {
            label: t.get("inbox-fix-only"),
            href: without(&|c| c.fix = false),
        });
    }
    if let Some(conf) = f.conf {
        out.push(Chip {
            label: format!("{}: {}", t.get("inbox-group-conf"), t.get(conf.label_id())),
            href: without(&|c| c.conf = None),
        });
    }
    if let Some(k) = f.kind {
        let label = match k {
            "watch" => t.get("inbox-kind-watch"),
            k => Kind::parse(k).map_or_else(String::new, |k| t.get(k.label_id())),
        };
        out.push(Chip {
            label: format!("{}: {label}", t.get("inbox-group-kind")),
            href: without(&|c| c.kind = None),
        });
    }
    if let Some(h) = &f.host {
        out.push(Chip {
            label: format!("{}: {h}", t.get("inbox-group-host")),
            href: without(&|c| c.host = None),
        });
    }
    if let Some(a) = f.asset {
        let name = rows
            .iter()
            .find(|r| r.asset_id == Some(a))
            .map_or_else(|| format!("#{a}"), |r| subject_name(t, r));
        out.push(Chip {
            label: format!("{}: {name}", t.get("inbox-asset")),
            href: without(&|c| c.asset = None),
        });
    }
    if let Some(w) = f.watch {
        let name = rows
            .iter()
            .find(|r| r.watch_id == Some(w))
            .and_then(|r| r.keyword.clone())
            .unwrap_or_else(|| format!("#{w}"));
        out.push(Chip {
            label: format!("{}: {name}", t.get("inbox-kind-watch")),
            href: without(&|c| c.watch = None),
        });
    }
    out
}

/// The filters as hidden fields of the sort form.
fn hidden_fields(f: &Filter) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    if f.view != View::Open {
        out.push(("view", f.view.as_str().to_owned()));
    }
    if let Some(b) = f.sev {
        out.push(("sev", b.as_str().to_owned()));
    }
    if f.kev {
        out.push(("kev", "1".to_owned()));
    }
    if f.fix {
        out.push(("fix", "1".to_owned()));
    }
    if let Some(c) = f.conf {
        out.push(("conf", c.as_str().to_owned()));
    }
    if let Some(k) = f.kind {
        out.push(("kind", k.to_owned()));
    }
    if let Some(h) = &f.host {
        out.push(("host", h.clone()));
    }
    if let Some(a) = f.asset {
        out.push(("asset", a.to_string()));
    }
    if let Some(w) = f.watch {
        out.push(("watch", w.to_string()));
    }
    out
}

/// The detail of a vulnerability in the inbox.
async fn detail(
    state: &AppState,
    t: Lang,
    vuln: &str,
    rows: &[Row],
    back_href: String,
    triage: (String, String),
) -> Result<Option<DetailKind>> {
    let own = own_box(&state.pool, t, vuln, Some(triage)).await?;
    if crate::sources::cve5::is_cve_id(vuln)
        && let Some(d) = cve_list::detail(&state.pool, vuln).await?
    {
        let mut view =
            crate::web::cves::detail_view_for(&state.pool, t, d, back_href, false).await?;
        view.own = own;
        return Ok(Some(DetailKind::Cve(Box::new(view))));
    }
    if let Some(seq) = vuln
        .strip_prefix("adv:")
        .and_then(|s| s.parse::<i64>().ok())
        && let Some(d) = advisory_list::detail(&state.pool, seq).await?
    {
        let mut view = crate::web::advisories::detail_view(t, d, back_href, false);
        view.own = own;
        return Ok(Some(DetailKind::Advisory(Box::new(view))));
    }
    let Some(first) = rows.iter().find(|r| r.vuln == vuln) else {
        return Ok(own.map(|own| {
            DetailKind::Simple(Box::new(SimpleDetail {
                label: vuln_label(vuln, ""),
                title: String::new(),
                prio: 0,
                band: "low",
                link: source_link(vuln, &[]),
                back_href: back_href.clone(),
                own: Some(own),
            }))
        }));
    };
    let prio = rows
        .iter()
        .filter(|r| r.vuln == vuln)
        .map(Row::prio)
        .max()
        .unwrap_or(0);
    Ok(Some(DetailKind::Simple(Box::new(SimpleDetail {
        label: vuln_label(vuln, &first.evidence),
        title: first.title.clone(),
        prio,
        band: Band::of_prio(prio).as_str(),
        link: source_link(vuln, rows),
        back_href,
        own,
    }))))
}

// ---------------------------------------------------------------------------------------------------
// Triage

/// Done, later, ignore or reopen; from the detail (one vulnerability, possibly some of its matches) or
/// the bulk bar (several vulnerabilities).
pub async fn act(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(fields): Form<Vec<(String, String)>>,
) -> Result<Response> {
    let field = |name: &str| {
        fields
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .unwrap_or_default()
    };
    user.verify_csrf(field("csrf_token"))?;
    let vulns: Vec<String> = fields
        .iter()
        .filter(|(k, v)| k == "vuln" && !v.is_empty() && v.len() <= 200)
        .map(|(_, v)| v.clone())
        .take(5000)
        .collect();
    let chosen: BTreeSet<i64> = fields
        .iter()
        .filter(|(k, _)| k == "id")
        .filter_map(|(_, v)| v.parse().ok())
        .collect();
    let now = now_ms();
    // "later:7" (the bulk bar) or "later" with `days` (the detail).
    let (action, days) = match field("action").split_once(':') {
        Some((a, d)) => (a, d),
        None => (field("action"), field("days")),
    };
    let (change, from, msg) = match action {
        "done" => (
            Change {
                state: MatchState::Done,
                until_ms: None,
                reason: String::new(),
                note: String::new(),
            },
            &[MatchState::New, MatchState::Seen, MatchState::Later][..],
            "triage_done",
        ),
        "later" => {
            let days: i64 = days.parse().unwrap_or(7).clamp(1, 365);
            (
                Change {
                    state: MatchState::Later,
                    until_ms: Some(now + days * DAY_MS),
                    reason: String::new(),
                    note: String::new(),
                },
                &[MatchState::New, MatchState::Seen, MatchState::Later][..],
                "triage_later",
            )
        }
        "ignore" => {
            let reason = field("reason");
            let reason = if REASONS.contains(&reason) {
                reason
            } else {
                "other"
            };
            let note: String = field("note")
                .chars()
                .filter(|c| !c.is_control() || *c == '\n')
                .take(MAX_NOTE)
                .collect();
            (
                Change {
                    state: MatchState::Ignored,
                    until_ms: None,
                    reason: reason.to_owned(),
                    note: note.trim().to_owned(),
                },
                &[MatchState::New, MatchState::Seen, MatchState::Later][..],
                "triage_ignored",
            )
        }
        "reopen" => (
            Change {
                state: MatchState::Seen,
                until_ms: None,
                reason: String::new(),
                note: String::new(),
            },
            &[MatchState::Later, MatchState::Done, MatchState::Ignored][..],
            "triage_reopened",
        ),
        _ => {
            return Err(Error::invalid(crate::i18n::Msg::new("inbox-error-action")));
        }
    };
    let mut ids = matches::ids_of(&state.pool, &vulns, from).await?;
    if !chosen.is_empty() {
        ids.retain(|id| chosen.contains(id));
    }
    if change.state == MatchState::Seen {
        // Reopening: "seen" applies only to new matches in `set_state`; set it directly.
        reopen(&state.pool, &ids, now).await?;
    } else {
        matches::set_state(&state.pool, &ids, &change, now).await?;
    }
    let back = clean_back(field("back"));
    let next = field("next");
    let sel = if !next.is_empty() && next.len() <= 200 {
        Some(next.to_owned())
    } else if vulns.len() == 1 {
        vulns.first().cloned()
    } else {
        None
    };
    let mut query = back.query();
    for part in [
        sel.map(|s| format!("sel={}", encode(&s))),
        Some(format!("msg={msg}")),
    ]
    .into_iter()
    .flatten()
    {
        if !query.is_empty() {
            query.push('&');
        }
        query.push_str(&part);
    }
    Ok(Redirect::to(&format!("/?{query}")).into_response())
}

async fn reopen(pool: &sqlx::SqlitePool, ids: &[i64], now: i64) -> Result<()> {
    for chunk in ids.chunks(500) {
        let marks = vec!["?"; chunk.len()].join(",");
        let sql = format!(
            "UPDATE matches SET state = 'seen', until_ms = NULL, reason = '', note = '', auto = 0,
             state_ms = ? WHERE id IN ({marks})"
        );
        let mut q = sqlx::query(&sql).bind(now);
        for id in chunk {
            q = q.bind(id);
        }
        q.execute(pool).await?;
    }
    Ok(())
}

/// The filters of the list the form came from, parsed and written again (never echoed).
fn clean_back(back: &str) -> Filter {
    let mut query = String::with_capacity(back.len());
    for b in back.bytes().take(2000) {
        if b.is_ascii_alphanumeric() || b"-._~&=%+".contains(&b) {
            query.push(char::from(b));
        } else {
            query.push_str(&format!("%{b:02X}"));
        }
    }
    format!("/?{query}")
        .parse::<Uri>()
        .ok()
        .and_then(|uri| Query::<Params>::try_from_uri(&uri).ok())
        .map_or_else(Filter::cleared, |q| q.0.filter())
}

/// Texts that only templates use, for the catalog check: "inbox-filters" "inbox-views" "inbox-list"
/// "inbox-select-all" "inbox-select" "inbox-selected" "inbox-bulk-clear" "inbox-sort"
/// "inbox-close-filters" "inbox-keys" "inbox-reset" "inbox-reset-all" "inbox-remove" "inbox-new"
/// "inbox-detail" "inbox-detail-empty" "inbox-done-title" "inbox-done-text" "inbox-checked"
/// "inbox-to-situation" "inbox-nothing-title" "inbox-nothing-text" "inbox-setup-title" "inbox-setup-text"
/// "inbox-setup-assets" "inbox-setup-watch" "triage-done" "triage-later" "triage-later-1" "triage-later-7"
/// "triage-later-30" "triage-ignore" "triage-ignore-ok" "triage-reason" "triage-note" "triage-for"
/// "triage-ignore-help" "triage-reopen" "triage-open-source" "own-installed" "own-fixed"
/// "own-method" "own-evidence" "own-open-inbox" "inbox-apply"
#[cfg(test)]
mod tests;
