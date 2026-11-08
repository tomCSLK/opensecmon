//! "All CVEs": the list with filters and the detail of one CVE (beside the list, or as a page of its own).
//!
//! Everything is rendered on the server: filters, sorting and paging are links, so the page works without
//! JavaScript; `static/cves.js` only swaps the detail pane without reloading the whole page. Texts of the
//! CVE records are data from outside and are escaped like every other value.

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde_json::Value;

use crate::error::{Error, Result};
use crate::i18n::Lang;
use crate::sources::{name_key, now_ms};
use crate::storage::cve_list::{
    self, Band, Detail, Filter, MAX_PAGE, PAGE_SIZE, Period, Sort, id_prefix,
};
use crate::storage::{advisory_list, distros};
use crate::web::auth::CurrentUser;
use crate::web::distro_view::{self, DistroView};
use crate::web::{AppState, Layout};

/// The query string of the list. Every value is text and parsed leniently: a broken link shows the list
/// with defaults instead of an error.
#[derive(Debug, Default, serde::Deserialize)]
pub struct Params {
    q: Option<String>,
    period: Option<String>,
    sev: Option<String>,
    kev: Option<String>,
    epss: Option<String>,
    vendor: Option<String>,
    rejected: Option<String>,
    mine: Option<String>,
    sort: Option<String>,
    page: Option<String>,
    sel: Option<String>,
}

impl Params {
    fn filter(&self) -> Filter {
        let flag = |v: &Option<String>| v.as_deref().is_some_and(|v| !v.is_empty() && v != "0");
        Filter {
            q: self
                .q
                .as_deref()
                .unwrap_or_default()
                .trim()
                .chars()
                .take(200)
                .collect(),
            period: self
                .period
                .as_deref()
                .and_then(Period::parse)
                .unwrap_or(Period::Days(30)),
            band: self.sev.as_deref().and_then(Band::parse),
            kev: flag(&self.kev),
            epss: flag(&self.epss),
            vendor: name_key(self.vendor.as_deref().unwrap_or_default())
                .chars()
                .take(100)
                .collect(),
            rejected: flag(&self.rejected),
            mine: flag(&self.mine),
            sort: self
                .sort
                .as_deref()
                .and_then(Sort::parse)
                .unwrap_or(Sort::Published),
        }
    }

    fn page(&self) -> i64 {
        self.page
            .as_deref()
            .and_then(|p| p.parse().ok())
            .unwrap_or(1)
            .clamp(1, MAX_PAGE)
    }

    fn selected(&self) -> Option<String> {
        self.sel
            .as_deref()
            .map(|s| s.trim().to_ascii_uppercase())
            .filter(|s| crate::sources::cve5::is_cve_id(s))
    }
}

/// Percent-encodes a query value (everything but the unreserved characters).
pub(crate) fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The query string of a list view (only what differs from the defaults).
fn query_string(filter: &Filter, page: i64, sel: Option<&str>) -> String {
    let default = Filter::default();
    let mut parts = Vec::new();
    if !filter.q.is_empty() {
        parts.push(format!("q={}", encode(&filter.q)));
    }
    if filter.period != default.period {
        parts.push(format!("period={}", filter.period.as_str()));
    }
    if let Some(band) = filter.band {
        parts.push(format!("sev={}", band.as_str()));
    }
    if filter.kev {
        parts.push("kev=1".to_owned());
    }
    if filter.epss {
        parts.push("epss=1".to_owned());
    }
    if !filter.vendor.is_empty() {
        parts.push(format!("vendor={}", encode(&filter.vendor)));
    }
    if filter.rejected {
        parts.push("rejected=1".to_owned());
    }
    if filter.mine {
        parts.push("mine=1".to_owned());
    }
    if filter.sort != default.sort {
        parts.push(format!("sort={}", filter.sort.as_str()));
    }
    if page > 1 {
        parts.push(format!("page={page}"));
    }
    if let Some(sel) = sel {
        parts.push(format!("sel={}", encode(sel)));
    }
    parts.join("&")
}

fn list_href(filter: &Filter, page: i64, sel: Option<&str>) -> String {
    let query = query_string(filter, page, sel);
    if query.is_empty() {
        "/cves".to_owned()
    } else {
        format!("/cves?{query}")
    }
}

/// A date (UTC) of Unix milliseconds in the order of the language.
pub(crate) fn date(t: Lang, ms: Option<i64>) -> String {
    let Some(ms) = ms else {
        return "–".to_owned();
    };
    match jiff::Timestamp::from_millisecond(ms) {
        Ok(ts) => {
            let d = ts.to_zoned(jiff::tz::TimeZone::UTC).date();
            iso_date(t, &d.to_string())
        }
        Err(_) => "–".to_owned(),
    }
}

/// `2026-11-05` (or the start of a timestamp) in the order of the language.
fn iso_date(t: Lang, iso: &str) -> String {
    let d: String = iso.chars().take(10).collect();
    let parts: Vec<&str> = d.split('-').collect();
    match (parts.as_slice(), t) {
        ([y, m, d], Lang::De) if y.len() == 4 => format!("{d}.{m}.{y}"),
        ([y, m, d], Lang::En) if y.len() == 4 => format!("{y}-{m}-{d}"),
        _ => d,
    }
}

/// A chip of the filter bar: active (with a link that removes it) or offered (a link that sets it).
pub struct Chip {
    pub label: String,
    pub href: String,
    pub active: bool,
}

/// A choice in the menu of a chip (the period).
pub struct Choice {
    pub label: String,
    pub href: String,
    pub current: bool,
}

pub struct Column {
    pub label: String,
    pub href: Option<String>,
    pub sorted: bool,
    pub class: &'static str,
}

pub struct Row {
    pub id: String,
    pub href: String,
    pub title: String,
    pub rejected: bool,
    pub prio: i64,
    pub prio_band: &'static str,
    pub prio_title: String,
    pub cvss: String,
    pub cvss_band: &'static str,
    pub epss: String,
    pub kev: bool,
    pub published: String,
    pub selected: bool,
}

pub struct PageLink {
    pub label: String,
    pub href: Option<String>,
    pub current: bool,
}

/// One part of a CVSS vector: name, value, and whether the value is the worst one.
pub struct VectorPart {
    pub name: String,
    pub value: String,
    pub bad: bool,
}

pub struct FormulaLine {
    pub label: String,
    pub value: String,
}

pub struct MetricView {
    pub provider: String,
    pub source: String,
    pub version: String,
    pub score: String,
    pub band: &'static str,
    pub vector: String,
}

pub struct KevView {
    pub name: String,
    pub added: String,
    pub due: String,
    pub due_passed: bool,
    pub ransomware: bool,
    pub action: String,
    pub notes: String,
}

pub struct AffectedView {
    pub name: String,
    pub versions: Vec<String>,
    pub package: String,
}

pub struct ProductView {
    pub name: String,
    pub origin: String,
    pub href: String,
}

pub struct LinkView {
    pub kind: &'static str,
    pub label: String,
    pub url: String,
}

/// An advisory that names the CVE (BSI CERT-Bund or a vendor's CSAF).
pub struct AdvisoryLink {
    pub kind: &'static str,
    pub id: String,
    pub title: String,
    pub publisher: String,
    pub href: String,
}

pub struct RefView {
    pub url: String,
    pub host: String,
    pub tags: String,
}

/// What the detail of one CVE shows.
pub struct DetailView {
    pub id: String,
    pub title: String,
    pub description: String,
    pub rejected: bool,
    pub assigner: String,
    pub published: String,
    pub updated: String,
    pub cwes: Vec<String>,
    pub nvd_status: Option<String>,
    pub prio: i64,
    pub prio_band: &'static str,
    pub prio_label: String,
    pub cvss_label: String,
    pub cvss: Option<String>,
    pub cvss_band: &'static str,
    pub cvss_band_label: String,
    pub cvss_source: String,
    pub vector: Vec<VectorPart>,
    pub vector_raw: String,
    pub epss: Option<String>,
    pub percentile: String,
    /// Width class of the percentile bar (`w0` … `w100` in steps of 5; no inline styles under the CSP).
    pub percentile_class: String,
    pub formula: Vec<FormulaLine>,
    pub kev_floor: bool,
    pub kev: Option<KevView>,
    pub metrics: Vec<MetricView>,
    pub affected: Vec<AffectedView>,
    pub products: Vec<ProductView>,
    pub links: Vec<LinkView>,
    pub advisories: Vec<AdvisoryLink>,
    /// What Debian and Ubuntu say about the CVE.
    pub distros: Vec<DistroView>,
    pub refs: Vec<RefView>,
    pub back_href: String,
    /// A page of its own (not the pane beside the list): the back link is always shown.
    pub standalone: bool,
    /// The own assets the CVE affects (with the triage in the inbox).
    pub own: Option<crate::web::inbox::OwnBox>,
}

#[derive(Template)]
#[template(path = "cves.html")]
struct ListTemplate {
    t: Lang,
    layout: Layout,
    view: &'static str,
    q: String,
    hidden: Vec<(&'static str, String)>,
    count_text: String,
    period_label: String,
    periods: Vec<Choice>,
    chips: Vec<Chip>,
    bands: Vec<Choice>,
    vendor: String,
    rejected: bool,
    columns: Vec<Column>,
    rows: Vec<Row>,
    pages: Vec<PageLink>,
    page_text: String,
    empty_db: bool,
    unknown_id: Option<String>,
    detail: Option<DetailView>,
    sheet_open: bool,
    /// The CSV of the filtered list.
    export_href: String,
}

#[derive(Template)]
#[template(path = "cve_page.html")]
struct DetailTemplate {
    t: Lang,
    layout: Layout,
    d: DetailView,
}

/// The list. A search that is a complete, known CVE id opens that CVE.
pub async fn list(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(params): Query<Params>,
) -> Result<Response> {
    let t = user.lang;
    let filter = params.filter();
    let mut unknown_id = None;
    if let Some(id) = id_prefix(&filter.q).filter(|id| crate::sources::cve5::is_cve_id(id)) {
        if cve_list::exists(&state.pool, &id).await? {
            return Ok(Redirect::to(&format!("/cves/{id}")).into_response());
        }
        unknown_id = Some(id);
    }
    let page_no = params.page();
    let page = cve_list::list(&state.pool, &filter, page_no, now_ms()).await?;
    let all = cve_list::count_published(&state.pool).await?;
    let explicit = params.selected();
    // Without a choice the first row is shown beside the list (on wide screens; narrow ones show the
    // detail only when a row was picked).
    let shown = explicit
        .clone()
        .or_else(|| page.rows.first().map(|r| r.id.clone()));
    let detail = match &shown {
        Some(id) => match cve_list::detail(&state.pool, id).await? {
            Some(d) => {
                let mut view =
                    detail_view_for(&state.pool, t, d, list_href(&filter, page_no, None), false)
                        .await?;
                view.own = crate::web::inbox::own_box(&state.pool, t, id, None).await?;
                Some(view)
            }
            None => None,
        },
        None => None,
    };
    let rows = page
        .rows
        .iter()
        .map(|r| {
            let band = Band::of_prio(r.prio);
            Row {
                href: list_href(&filter, page_no, Some(&r.id)),
                selected: shown.as_deref() == Some(r.id.as_str()),
                title: if r.title.is_empty() {
                    t.get("cve-no-title")
                } else {
                    r.title.clone()
                },
                rejected: r.state == "rejected",
                prio: r.prio,
                prio_band: band.as_str(),
                prio_title: t.fmt(
                    "cve-prio-title",
                    &[
                        ("prio", r.prio.into()),
                        ("band", t.get(band.label_id()).into()),
                    ],
                ),
                cvss: r
                    .cvss_score
                    .map_or_else(|| "–".to_owned(), |s| t.decimal(s, 1)),
                cvss_band: Band::of_cvss(r.cvss_score).as_str(),
                epss: r.epss.map_or_else(
                    || "–".to_owned(),
                    |e| format!("{} %", t.decimal(e * 100.0, 1)),
                ),
                kev: r.kev_added.is_some(),
                published: date(t, r.published_ms),
                id: r.id.clone(),
            }
        })
        .collect();
    let pages_total = ((page.total + PAGE_SIZE - 1) / PAGE_SIZE).clamp(1, MAX_PAGE);
    let html = ListTemplate {
        t,
        view: "cves",
        layout: user.layout().at("cves"),
        q: filter.q.clone(),
        hidden: hidden_fields(&filter),
        count_text: t.fmt(
            "cves-count",
            &[
                ("shown", t.number(page.total).into()),
                ("all", t.number(all).into()),
            ],
        ),
        period_label: period_label(t, filter.period),
        periods: Period::CHOICES
            .iter()
            .map(|&p| Choice {
                label: period_label(t, p),
                href: list_href(
                    &Filter {
                        period: p,
                        ..filter.clone()
                    },
                    1,
                    None,
                ),
                current: p == filter.period,
            })
            .collect(),
        chips: chips(t, &filter),
        bands: Band::ALL
            .iter()
            .map(|&b| Choice {
                label: t.get(b.label_id()),
                href: b.as_str().to_owned(),
                current: filter.band == Some(b),
            })
            .collect(),
        vendor: filter.vendor.clone(),
        rejected: filter.rejected,
        columns: columns(t, &filter),
        rows,
        pages: pager(&filter, page_no, pages_total),
        page_text: t.fmt(
            "cves-page",
            &[("page", page_no.into()), ("pages", pages_total.into())],
        ),
        empty_db: all == 0,
        unknown_id,
        sheet_open: explicit.is_some(),
        detail,
        export_href: export_href(&filter),
    }
    .render()?;
    Ok(Html(html).into_response())
}

fn export_href(filter: &Filter) -> String {
    let query = query_string(filter, 1, None);
    if query.is_empty() {
        "/cves.csv".to_owned()
    } else {
        format!("/cves.csv?{query}")
    }
}

/// The filtered list as CSV (in the order of the list, at most [`csv_export::MAX_ROWS`] rows).
pub async fn export(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(params): Query<Params>,
) -> Result<Response> {
    use crate::web::csv_export::{self, Csv};
    let t = user.lang;
    let filter = params.filter();
    let now = now_ms();
    let rows = cve_list::export(&state.pool, &filter, now, csv_export::MAX_ROWS).await?;
    let tz = &state.time_zone;
    let mut csv = Csv::new(t);
    csv.line(
        &[
            "export-cve-id",
            "export-state",
            "export-published",
            "export-title",
            "export-prio",
            "export-band",
            "export-cvss",
            "export-cvss-version",
            "export-cvss-vector",
            "export-epss",
            "export-epss-percentile",
            "export-kev",
            "export-assigner",
            "export-mine",
        ]
        .map(|id| csv.text(&t.get(id))),
    );
    for r in &rows {
        let band = Band::of_prio(r.prio);
        csv.line(&[
            csv.text(&r.id),
            csv.text(&r.state),
            csv_export::day(tz, r.published_ms),
            csv.text(&r.title),
            r.prio.to_string(),
            csv.text(&t.get(band.label_id())),
            csv.num(r.cvss_score, 1),
            csv.text(r.cvss_version.as_deref().unwrap_or_default()),
            csv.text(r.cvss_vector.as_deref().unwrap_or_default()),
            csv.num(r.epss.map(|e| e * 100.0), 2),
            csv.num(r.epss_percentile.map(|e| e * 100.0), 1),
            csv.text(r.kev_added.as_deref().unwrap_or_default()),
            csv.text(&r.assigner),
            csv.text(&t.get(if r.mine { "export-yes" } else { "export-no" })),
        ]);
    }
    Ok(csv.into_response("cves", &csv_export::day(tz, Some(now))))
}

/// The detail of a CVE with its advisories, distributions and own assets.
pub(crate) async fn detail_view_for(
    pool: &sqlx::SqlitePool,
    t: Lang,
    d: Detail,
    back_href: String,
    standalone: bool,
) -> Result<DetailView> {
    let id = d.record.id.clone();
    let advisories = advisory_list::for_cve(pool, &id).await?;
    let distros = distros_of(pool, t, &id).await?;
    let weights = crate::storage::prio::load(pool).await?;
    Ok(detail_view(
        t, d, advisories, distros, back_href, standalone, &weights,
    ))
}

/// The detail of one CVE as a page of its own (links from mails, the search, other pages).
pub async fn page(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> Result<Html<String>> {
    let t = user.lang;
    let id = id.trim().to_ascii_uppercase();
    if !crate::sources::cve5::is_cve_id(&id) {
        return Err(Error::NotFound);
    }
    let detail = cve_list::detail(&state.pool, &id)
        .await?
        .ok_or(Error::NotFound)?;
    let mut d = detail_view_for(&state.pool, t, detail, "/cves".to_owned(), true).await?;
    d.own = crate::web::inbox::own_box(&state.pool, t, &id, None).await?;
    Ok(Html(
        DetailTemplate {
            t,
            layout: user.layout().at("cves"),
            d,
        }
        .render()?,
    ))
}

/// The filters other than the search text, as hidden fields of the search form.
fn hidden_fields(filter: &Filter) -> Vec<(&'static str, String)> {
    let default = Filter::default();
    let mut out = Vec::new();
    if filter.period != default.period {
        out.push(("period", filter.period.as_str()));
    }
    if let Some(b) = filter.band {
        out.push(("sev", b.as_str().to_owned()));
    }
    if filter.kev {
        out.push(("kev", "1".to_owned()));
    }
    if filter.epss {
        out.push(("epss", "1".to_owned()));
    }
    if !filter.vendor.is_empty() {
        out.push(("vendor", filter.vendor.clone()));
    }
    if filter.rejected {
        out.push(("rejected", "1".to_owned()));
    }
    if filter.mine {
        out.push(("mine", "1".to_owned()));
    }
    if filter.sort != default.sort {
        out.push(("sort", filter.sort.as_str().to_owned()));
    }
    out
}

pub(crate) fn period_label(t: Lang, p: Period) -> String {
    match p {
        Period::Days(days) => t.get1("cves-period-days", "days", days),
        Period::All => t.get("cves-period-all"),
    }
}

fn chips(t: Lang, filter: &Filter) -> Vec<Chip> {
    let toggle = |label: &str, f: Filter, active: bool| Chip {
        label: t.get(label),
        href: list_href(&f, 1, None),
        active,
    };
    let mut out = vec![
        toggle(
            "cves-chip-mine",
            Filter {
                mine: !filter.mine,
                ..filter.clone()
            },
            filter.mine,
        ),
        toggle(
            "cves-chip-kev",
            Filter {
                kev: !filter.kev,
                ..filter.clone()
            },
            filter.kev,
        ),
        toggle(
            "cves-chip-epss",
            Filter {
                epss: !filter.epss,
                ..filter.clone()
            },
            filter.epss,
        ),
    ];
    if let Some(b) = filter.band {
        out.push(Chip {
            label: t.get1("cves-chip-band", "band", t.get(b.label_id())),
            href: list_href(
                &Filter {
                    band: None,
                    ..filter.clone()
                },
                1,
                None,
            ),
            active: true,
        });
    }
    if !filter.vendor.is_empty() {
        out.push(Chip {
            label: t.get1("cves-chip-vendor", "vendor", filter.vendor.clone()),
            href: list_href(
                &Filter {
                    vendor: String::new(),
                    ..filter.clone()
                },
                1,
                None,
            ),
            active: true,
        });
    }
    if filter.rejected {
        out.push(Chip {
            label: t.get("cves-chip-rejected"),
            href: list_href(
                &Filter {
                    rejected: false,
                    ..filter.clone()
                },
                1,
                None,
            ),
            active: true,
        });
    }
    if !filter.q.is_empty() {
        out.push(Chip {
            label: t.get1("cves-chip-search", "q", filter.q.clone()),
            href: list_href(
                &Filter {
                    q: String::new(),
                    ..filter.clone()
                },
                1,
                None,
            ),
            active: true,
        });
    }
    out
}

fn columns(t: Lang, filter: &Filter) -> Vec<Column> {
    let sortable = |label: &str, sort: Sort, class: &'static str| Column {
        label: t.get(label),
        href: Some(list_href(
            &Filter {
                sort,
                ..filter.clone()
            },
            1,
            None,
        )),
        sorted: filter.sort == sort,
        class,
    };
    let plain = |label: &str, class: &'static str| Column {
        label: t.get(label),
        href: None,
        sorted: false,
        class,
    };
    vec![
        sortable("cves-col-prio", Sort::Prio, ""),
        plain("cves-col-id", ""),
        plain("cves-col-title", ""),
        sortable("cves-col-cvss", Sort::Cvss, "num"),
        sortable("cves-col-epss", Sort::Epss, "num hide-sm"),
        plain("cves-col-kev", ""),
        sortable("cves-col-published", Sort::Published, "num hide-sm"),
    ]
}

fn pager(filter: &Filter, page: i64, pages: i64) -> Vec<PageLink> {
    page_links(page, pages, |to| list_href(filter, to, None))
}

/// Page links: first, previous, a few around the current one, next, last.
pub(crate) fn page_links(page: i64, pages: i64, href: impl Fn(i64) -> String) -> Vec<PageLink> {
    let link = |label: String, to: i64| PageLink {
        label,
        href: (to != page).then(|| href(to)),
        current: to == page,
    };
    let mut out = Vec::new();
    if page > 1 {
        out.push(link("‹".to_owned(), page - 1));
    }
    let from = (page - 2).max(1);
    let to = (page + 2).min(pages);
    if from > 1 {
        out.push(link("1".to_owned(), 1));
        if from > 2 {
            out.push(PageLink {
                label: "…".to_owned(),
                href: None,
                current: false,
            });
        }
    }
    for p in from..=to {
        out.push(link(p.to_string(), p));
    }
    if to < pages {
        if to < pages - 1 {
            out.push(PageLink {
                label: "…".to_owned(),
                href: None,
                current: false,
            });
        }
        out.push(link(pages.to_string(), pages));
    }
    if page < pages {
        out.push(link("›".to_owned(), page + 1));
    }
    out
}

/// The parts of a CVSS 3.x vector with names and values in the language of the page; the worst value of
/// each part is marked. Other versions show only the raw vector.
fn vector_parts(t: Lang, vector: &str) -> Vec<VectorPart> {
    // (metric, worst value, values)
    const METRICS: [(&str, &str, &[&str]); 8] = [
        ("AV", "N", &["N", "A", "L", "P"]),
        ("AC", "L", &["L", "H"]),
        ("PR", "N", &["N", "L", "H"]),
        ("UI", "N", &["N", "R"]),
        ("S", "C", &["U", "C"]),
        ("C", "H", &["H", "L", "N"]),
        ("I", "H", &["H", "L", "N"]),
        ("A", "H", &["H", "L", "N"]),
    ];
    if !vector.starts_with("CVSS:3.") {
        return Vec::new();
    }
    let mut out = Vec::new();
    for part in vector.split('/').skip(1) {
        let Some((key, value)) = part.split_once(':') else {
            continue;
        };
        let Some((metric, worst, values)) = METRICS.iter().find(|(m, _, _)| *m == key) else {
            continue;
        };
        if !values.contains(&value) {
            continue;
        }
        out.push(VectorPart {
            name: t.get(&format!("cvss-{metric}")),
            value: t.get(&format!("cvss-{metric}-{value}")),
            bad: value == *worst,
        });
    }
    out
}

// The ids of `vector_parts`, spelled out for the catalog check:
// "cvss-AV" "cvss-AV-N" "cvss-AV-A" "cvss-AV-L" "cvss-AV-P" "cvss-AC" "cvss-AC-L" "cvss-AC-H"
// "cvss-PR" "cvss-PR-N" "cvss-PR-L" "cvss-PR-H" "cvss-UI" "cvss-UI-N" "cvss-UI-R" "cvss-S" "cvss-S-U"
// "cvss-S-C" "cvss-C" "cvss-C-H" "cvss-C-L" "cvss-C-N" "cvss-I" "cvss-I-H" "cvss-I-L" "cvss-I-N"
// "cvss-A" "cvss-A-H" "cvss-A-L" "cvss-A-N"

/// The affected versions of a CVE record (`affected` in cvelistV5), as short ranges: `< 8.20`,
/// `≥ 1.0, < 2.0`, `= 1.2.3`.
/// "Vendor Product", without placeholders and without the vendor when the product already starts with it
/// ("Red Hat" + "Red Hat Enterprise Linux 9" → "Red Hat Enterprise Linux 9").
pub(crate) fn product_name(vendor: &str, product: &str) -> String {
    let real = |p: &str| !p.is_empty() && !p.eq_ignore_ascii_case("n/a");
    let (vendor, product) = (vendor.trim(), product.trim());
    match (real(vendor), real(product)) {
        (true, true) => {
            let lower = product.to_lowercase();
            if lower.starts_with(&vendor.to_lowercase()) {
                product.to_owned()
            } else {
                format!("{vendor} {product}")
            }
        }
        (true, false) => vendor.to_owned(),
        (false, true) => product.to_owned(),
        (false, false) => String::new(),
    }
}

fn affected_view(t: Lang, json: &str) -> Vec<AffectedView> {
    let items: Vec<Value> = serde_json::from_str(json).unwrap_or_default();
    let s = |v: &Value, k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    items
        .iter()
        .take(30)
        .filter_map(|a| {
            let vendor = s(a, "vendor");
            let product = s(a, "product");
            let package = s(a, "package");
            let name = product_name(&vendor, &product);
            let name = if name.is_empty() {
                package.clone()
            } else {
                name
            };
            if name.is_empty() {
                return None;
            }
            let mut versions: Vec<String> = a
                .get("versions")
                .and_then(Value::as_array)
                .map_or(&[][..], Vec::as_slice)
                .iter()
                .filter(|v| s(v, "status") == "affected")
                .filter_map(|v| {
                    let start = s(v, "version");
                    let open_start = start.is_empty()
                        || matches!(start.as_str(), "0" | "*" | "n/a" | "unspecified");
                    let lt = s(v, "less_than");
                    let lte = s(v, "less_than_or_equal");
                    let end = if !lt.is_empty() && lt != "*" {
                        Some(format!("< {lt}"))
                    } else if !lte.is_empty() && lte != "*" {
                        Some(format!("≤ {lte}"))
                    } else {
                        None
                    };
                    match (open_start, end) {
                        (true, Some(end)) => Some(end),
                        (false, Some(end)) => Some(format!("≥ {start}, {end}")),
                        (false, None) if lt == "*" || lte == "*" => Some(format!("≥ {start}")),
                        (false, None) => Some(start),
                        (true, None) => None,
                    }
                })
                .take(20)
                .collect();
            if versions.is_empty() && s(a, "default") == "affected" {
                versions.push(t.get("cve-all-versions"));
            }
            Some(AffectedView {
                name,
                versions,
                package: if package.is_empty() || package == product {
                    String::new()
                } else {
                    package
                },
            })
        })
        .collect()
}

fn refs_view(json: &str) -> Vec<RefView> {
    let items: Vec<Value> = serde_json::from_str(json).unwrap_or_default();
    items
        .iter()
        .take(200)
        .filter_map(|r| {
            let url = r.get("url")?.as_str()?;
            // Stored references are http(s) only (checked when the record is read); checked again here.
            let rest = url
                .strip_prefix("https://")
                .or_else(|| url.strip_prefix("http://"))?;
            let host = rest
                .split(['/', '?', '#'])
                .next()
                .unwrap_or_default()
                .to_owned();
            let tags = r
                .get("tags")
                .and_then(Value::as_array)
                .map(|tags| {
                    tags.iter()
                        .filter_map(Value::as_str)
                        .take(5)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            Some(RefView {
                url: url.to_owned(),
                host,
                tags,
            })
        })
        .collect()
}

fn provider_label(t: Lang, provider: &str) -> String {
    match provider {
        "cna" => t.get("cve-provider-cna"),
        "nvd" => t.get("cve-provider-nvd"),
        _ => t.get("cve-provider-adp"),
    }
}

/// The section "Distributions" of a CVE.
async fn distros_of(
    pool: &sqlx::SqlitePool,
    t: Lang,
    cve_id: &str,
) -> crate::error::Result<Vec<DistroView>> {
    let rows = distros::affected_for_cve(pool, cve_id).await?;
    let tracker = distros::tracker_for_cve(pool, cve_id).await?;
    Ok(distro_view::build(t, cve_id, rows, &tracker))
}

pub(crate) fn detail_view(
    t: Lang,
    d: Detail,
    advisories: Vec<advisory_list::ForCve>,
    distros: Vec<DistroView>,
    back_href: String,
    standalone: bool,
    w: &crate::storage::prio::Weights,
) -> DetailView {
    let r = d.record;
    let prio_band = Band::of_prio(r.prio);
    let cvss_band = Band::of_cvss(r.cvss_score);
    let percentile = r.epss_percentile.unwrap_or(0.0);
    let cvss_part = r.cvss_score.unwrap_or(0.0) * w.cvss_weight;
    let epss_part = percentile * w.epss_weight;
    let kev_floor =
        r.kev_added.is_some() && (cvss_part + epss_part).min(100.0) < w.kev_floor as f64;
    let mut formula = vec![
        FormulaLine {
            label: t.get2(
                "cve-formula-cvss",
                "cvss",
                r.cvss_score
                    .map_or_else(|| "–".to_owned(), |s| t.decimal(s, 1)),
                "weight",
                crate::web::prio_settings::weight_text(t, w.cvss_weight),
            ),
            value: t.decimal(cvss_part, 1),
        },
        FormulaLine {
            label: t.get2(
                "cve-formula-epss",
                "percentile",
                t.decimal(percentile * 100.0, 1),
                "weight",
                crate::web::prio_settings::weight_text(t, w.epss_weight),
            ),
            value: t.decimal(epss_part, 1),
        },
        FormulaLine {
            label: t.get("cve-formula-no-match"),
            value: "+0".to_owned(),
        },
    ];
    if kev_floor {
        formula.push(FormulaLine {
            label: t.get1(
                "cve-formula-kev",
                "sum",
                t.decimal(cvss_part + epss_part, 1),
            ),
            value: w.kev_floor.to_string(),
        });
    }
    let kev = d.kev.map(|k| {
        let today = jiff::Zoned::now().date().to_string();
        KevView {
            name: if k.name.is_empty() {
                format!("{} {}", k.vendor, k.product)
            } else {
                k.name
            },
            added: iso_date(t, &k.date_added),
            due_passed: !k.due_date.is_empty() && k.due_date.as_str() < today.as_str(),
            due: iso_date(t, &k.due_date),
            ransomware: k.ransomware.eq_ignore_ascii_case("known"),
            action: k.required_action,
            notes: k.notes,
        }
    });
    let mut links = vec![
        LinkView {
            kind: "CVE",
            label: t.get("cve-link-cve-org"),
            url: format!("https://www.cve.org/CVERecord?id={}", r.id),
        },
        LinkView {
            kind: "NVD",
            label: t.get("cve-link-nvd"),
            url: format!("https://nvd.nist.gov/vuln/detail/{}", r.id),
        },
    ];
    if kev.is_some() {
        links.push(LinkView {
            kind: "KEV",
            label: t.get("cve-link-kev"),
            url: format!(
                "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={}",
                r.id
            ),
        });
    }
    let cvss_source = r
        .cvss_source
        .as_deref()
        .and_then(|s| s.split_once(':'))
        .map(|(provider, source)| format!("{} ({source})", provider_label(t, provider)))
        .unwrap_or_default();
    let vector_raw = r.cvss_vector.clone().unwrap_or_default();
    DetailView {
        title: if r.title.is_empty() {
            t.get("cve-no-title")
        } else {
            r.title
        },
        description: r.description,
        rejected: r.state == "rejected",
        assigner: r.assigner,
        published: date(t, r.published_ms),
        updated: date(t, r.updated_ms),
        cwes: r
            .cwes
            .split(',')
            .filter(|c| !c.is_empty())
            .map(str::to_owned)
            .collect(),
        nvd_status: d.nvd.map(|n| n.status).filter(|s| !s.is_empty()),
        prio: r.prio,
        prio_band: prio_band.as_str(),
        prio_label: t.get(prio_band.label_id()),
        cvss_label: r
            .cvss_version
            .as_deref()
            .map_or_else(|| "CVSS".to_owned(), |v| format!("CVSS {v}")),
        cvss: r.cvss_score.map(|s| t.decimal(s, 1)),
        cvss_band: cvss_band.as_str(),
        cvss_band_label: t.get(cvss_band.label_id()),
        cvss_source,
        vector: vector_parts(t, &vector_raw),
        vector_raw,
        epss: r.epss.map(|e| format!("{} %", t.decimal(e * 100.0, 1))),
        percentile: t.decimal(percentile * 100.0, 1),
        percentile_class: format!("w{}", ((percentile * 20.0).round() as i64).clamp(0, 20) * 5),
        formula,
        kev_floor,
        kev,
        metrics: d
            .metrics
            .into_iter()
            .map(|m| MetricView {
                provider: provider_label(t, &m.provider),
                source: m.source,
                version: m.version,
                score: t.decimal(m.score, 1),
                band: Band::of_cvss(Some(m.score)).as_str(),
                vector: m.vector,
            })
            .collect(),
        affected: affected_view(t, &r.affected),
        products: d
            .products
            .into_iter()
            .map(|p| ProductView {
                name: product_name(&p.vendor_name, &p.product_name),
                origin: provider_label(t, &p.origin),
                href: list_href(
                    &Filter {
                        vendor: p.vendor,
                        period: Period::All,
                        ..Filter::default()
                    },
                    1,
                    None,
                ),
            })
            .collect(),
        links,
        advisories: advisories
            .into_iter()
            .map(|a| AdvisoryLink {
                kind: if a.source == "bsi" { "BSI" } else { "CSAF" },
                id: a.display_id,
                title: a.title,
                publisher: a.publisher,
                href: format!("/advisories/{}", a.seq),
            })
            .collect(),
        distros,
        refs: refs_view(&r.refs),
        id: r.id,
        back_href,
        standalone,
        own: None,
    }
}

/// Texts that only templates use, for the catalog check: "cves-search" "cves-search-placeholder"
/// "cves-filter-more" "cves-filter-band" "cves-filter-band-any" "cves-filter-vendor"
/// "cves-filter-vendor-help" "cves-filter-rejected" "cves-filter-apply" "cves-remove"
/// "cves-empty-db-title" "cves-empty-db-text" "cves-empty-title" "cves-empty-text" "cves-unknown-id"
/// "cves-per-page" "cves-detail" "cves-detail-empty" "cve-back" "cve-rejected" "cve-kev-title"
/// "cve-kev-since" "cve-kev-due" "cve-kev-due-passed" "cve-kev-ransomware" "cve-kev-action" "cve-section-affected"
/// "cve-no-assets" "cve-section-rating" "cve-epss-label" "cve-percentile" "cve-prio-label" "cve-no-score"
/// "cve-formula-title" "cve-formula-sum" "cve-section-description" "cve-published" "cve-updated" "cve-assigner"
/// "cve-nvd-status" "cve-section-metrics" "cve-section-products" "cve-section-sources" "cve-section-refs"
/// "cve-open-source" "cve-score-source" "cve-products-vendor-help" "band-crit" "band-high" "band-med"
/// "band-low" "band-none" "cves-chip-kev" "cves-chip-epss" "cves-chip-rejected"
#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::testutil::*;
    use axum::http::StatusCode;

    #[tokio::test]
    async fn the_detail_shows_what_debian_and_ubuntu_say() {
        use crate::sources::osv::{Distro, parse, tests as osv};
        let h = harness(true).await;
        let (session, _) = login(&h, "anna").await;
        sqlx::query(
            "INSERT INTO cves (id, state, title, published_ms) VALUES ('CVE-2026-33416', 'published', 'x', 1)",
        )
        .execute(&h.state.pool)
        .await
        .unwrap();
        let mut conn = h.state.pool.acquire().await.unwrap();
        let mut dsa = parse(osv::DSA.as_bytes(), Distro::Debian).unwrap();
        dsa.affected[0].package = "<i>libpng1.6".into();
        dsa.affected[1].package = "<i>libpng1.6".into();
        let mut cve = parse(osv::DEBIAN_CVE.as_bytes(), Distro::Debian).unwrap();
        for a in &mut cve.affected {
            a.package = "<i>libpng1.6".into();
        }
        for r in [dsa, cve] {
            distros::upsert(&mut conn, &r, 1).await.unwrap();
        }
        drop(conn);
        let mut tracker = crate::sources::debian_tracker::parse(
            crate::sources::debian_tracker::tests::TRACKER.as_bytes(),
        )
        .unwrap();
        for r in &mut tracker {
            if r.package == "libpng1.6" {
                r.package = "<i>libpng1.6".into();
            }
        }
        distros::replace_tracker(&h.state.pool, tracker)
            .await
            .unwrap();

        let page = send(&h.app, get("/cves/CVE-2026-33416", Some(&session))).await;
        assert_eq!(page.status, StatusCode::OK);
        let body = &page.body;
        assert!(body.contains("Distributionen"), "{body}");
        assert!(body.contains("12 (bookworm)"));
        assert!(body.contains("1.6.39-2+deb12u4"));
        assert!(body.contains("https://security-tracker.debian.org/tracker/DSA-6189-1"));
        assert!(body.contains("14 (forky)"));
        assert!(
            body.contains("unklar"),
            "the tracker says undetermined for forky"
        );
        assert!(body.contains("13 (trixie)"));
        assert!(body.contains("kein DSA geplant (verschoben): Minor issue"));
        assert!(!body.contains("<i>libpng"), "package names are escaped");

        // A CVE nobody reports has no such section.
        sqlx::query(
            "INSERT INTO cves (id, state, title, published_ms) VALUES ('CVE-2026-1', 'published', 'x', 1)",
        )
        .execute(&h.state.pool)
        .await
        .unwrap();
        let other = send(&h.app, get("/cves/CVE-2026-1", Some(&session))).await;
        assert!(!other.body.contains("Distributionen"));
    }

    #[tokio::test]
    async fn the_list_and_the_detail_show_the_records_escaped() {
        let h = harness(true).await;
        let (session, _) = login(&h, "anna").await;
        let empty = send(&h.app, get("/cves", Some(&session))).await;
        assert!(empty.body.contains("Noch keine CVEs geladen"));
        let now = now_ms();
        sqlx::query(
            "INSERT INTO cves (id, state, title, description, published_ms, cvss_score, cvss_version,
                               cvss_vector, kev_added, prio, refs)
             VALUES ('CVE-2026-0001', 'published', '<script>alert(1)</script>', 'Line one', ?, 9.8, '3.1',
                     'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', '2026-11-01', 90,
                     '[{\"url\": \"https://example.org/advisory\"}]')",
        )
        .bind(now)
        .execute(&h.state.pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO kev (cve_id, date_added, due_date, ransomware) VALUES ('CVE-2026-0001', '2026-11-01', '2026-11-22', 'Known')")
            .execute(&h.state.pool)
            .await
            .unwrap();

        let list = send(&h.app, get("/cves", Some(&session))).await;
        assert_eq!(list.status, StatusCode::OK);
        assert!(
            !list.body.contains("<script>alert"),
            "the title must be escaped"
        );
        assert!(list.body.contains("&#60;script&#62;") || list.body.contains("&lt;script&gt;"));
        assert!(list.body.contains("1 von 1 CVEs"), "{}", list.body);
        assert!(list.body.contains("data-href=\"/cves?sel=CVE-2026-0001\""));
        assert!(
            list.body.contains("Angriffsweg"),
            "the first row is shown beside the list"
        );
        assert!(list.body.contains("Bekannte Nutzung durch Ransomware"));
        assert!(list.body.contains("https://example.org/advisory"));

        let kev_only = send(&h.app, get("/cves?kev=1&period=7", Some(&session))).await;
        assert!(kev_only.body.contains("CVE-2026-0001"));
        let none = send(&h.app, get("/cves?q=nothing-like-this", Some(&session))).await;
        assert!(none.body.contains("Keine passenden CVEs"));

        let search = send(&h.app, get("/cves?q=cve-2026-0001", Some(&session))).await;
        assert_eq!(search.location(), "/cves/CVE-2026-0001");
        let unknown = send(&h.app, get("/cves?q=CVE-2026-9999", Some(&session))).await;
        assert!(unknown.body.contains("CVE-2026-9999"));

        let page = send(&h.app, get("/cves/CVE-2026-0001", Some(&session))).await;
        assert_eq!(page.status, StatusCode::OK);
        assert!(page.body.contains("back always"));
        let missing = send(&h.app, get("/cves/CVE-2026-9999", Some(&session))).await;
        assert_eq!(missing.status, StatusCode::NOT_FOUND);
        let bad = send(&h.app, get("/cves/..%2Fetc", Some(&session))).await;
        assert_eq!(bad.status, StatusCode::NOT_FOUND);
        let anonymous = send(&h.app, get("/cves/CVE-2026-0001", None)).await;
        assert_eq!(anonymous.location(), "/login");
    }

    #[test]
    fn links_keep_the_filters_and_drop_the_defaults() {
        let f = Filter::default();
        assert_eq!(list_href(&f, 1, None), "/cves");
        let f = Filter {
            q: "fritz box&x=1".into(),
            kev: true,
            sort: Sort::Prio,
            ..Filter::default()
        };
        assert_eq!(
            list_href(&f, 3, Some("CVE-2026-0001")),
            "/cves?q=fritz%20box%26x%3D1&kev=1&sort=prio&page=3&sel=CVE-2026-0001"
        );
        let p = Params {
            q: Some(" fritz ".into()),
            period: Some("7".into()),
            sev: Some("crit".into()),
            kev: Some("1".into()),
            page: Some("x".into()),
            sel: Some("cve-2026-0001".into()),
            vendor: Some("Example Corp".into()),
            ..Params::default()
        };
        let f = p.filter();
        assert_eq!(f.q, "fritz");
        assert_eq!(f.period, Period::Days(7));
        assert_eq!(f.band, Some(Band::Crit));
        assert!(f.kev && !f.epss);
        assert_eq!(f.vendor, "examplecorp");
        assert_eq!(p.page(), 1);
        assert_eq!(p.selected().as_deref(), Some("CVE-2026-0001"));
        assert_eq!(
            Params {
                sel: Some("<x>".into()),
                ..Params::default()
            }
            .selected(),
            None
        );
    }

    #[test]
    fn the_pager_shows_the_pages_around_the_current_one() {
        let f = Filter::default();
        let labels = |page, pages| -> Vec<String> {
            pager(&f, page, pages)
                .into_iter()
                .map(|p| p.label)
                .collect()
        };
        assert_eq!(labels(1, 1), ["1"]);
        assert_eq!(labels(1, 3), ["1", "2", "3", "›"]);
        assert_eq!(
            labels(10, 40),
            ["‹", "1", "…", "8", "9", "10", "11", "12", "…", "40", "›"]
        );
    }

    #[test]
    fn product_names_skip_placeholders_and_repeated_vendors() {
        assert_eq!(
            product_name("Red Hat", "Red Hat Enterprise Linux 9"),
            "Red Hat Enterprise Linux 9"
        );
        assert_eq!(product_name("AVM", "FRITZ!OS"), "AVM FRITZ!OS");
        assert_eq!(product_name("n/a", "openssh"), "openssh");
        assert_eq!(product_name("linux", "n/a"), "linux");
        assert_eq!(product_name(" ", ""), "");
    }

    #[test]
    fn vectors_and_versions_are_explained() {
        let parts = vector_parts(Lang::De, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N/X:Y");
        assert_eq!(parts.len(), 8);
        assert_eq!(parts[0].name, "Angriffsweg");
        assert!(parts[0].bad && !parts[3].bad);
        assert!(vector_parts(Lang::De, "AV:N/AC:L/Au:N").is_empty());
        let affected = affected_view(
            Lang::De,
            r#"[{"vendor": "AVM", "product": "FRITZ!OS", "default": "unaffected", "versions": [
                {"version": "0", "less_than": "8.20", "status": "affected"},
                {"version": "7.0", "less_than_or_equal": "7.5", "status": "affected"},
                {"version": "8.20", "status": "unaffected"},
                {"version": "6.1", "status": "affected"}]},
               {"vendor": "n/a", "product": "n/a"},
               {"vendor": "Example", "product": "Tool", "default": "affected"}]"#,
        );
        assert_eq!(affected[0].name, "AVM FRITZ!OS");
        assert_eq!(affected[0].versions, ["< 8.20", "≥ 7.0, ≤ 7.5", "6.1"]);
        assert_eq!(affected[1].versions, ["alle Versionen"]);
        assert_eq!(affected.len(), 2);
        let refs = refs_view(
            r#"[{"url": "https://example.org/a?b#c", "tags": ["patch"]}, {"url": "javascript:alert(1)"}]"#,
        );
        assert_eq!(refs.len(), 1);
        assert_eq!(
            (refs[0].host.as_str(), refs[0].tags.as_str()),
            ("example.org", "patch")
        );
        assert_eq!(iso_date(Lang::De, "2026-11-05"), "05.11.2026");
        assert_eq!(iso_date(Lang::En, "2026-11-05T10:00:00"), "2026-11-05");
    }
}
