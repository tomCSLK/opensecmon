//! "Advisories": the CSAF documents of BSI CERT-Bund and the vendors, as a list with filters and a detail
//! beside it (or as a page of its own). A second view of the page "All CVEs", switched in the toolbar.
//!
//! Like the CVE list it works without JavaScript; `static/cves.js` swaps the detail pane. Every text of a
//! document is data from outside and escaped.

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};

use crate::csaf::document::{Note, Reference};
use crate::error::{Error, Result};
use crate::i18n::Lang;
use crate::sources::{name_key, now_ms};
use crate::storage::advisory_list::{self, Detail, Filter, band};
use crate::storage::cve_list::{Band, MAX_PAGE, PAGE_SIZE, Period};
use crate::web::auth::CurrentUser;
use crate::web::cves::{
    Chip, Choice, PageLink, date, encode, page_links, period_label, product_name,
};
use crate::web::{AppState, Layout};

#[derive(Debug, Default, serde::Deserialize)]
pub struct Params {
    q: Option<String>,
    period: Option<String>,
    sev: Option<String>,
    src: Option<String>,
    vendor: Option<String>,
    page: Option<String>,
    sel: Option<String>,
}

fn source_of(s: &str) -> Option<&'static str> {
    match s {
        "bsi" => Some("bsi"),
        "vendor" => Some("vendor"),
        _ => None,
    }
}

impl Params {
    fn filter(&self) -> Filter {
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
            source: self.src.as_deref().and_then(source_of),
            vendor: name_key(self.vendor.as_deref().unwrap_or_default())
                .chars()
                .take(100)
                .collect(),
        }
    }

    fn page(&self) -> i64 {
        self.page
            .as_deref()
            .and_then(|p| p.parse().ok())
            .unwrap_or(1)
            .clamp(1, MAX_PAGE)
    }

    fn selected(&self) -> Option<i64> {
        self.sel.as_deref().and_then(|s| s.trim().parse().ok())
    }
}

fn query_string(filter: &Filter, page: i64, sel: Option<i64>) -> String {
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
    if let Some(src) = filter.source {
        parts.push(format!("src={src}"));
    }
    if !filter.vendor.is_empty() {
        parts.push(format!("vendor={}", encode(&filter.vendor)));
    }
    if page > 1 {
        parts.push(format!("page={page}"));
    }
    if let Some(sel) = sel {
        parts.push(format!("sel={sel}"));
    }
    parts.join("&")
}

pub(crate) fn list_href(filter: &Filter, page: i64, sel: Option<i64>) -> String {
    let query = query_string(filter, page, sel);
    if query.is_empty() {
        "/advisories".to_owned()
    } else {
        format!("/advisories?{query}")
    }
}

/// The label of a source (`bsi`, `vendor`).
pub(crate) fn source_label(t: Lang, source: &str) -> String {
    match source {
        "bsi" => "BSI CERT-Bund".to_owned(),
        _ => t.get("advisories-source-vendor"),
    }
}

/// The severity as shown: the publisher's word if there is one, else the name of the band.
fn severity_label(t: Lang, severity: &str, text: &str) -> String {
    if text.is_empty() {
        t.get(band(severity).label_id())
    } else {
        text.to_owned()
    }
}

pub struct Row {
    pub seq: i64,
    pub href: String,
    pub id: String,
    pub title: String,
    pub publisher: String,
    pub band: &'static str,
    pub band_icon: &'static str,
    pub severity: String,
    pub cves: String,
    pub updated: String,
    pub selected: bool,
}

pub struct CveView {
    pub id: String,
    pub title: String,
    pub known: bool,
    pub prio: String,
    pub prio_band: &'static str,
    pub kev: bool,
}

pub struct ProductView {
    pub name: String,
    pub version: String,
    pub range: bool,
    pub status: &'static str,
    pub status_label: String,
    pub cpe: String,
    pub href: String,
}

pub struct RefView {
    pub url: String,
    pub host: String,
    pub summary: String,
}

pub struct DetailView {
    pub seq: i64,
    pub display_id: String,
    pub tracking_id: Option<String>,
    pub title: String,
    pub summary: String,
    pub band: &'static str,
    pub band_icon: &'static str,
    pub severity: String,
    pub cvss: Option<String>,
    pub publisher: String,
    pub source: String,
    pub published: String,
    pub updated: String,
    pub version: String,
    pub status: String,
    pub tlp: String,
    pub lang: String,
    /// The language of the texts as an HTML `lang` value (`de`, `en`), empty if the document does not say.
    pub text_lang: String,
    /// The title comes from the document, not the "(no title)" of the interface.
    pub title_from_doc: bool,
    /// The texts are in the other language of the interface: offer the translation in the browser.
    pub translate: bool,
    pub hash_checked: bool,
    pub web_url: String,
    pub doc_url: String,
    pub notes: Vec<Note>,
    pub cves: Vec<CveView>,
    pub products: Vec<ProductView>,
    pub products_more: Option<String>,
    pub refs: Vec<RefView>,
    pub back_href: String,
    pub standalone: bool,
    /// The own assets the advisory affects (with the triage in the inbox).
    pub own: Option<crate::web::inbox::OwnBox>,
}

#[derive(Template)]
#[template(path = "advisories.html")]
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
    sources: Vec<Choice>,
    vendor: String,
    rows: Vec<Row>,
    pages: Vec<PageLink>,
    page_text: String,
    empty_db: bool,
    detail: Option<DetailView>,
    sheet_open: bool,
}

#[derive(Template)]
#[template(path = "advisory_page.html")]
struct DetailTemplate {
    t: Lang,
    layout: Layout,
    d: DetailView,
}

/// The list. A search that is the id of an advisory opens it.
pub async fn list(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(params): Query<Params>,
) -> Result<Response> {
    let t = user.lang;
    let filter = params.filter();
    if let Some(seq) = advisory_list::find_id(&state.pool, &filter.q).await? {
        return Ok(Redirect::to(&format!("/advisories/{seq}")).into_response());
    }
    let page_no = params.page();
    let page = advisory_list::list(&state.pool, &filter, page_no, now_ms()).await?;
    let all = advisory_list::count(&state.pool).await?;
    let explicit = params.selected();
    let shown = explicit.or_else(|| page.rows.first().map(|r| r.seq));
    let detail = match shown {
        Some(seq) => match advisory_list::detail(&state.pool, seq).await? {
            Some(d) => {
                let mut view = detail_view(t, d, list_href(&filter, page_no, None), false);
                view.own =
                    crate::web::inbox::own_box(&state.pool, t, &format!("adv:{seq}"), None).await?;
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
            let b = band(&r.severity);
            Row {
                seq: r.seq,
                href: list_href(&filter, page_no, Some(r.seq)),
                id: r.display_id.clone(),
                title: r.title.clone(),
                publisher: r.publisher.clone(),
                band: b.as_str(),
                band_icon: b.icon(),
                severity: severity_label(t, &r.severity, &r.severity_text),
                cves: t.number(r.cve_count),
                updated: date(t, r.updated_ms),
                selected: shown == Some(r.seq),
            }
        })
        .collect();
    let pages_total = ((page.total + PAGE_SIZE - 1) / PAGE_SIZE).clamp(1, MAX_PAGE);
    let html = ListTemplate {
        t,
        view: "advisories",
        layout: user.layout().at("cves"),
        q: filter.q.clone(),
        hidden: hidden_fields(&filter),
        count_text: t.fmt(
            "advisories-count",
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
        sources: ["bsi", "vendor"]
            .iter()
            .map(|&s| Choice {
                label: source_label(t, s),
                href: s.to_owned(),
                current: filter.source == Some(s),
            })
            .collect(),
        vendor: filter.vendor.clone(),
        rows,
        pages: page_links(page_no, pages_total, |to| list_href(&filter, to, None)),
        page_text: t.fmt(
            "cves-page",
            &[("page", page_no.into()), ("pages", pages_total.into())],
        ),
        empty_db: all == 0,
        sheet_open: explicit.is_some(),
        detail,
    }
    .render()?;
    Ok(Html(html).into_response())
}

/// One advisory as a page of its own.
pub async fn page(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(seq): Path<String>,
) -> Result<Html<String>> {
    let seq: i64 = seq.trim().parse().map_err(|_| Error::NotFound)?;
    let detail = advisory_list::detail(&state.pool, seq)
        .await?
        .ok_or(Error::NotFound)?;
    let t = user.lang;
    let mut d = detail_view(t, detail, "/advisories".to_owned(), true);
    d.own = crate::web::inbox::own_box(&state.pool, t, &format!("adv:{seq}"), None).await?;
    Ok(Html(
        DetailTemplate {
            t,
            layout: user.layout().at("cves"),
            d,
        }
        .render()?,
    ))
}

fn hidden_fields(filter: &Filter) -> Vec<(&'static str, String)> {
    let default = Filter::default();
    let mut out = Vec::new();
    if filter.period != default.period {
        out.push(("period", filter.period.as_str()));
    }
    if let Some(b) = filter.band {
        out.push(("sev", b.as_str().to_owned()));
    }
    if let Some(src) = filter.source {
        out.push(("src", src.to_owned()));
    }
    if !filter.vendor.is_empty() {
        out.push(("vendor", filter.vendor.clone()));
    }
    out
}

fn chips(t: Lang, filter: &Filter) -> Vec<Chip> {
    let remove = |label: String, f: Filter| Chip {
        label,
        href: list_href(&f, 1, None),
        active: true,
    };
    let mut out = Vec::new();
    for s in ["bsi", "vendor"] {
        let active = filter.source == Some(s);
        out.push(Chip {
            label: source_label(t, s),
            href: list_href(
                &Filter {
                    source: (!active).then_some(s),
                    ..filter.clone()
                },
                1,
                None,
            ),
            active,
        });
    }
    if let Some(b) = filter.band {
        out.push(remove(
            t.get1("cves-chip-band", "band", t.get(b.label_id())),
            Filter {
                band: None,
                ..filter.clone()
            },
        ));
    }
    if !filter.vendor.is_empty() {
        out.push(remove(
            t.get1("cves-chip-vendor", "vendor", filter.vendor.clone()),
            Filter {
                vendor: String::new(),
                ..filter.clone()
            },
        ));
    }
    if !filter.q.is_empty() {
        out.push(remove(
            t.get1("cves-chip-search", "q", filter.q.clone()),
            Filter {
                q: String::new(),
                ..filter.clone()
            },
        ));
    }
    out
}

fn status_label(t: Lang, status: &str) -> String {
    t.get(match status {
        "affected" => "advisory-status-affected",
        "fixed" => "advisory-status-fixed",
        "not_affected" => "advisory-status-not-affected",
        "investigating" => "advisory-status-investigating",
        "recommended" => "advisory-status-recommended",
        _ => "advisory-status-listed",
    })
}

fn status_class(status: &str) -> &'static str {
    match status {
        "affected" => "st-affected",
        "fixed" => "st-fixed",
        "investigating" => "st-investigating",
        "not_affected" => "st-not-affected",
        "recommended" => "st-recommended",
        _ => "st-listed",
    }
}

fn host_of(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    Some(
        rest.split(['/', '?', '#'])
            .next()
            .unwrap_or_default()
            .to_owned(),
    )
}

/// The primary language of a CSAF document (`de-DE` → `de`) for the HTML `lang` attribute; empty if the
/// document gives none or something that is not a language tag.
fn text_lang(lang: &str) -> String {
    let primary = lang.split(['-', '_']).next().unwrap_or("").trim();
    if (2..=3).contains(&primary.len()) && primary.chars().all(|c| c.is_ascii_alphabetic()) {
        primary.to_ascii_lowercase()
    } else {
        String::new()
    }
}

pub(crate) fn detail_view(t: Lang, d: Detail, back_href: String, standalone: bool) -> DetailView {
    let r = d.record;
    let b = band(&r.severity);
    let notes: Vec<Note> = serde_json::from_str(&r.notes).unwrap_or_default();
    let refs: Vec<Reference> = serde_json::from_str(&r.refs).unwrap_or_default();
    let shown_products = d.products.len() as i64;
    // The summary is shown on its own; the other notes follow it.
    let notes: Vec<Note> = notes
        .into_iter()
        .filter(|n| !(n.category == "summary" && n.text == r.summary))
        .collect();
    let text_lang = text_lang(&r.lang);
    DetailView {
        title_from_doc: !r.title.is_empty(),
        translate: Lang::ALL.iter().any(|l| l.code() == text_lang) && text_lang != t.code(),
        text_lang,
        seq: r.seq,
        tracking_id: (r.tracking_id != r.display_id).then(|| r.tracking_id.clone()),
        display_id: r.display_id,
        title: if r.title.is_empty() {
            t.get("cve-no-title")
        } else {
            r.title
        },
        summary: r.summary,
        band: b.as_str(),
        band_icon: b.icon(),
        severity: severity_label(t, &r.severity, &r.severity_text),
        cvss: r.cvss_score.map(|s| t.decimal(s, 1)),
        publisher: r.publisher,
        source: if r.source == "bsi" {
            source_label(t, "bsi")
        } else {
            r.provider_name
        },
        published: date(t, r.published_ms),
        updated: date(t, r.updated_ms),
        version: r.version,
        status: r.status,
        tlp: r.tlp,
        lang: r.lang,
        hash_checked: r.hash_checked,
        web_url: r.web_url,
        doc_url: r.url,
        notes,
        cves: d
            .cves
            .into_iter()
            .map(|c| {
                let prio_band = Band::of_prio(c.prio.unwrap_or(0));
                CveView {
                    known: c.title.is_some(),
                    title: c
                        .title
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| t.get("advisory-cve-unknown")),
                    prio: c.prio.map_or_else(|| "–".to_owned(), |p| p.to_string()),
                    prio_band: if c.prio.is_some() {
                        prio_band.as_str()
                    } else {
                        "none"
                    },
                    kev: c.kev_added.is_some(),
                    id: c.cve_id,
                }
            })
            .collect(),
        products: d
            .products
            .into_iter()
            .map(|p| {
                let name = if p.product_name.is_empty() {
                    p.name.clone()
                } else {
                    product_name(&p.vendor_name, &p.product_name)
                };
                ProductView {
                    name,
                    version: p.version,
                    range: p.version_range,
                    status: status_class(&p.status),
                    status_label: status_label(t, &p.status),
                    cpe: if p.cpe.is_empty() { p.purl } else { p.cpe },
                    href: list_href(
                        &Filter {
                            vendor: p.vendor,
                            period: Period::All,
                            ..Filter::default()
                        },
                        1,
                        None,
                    ),
                }
            })
            .collect(),
        products_more: (r.product_count > shown_products).then(|| {
            t.fmt(
                "advisory-products-more",
                &[
                    ("shown", t.number(shown_products).into()),
                    ("all", t.number(r.product_count).into()),
                ],
            )
        }),
        refs: refs
            .into_iter()
            .filter(|r| r.category != "self")
            .filter_map(|r| {
                Some(RefView {
                    host: host_of(&r.url)?,
                    summary: r.summary,
                    url: r.url,
                })
            })
            .collect(),
        back_href,
        standalone,
        own: None,
    }
}

/// Texts that only templates use, for the catalog check: "advisories-title" "advisories-search-placeholder"
/// "advisories-filter-source" "advisories-filter-source-any" "advisories-filter-vendor-help"
/// "advisories-empty-db-title" "advisories-empty-db-text"
/// "advisories-empty-title" "advisories-empty-text" "advisories-detail-empty" "advisories-col-severity" "advisories-col-id"
/// "advisories-col-title" "advisories-col-publisher" "advisories-col-cves" "advisories-col-updated"
/// "advisory-section-summary" "advisory-section-cves" "advisory-section-products" "advisory-section-notes"
/// "advisory-section-sources" "advisory-section-refs" "advisory-published" "advisory-updated" "advisory-version"
/// "advisory-status" "advisory-tlp" "advisory-lang" "advisory-hash-checked" "advisory-hash-unchecked"
/// "advisory-open-portal" "advisory-open-csaf" "advisory-tracking-id" "advisory-publisher" "advisory-cvss"
/// "advisory-products-help" "advisory-version-range" "advisory-no-cves" "advisory-no-products" "view-cves"
/// "view-advisories" "advisory-status-affected" "advisory-status-fixed" "advisory-status-not-affected"
/// "advisory-status-investigating" "advisory-status-recommended" "advisory-status-listed"
#[cfg(test)]
mod tests {
    use super::*;
    use crate::csaf::document::{parse, tests::BSI_DOC};
    use crate::storage::advisories::{self as store, Origin};
    use crate::web::testutil::*;
    use axum::http::StatusCode;

    #[tokio::test]
    async fn the_list_and_the_detail_show_the_documents_escaped() {
        let h = harness(true).await;
        let (session, _) = login(&h, "anna").await;
        let empty = send(&h.app, get("/advisories", Some(&session))).await;
        assert_eq!(empty.status, StatusCode::OK);
        assert!(
            empty.body.contains("Noch keine Advisories"),
            "{}",
            empty.body
        );

        let bsi = store::bsi_provider(&h.state.pool, "https://bsi.example/pm.json")
            .await
            .unwrap();
        let mut a = parse(BSI_DOC.as_bytes()).unwrap();
        a.title = "<script>alert(1)</script> OpenSSH".into();
        a.updated_ms = Some(now_ms());
        let mut conn = h.state.pool.acquire().await.unwrap();
        store::store(
            &mut conn,
            &Origin {
                provider_id: bsi.id,
                source: "bsi",
                url: "https://bsi.example/a.json",
                feed_updated: "x",
                hash_checked: true,
                now_ms: 1,
            },
            &a,
        )
        .await
        .unwrap();
        drop(conn);

        let list = send(&h.app, get("/advisories", Some(&session))).await;
        assert_eq!(list.status, StatusCode::OK);
        assert!(!list.body.contains("<script>alert"), "titles are escaped");
        assert!(list.body.contains("WID-SEC-2026-4365"));
        assert!(
            list.body.contains("Ein entfernter, anonymer Angreifer"),
            "the detail beside the list"
        );
        assert!(list.body.contains("Open Source OpenSSH"));
        assert!(list.body.contains("&#60;10.6p2") || list.body.contains("&lt;10.6p2"));

        let found = send(
            &h.app,
            get("/advisories?q=WID-SEC-W-2026-4365", Some(&session)),
        )
        .await;
        let target = found.location().to_owned();
        assert!(target.starts_with("/advisories/"), "{target}");
        let page = send(&h.app, get(&target, Some(&session))).await;
        assert_eq!(page.status, StatusCode::OK);
        assert!(
            page.body.contains("WID-SEC-W-2026-4365"),
            "the tracking id is shown too"
        );
        assert!(page.body.contains("/cves/CVE-2026-123158"));
        assert!(page.body.contains("portal/wid/securityadvisory"));

        // The CVE's detail names the advisory.
        sqlx::query("INSERT INTO cves (id, state, title, published_ms) VALUES ('CVE-2026-123158', 'published', 'x', 1)")
            .execute(&h.state.pool)
            .await
            .unwrap();
        let cve = send(&h.app, get("/cves/CVE-2026-123158", Some(&session))).await;
        assert_eq!(cve.status, StatusCode::OK);
        assert!(cve.body.contains(&target), "{}", cve.body);
        assert!(cve.body.contains("&#60;script&#62;") || cve.body.contains("&lt;script&gt;"));
        assert!(!cve.body.contains("<script>alert"));

        let none = send(&h.app, get("/advisories/999", Some(&session))).await;
        assert_eq!(none.status, StatusCode::NOT_FOUND);
        let bad = send(&h.app, get("/advisories/x", Some(&session))).await;
        assert_eq!(bad.status, StatusCode::NOT_FOUND);
        let filtered = send(&h.app, get("/advisories?src=vendor", Some(&session))).await;
        assert!(
            filtered.body.contains("Keine passenden Advisories"),
            "{}",
            filtered.body
        );
    }

    #[test]
    fn the_text_language_is_the_primary_tag() {
        assert_eq!(text_lang("de-DE"), "de");
        assert_eq!(text_lang("EN_us"), "en");
        assert_eq!(text_lang("en"), "en");
        assert_eq!(text_lang(""), "");
        assert_eq!(text_lang("\"><x"), "");
        assert_eq!(text_lang("deutsch"), "");
    }

    #[tokio::test]
    async fn a_german_advisory_offers_the_translation_in_english_only() {
        let h = harness(true).await;
        let (session, _) = login(&h, "anna").await;
        let bsi = store::bsi_provider(&h.state.pool, "https://bsi.example/pm.json")
            .await
            .unwrap();
        let a = parse(BSI_DOC.as_bytes()).unwrap();
        let mut conn = h.state.pool.acquire().await.unwrap();
        store::store(
            &mut conn,
            &Origin {
                provider_id: bsi.id,
                source: "bsi",
                url: "https://bsi.example/a.json",
                feed_updated: "x",
                hash_checked: true,
                now_ms: 1,
            },
            &a,
        )
        .await
        .unwrap();
        drop(conn);
        let seq: i64 = sqlx::query_scalar("SELECT seq FROM advisories")
            .fetch_one(&h.state.pool)
            .await
            .unwrap();
        let path = format!("/advisories/{seq}");

        let de = send(&h.app, get(&path, Some(&session))).await;
        assert_eq!(de.status, StatusCode::OK);
        assert!(
            de.body.contains(r#"<h1 lang="de">OpenSSH: Schwachstelle"#),
            "{}",
            de.body
        );
        assert!(
            de.body
                .contains(r#"<p class="desc prewrap" lang="de">Ein entfernter"#)
        );
        assert!(!de.body.contains("data-tr-from"));

        let en = send(&h.app, accepting(get(&path, Some(&session)), "en")).await;
        assert_eq!(en.status, StatusCode::OK);
        assert!(
            en.body
                .contains(r#"<h1 lang="de" data-tr>OpenSSH: Schwachstelle"#),
            "{}",
            en.body
        );
        assert!(
            en.body
                .contains(r#"<p class="desc prewrap" lang="de" data-tr>Ein entfernter"#)
        );
        assert!(en.body.contains(r#"data-tr-from="de""#));
        assert!(en.body.contains("Translate"));
    }
}
