//! The queries of the advisory pages: the filtered list, the detail of one advisory and the advisories of a CVE.

use sqlx::{QueryBuilder, Sqlite, SqlitePool};

use crate::error::Result;
use crate::storage::cve_list::{Band, MAX_PAGE, PAGE_SIZE, Period, fts_query};

/// The band of a stored severity (`critical` … `low`, or empty).
pub fn band(severity: &str) -> Band {
    match severity {
        "critical" => Band::Crit,
        "high" => Band::High,
        "medium" => Band::Med,
        "low" => Band::Low,
        _ => Band::None,
    }
}

fn severity_of(band: Band) -> &'static str {
    match band {
        Band::Crit => "critical",
        Band::High => "high",
        Band::Med => "medium",
        Band::Low => "low",
        Band::None => "",
    }
}

/// The filters of the list.
#[derive(Debug, Clone, PartialEq)]
pub struct Filter {
    /// Full-text search (id, title, summary, products) or a complete CVE id.
    pub q: String,
    /// The time span, by the date of the current version.
    pub period: Period,
    pub band: Option<Band>,
    /// `bsi` or `vendor`.
    pub source: Option<&'static str>,
    /// A vendor key of the product tree (see `sources::name_key`).
    pub vendor: String,
}

impl Default for Filter {
    fn default() -> Self {
        Self {
            q: String::new(),
            period: Period::Days(30),
            band: None,
            source: None,
            vendor: String::new(),
        }
    }
}

/// One row of the list.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Row {
    pub seq: i64,
    pub display_id: String,
    pub title: String,
    pub publisher: String,
    pub source: String,
    pub severity: String,
    pub severity_text: String,
    pub cvss_score: Option<f64>,
    pub cve_count: i64,
    pub updated_ms: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct Page {
    pub rows: Vec<Row>,
    pub total: i64,
}

fn push_where(qb: &mut QueryBuilder<'_, Sqlite>, filter: &Filter, now_ms: i64) {
    qb.push(" WHERE 1 = 1");
    if let Period::Days(days) = filter.period {
        qb.push(" AND updated_ms >= ")
            .push_bind(now_ms - days * 86_400_000);
    }
    if let Some(band) = filter.band {
        qb.push(" AND severity = ").push_bind(severity_of(band));
    }
    if let Some(source) = filter.source {
        qb.push(" AND source = ").push_bind(source);
    }
    if !filter.vendor.is_empty() {
        qb.push(" AND seq IN (SELECT advisory_seq FROM advisory_products WHERE vendor = ")
            .push_bind(filter.vendor.clone())
            .push(")");
    }
    let q = filter.q.trim().to_ascii_uppercase();
    if crate::sources::cve5::is_cve_id(&q) {
        qb.push(" AND seq IN (SELECT advisory_seq FROM advisory_cves WHERE cve_id = ")
            .push_bind(q)
            .push(")");
    } else if let Some(fts) = fts_query(&filter.q) {
        qb.push(" AND seq IN (SELECT rowid FROM advisories_fts WHERE advisories_fts MATCH ")
            .push_bind(fts)
            .push(")");
    }
}

/// One page (1-based) of the list, newest version first.
pub async fn list(pool: &SqlitePool, filter: &Filter, page: i64, now_ms: i64) -> Result<Page> {
    let page = page.clamp(1, MAX_PAGE);
    let mut qb = QueryBuilder::<Sqlite>::new("SELECT COUNT(*) FROM advisories");
    push_where(&mut qb, filter, now_ms);
    let total: i64 = qb.build_query_scalar().fetch_one(pool).await?;
    let mut qb = QueryBuilder::<Sqlite>::new(
        "SELECT seq, display_id, title, publisher, source, severity, severity_text, cvss_score, cve_count,
                updated_ms FROM advisories",
    );
    push_where(&mut qb, filter, now_ms);
    qb.push(" ORDER BY updated_ms DESC, seq DESC LIMIT ")
        .push_bind(PAGE_SIZE)
        .push(" OFFSET ")
        .push_bind((page - 1) * PAGE_SIZE);
    let rows = qb.build_query_as::<Row>().fetch_all(pool).await?;
    Ok(Page { rows, total })
}

pub async fn count(pool: &SqlitePool) -> Result<i64> {
    Ok(sqlx::query_scalar("SELECT COUNT(*) FROM advisories")
        .fetch_one(pool)
        .await?)
}

/// The advisory whose id (as shown, or the tracking id) is `q`, for a search that is an id.
pub async fn find_id(pool: &SqlitePool, q: &str) -> Result<Option<i64>> {
    let q = q.trim();
    if q.is_empty() || q.len() > 100 || q.contains(char::is_whitespace) {
        return Ok(None);
    }
    let upper = q.to_ascii_uppercase();
    Ok(sqlx::query_scalar(
        "SELECT seq FROM advisories WHERE display_id IN (?1, ?2) OR tracking_id IN (?1, ?2)
         ORDER BY updated_ms DESC LIMIT 1",
    )
    .bind(q)
    .bind(&upper)
    .fetch_optional(pool)
    .await?)
}

/// Everything the detail of one advisory shows.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Record {
    pub seq: i64,
    pub source: String,
    pub url: String,
    pub tracking_id: String,
    pub display_id: String,
    pub publisher: String,
    pub title: String,
    pub summary: String,
    pub lang: String,
    pub tlp: String,
    pub severity: String,
    pub severity_text: String,
    pub cvss_score: Option<f64>,
    pub status: String,
    pub version: String,
    pub published_ms: Option<i64>,
    pub updated_ms: Option<i64>,
    pub web_url: String,
    pub hash_checked: bool,
    pub product_count: i64,
    pub notes: String,
    pub refs: String,
    pub fetched_ms: i64,
    pub provider_name: String,
}

/// A CVE an advisory names, with what the CVE list knows about it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CveRow {
    pub cve_id: String,
    pub title: Option<String>,
    pub prio: Option<i64>,
    pub cvss_score: Option<f64>,
    pub kev_added: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ProductRow {
    pub vendor: String,
    pub vendor_name: String,
    pub product_name: String,
    pub name: String,
    pub version: String,
    pub version_range: bool,
    pub cpe: String,
    pub purl: String,
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct Detail {
    pub record: Record,
    pub cves: Vec<CveRow>,
    pub products: Vec<ProductRow>,
}

/// Most CVEs and products shown in a detail.
pub const DETAIL_ROWS: i64 = 500;

pub async fn detail(pool: &SqlitePool, seq: i64) -> Result<Option<Detail>> {
    let Some(record) = sqlx::query_as::<_, Record>(
        "SELECT a.seq, a.source, a.url, a.tracking_id, a.display_id, a.publisher, a.title, a.summary, a.lang,
                a.tlp, a.severity, a.severity_text, a.cvss_score, a.status, a.version, a.published_ms,
                a.updated_ms, a.web_url, a.hash_checked, a.product_count, a.notes, a.refs, a.fetched_ms,
                p.name AS provider_name
         FROM advisories a JOIN csaf_providers p ON p.id = a.provider_id WHERE a.seq = ?",
    )
    .bind(seq)
    .fetch_optional(pool)
    .await?
    else {
        return Ok(None);
    };
    let cves = sqlx::query_as::<_, CveRow>(
        "SELECT ac.cve_id, c.title, c.prio, c.cvss_score, c.kev_added
         FROM advisory_cves ac LEFT JOIN cves c ON c.id = ac.cve_id
         WHERE ac.advisory_seq = ? ORDER BY c.prio DESC NULLS LAST, ac.cve_id LIMIT ?",
    )
    .bind(seq)
    .bind(DETAIL_ROWS)
    .fetch_all(pool)
    .await?;
    let products = sqlx::query_as::<_, ProductRow>(
        "SELECT vendor, vendor_name, product_name, name, version, version_range, cpe, purl, status
         FROM advisory_products WHERE advisory_seq = ?
         ORDER BY CASE status WHEN 'affected' THEN 0 WHEN 'investigating' THEN 1 WHEN 'fixed' THEN 2
                  WHEN 'recommended' THEN 3 WHEN '' THEN 4 ELSE 5 END,
                  vendor_name, product_name, version LIMIT ?",
    )
    .bind(seq)
    .bind(DETAIL_ROWS)
    .fetch_all(pool)
    .await?;
    Ok(Some(Detail {
        record,
        cves,
        products,
    }))
}

/// An advisory that names a CVE (for the CVE detail).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ForCve {
    pub seq: i64,
    pub display_id: String,
    pub title: String,
    pub publisher: String,
    pub source: String,
    pub severity: String,
    pub updated_ms: Option<i64>,
}

pub async fn for_cve(pool: &SqlitePool, cve_id: &str) -> Result<Vec<ForCve>> {
    Ok(sqlx::query_as::<_, ForCve>(
        "SELECT a.seq, a.display_id, a.title, a.publisher, a.source, a.severity, a.updated_ms
         FROM advisory_cves ac JOIN advisories a ON a.seq = ac.advisory_seq
         WHERE ac.cve_id = ? ORDER BY a.updated_ms DESC LIMIT 50",
    )
    .bind(cve_id)
    .fetch_all(pool)
    .await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csaf::document::{parse, tests::BSI_DOC};
    use crate::storage::advisories::{self as store, Origin};

    async fn pool_with_advisories() -> (SqlitePool, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pool = crate::storage::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        crate::storage::migrate(&pool).await.unwrap();
        let bsi = store::bsi_provider(&pool, "https://bsi.example/pm.json")
            .await
            .unwrap();
        let mut conn = pool.acquire().await.unwrap();
        let a = parse(BSI_DOC.as_bytes()).unwrap();
        let mut b = a.clone();
        b.display_id = "WID-SEC-2026-0002".into();
        b.tracking_id = "WID-SEC-W-2026-0002".into();
        b.title = "FRITZ!Box: Schwachstelle".into();
        b.summary = "Ein Angreifer kann die Box übernehmen.".into();
        b.severity = "critical";
        b.cves = vec!["CVE-2026-0002".into()];
        b.products.clear();
        b.updated_ms = Some(1_000);
        for (doc, url) in [
            (&a, "https://bsi.example/a.json"),
            (&b, "https://bsi.example/b.json"),
        ] {
            let origin = Origin {
                provider_id: bsi.id,
                source: "bsi",
                url,
                feed_updated: "x",
                hash_checked: true,
                now_ms: 1,
            };
            store::store(&mut conn, &origin, doc).await.unwrap();
        }
        sqlx::query(
            "INSERT INTO cves (id, state, title, cvss_score, prio) VALUES ('CVE-2026-123158', 'published', 'OpenSSH', 9.8, 70)",
        )
        .execute(&pool)
        .await
        .unwrap();
        (pool, dir)
    }

    #[tokio::test]
    async fn the_list_filters_by_text_cve_band_source_and_vendor() {
        let (pool, _dir) = pool_with_advisories().await;
        let now = 1_793_919_600_000 + 86_400_000;
        let all = Filter {
            period: Period::All,
            ..Filter::default()
        };
        let ids = |p: Page| p.rows.into_iter().map(|r| r.display_id).collect::<Vec<_>>();
        assert_eq!(
            ids(list(&pool, &all, 1, now).await.unwrap()),
            ["WID-SEC-2026-4365", "WID-SEC-2026-0002"]
        );
        assert_eq!(
            ids(list(&pool, &Filter::default(), 1, now).await.unwrap()),
            ["WID-SEC-2026-4365"],
            "the second is older than 30 days"
        );
        for (filter, want) in [
            (
                Filter {
                    q: "openssh".into(),
                    ..all.clone()
                },
                vec!["WID-SEC-2026-4365"],
            ),
            (
                Filter {
                    q: "WID-SEC-2026-0002".into(),
                    ..all.clone()
                },
                vec!["WID-SEC-2026-0002"],
            ),
            (
                Filter {
                    q: "cve-2026-0002".into(),
                    ..all.clone()
                },
                vec!["WID-SEC-2026-0002"],
            ),
            (
                Filter {
                    band: Some(Band::Crit),
                    ..all.clone()
                },
                vec!["WID-SEC-2026-0002"],
            ),
            (
                Filter {
                    source: Some("vendor"),
                    ..all.clone()
                },
                vec![],
            ),
            (
                Filter {
                    vendor: "opensource".into(),
                    ..all.clone()
                },
                vec!["WID-SEC-2026-4365"],
            ),
        ] {
            let page = list(&pool, &filter, 1, now).await.unwrap();
            assert_eq!(page.total, want.len() as i64, "{filter:?}");
            assert_eq!(ids(page), want, "{filter:?}");
        }
        assert!(
            find_id(&pool, "wid-sec-w-2026-4365")
                .await
                .unwrap()
                .is_some()
        );
        assert!(find_id(&pool, "WID-SEC-2026-0002").await.unwrap().is_some());
        assert_eq!(find_id(&pool, "openssh").await.unwrap(), None);
        assert_eq!(count(&pool).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn the_detail_joins_cves_and_products() {
        let (pool, _dir) = pool_with_advisories().await;
        let seq = find_id(&pool, "WID-SEC-2026-4365").await.unwrap().unwrap();
        let d = detail(&pool, seq).await.unwrap().unwrap();
        assert_eq!(d.record.provider_name, "BSI CERT-Bund");
        assert!(d.record.hash_checked);
        assert_eq!(d.cves.len(), 1);
        assert_eq!(d.cves[0].prio, Some(70));
        let statuses: Vec<_> = d.products.iter().map(|p| p.status.as_str()).collect();
        assert_eq!(statuses, ["affected", "affected", ""]);
        assert!(detail(&pool, 999).await.unwrap().is_none());
        let refs = for_cve(&pool, "CVE-2026-123158").await.unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].display_id, "WID-SEC-2026-4365");
        assert_eq!(band("medium"), Band::Med);
        assert_eq!(band(""), Band::None);
    }
}
