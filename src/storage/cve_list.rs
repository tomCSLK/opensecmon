//! The queries of the page "All CVEs": the filtered, sorted list and the detail of one CVE.

use sqlx::{QueryBuilder, Sqlite, SqlitePool};

use crate::error::Result;

/// Rows per page of the list.
pub const PAGE_SIZE: i64 = 50;
/// Deepest page (offset paging gets slow, and nobody pages that far; narrow the filter instead).
pub const MAX_PAGE: i64 = 200;

/// The time span of the list, by publication date.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Period {
    Days(i64),
    All,
}

impl Period {
    pub const CHOICES: [Self; 5] = [
        Self::Days(7),
        Self::Days(30),
        Self::Days(90),
        Self::Days(365),
        Self::All,
    ];

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "all" => Some(Self::All),
            _ => s
                .parse()
                .ok()
                .map(Self::Days)
                .filter(|p| Self::CHOICES.contains(p)),
        }
    }

    pub fn as_str(self) -> String {
        match self {
            Self::Days(d) => d.to_string(),
            Self::All => "all".to_owned(),
        }
    }
}

/// A band of the main CVSS score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Band {
    Crit,
    High,
    Med,
    Low,
    /// No CVSS score at all.
    None,
}

impl Band {
    pub const ALL: [Self; 5] = [Self::Crit, Self::High, Self::Med, Self::Low, Self::None];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Crit => "crit",
            Self::High => "high",
            Self::Med => "med",
            Self::Low => "low",
            Self::None => "none",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|b| b.as_str() == s)
    }

    /// The band of a CVSS score (the qualitative ratings of CVSS 3.x).
    pub fn of_cvss(score: Option<f64>) -> Self {
        match score {
            Some(s) if s >= 9.0 => Self::Crit,
            Some(s) if s >= 7.0 => Self::High,
            Some(s) if s >= 4.0 => Self::Med,
            Some(_) => Self::Low,
            None => Self::None,
        }
    }

    /// The band of a priority (0–100), as in the drafts: 85, 65, 45.
    pub fn of_prio(prio: i64) -> Self {
        match prio {
            p if p >= 85 => Self::Crit,
            p if p >= 65 => Self::High,
            p if p >= 45 => Self::Med,
            _ => Self::Low,
        }
    }

    /// Catalog id of the name of the band.
    pub fn label_id(self) -> &'static str {
        match self {
            Self::Crit => "band-crit",
            Self::High => "band-high",
            Self::Med => "band-med",
            Self::Low => "band-low",
            Self::None => "band-none",
        }
    }

    /// Icon of the band (`none` has no icon of its own).
    pub fn icon(self) -> &'static str {
        match self {
            Self::None => "low",
            b => b.as_str(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sort {
    Published,
    Prio,
    Cvss,
    Epss,
}

impl Sort {
    pub const ALL: [Self; 4] = [Self::Published, Self::Prio, Self::Cvss, Self::Epss];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "pub",
            Self::Prio => "prio",
            Self::Cvss => "cvss",
            Self::Epss => "epss",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }

    fn order_by(self) -> &'static str {
        match self {
            Self::Published => " ORDER BY published_ms DESC, seq DESC",
            Self::Prio => " ORDER BY prio DESC, published_ms DESC, seq DESC",
            // SQLite sorts NULL first ascending and last descending, so these keep records without a score
            // at the end and can still walk the index on the score.
            Self::Cvss => " ORDER BY cvss_score DESC, published_ms DESC, seq DESC",
            Self::Epss => " ORDER BY epss DESC, published_ms DESC, seq DESC",
        }
    }
}

/// The filters of the list.
#[derive(Debug, Clone, PartialEq)]
pub struct Filter {
    /// Full-text search (title, description, products) or the start of a CVE id.
    pub q: String,
    pub period: Period,
    pub band: Option<Band>,
    pub kev: bool,
    /// EPSS at least 10 %.
    pub epss: bool,
    /// A vendor key (see `sources::name_key`).
    pub vendor: String,
    /// Also rejected records.
    pub rejected: bool,
    /// Only CVEs that affect an own asset (any match that is not ignored).
    pub mine: bool,
    pub sort: Sort,
}

impl Filter {
    /// Whether a filter with an index of its own (search, vendor, KEV, EPSS, band) is set. SQLite has no statistics
    /// and otherwise starts from `state = ?`, which matches almost every record: then it walks a (state, …)
    /// index over all published CVEs and tests each one (vendor 0.9 s → 0 ms, KEV 15 s → 1 ms, EPSS and
    /// band 1.3 s → 0.1 s, an id prefix such as `CVE-2024` 2 s → 0.1 s). With such a filter the state is tested as `+state`, which no index serves.
    fn selective(&self) -> bool {
        !self.q.trim().is_empty()
            || !self.vendor.is_empty()
            || self.kev
            || self.epss
            || self.band.is_some()
            || self.mine
    }

    /// The index for the rows of a page sorted over the whole period. Without a hint SQLite takes
    /// (state, published_ms) and sorts every published CVE (1.5–3 s); walking the index of the sort key
    /// reads only the rows of the page. Not with a selective filter or a period, whose own
    /// indexes find fewer rows, and not with rejected records ((state, prio) needs the state condition).
    fn index_hint(&self) -> &'static str {
        if self.selective() || self.period != Period::All || self.rejected {
            return "";
        }
        match self.sort {
            Sort::Published => "",
            Sort::Prio => " INDEXED BY cves_state_prio",
            Sort::Cvss => " INDEXED BY cves_cvss",
            Sort::Epss => " INDEXED BY cves_epss",
        }
    }
}

impl Default for Filter {
    fn default() -> Self {
        Self {
            q: String::new(),
            period: Period::Days(30),
            band: None,
            kev: false,
            epss: false,
            vendor: String::new(),
            rejected: false,
            mine: false,
            sort: Sort::Published,
        }
    }
}

/// One row of the list.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Row {
    pub id: String,
    pub state: String,
    pub title: String,
    pub cvss_score: Option<f64>,
    pub cvss_version: Option<String>,
    pub epss: Option<f64>,
    pub kev_added: Option<String>,
    pub prio: i64,
    pub published_ms: Option<i64>,
}

/// A page of the list and the number of matching CVEs.
#[derive(Debug, Clone)]
pub struct Page {
    pub rows: Vec<Row>,
    pub total: i64,
}

/// The FTS5 query for what the user typed: every word as a quoted prefix, all of them required. Quotes are
/// doubled, operators lose their meaning inside the quotes. `None` if nothing searchable is left.
pub fn fts_query(q: &str) -> Option<String> {
    let words: Vec<String> = q
        .split(|c: char| !(c.is_alphanumeric() || c == '-' || c == '_' || c == '.'))
        .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()))
        .filter(|w| !w.is_empty())
        .take(8)
        .map(|w| {
            let w: String = w.chars().take(60).collect();
            format!("\"{}\"*", w.replace('"', "\"\""))
        })
        .collect();
    (!words.is_empty()).then(|| words.join(" AND "))
}

/// The start of a CVE id (`CVE-2026-4`, `cve-2026`), upper-cased; such a search looks at the ids only.
pub fn id_prefix(q: &str) -> Option<String> {
    let q = q.trim().to_ascii_uppercase();
    let rest = q.strip_prefix("CVE-")?;
    (rest.len() <= 20
        && !rest.is_empty()
        && rest.bytes().all(|b| b.is_ascii_digit() || b == b'-')
        && rest.as_bytes()[0].is_ascii_digit())
    .then_some(q)
}

fn push_where(qb: &mut QueryBuilder<'_, Sqlite>, filter: &Filter, now_ms: i64) {
    qb.push(" WHERE 1 = 1");
    if !filter.rejected {
        if !filter.selective() {
            qb.push(" AND state = 'published'");
        } else {
            qb.push(" AND +state = 'published'");
        }
    }
    if let Period::Days(days) = filter.period {
        qb.push(" AND published_ms >= ")
            .push_bind(now_ms - days * 86_400_000);
    }
    match filter.band {
        Some(Band::Crit) => {
            qb.push(" AND cvss_score >= 9");
        }
        Some(Band::High) => {
            qb.push(" AND cvss_score >= 7 AND cvss_score < 9");
        }
        Some(Band::Med) => {
            qb.push(" AND cvss_score >= 4 AND cvss_score < 7");
        }
        Some(Band::Low) => {
            qb.push(" AND cvss_score < 4");
        }
        Some(Band::None) => {
            qb.push(" AND cvss_score IS NULL");
        }
        None => {}
    }
    if filter.kev {
        qb.push(" AND kev_added IS NOT NULL");
    }
    if filter.epss {
        qb.push(" AND epss >= 0.1");
    }
    if filter.mine {
        qb.push(" AND id IN (")
            .push(crate::storage::matches::MINE_SQL)
            .push(")");
    }
    if !filter.vendor.is_empty() {
        // Through the index on (vendor, product); EXISTS per row would read every CVE.
        qb.push(" AND id IN (SELECT cve_id FROM cve_products WHERE vendor = ")
            .push_bind(filter.vendor.clone())
            .push(")");
    }
    if let Some(prefix) = id_prefix(&filter.q) {
        // `id` is unique, so this range uses its index; ids are ASCII, `~` sorts after every digit.
        qb.push(" AND id >= ")
            .push_bind(prefix.clone())
            .push(" AND id < ")
            .push_bind(format!("{prefix}~"));
    } else if let Some(fts) = fts_query(&filter.q) {
        qb.push(" AND seq IN (SELECT rowid FROM cves_fts WHERE cves_fts MATCH ")
            .push_bind(fts)
            .push(")");
    }
}

/// One page (1-based) of the list.
pub async fn list(pool: &SqlitePool, filter: &Filter, page: i64, now_ms: i64) -> Result<Page> {
    let page = page.clamp(1, MAX_PAGE);
    let mut qb = QueryBuilder::<Sqlite>::new("SELECT COUNT(*) FROM cves");
    push_where(&mut qb, filter, now_ms);
    let total: i64 = qb.build_query_scalar().fetch_one(pool).await?;
    let mut qb = QueryBuilder::<Sqlite>::new(
        "SELECT id, state, title, cvss_score, cvss_version, epss, kev_added, prio, published_ms FROM cves",
    );
    qb.push(filter.index_hint());
    push_where(&mut qb, filter, now_ms);
    qb.push(filter.sort.order_by())
        .push(" LIMIT ")
        .push_bind(PAGE_SIZE)
        .push(" OFFSET ")
        .push_bind((page - 1) * PAGE_SIZE);
    let rows = qb.build_query_as::<Row>().fetch_all(pool).await?;
    Ok(Page { rows, total })
}

/// One row of the CSV export: the list row and a little more.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ExportRow {
    pub id: String,
    pub state: String,
    pub assigner: String,
    pub title: String,
    pub cvss_score: Option<f64>,
    pub cvss_version: Option<String>,
    pub cvss_vector: Option<String>,
    pub epss: Option<f64>,
    pub epss_percentile: Option<f64>,
    pub kev_added: Option<String>,
    pub prio: i64,
    pub published_ms: Option<i64>,
    pub mine: bool,
}

/// The rows of the list for the CSV export, in the order of the list, at most `limit`.
pub async fn export(
    pool: &SqlitePool,
    filter: &Filter,
    now_ms: i64,
    limit: i64,
) -> Result<Vec<ExportRow>> {
    let mut qb = QueryBuilder::<Sqlite>::new(
        "SELECT id, state, assigner, title, cvss_score, cvss_version, cvss_vector, epss, epss_percentile, kev_added,
             prio, published_ms, id IN (",
    );
    qb.push(crate::storage::matches::MINE_SQL)
        .push(") AS mine FROM cves");
    qb.push(filter.index_hint());
    push_where(&mut qb, filter, now_ms);
    qb.push(filter.sort.order_by())
        .push(" LIMIT ")
        .push_bind(limit);
    Ok(qb.build_query_as::<ExportRow>().fetch_all(pool).await?)
}

/// Number of all CVE records that are not rejected.
pub async fn count_published(pool: &SqlitePool) -> Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT COUNT(*) FROM cves WHERE state = 'published'")
            .fetch_one(pool)
            .await?,
    )
}

/// Whether a CVE id is known.
pub async fn exists(pool: &SqlitePool, id: &str) -> Result<bool> {
    Ok(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM cves WHERE id = ?")
            .bind(id)
            .fetch_one(pool)
            .await?
            > 0,
    )
}

/// Everything the detail of one CVE shows.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Record {
    pub id: String,
    pub state: String,
    pub assigner: String,
    pub title: String,
    pub description: String,
    pub published_ms: Option<i64>,
    pub updated_ms: Option<i64>,
    pub cwes: String,
    pub refs: String,
    pub affected: String,
    /// Deflated `refs`/`affected` (see `storage::packed`); [`detail`] unpacks them into the text fields.
    #[sqlx(default)]
    pub refs_z: Option<Vec<u8>>,
    #[sqlx(default)]
    pub affected_z: Option<Vec<u8>>,
    pub cvss_score: Option<f64>,
    pub cvss_version: Option<String>,
    pub cvss_vector: Option<String>,
    pub cvss_source: Option<String>,
    pub epss: Option<f64>,
    pub epss_percentile: Option<f64>,
    pub kev_added: Option<String>,
    pub prio: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MetricRow {
    pub provider: String,
    pub source: String,
    pub version: String,
    pub score: f64,
    pub vector: String,
    pub severity: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct KevRow {
    pub vendor: String,
    pub product: String,
    pub name: String,
    pub date_added: String,
    pub due_date: String,
    pub ransomware: String,
    pub required_action: String,
    pub notes: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct NvdRow {
    pub status: String,
    pub last_modified: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ProductRow {
    pub origin: String,
    pub vendor: String,
    pub vendor_name: String,
    pub product_name: String,
}

#[derive(Debug, Clone)]
pub struct Detail {
    pub record: Record,
    pub metrics: Vec<MetricRow>,
    pub kev: Option<KevRow>,
    pub nvd: Option<NvdRow>,
    pub products: Vec<ProductRow>,
}

/// The detail of one CVE, `None` if it is unknown.
pub async fn detail(pool: &SqlitePool, id: &str) -> Result<Option<Detail>> {
    let Some(mut record) = sqlx::query_as::<_, Record>(
        "SELECT id, state, assigner, title, description, published_ms, updated_ms, cwes, refs, affected,
                refs_z, affected_z, cvss_score, cvss_version, cvss_vector, cvss_source, epss, epss_percentile, kev_added, prio
         FROM cves WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    else {
        return Ok(None);
    };
    record.refs =
        crate::storage::packed::text(std::mem::take(&mut record.refs), record.refs_z.take());
    record.affected = crate::storage::packed::text(
        std::mem::take(&mut record.affected),
        record.affected_z.take(),
    );
    let metrics = sqlx::query_as::<_, MetricRow>(
        "SELECT provider, source, version, score, vector, severity FROM cve_metrics WHERE cve_id = ?
         ORDER BY CASE provider WHEN 'cna' THEN 0 WHEN 'nvd' THEN 1 ELSE 2 END, version DESC, source",
    )
    .bind(id)
    .fetch_all(pool)
    .await?;
    let kev = sqlx::query_as::<_, KevRow>(
        "SELECT vendor, product, name, date_added, due_date, ransomware, required_action, notes
         FROM kev WHERE cve_id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    let nvd =
        sqlx::query_as::<_, NvdRow>("SELECT status, last_modified FROM nvd_cves WHERE cve_id = ?")
            .bind(id)
            .fetch_optional(pool)
            .await?;
    let products = sqlx::query_as::<_, ProductRow>(
        "SELECT origin, vendor, vendor_name, product_name FROM cve_products WHERE cve_id = ?
         ORDER BY origin, vendor_name, product_name LIMIT 200",
    )
    .bind(id)
    .fetch_all(pool)
    .await?;
    Ok(Some(Detail {
        record,
        metrics,
        kev,
        nvd,
        products,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn searches_become_safe_fts_queries() {
        assert_eq!(fts_query("openssh"), Some("\"openssh\"*".into()));
        assert_eq!(
            fts_query("FRITZ!Box 7590"),
            Some("\"FRITZ\"* AND \"Box\"* AND \"7590\"*".into())
        );
        assert_eq!(
            fts_query("a\" OR b NEAR(c)"),
            Some("\"a\"* AND \"OR\"* AND \"b\"* AND \"NEAR\"* AND \"c\"*".into())
        );
        assert_eq!(
            fts_query("libssl3t64 3.5.3-1"),
            Some("\"libssl3t64\"* AND \"3.5.3-1\"*".into())
        );
        assert_eq!(fts_query("  *** "), None);
        assert_eq!(
            fts_query(&"x ".repeat(50)).unwrap().matches("AND").count(),
            7
        );
    }

    #[test]
    fn cve_ids_are_recognised() {
        assert_eq!(id_prefix(" cve-2026-41 "), Some("CVE-2026-41".into()));
        assert_eq!(id_prefix("CVE-2026-0001"), Some("CVE-2026-0001".into()));
        assert_eq!(id_prefix("CVE-"), None);
        assert_eq!(id_prefix("CVE-x"), None);
        assert_eq!(id_prefix("openssh"), None);
    }

    #[test]
    fn bands_follow_cvss_and_priority() {
        assert_eq!(Band::of_cvss(Some(9.8)), Band::Crit);
        assert_eq!(Band::of_cvss(Some(7.0)), Band::High);
        assert_eq!(Band::of_cvss(Some(6.9)), Band::Med);
        assert_eq!(Band::of_cvss(Some(0.0)), Band::Low);
        assert_eq!(Band::of_cvss(None), Band::None);
        assert_eq!(Band::of_prio(90), Band::Crit);
        assert_eq!(Band::of_prio(44), Band::Low);
        assert_eq!(Period::parse("30"), Some(Period::Days(30)));
        assert_eq!(Period::parse("31"), None);
        assert_eq!(Period::parse("all"), Some(Period::All));
    }

    async fn pool_with_cves() -> (SqlitePool, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pool = crate::storage::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        crate::storage::migrate(&pool).await.unwrap();
        let day: i64 = 86_400_000;
        let now = 100 * day;
        for (i, (id, title, cvss, epss, kev, age_days)) in [
            (
                "CVE-2026-0001",
                "OpenSSH remote code execution",
                Some(9.8),
                Some(0.5),
                true,
                1,
            ),
            (
                "CVE-2026-0002",
                "FRITZ!Box web interface XSS",
                Some(6.1),
                Some(0.01),
                false,
                10,
            ),
            ("CVE-2025-0003", "Old curl bug", Some(3.1), None, false, 60),
            ("CVE-2026-0004", "No score yet", None, None, false, 2),
        ]
        .into_iter()
        .enumerate()
        {
            sqlx::query(
                "INSERT INTO cves (id, state, title, cvss_score, epss, kev_added, published_ms, prio)
                 VALUES (?, 'published', ?, ?, ?, ?, ?, ?)",
            )
            .bind(id)
            .bind(title)
            .bind(cvss)
            .bind(epss)
            .bind(kev.then_some("2026-11-01"))
            .bind(now - age_days * day)
            .bind(i64::try_from(i).unwrap() * 10)
            .execute(&pool)
            .await
            .unwrap();
        }
        sqlx::query("INSERT INTO cves (id, state, title, published_ms) VALUES ('CVE-2026-0005', 'rejected', 'x', ?)")
            .bind(now)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO cve_products VALUES ('CVE-2026-0002', 'cna', 'avm', 'fritzbox', 'AVM', 'FRITZ!Box')",
        )
        .execute(&pool)
        .await
        .unwrap();
        (pool, dir)
    }

    fn ids(page: &Page) -> Vec<&str> {
        page.rows.iter().map(|r| r.id.as_str()).collect()
    }

    #[tokio::test]
    async fn the_list_filters_and_sorts() {
        let (pool, _dir) = pool_with_cves().await;
        let now: i64 = 100 * 86_400_000;
        let f = Filter::default();
        let page = list(&pool, &f, 1, now).await.unwrap();
        assert_eq!(
            ids(&page),
            ["CVE-2026-0001", "CVE-2026-0004", "CVE-2026-0002"]
        );
        assert_eq!(page.total, 3);
        let all = Filter {
            period: Period::All,
            sort: Sort::Cvss,
            ..f.clone()
        };
        assert_eq!(
            ids(&list(&pool, &all, 1, now).await.unwrap()),
            [
                "CVE-2026-0001",
                "CVE-2026-0002",
                "CVE-2025-0003",
                "CVE-2026-0004"
            ]
        );
        let with_rejected = Filter {
            rejected: true,
            ..all.clone()
        };
        assert_eq!(list(&pool, &with_rejected, 1, now).await.unwrap().total, 5);
        for (filter, expected) in [
            (
                Filter {
                    kev: true,
                    ..all.clone()
                },
                vec!["CVE-2026-0001"],
            ),
            (
                Filter {
                    epss: true,
                    ..all.clone()
                },
                vec!["CVE-2026-0001"],
            ),
            (
                Filter {
                    band: Some(Band::Med),
                    ..all.clone()
                },
                vec!["CVE-2026-0002"],
            ),
            (
                Filter {
                    band: Some(Band::None),
                    ..all.clone()
                },
                vec!["CVE-2026-0004"],
            ),
            (
                Filter {
                    vendor: "avm".into(),
                    ..all.clone()
                },
                vec!["CVE-2026-0002"],
            ),
            (
                Filter {
                    q: "fritz".into(),
                    ..all.clone()
                },
                vec!["CVE-2026-0002"],
            ),
            (
                Filter {
                    q: "remote openss".into(),
                    ..all.clone()
                },
                vec!["CVE-2026-0001"],
            ),
            (
                Filter {
                    q: "cve-2025".into(),
                    ..all.clone()
                },
                vec!["CVE-2025-0003"],
            ),
            (
                Filter {
                    q: "\"".into(),
                    ..all.clone()
                },
                vec![
                    "CVE-2026-0001",
                    "CVE-2026-0002",
                    "CVE-2025-0003",
                    "CVE-2026-0004",
                ],
            ),
        ] {
            assert_eq!(
                ids(&list(&pool, &filter, 1, now).await.unwrap()),
                expected,
                "{filter:?}"
            );
        }
        // By priority over the whole period the list walks its own index; the hint must not break filters.
        let by_prio = Filter {
            sort: Sort::Prio,
            ..all.clone()
        };
        assert_eq!(by_prio.index_hint(), " INDEXED BY cves_state_prio");
        assert_eq!(all.index_hint(), " INDEXED BY cves_cvss");
        let by_epss = Filter {
            sort: Sort::Epss,
            ..all.clone()
        };
        assert_eq!(by_epss.index_hint(), " INDEXED BY cves_epss");
        assert_eq!(list(&pool, &by_epss, 1, now).await.unwrap().rows.len(), 4);
        let page = list(&pool, &by_prio, 1, now).await.unwrap();
        assert_eq!(page.rows.len(), 4);
        assert!(page.rows.windows(2).all(|w| w[0].prio >= w[1].prio));
        for filter in [
            Filter {
                band: Some(Band::High),
                ..by_prio.clone()
            },
            Filter {
                epss: true,
                ..by_prio.clone()
            },
            Filter {
                kev: true,
                ..by_prio.clone()
            },
            Filter {
                vendor: "avm".into(),
                ..by_prio.clone()
            },
            Filter {
                rejected: true,
                ..by_prio.clone()
            },
            Filter {
                period: Period::Days(30),
                ..by_prio.clone()
            },
        ] {
            assert_eq!(filter.index_hint(), "", "{filter:?}");
        }
        assert!(exists(&pool, "CVE-2026-0002").await.unwrap());
        assert!(!exists(&pool, "CVE-2026-9999").await.unwrap());
        assert_eq!(count_published(&pool).await.unwrap(), 4);
        let d = detail(&pool, "CVE-2026-0002").await.unwrap().unwrap();
        assert_eq!(d.products[0].product_name, "FRITZ!Box");
        assert!(d.kev.is_none());
        assert!(detail(&pool, "CVE-1999-0001").await.unwrap().is_none());
    }
}
