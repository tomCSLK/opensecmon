//! CVE records and what the sources add to them: writing (by the sources) and the derived columns.
//! The queries of the pages are in `storage::cve_list`.

use sqlx::{Sqlite, SqliteConnection, SqlitePool, Transaction};

use crate::error::Result;
use crate::sources::cve5::{Cve, CveState, Metric, Product};

/// The priority of a CVE without an own match (see PLAN.md, "Priorität"): CVSS × weight + EPSS percentile ×
/// weight (at most 100), a CVE in CISA KEV at least its floor; 0 to 100. The weights come from `prio_settings`
/// (`storage::prio`, defaults 7, 20 and 90); the subqueries are not correlated, so SQLite reads them once per
/// statement. The confidence of a match takes off from it (`Weights::match_prio`).
pub const PRIO_SQL: &str = "CAST(round(max(min(100, \
     COALESCE(cvss_score, 0) * (SELECT cvss_weight FROM prio_settings WHERE id = 1) \
     + COALESCE(epss_percentile, 0) * (SELECT epss_weight FROM prio_settings WHERE id = 1)), \
     CASE WHEN kev_added IS NOT NULL THEN (SELECT kev_floor FROM prio_settings WHERE id = 1) ELSE 0 END)) \
     AS INTEGER)";

/// The main CVSS score of a CVE: CVSS 3.x before 4.0 before 2.0 (the priority formula is calibrated on 3.x,
/// and 3.x is what most providers give), and within a version the CNA (the vendor or coordinator who
/// assigned the CVE) before the NVD before an ADP such as CISA.
const MAIN_METRIC: &str =
    "SELECT score, version, vector, provider || ':' || source FROM cve_metrics m
     WHERE m.cve_id = cves.id
     ORDER BY CASE WHEN version IN ('3.1', '3.0') THEN 0 WHEN version = '4.0' THEN 1 ELSE 2 END,
              CASE provider WHEN 'cna' THEN 0 WHEN 'nvd' THEN 1 ELSE 2 END, version DESC
     LIMIT 1";

/// Recomputes the main CVSS score and the priority of one CVE.
pub async fn refresh_derived(conn: &mut SqliteConnection, cve_id: &str) -> Result<()> {
    sqlx::query(&format!(
        "UPDATE cves SET (cvss_score, cvss_version, cvss_vector, cvss_source) = ({MAIN_METRIC})
         WHERE id = ?1"
    ))
    .bind(cve_id)
    .execute(&mut *conn)
    .await?;
    // A CVE without any metric keeps NULLs from the subquery above (no row → NULL for all four).
    sqlx::query(&format!("UPDATE cves SET prio = {PRIO_SQL} WHERE id = ?1"))
        .bind(cve_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Rows per statement of [`in_batches`].
const BATCH_ROWS: i64 = 10_000;

/// Runs an UPDATE over all CVEs in slices of their `seq` (`sql` takes the bounds as `?1 < seq <= ?2`).
/// One statement over all 400,000 rows held the write lock for up to half a minute, longer than the
/// web requests wait for it (sign-in, sessions); a slice takes well under a second.
pub async fn in_batches(pool: &SqlitePool, sql: &str) -> Result<u64> {
    let max: Option<i64> = sqlx::query_scalar("SELECT MAX(seq) FROM cves")
        .fetch_one(pool)
        .await?;
    let mut done = 0;
    let mut start = 0;
    while start < max.unwrap_or(0) {
        done += sqlx::query(sql)
            .bind(start)
            .bind(start + BATCH_ROWS)
            .execute(pool)
            .await?
            .rows_affected();
        start += BATCH_ROWS;
    }
    Ok(done)
}

/// Recomputes the priority wherever it is out of date (after EPSS changed many rows).
pub async fn refresh_all_prios(pool: &SqlitePool) -> Result<u64> {
    in_batches(
        pool,
        &format!(
            "UPDATE cves SET prio = {PRIO_SQL} WHERE seq > ?1 AND seq <= ?2 AND prio IS NOT {PRIO_SQL}"
        ),
    )
    .await
}

/// Recomputes the priority of the CVEs in CISA KEV (through the partial index on `kev_added`).
pub async fn refresh_kev_prios(conn: &mut SqliteConnection) -> Result<u64> {
    let done = sqlx::query(&format!(
        "UPDATE cves SET prio = {PRIO_SQL} WHERE kev_added IS NOT NULL AND prio IS NOT {PRIO_SQL}"
    ))
    .execute(&mut *conn)
    .await?;
    Ok(done.rows_affected())
}

/// What happened to a record that was offered to [`upsert`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Upserted {
    New,
    Changed,
    Unchanged,
}

/// Stores a cvelistV5 record with its metrics and products. A record whose `dateUpdated` we already have
/// is skipped (the hourly deltas repeat everything since midnight).
pub async fn upsert(tx: &mut Transaction<'_, Sqlite>, cve: &Cve) -> Result<Upserted> {
    let known: Option<String> = sqlx::query_scalar("SELECT record_updated FROM cves WHERE id = ?")
        .bind(&cve.id)
        .fetch_optional(&mut **tx)
        .await?;
    if known.as_deref() == Some(cve.record_updated.as_str()) {
        return Ok(Upserted::Unchanged);
    }
    let state = match cve.state {
        CveState::Published => "published",
        CveState::Rejected => "rejected",
    };
    let products_text = product_text(&cve.products);
    let (refs, refs_z) = crate::storage::packed::pack(&cve.refs_json);
    let (affected, affected_z) = crate::storage::packed::pack(&cve.affected_json);
    sqlx::query(
        "INSERT INTO cves (id, state, assigner, title, description, products, published_ms, updated_ms,
                           record_updated, cwes, refs, affected, refs_z, affected_z, epss, epss_percentile,
                           kev_added)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                 (SELECT score FROM epss WHERE cve_id = ?1),
                 (SELECT percentile FROM epss WHERE cve_id = ?1),
                 (SELECT date_added FROM kev WHERE cve_id = ?1))
         ON CONFLICT (id) DO UPDATE SET
            state = excluded.state, assigner = excluded.assigner, title = excluded.title,
            description = excluded.description, products = excluded.products,
            published_ms = excluded.published_ms, updated_ms = excluded.updated_ms,
            record_updated = excluded.record_updated, cwes = excluded.cwes, refs = excluded.refs,
            affected = excluded.affected, refs_z = excluded.refs_z, affected_z = excluded.affected_z",
    )
    .bind(&cve.id)
    .bind(state)
    .bind(&cve.assigner)
    .bind(&cve.title)
    .bind(&cve.description)
    .bind(&products_text)
    .bind(cve.published_ms)
    .bind(cve.updated_ms)
    .bind(&cve.record_updated)
    .bind(cve.cwes.join(","))
    .bind(refs)
    .bind(affected)
    .bind(refs_z)
    .bind(affected_z)
    .execute(&mut **tx)
    .await?;
    replace_metrics(tx, &cve.id, &["cna", "adp"], &cve.metrics).await?;
    replace_products(tx, &cve.id, "cna", &cve.products).await?;
    refresh_derived(tx, &cve.id).await?;
    Ok(if known.is_some() {
        Upserted::Changed
    } else {
        Upserted::New
    })
}

/// Product names for the full-text index: "Vendor Product" pairs, each once.
fn product_text(products: &[Product]) -> String {
    let mut seen = std::collections::BTreeSet::new();
    for p in products {
        seen.insert(format!("{} {}", p.vendor_name, p.product_name));
    }
    seen.into_iter().collect::<Vec<_>>().join("; ")
}

/// Replaces the metrics of the given providers.
pub async fn replace_metrics(
    conn: &mut SqliteConnection,
    cve_id: &str,
    providers: &[&str],
    metrics: &[Metric],
) -> Result<()> {
    for provider in providers {
        sqlx::query("DELETE FROM cve_metrics WHERE cve_id = ? AND provider = ?")
            .bind(cve_id)
            .bind(provider)
            .execute(&mut *conn)
            .await?;
    }
    for m in metrics {
        sqlx::query(
            "INSERT OR IGNORE INTO cve_metrics (cve_id, provider, source, version, score, vector, severity)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(cve_id)
        .bind(m.provider)
        .bind(&m.source)
        .bind(&m.version)
        .bind(m.score)
        .bind(&m.vector)
        .bind(&m.severity)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

/// Replaces the products of one origin (`cna`, `nvd`).
pub async fn replace_products(
    conn: &mut SqliteConnection,
    cve_id: &str,
    origin: &str,
    products: &[Product],
) -> Result<()> {
    sqlx::query("DELETE FROM cve_products WHERE cve_id = ? AND origin = ?")
        .bind(cve_id)
        .bind(origin)
        .execute(&mut *conn)
        .await?;
    for p in products {
        sqlx::query(
            "INSERT OR IGNORE INTO cve_products (cve_id, origin, vendor, product, vendor_name, product_name)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(cve_id)
        .bind(origin)
        .bind(&p.vendor)
        .bind(&p.product)
        .bind(&p.vendor_name)
        .bind(&p.product_name)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

/// Number of CVE records (published and rejected).
pub async fn count(pool: &SqlitePool) -> Result<i64> {
    Ok(sqlx::query_scalar("SELECT COUNT(*) FROM cves")
        .fetch_one(pool)
        .await?)
}
