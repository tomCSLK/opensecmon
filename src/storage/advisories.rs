//! CSAF providers, feeds and advisories: writing (by the CSAF sources) and the provider settings. The queries
//! of the advisory pages are in `storage::advisory_list`.

use std::collections::HashMap;

use sqlx::{SqliteConnection, SqlitePool};

use crate::csaf::document::Advisory;
use crate::csaf::{Distribution, Listed};
use crate::error::Result;
use crate::sources::name_key;

/// One row of `csaf_providers`.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct Provider {
    pub id: i64,
    pub source: String,
    pub url: String,
    pub name: String,
    pub enabled: bool,
    pub since: String,
    pub skip: String,
    pub distributions: String,
    pub added_ms: i64,
    pub checked_ms: Option<i64>,
    pub last_error: Option<String>,
    pub documents: i64,
}

impl Provider {
    /// The distributions of the last metadata.
    pub fn distributions(&self) -> Vec<Distribution> {
        serde_json::from_str(&self.distributions).unwrap_or_default()
    }

    /// The distribution URLs not to load.
    pub fn skip(&self) -> Vec<String> {
        serde_json::from_str(&self.skip).unwrap_or_default()
    }

    /// The first day of documents to load (Unix milliseconds), if a day is set.
    pub fn since_ms(&self) -> Option<i64> {
        (!self.since.is_empty())
            .then(|| crate::sources::parse_time_ms(&self.since))
            .flatten()
    }
}

pub async fn providers(pool: &SqlitePool, source: &str) -> Result<Vec<Provider>> {
    Ok(sqlx::query_as::<_, Provider>(
        "SELECT * FROM csaf_providers WHERE source = ? ORDER BY name COLLATE NOCASE, id",
    )
    .bind(source)
    .fetch_all(pool)
    .await?)
}

pub async fn provider(pool: &SqlitePool, id: i64) -> Result<Option<Provider>> {
    Ok(
        sqlx::query_as::<_, Provider>("SELECT * FROM csaf_providers WHERE id = ?")
            .bind(id)
            .fetch_optional(pool)
            .await?,
    )
}

pub async fn provider_by_url(pool: &SqlitePool, url: &str) -> Result<Option<Provider>> {
    Ok(
        sqlx::query_as::<_, Provider>("SELECT * FROM csaf_providers WHERE url = ?")
            .bind(url)
            .fetch_optional(pool)
            .await?,
    )
}

/// Points the BSI row at `url` (the tests use a local server) and returns it.
pub async fn bsi_provider(pool: &SqlitePool, url: &str) -> Result<Provider> {
    sqlx::query("UPDATE csaf_providers SET url = ? WHERE source = 'bsi' AND url <> ?")
        .bind(url)
        .bind(url)
        .execute(pool)
        .await?;
    Ok(
        sqlx::query_as::<_, Provider>("SELECT * FROM csaf_providers WHERE source = 'bsi'")
            .fetch_one(pool)
            .await?,
    )
}

/// What a new vendor provider starts with.
pub struct NewProvider<'a> {
    pub url: &'a str,
    pub name: &'a str,
    pub since: &'a str,
    pub skip: &'a [String],
    pub distributions: &'a [Distribution],
    pub now_ms: i64,
}

pub async fn add_provider(pool: &SqlitePool, p: &NewProvider<'_>) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "INSERT INTO csaf_providers (source, url, name, since, skip, distributions, added_ms)
         VALUES ('vendor', ?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(p.url)
    .bind(p.name)
    .bind(p.since)
    .bind(serde_json::to_string(p.skip).unwrap_or_else(|_| "[]".into()))
    .bind(serde_json::to_string(p.distributions).unwrap_or_else(|_| "[]".into()))
    .bind(p.now_ms)
    .fetch_one(pool)
    .await?)
}

/// Changes the settings of a provider. A new `since` or a distribution switched on again makes the feeds
/// load in full on the next run (their validators are forgotten).
pub async fn configure_provider(
    pool: &SqlitePool,
    id: i64,
    enabled: bool,
    since: &str,
    skip: &[String],
) -> Result<()> {
    let mut tx = pool.begin().await?;
    let before: Option<(String, String)> =
        sqlx::query_as("SELECT since, skip FROM csaf_providers WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let skip_json = serde_json::to_string(skip).unwrap_or_else(|_| "[]".into());
    sqlx::query("UPDATE csaf_providers SET enabled = ?, since = ?, skip = ? WHERE id = ?")
        .bind(enabled)
        .bind(since)
        .bind(&skip_json)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    if before.is_some_and(|(s, k)| s != since || k != skip_json) {
        sqlx::query("DELETE FROM csaf_feeds WHERE provider_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Removes a vendor provider with its advisories.
pub async fn delete_provider(pool: &SqlitePool, id: i64) -> Result<bool> {
    Ok(
        sqlx::query("DELETE FROM csaf_providers WHERE id = ? AND source = 'vendor'")
            .bind(id)
            .execute(pool)
            .await?
            .rows_affected()
            > 0,
    )
}

/// Records what the metadata said (name, distributions) or why a provider failed.
pub async fn provider_checked(
    pool: &SqlitePool,
    id: i64,
    now_ms: i64,
    name: Option<&str>,
    distributions: Option<&[Distribution]>,
    error: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "UPDATE csaf_providers SET checked_ms = ?, name = COALESCE(NULLIF(?, ''), name),
            distributions = COALESCE(?, distributions), last_error = ?,
            documents = (SELECT COUNT(*) FROM advisories WHERE provider_id = csaf_providers.id)
         WHERE id = ?",
    )
    .bind(now_ms)
    .bind(name)
    .bind(distributions.map(|d| serde_json::to_string(d).unwrap_or_else(|_| "[]".into())))
    .bind(error)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn feed_validators(
    pool: &SqlitePool,
    url: &str,
) -> Result<(Option<String>, Option<String>)> {
    Ok(
        sqlx::query_as("SELECT etag, last_modified FROM csaf_feeds WHERE url = ?")
            .bind(url)
            .fetch_optional(pool)
            .await?
            .unwrap_or((None, None)),
    )
}

pub async fn save_feed(
    pool: &SqlitePool,
    url: &str,
    provider_id: i64,
    etag: Option<&str>,
    last_modified: Option<&str>,
    now_ms: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO csaf_feeds (url, provider_id, etag, last_modified, checked_ms) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (url) DO UPDATE SET provider_id = excluded.provider_id, etag = excluded.etag,
            last_modified = excluded.last_modified, checked_ms = excluded.checked_ms",
    )
    .bind(url)
    .bind(provider_id)
    .bind(etag)
    .bind(last_modified)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

/// The documents of a provider already handled: URL → `updated` of the feed (stored or skipped).
pub async fn known(pool: &SqlitePool, provider_id: i64) -> Result<HashMap<String, String>> {
    let mut known: HashMap<String, String> = sqlx::query_as::<_, (String, String)>(
        "SELECT url, updated FROM csaf_skipped WHERE provider_id = ?",
    )
    .bind(provider_id)
    .fetch_all(pool)
    .await?
    .into_iter()
    .collect();
    known.extend(
        sqlx::query_as::<_, (String, String)>(
            "SELECT url, feed_updated FROM advisories WHERE provider_id = ?",
        )
        .bind(provider_id)
        .fetch_all(pool)
        .await?,
    );
    Ok(known)
}

/// Remembers a document that was fetched but refused, so it is not fetched again until it changes.
pub async fn skip(
    conn: &mut SqliteConnection,
    provider_id: i64,
    url: &str,
    updated: &str,
    reason: &str,
    now_ms: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO csaf_skipped (url, provider_id, updated, reason, checked_ms) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (url) DO UPDATE SET provider_id = excluded.provider_id, updated = excluded.updated,
            reason = excluded.reason, checked_ms = excluded.checked_ms",
    )
    .bind(url)
    .bind(provider_id)
    .bind(updated)
    .bind(crate::sources::cve5::clip(reason, 300))
    .bind(now_ms)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Where a stored document came from.
pub struct Origin<'a> {
    pub provider_id: i64,
    pub source: &'a str,
    pub url: &'a str,
    pub feed_updated: &'a str,
    pub hash_checked: bool,
    pub now_ms: i64,
}

/// Stores a document (new or a new version); returns true when it is new.
pub async fn store(conn: &mut SqliteConnection, o: &Origin<'_>, a: &Advisory) -> Result<bool> {
    let existing: Option<i64> = sqlx::query_scalar("SELECT seq FROM advisories WHERE url = ?")
        .bind(o.url)
        .fetch_optional(&mut *conn)
        .await?;
    let notes = serde_json::to_string(&a.notes).unwrap_or_else(|_| "[]".into());
    let refs = serde_json::to_string(&a.refs).unwrap_or_else(|_| "[]".into());
    let products = a.products_text();
    let seq: i64 = sqlx::query_scalar(
        "INSERT INTO advisories (provider_id, source, url, feed_updated, tracking_id, display_id, publisher,
             title, summary, products, lang, tlp, severity, severity_text, cvss_score, status, version,
             published_ms, updated_ms, web_url, hash_checked, cve_count, product_count, notes, refs, fetched_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (url) DO UPDATE SET provider_id = excluded.provider_id, source = excluded.source,
             feed_updated = excluded.feed_updated, tracking_id = excluded.tracking_id,
             display_id = excluded.display_id, publisher = excluded.publisher, title = excluded.title,
             summary = excluded.summary, products = excluded.products, lang = excluded.lang, tlp = excluded.tlp,
             severity = excluded.severity, severity_text = excluded.severity_text,
             cvss_score = excluded.cvss_score, status = excluded.status, version = excluded.version,
             published_ms = excluded.published_ms, updated_ms = excluded.updated_ms,
             web_url = excluded.web_url, hash_checked = excluded.hash_checked,
             cve_count = excluded.cve_count, product_count = excluded.product_count,
             notes = excluded.notes, refs = excluded.refs, fetched_ms = excluded.fetched_ms
         RETURNING seq",
    )
    .bind(o.provider_id)
    .bind(o.source)
    .bind(o.url)
    .bind(o.feed_updated)
    .bind(&a.tracking_id)
    .bind(&a.display_id)
    .bind(&a.publisher)
    .bind(&a.title)
    .bind(&a.summary)
    .bind(&products)
    .bind(&a.lang)
    .bind(&a.tlp)
    .bind(a.severity)
    .bind(&a.severity_text)
    .bind(a.cvss_score)
    .bind(&a.status)
    .bind(&a.version)
    .bind(a.published_ms)
    .bind(a.updated_ms)
    .bind(&a.web_url)
    .bind(o.hash_checked)
    .bind(i64::try_from(a.cves.len()).unwrap_or(i64::MAX))
    .bind(i64::try_from(a.products.len() + a.products_cut).unwrap_or(i64::MAX))
    .bind(&notes)
    .bind(&refs)
    .bind(o.now_ms)
    .fetch_one(&mut *conn)
    .await?;

    sqlx::query("DELETE FROM advisory_cves WHERE advisory_seq = ?")
        .bind(seq)
        .execute(&mut *conn)
        .await?;
    for cve in &a.cves {
        sqlx::query("INSERT OR IGNORE INTO advisory_cves (advisory_seq, cve_id) VALUES (?, ?)")
            .bind(seq)
            .bind(cve)
            .execute(&mut *conn)
            .await?;
    }
    sqlx::query("DELETE FROM advisory_products WHERE advisory_seq = ?")
        .bind(seq)
        .execute(&mut *conn)
        .await?;
    for p in &a.products {
        sqlx::query(
            "INSERT OR IGNORE INTO advisory_products (advisory_seq, product_id, vendor, product, vendor_name,
                 product_name, name, version, version_range, cpe, purl, status)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(seq)
        .bind(&p.id)
        .bind(name_key(&p.vendor_name))
        .bind(name_key(&p.product_name))
        .bind(&p.vendor_name)
        .bind(&p.product_name)
        .bind(&p.name)
        .bind(&p.version)
        .bind(p.version_range)
        .bind(&p.cpe)
        .bind(&p.purl)
        .bind(p.status)
        .execute(&mut *conn)
        .await?;
    }
    sqlx::query("DELETE FROM csaf_skipped WHERE url = ?")
        .bind(o.url)
        .execute(&mut *conn)
        .await?;
    Ok(existing.is_none())
}

/// How many advisories a source has.
pub async fn count(pool: &SqlitePool, source: &str) -> Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT COUNT(*) FROM advisories WHERE source = ?")
            .bind(source)
            .fetch_one(pool)
            .await?,
    )
}

/// The newest `updated` day of a source's advisories (`YYYY-MM-DD`).
pub async fn newest_day(pool: &SqlitePool, source: &str) -> Result<Option<String>> {
    let ms: Option<i64> =
        sqlx::query_scalar("SELECT MAX(updated_ms) FROM advisories WHERE source = ?")
            .bind(source)
            .fetch_one(pool)
            .await?;
    Ok(ms
        .and_then(|ms| jiff::Timestamp::from_millisecond(ms).ok())
        .map(|ts| ts.to_zoned(jiff::tz::TimeZone::UTC).date().to_string()))
}

/// Replaces the cached provider list of the BSI.
pub async fn replace_lister(pool: &SqlitePool, listed: &[Listed], now_ms: i64) -> Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM csaf_lister")
        .execute(&mut *tx)
        .await?;
    for l in listed {
        sqlx::query(
            "INSERT OR IGNORE INTO csaf_lister (url, name, role, loaded_ms) VALUES (?, ?, ?, ?)",
        )
        .bind(&l.url)
        .bind(&l.name)
        .bind(&l.role)
        .bind(now_ms)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// The cached provider list and when it was loaded.
pub async fn lister(pool: &SqlitePool) -> Result<(Vec<Listed>, Option<i64>)> {
    let rows: Vec<(String, String, String, i64)> = sqlx::query_as(
        "SELECT url, name, role, loaded_ms FROM csaf_lister ORDER BY name COLLATE NOCASE",
    )
    .fetch_all(pool)
    .await?;
    let loaded = rows.iter().map(|r| r.3).max();
    Ok((
        rows.into_iter()
            .map(|(url, name, role, _)| Listed { url, name, role })
            .collect(),
        loaded,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csaf::DistKind;
    use crate::csaf::document::{parse, tests::BSI_DOC};

    async fn pool() -> (SqlitePool, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pool = crate::storage::connect(&dir.path().join("a.db"))
            .await
            .unwrap();
        crate::storage::migrate(&pool).await.unwrap();
        (pool, dir)
    }

    #[tokio::test]
    async fn documents_are_stored_replaced_and_skipped() {
        let (pool, _dir) = pool().await;
        let bsi = bsi_provider(&pool, "https://bsi.example/pm.json")
            .await
            .unwrap();
        assert_eq!(bsi.url, "https://bsi.example/pm.json");
        let mut a = parse(BSI_DOC.as_bytes()).unwrap();
        let origin = Origin {
            provider_id: bsi.id,
            source: "bsi",
            url: "https://bsi.example/white/2026/a.json",
            feed_updated: "2026-11-05T23:00:00Z",
            hash_checked: true,
            now_ms: 1,
        };
        let mut conn = pool.acquire().await.unwrap();
        assert!(store(&mut conn, &origin, &a).await.unwrap());
        a.cves.push("CVE-2026-9999".into());
        a.products.truncate(1);
        assert!(!store(&mut conn, &origin, &a).await.unwrap());
        let cves: Vec<String> =
            sqlx::query_scalar("SELECT cve_id FROM advisory_cves ORDER BY cve_id")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(cves, ["CVE-2026-123158", "CVE-2026-9999"]);
        let products: Vec<(String, String, String)> =
            sqlx::query_as("SELECT vendor, product, status FROM advisory_products")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(
            products,
            [(
                "opensource".into(),
                "opensourcealpinelinux".into(),
                "affected".into()
            )]
        );
        let hits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM advisories_fts WHERE advisories_fts MATCH 'openssh'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(hits, 1);

        skip(
            &mut conn,
            bsi.id,
            "https://bsi.example/white/2026/b.json",
            "u1",
            "TLP:GREEN",
            2,
        )
        .await
        .unwrap();
        let known = known(&pool, bsi.id).await.unwrap();
        assert_eq!(known.len(), 2);
        assert_eq!(known["https://bsi.example/white/2026/b.json"], "u1");
        assert_eq!(count(&pool, "bsi").await.unwrap(), 1);
        assert_eq!(
            newest_day(&pool, "bsi").await.unwrap().as_deref(),
            Some("2026-11-05")
        );
    }

    #[tokio::test]
    async fn vendor_providers_are_added_configured_and_removed() {
        let (pool, _dir) = pool().await;
        let dists = [Distribution {
            kind: DistKind::Directory,
            url: "https://v.example/csaf".into(),
            tlp: String::new(),
            summary: String::new(),
        }];
        let id = add_provider(
            &pool,
            &NewProvider {
                url: "https://v.example/pm.json",
                name: "Vendor",
                since: "2025-01-01",
                skip: &[],
                distributions: &dists,
                now_ms: 5,
            },
        )
        .await
        .unwrap();
        let p = provider(&pool, id).await.unwrap().unwrap();
        assert_eq!(p.distributions(), dists);
        assert_eq!(p.since_ms(), crate::sources::parse_time_ms("2025-01-01"));
        save_feed(
            &pool,
            "https://v.example/csaf/changes.csv",
            id,
            Some("\"e\""),
            None,
            6,
        )
        .await
        .unwrap();
        configure_provider(&pool, id, true, "2025-01-01", &[])
            .await
            .unwrap();
        assert_eq!(
            feed_validators(&pool, "https://v.example/csaf/changes.csv")
                .await
                .unwrap()
                .0
                .as_deref(),
            Some("\"e\""),
            "unchanged settings keep the validators"
        );
        configure_provider(
            &pool,
            id,
            false,
            "2024-01-01",
            &["https://v.example/csaf".into()],
        )
        .await
        .unwrap();
        let p = provider(&pool, id).await.unwrap().unwrap();
        assert!(!p.enabled);
        assert_eq!(p.skip(), ["https://v.example/csaf"]);
        assert_eq!(
            feed_validators(&pool, "https://v.example/csaf/changes.csv")
                .await
                .unwrap(),
            (None, None)
        );
        provider_checked(&pool, id, 9, Some("Vendor Inc."), None, Some("boom"))
            .await
            .unwrap();
        let p = provider(&pool, id).await.unwrap().unwrap();
        assert_eq!(
            (p.name.as_str(), p.last_error.as_deref()),
            ("Vendor Inc.", Some("boom"))
        );
        assert!(delete_provider(&pool, id).await.unwrap());
        let bsi = bsi_provider(&pool, "https://x.example/pm.json")
            .await
            .unwrap();
        assert!(!delete_provider(&pool, bsi.id).await.unwrap(), "BSI stays");

        let listed = vec![Listed {
            url: "https://a.example/pm.json".into(),
            name: "A".into(),
            role: "csaf_provider".into(),
        }];
        replace_lister(&pool, &listed, 7).await.unwrap();
        assert_eq!(lister(&pool).await.unwrap(), (listed, Some(7)));
    }
}
