//! Large JSON columns stored deflated (`nvd_cves.configs`, `cves.refs`, `cves.affected`): the text column holds
//! `''` and the `_z` column the deflated text; rows from before (or `'[]'`) keep the text. Readers go through
//! [`text`]; [`convert`] packs the rows of older versions in the background.

use std::io::{Read, Write};

use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use sqlx::SqlitePool;

use crate::error::Result;

/// More than any column holds (the largest NVD configuration is a few MB); guards against a broken value.
const MAX_TEXT: u64 = 64 * 1024 * 1024;
const BATCH: i64 = 2000;

/// The two columns to store for a JSON text: `('', deflated)`, or the text itself when it is (nearly) empty.
pub fn pack(text: &str) -> (&str, Option<Vec<u8>>) {
    if text.len() <= 2 {
        return (text, None);
    }
    let mut enc = DeflateEncoder::new(Vec::with_capacity(text.len() / 3), Compression::default());
    // Writing into a Vec cannot fail.
    let _ = enc.write_all(text.as_bytes());
    match enc.finish() {
        Ok(z) => ("", Some(z)),
        Err(_) => (text, None),
    }
}

/// The JSON text of a column pair; `'[]'` when the deflated value is broken.
pub fn text(plain: String, z: Option<Vec<u8>>) -> String {
    let Some(z) = z else { return plain };
    let mut out = String::new();
    match DeflateDecoder::new(z.as_slice())
        .take(MAX_TEXT)
        .read_to_string(&mut out)
    {
        Ok(_) => out,
        Err(e) => {
            tracing::warn!(error = %e, "a packed column cannot be read");
            "[]".to_owned()
        }
    }
}

/// How many rows still hold their JSON as text.
pub async fn unpacked(pool: &SqlitePool) -> Result<i64> {
    let nvd: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nvd_cves WHERE length(configs) > 2")
        .fetch_one(pool)
        .await?;
    let cves: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM cves WHERE length(refs) > 2 OR length(affected) > 2",
    )
    .fetch_one(pool)
    .await?;
    Ok(nvd + cves)
}

/// Packs the rows of older versions, in small transactions; returns how many rows changed.
pub async fn convert(pool: &SqlitePool) -> Result<u64> {
    let mut changed = 0u64;
    // nvd_cves has no rowid: walk the key.
    let mut after = String::new();
    loop {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT cve_id, configs FROM nvd_cves WHERE cve_id > ? ORDER BY cve_id LIMIT ?",
        )
        .bind(&after)
        .bind(BATCH)
        .fetch_all(pool)
        .await?;
        let Some((last, _)) = rows.last() else { break };
        after = last.clone();
        let packed = tokio::task::spawn_blocking(move || {
            rows.into_iter()
                .filter(|(_, c)| c.len() > 2)
                .filter_map(|(id, c)| pack(&c).1.map(|z| (id, z)))
                .collect::<Vec<_>>()
        })
        .await
        .map_err(|e| crate::error::Error::Internal(e.to_string()))?;
        if packed.is_empty() {
            continue;
        }
        let mut tx = pool.begin().await?;
        for (id, z) in &packed {
            sqlx::query("UPDATE nvd_cves SET configs = '', configs_z = ? WHERE cve_id = ? AND length(configs) > 2")
                .bind(z)
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        changed += packed.len() as u64;
    }
    let max: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM cves")
        .fetch_one(pool)
        .await?;
    let mut start = 0;
    while start < max {
        let rows: Vec<(i64, String, String)> = sqlx::query_as(
            "SELECT seq, refs, affected FROM cves
             WHERE seq > ? AND seq <= ? AND (length(refs) > 2 OR length(affected) > 2)",
        )
        .bind(start)
        .bind(start + BATCH)
        .fetch_all(pool)
        .await?;
        start += BATCH;
        if rows.is_empty() {
            continue;
        }
        let packed = tokio::task::spawn_blocking(move || {
            rows.into_iter()
                .map(|(seq, refs, affected)| {
                    let (r, rz) = pack(&refs);
                    let (a, az) = pack(&affected);
                    (seq, r.to_owned(), rz, a.to_owned(), az)
                })
                .collect::<Vec<_>>()
        })
        .await
        .map_err(|e| crate::error::Error::Internal(e.to_string()))?;
        let mut tx = pool.begin().await?;
        for (seq, refs, refs_z, affected, affected_z) in &packed {
            // Only columns that are still text (a newer write in between is already packed).
            sqlx::query(
                "UPDATE cves SET
                     refs_z = CASE WHEN length(refs) > 2 THEN ?2 ELSE refs_z END,
                     refs = CASE WHEN length(refs) > 2 THEN ?1 ELSE refs END,
                     affected_z = CASE WHEN length(affected) > 2 THEN ?4 ELSE affected_z END,
                     affected = CASE WHEN length(affected) > 2 THEN ?3 ELSE affected END
                 WHERE seq = ?5",
            )
            .bind(refs)
            .bind(refs_z)
            .bind(affected)
            .bind(affected_z)
            .bind(seq)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        changed += packed.len() as u64;
    }
    Ok(changed)
}

/// Starts [`convert`] in the background when rows of an older version are left (on start).
pub fn spawn_convert(pool: SqlitePool) {
    tokio::spawn(async move {
        match unpacked(&pool).await {
            Ok(0) => return,
            Ok(_) => {}
            Err(e) => {
                tracing::error!(error = %e, "counting the rows to pack failed");
                return;
            }
        }
        let started = std::time::Instant::now();
        match convert(&pool).await {
            Ok(changed) => tracing::info!(
                changed,
                secs = started.elapsed().as_secs(),
                "packed the JSON columns of older rows"
            ),
            Err(e) => tracing::error!(error = %e, "packing the JSON columns failed"),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{connect, migrate};

    #[test]
    fn packing_round_trips_and_leaves_empty_lists_alone() {
        let json =
            r#"[{"url":"https://example.org/a"},{"url":"https://example.org/b"}]"#.repeat(20);
        let (plain, z) = pack(&json);
        assert_eq!(plain, "");
        let z = z.unwrap();
        assert!(z.len() < json.len() / 5);
        assert_eq!(text(plain.to_owned(), Some(z)), json);
        assert_eq!(pack("[]"), ("[]", None));
        assert_eq!(text("[]".to_owned(), None), "[]");
        assert_eq!(text(String::new(), Some(vec![1, 2, 3])), "[]", "broken");
    }

    #[tokio::test]
    async fn older_rows_are_packed_and_read_the_same() {
        let dir = tempfile::tempdir().unwrap();
        let pool = connect(&dir.path().join("p.db")).await.unwrap();
        migrate(&pool).await.unwrap();
        sqlx::raw_sql(
            r#"WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 4500)
               INSERT INTO cves (id, state, refs, affected)
                 SELECT 'CVE-' || i, 'published', '[{"url":"https://example.org/' || i || '"}]',
                        CASE WHEN i % 2 = 0 THEN '[]' ELSE '[{"vendor":"v","product":"p' || i || '"}]' END
                 FROM n;
               WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 2500)
               INSERT INTO nvd_cves (cve_id, configs)
                 SELECT 'CVE-' || i, '[{"nodes":[{"cpeMatch":[{"criteria":"cpe:2.3:a:v:p' || i || '"}]}]}]' FROM n;"#,
        )
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(unpacked(&pool).await.unwrap(), 4500 + 2500);
        assert_eq!(convert(&pool).await.unwrap(), 4500 + 2500);
        assert_eq!(unpacked(&pool).await.unwrap(), 0);
        assert_eq!(convert(&pool).await.unwrap(), 0, "nothing left");

        let (refs, refs_z, affected, affected_z): (
            String,
            Option<Vec<u8>>,
            String,
            Option<Vec<u8>>,
        ) = sqlx::query_as(
            "SELECT refs, refs_z, affected, affected_z FROM cves WHERE id = 'CVE-4'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(text(refs, refs_z), r#"[{"url":"https://example.org/4"}]"#);
        assert_eq!((affected.as_str(), affected_z.is_none()), ("[]", true));
        let (configs, z): (String, Option<Vec<u8>>) =
            sqlx::query_as("SELECT configs, configs_z FROM nvd_cves WHERE cve_id = 'CVE-2499'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(text(configs, z).contains("cpe:2.3:a:v:p2499"));
    }
}
