//! The distributions: OSV records of Debian and Ubuntu (`osv_records`, `osv_cves`, `osv_affected`) and the
//! open issues of the Debian Security Tracker (`debian_tracker`). Written by the sources, read by the CVE
//! detail (and later by the matching of installed packages).

use std::collections::{HashMap, HashSet};

use sqlx::{SqliteConnection, SqlitePool};

use crate::error::Result;
use crate::sources::osv::Record;
use crate::storage::cves::Upserted;

/// Ids per DELETE statement.
const DELETE_CHUNK: usize = 500;

/// Stores an OSV record with its CVEs and affected packages. A record whose `modified` we already have is
/// left alone.
pub async fn upsert(conn: &mut SqliteConnection, r: &Record, now_ms: i64) -> Result<Upserted> {
    let existing: Option<(i64, String)> =
        sqlx::query_as("SELECT seq, modified FROM osv_records WHERE id = ?")
            .bind(&r.id)
            .fetch_optional(&mut *conn)
            .await?;
    let (seq, outcome) = match existing {
        Some((_, modified)) if modified == r.modified => return Ok(Upserted::Unchanged),
        Some((seq, _)) => {
            sqlx::query(
                "UPDATE osv_records SET source = ?, kind = ?, summary = ?, details = ?, priority = ?,
                     url = ?, published_ms = ?, modified = ?, modified_ms = ?, withdrawn_ms = ?,
                     fetched_ms = ?
                 WHERE seq = ?",
            )
            .bind(r.distro.as_str())
            .bind(r.kind.as_str())
            .bind(&r.summary)
            .bind(&r.details)
            .bind(&r.priority)
            .bind(&r.url)
            .bind(r.published_ms)
            .bind(&r.modified)
            .bind(r.modified_ms)
            .bind(r.withdrawn_ms)
            .bind(now_ms)
            .bind(seq)
            .execute(&mut *conn)
            .await?;
            delete_children(conn, seq).await?;
            (seq, Upserted::Changed)
        }
        None => {
            let seq = sqlx::query(
                "INSERT INTO osv_records (id, source, kind, summary, details, priority, url,
                     published_ms, modified, modified_ms, withdrawn_ms, fetched_ms)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&r.id)
            .bind(r.distro.as_str())
            .bind(r.kind.as_str())
            .bind(&r.summary)
            .bind(&r.details)
            .bind(&r.priority)
            .bind(&r.url)
            .bind(r.published_ms)
            .bind(&r.modified)
            .bind(r.modified_ms)
            .bind(r.withdrawn_ms)
            .bind(now_ms)
            .execute(&mut *conn)
            .await?
            .last_insert_rowid();
            (seq, Upserted::New)
        }
    };
    for cve in &r.cves {
        sqlx::query("INSERT OR IGNORE INTO osv_cves (cve_id, record_seq) VALUES (?, ?)")
            .bind(cve)
            .bind(seq)
            .execute(&mut *conn)
            .await?;
    }
    for a in &r.affected {
        sqlx::query(
            "INSERT INTO osv_affected (record_seq, ecosystem, release, package, introduced, fixed,
                 last_affected, urgency)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(seq)
        .bind(&a.ecosystem)
        .bind(&a.release)
        .bind(&a.package)
        .bind(&a.introduced)
        .bind(&a.fixed)
        .bind(&a.last_affected)
        .bind(&a.urgency)
        .execute(&mut *conn)
        .await?;
    }
    Ok(outcome)
}

async fn delete_children(conn: &mut SqliteConnection, seq: i64) -> Result<()> {
    sqlx::query("DELETE FROM osv_affected WHERE record_seq = ?")
        .bind(seq)
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM osv_cves WHERE record_seq = ?")
        .bind(seq)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// The ids of all records of `source` ('debian', 'ubuntu').
pub async fn ids(pool: &SqlitePool, source: &str) -> Result<HashSet<String>> {
    let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM osv_records WHERE source = ?")
        .bind(source)
        .fetch_all(pool)
        .await?;
    Ok(ids.into_iter().collect())
}

/// Removes records with their rows; returns how many.
pub async fn delete(pool: &SqlitePool, ids: &[String]) -> Result<u64> {
    let mut removed = 0;
    for chunk in ids.chunks(DELETE_CHUNK) {
        let marks = vec!["?"; chunk.len()].join(",");
        let mut tx = pool.begin().await?;
        let seqs: Vec<i64> = {
            let sql = format!("SELECT seq FROM osv_records WHERE id IN ({marks})");
            let mut q = sqlx::query_scalar(&sql);
            for id in chunk {
                q = q.bind(id);
            }
            q.fetch_all(&mut *tx).await?
        };
        for seq in seqs {
            delete_children(&mut tx, seq).await?;
            sqlx::query("DELETE FROM osv_records WHERE seq = ?")
                .bind(seq)
                .execute(&mut *tx)
                .await?;
            removed += 1;
        }
        tx.commit().await?;
    }
    Ok(removed)
}

/// The number of records of `source`.
pub async fn count(pool: &SqlitePool, source: &str) -> Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT COUNT(*) FROM osv_records WHERE source = ?")
            .bind(source)
            .fetch_one(pool)
            .await?,
    )
}

/// One row of the Debian Security Tracker that OSV does not give.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct TrackerRow {
    pub cve_id: String,
    pub package: String,
    pub release: String,
    pub status: String,
    pub urgency: String,
    pub nodsa: String,
    pub nodsa_reason: String,
    pub fixed_version: String,
}

/// What [`replace_tracker`] changed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Replaced {
    pub new: i64,
    pub changed: i64,
    pub removed: i64,
}

/// Replaces the tracker rows by `rows`, writing only the differences.
pub async fn replace_tracker(pool: &SqlitePool, rows: Vec<TrackerRow>) -> Result<Replaced> {
    let old: Vec<TrackerRow> = sqlx::query_as("SELECT * FROM debian_tracker")
        .fetch_all(pool)
        .await?;
    let mut old: HashMap<(String, String, String), TrackerRow> = old
        .into_iter()
        .map(|r| ((r.cve_id.clone(), r.package.clone(), r.release.clone()), r))
        .collect();
    let mut out = Replaced::default();
    let mut tx = pool.begin().await?;
    for row in rows {
        let key = (row.cve_id.clone(), row.package.clone(), row.release.clone());
        match old.remove(&key) {
            Some(same) if same == row => continue,
            Some(_) => out.changed += 1,
            None => out.new += 1,
        }
        sqlx::query(
            "INSERT OR REPLACE INTO debian_tracker (cve_id, package, release, status, urgency, nodsa,
                 nodsa_reason, fixed_version)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&row.cve_id)
        .bind(&row.package)
        .bind(&row.release)
        .bind(&row.status)
        .bind(&row.urgency)
        .bind(&row.nodsa)
        .bind(&row.nodsa_reason)
        .bind(&row.fixed_version)
        .execute(&mut *tx)
        .await?;
    }
    for (cve, package, release) in old.into_keys() {
        sqlx::query("DELETE FROM debian_tracker WHERE cve_id = ? AND package = ? AND release = ?")
            .bind(cve)
            .bind(package)
            .bind(release)
            .execute(&mut *tx)
            .await?;
        out.removed += 1;
    }
    tx.commit().await?;
    Ok(out)
}

/// The number of tracker rows.
pub async fn tracker_count(pool: &SqlitePool) -> Result<i64> {
    Ok(sqlx::query_scalar("SELECT COUNT(*) FROM debian_tracker")
        .fetch_one(pool)
        .await?)
}

/// One affected range of a record about a CVE, for the CVE detail.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct AffectedForCve {
    pub id: String,
    pub source: String,
    pub kind: String,
    pub priority: String,
    pub url: String,
    pub withdrawn: bool,
    pub ecosystem: String,
    pub release: String,
    pub package: String,
    pub introduced: String,
    pub fixed: String,
    pub last_affected: String,
    pub urgency: String,
}

/// All affected ranges of the records about `cve_id`.
pub async fn affected_for_cve(pool: &SqlitePool, cve_id: &str) -> Result<Vec<AffectedForCve>> {
    Ok(sqlx::query_as(
        "SELECT r.id, r.source, r.kind, r.priority, r.url, r.withdrawn_ms IS NOT NULL AS withdrawn,
                a.ecosystem, a.release, a.package, a.introduced, a.fixed, a.last_affected, a.urgency
         FROM osv_cves c
         JOIN osv_records r ON r.seq = c.record_seq
         JOIN osv_affected a ON a.record_seq = r.seq
         WHERE c.cve_id = ?
         ORDER BY r.source, r.kind DESC, r.id",
    )
    .bind(cve_id)
    .fetch_all(pool)
    .await?)
}

/// The tracker rows of `cve_id`.
pub async fn tracker_for_cve(pool: &SqlitePool, cve_id: &str) -> Result<Vec<TrackerRow>> {
    Ok(
        sqlx::query_as("SELECT * FROM debian_tracker WHERE cve_id = ? ORDER BY package, release")
            .bind(cve_id)
            .fetch_all(pool)
            .await?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(cve: &str, release: &str, status: &str) -> TrackerRow {
        TrackerRow {
            cve_id: cve.to_owned(),
            package: "openssl".to_owned(),
            release: release.to_owned(),
            status: status.to_owned(),
            urgency: "low".to_owned(),
            nodsa: String::new(),
            nodsa_reason: String::new(),
            fixed_version: String::new(),
        }
    }

    #[tokio::test]
    async fn the_tracker_is_replaced_by_its_differences() {
        let dir = tempfile::tempdir().unwrap();
        let pool = crate::storage::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        crate::storage::migrate(&pool).await.unwrap();
        let first = vec![
            row("CVE-2026-1", "trixie", "open"),
            row("CVE-2026-2", "trixie", "open"),
        ];
        let r = replace_tracker(&pool, first).await.unwrap();
        assert_eq!(
            r,
            Replaced {
                new: 2,
                changed: 0,
                removed: 0
            }
        );
        let second = vec![
            row("CVE-2026-1", "trixie", "open"),
            row("CVE-2026-2", "trixie", "undetermined"),
            row("CVE-2026-3", "bookworm", "open"),
        ];
        let r = replace_tracker(&pool, second).await.unwrap();
        assert_eq!(
            r,
            Replaced {
                new: 1,
                changed: 1,
                removed: 0
            }
        );
        let r = replace_tracker(&pool, vec![row("CVE-2026-3", "bookworm", "open")])
            .await
            .unwrap();
        assert_eq!(
            r,
            Replaced {
                new: 0,
                changed: 0,
                removed: 2
            }
        );
        assert_eq!(tracker_count(&pool).await.unwrap(), 1);
        assert_eq!(tracker_for_cve(&pool, "CVE-2026-3").await.unwrap().len(), 1);
    }
}
