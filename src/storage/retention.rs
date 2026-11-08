//! Retention and size of the database (page "Retention"): how long the audit log and closed matches stay, the
//! size of the areas (measured once a day) and "compact the database" (VACUUM in the background).

use sqlx::SqlitePool;

use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::FromRow)]
pub struct Settings {
    /// Days of the audit log; `None` = `retention_audit_days` of the configuration.
    pub audit_days: Option<i64>,
    /// Days after which done and ignored matches that are no longer found are removed; 0 keeps them.
    pub closed_days: i64,
}

pub async fn settings(pool: &SqlitePool) -> Result<Settings> {
    Ok(
        sqlx::query_as("SELECT audit_days, closed_days FROM retention_settings WHERE id = 1")
            .fetch_one(pool)
            .await?,
    )
}

pub async fn save(pool: &SqlitePool, s: &Settings) -> Result<()> {
    sqlx::query("UPDATE retention_settings SET audit_days = ?, closed_days = ? WHERE id = 1")
        .bind(s.audit_days)
        .bind(s.closed_days)
        .execute(pool)
        .await?;
    Ok(())
}

/// The size of the database file and the space inside it that is free (after deleting) until a VACUUM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileSize {
    pub total: i64,
    pub free: i64,
}

pub async fn file_size(pool: &SqlitePool) -> Result<FileSize> {
    let page_size: i64 = sqlx::query_scalar("PRAGMA page_size")
        .fetch_one(pool)
        .await?;
    let pages: i64 = sqlx::query_scalar("PRAGMA page_count")
        .fetch_one(pool)
        .await?;
    let free: i64 = sqlx::query_scalar("PRAGMA freelist_count")
        .fetch_one(pool)
        .await?;
    Ok(FileSize {
        total: pages * page_size,
        free: free * page_size,
    })
}

/// The bytes of the areas (tables with their indexes) as last measured.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, sqlx::FromRow)]
pub struct Areas {
    pub size_cves: i64,
    pub size_advisories: i64,
    pub size_distros: i64,
    pub size_own: i64,
    pub sizes_ms: Option<i64>,
}

pub async fn areas(pool: &SqlitePool) -> Result<Areas> {
    Ok(sqlx::query_as(
        "SELECT size_cves, size_advisories, size_distros, size_own, sizes_ms FROM retention_settings WHERE id = 1",
    )
    .fetch_one(pool)
    .await?)
}

/// The area of a table: the CVE list (CVE records, NVD, KEV, EPSS), CSAF advisories, distributions (OSV, Debian
/// tracker) or the own data (assets, matches, settings, audit log …).
fn area_of(table: &str) -> usize {
    if table.starts_with("cve") || table.starts_with("nvd_") || table == "kev" || table == "epss" {
        0
    } else if table.starts_with("advisor") || table.starts_with("csaf_") {
        1
    } else if table.starts_with("osv_") || table == "debian_tracker" {
        2
    } else {
        3
    }
}

/// Measures the areas with `dbstat` (reads the whole file: seconds on a full database) and stores them.
pub async fn measure(pool: &SqlitePool, now_ms: i64) -> Result<Areas> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT COALESCE(s.tbl_name, d.name), SUM(d.pgsize)
         FROM dbstat AS d LEFT JOIN sqlite_schema AS s ON s.name = d.name
         WHERE d.aggregate = TRUE
         GROUP BY 1",
    )
    .fetch_all(pool)
    .await?;
    let mut sizes = [0i64; 4];
    for (table, bytes) in rows {
        sizes[area_of(&table)] += bytes;
    }
    sqlx::query(
        "UPDATE retention_settings SET size_cves = ?, size_advisories = ?, size_distros = ?, size_own = ?,
             sizes_ms = ? WHERE id = 1",
    )
    .bind(sizes[0])
    .bind(sizes[1])
    .bind(sizes[2])
    .bind(sizes[3])
    .bind(now_ms)
    .execute(pool)
    .await?;
    areas(pool).await
}

/// Measures the areas when the last measurement is a day old (the housekeeping, every hour).
pub async fn measure_if_due(pool: &SqlitePool, now_ms: i64) -> Result<()> {
    let last = areas(pool).await?.sizes_ms;
    if last.is_none_or(|ms| now_ms - ms >= 86_400_000) {
        let started = std::time::Instant::now();
        measure(pool, now_ms).await?;
        tracing::info!(
            secs = started.elapsed().as_secs(),
            "measured the size of the database"
        );
    }
    Ok(())
}

/// The last "compact the database".
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct Vacuum {
    pub vacuum_started_ms: Option<i64>,
    pub vacuum_done_ms: Option<i64>,
    pub vacuum_error: String,
    pub vacuum_freed: i64,
}

impl Vacuum {
    pub fn running(&self) -> bool {
        self.vacuum_started_ms.is_some()
            && self
                .vacuum_done_ms
                .is_none_or(|done| Some(done) < self.vacuum_started_ms)
    }
}

pub async fn vacuum_state(pool: &SqlitePool) -> Result<Vacuum> {
    Ok(sqlx::query_as(
        "SELECT vacuum_started_ms, vacuum_done_ms, vacuum_error, vacuum_freed FROM retention_settings WHERE id = 1",
    )
    .fetch_one(pool)
    .await?)
}

/// A run cut off by a stop of the server counts as failed (on start).
pub async fn recover(pool: &SqlitePool, now_ms: i64) -> Result<()> {
    if vacuum_state(pool).await?.running() {
        sqlx::query(
            "UPDATE retention_settings SET vacuum_done_ms = ?, vacuum_error = 'interrupted', vacuum_freed = 0
             WHERE id = 1",
        )
        .bind(now_ms)
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// Marks the start of a VACUUM; false when one is already running.
pub async fn begin_vacuum(pool: &SqlitePool, now_ms: i64) -> Result<bool> {
    if vacuum_state(pool).await?.running() {
        return Ok(false);
    }
    sqlx::query(
        "UPDATE retention_settings SET vacuum_started_ms = ?, vacuum_error = '', vacuum_freed = 0 WHERE id = 1",
    )
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(true)
}

/// Rewrites the database without its free pages (`VACUUM`), then shrinks the WAL and measures the areas again;
/// only then the run counts as done.
/// Writers wait meanwhile (or fail after the busy timeout and retry with their next run).
pub async fn vacuum(pool: &SqlitePool, now_ms: impl Fn() -> i64) -> Result<i64> {
    let before = file_size(pool).await?.total;
    let outcome = async {
        sqlx::query("VACUUM").execute(pool).await?;
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(pool)
            .await?;
        // Before the run counts as done, so the page shows the new sizes with it.
        measure(pool, now_ms()).await?;
        Ok::<_, crate::error::Error>(())
    }
    .await;
    let after = file_size(pool).await?.total;
    let freed = (before - after).max(0);
    let error = match &outcome {
        Ok(()) => String::new(),
        Err(e) => e.to_string(),
    };
    sqlx::query(
        "UPDATE retention_settings SET vacuum_done_ms = ?, vacuum_error = ?, vacuum_freed = ? WHERE id = 1",
    )
    .bind(now_ms())
    .bind(&error)
    .bind(freed)
    .execute(pool)
    .await?;
    outcome?;
    Ok(freed)
}

/// Starts [`vacuum`] in the background (after [`begin_vacuum`]).
pub fn spawn_vacuum(pool: SqlitePool) {
    tokio::spawn(async move {
        let started = std::time::Instant::now();
        match vacuum(&pool, crate::sources::now_ms).await {
            Ok(freed) => tracing::info!(
                freed,
                secs = started.elapsed().as_secs(),
                "database compacted"
            ),
            Err(e) => tracing::error!(error = %e, "compacting the database failed"),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{connect, migrate};

    #[tokio::test]
    async fn the_areas_are_measured_and_a_vacuum_frees_the_deleted_pages() {
        let dir = tempfile::tempdir().unwrap();
        let pool = connect(&dir.path().join("r.db")).await.unwrap();
        migrate(&pool).await.unwrap();
        assert_eq!(
            settings(&pool).await.unwrap(),
            Settings {
                audit_days: None,
                closed_days: 365
            }
        );
        sqlx::raw_sql(
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 2000)
             INSERT INTO cves (id, state, description) SELECT 'CVE-' || i, 'published', hex(randomblob(400)) FROM n;",
        )
        .execute(&pool)
        .await
        .unwrap();
        let a = measure(&pool, 5).await.unwrap();
        assert!(a.size_cves > 1_000_000, "{a:?}");
        assert!(a.size_cves > a.size_own && a.size_own > 0);
        assert_eq!(a.sizes_ms, Some(5));

        sqlx::query("DELETE FROM cves")
            .execute(&pool)
            .await
            .unwrap();
        assert!(file_size(&pool).await.unwrap().free > 1_000_000);
        assert!(begin_vacuum(&pool, 10).await.unwrap());
        assert!(vacuum_state(&pool).await.unwrap().running());
        assert!(!begin_vacuum(&pool, 11).await.unwrap(), "one at a time");
        let freed = vacuum(&pool, || 20).await.unwrap();
        assert!(freed > 1_000_000);
        let v = vacuum_state(&pool).await.unwrap();
        assert!(!v.running());
        assert_eq!((v.vacuum_done_ms, v.vacuum_error.as_str()), (Some(20), ""));
        assert!(file_size(&pool).await.unwrap().free < 100_000);
        assert!(areas(&pool).await.unwrap().size_cves < a.size_cves);

        // A run cut off by a stop counts as failed.
        begin_vacuum(&pool, 30).await.unwrap();
        recover(&pool, 40).await.unwrap();
        let v = vacuum_state(&pool).await.unwrap();
        assert!(!v.running());
        assert_eq!(v.vacuum_error, "interrupted");
    }

    #[test]
    fn the_tables_fall_into_their_areas() {
        assert_eq!(area_of("cves_fts_data"), 0);
        assert_eq!(area_of("cve_products"), 0);
        assert_eq!(area_of("nvd_cves"), 0);
        assert_eq!(area_of("epss"), 0);
        assert_eq!(area_of("advisory_products"), 1);
        assert_eq!(area_of("csaf_feeds"), 1);
        assert_eq!(area_of("osv_affected"), 2);
        assert_eq!(area_of("debian_tracker"), 2);
        assert_eq!(area_of("matches"), 3);
        assert_eq!(area_of("sqlite_schema"), 3);
    }
}
