//! The state of every source (`source_state`): settings, validators of the last download, last run.

use sqlx::SqlitePool;

use crate::error::Result;

/// One row of `source_state`.
#[derive(Debug, Clone, Default, PartialEq, sqlx::FromRow)]
pub struct SourceState {
    pub source: String,
    pub enabled: bool,
    pub interval_secs: i64,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub cursor: Option<String>,
    pub version: Option<String>,
    pub item_count: Option<i64>,
    pub last_started_ms: Option<i64>,
    pub last_finished_ms: Option<i64>,
    pub last_success_ms: Option<i64>,
    pub last_duration_ms: Option<i64>,
    pub last_new: Option<i64>,
    pub last_changed: Option<i64>,
    pub last_error: Option<String>,
    pub failures: i64,
    pub next_run_ms: i64,
    pub last_warning: Option<String>,
}

/// What a successful run leaves behind.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Success {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub cursor: Option<String>,
    pub version: Option<String>,
    pub item_count: Option<i64>,
    pub new: i64,
    pub changed: i64,
    /// Something to look at although the run succeeded (documents skipped …).
    pub warning: Option<String>,
}

pub async fn all(pool: &SqlitePool) -> Result<Vec<SourceState>> {
    Ok(
        sqlx::query_as::<_, SourceState>("SELECT * FROM source_state ORDER BY source")
            .fetch_all(pool)
            .await?,
    )
}

pub async fn get(pool: &SqlitePool, source: &str) -> Result<Option<SourceState>> {
    Ok(
        sqlx::query_as::<_, SourceState>("SELECT * FROM source_state WHERE source = ?")
            .bind(source)
            .fetch_optional(pool)
            .await?,
    )
}

/// Marks the start of a run.
pub async fn started(pool: &SqlitePool, source: &str, now_ms: i64) -> Result<()> {
    sqlx::query("UPDATE source_state SET last_started_ms = ? WHERE source = ?")
        .bind(now_ms)
        .bind(source)
        .execute(pool)
        .await?;
    Ok(())
}

/// Records a successful run; `None` validators keep the stored ones.
pub async fn succeeded(
    pool: &SqlitePool,
    source: &str,
    now_ms: i64,
    duration_ms: i64,
    next_run_ms: i64,
    s: &Success,
) -> Result<()> {
    sqlx::query(
        "UPDATE source_state SET
            etag = COALESCE(?, etag), last_modified = COALESCE(?, last_modified),
            cursor = COALESCE(?, cursor), version = COALESCE(?, version),
            item_count = COALESCE(?, item_count),
            last_finished_ms = ?, last_success_ms = ?, last_duration_ms = ?,
            last_new = ?, last_changed = ?, last_error = NULL, failures = 0, next_run_ms = ?,
            last_warning = ?
         WHERE source = ?",
    )
    .bind(&s.etag)
    .bind(&s.last_modified)
    .bind(&s.cursor)
    .bind(&s.version)
    .bind(s.item_count)
    .bind(now_ms)
    .bind(now_ms)
    .bind(duration_ms)
    .bind(s.new)
    .bind(s.changed)
    .bind(next_run_ms)
    .bind(&s.warning)
    .bind(source)
    .execute(pool)
    .await?;
    Ok(())
}

/// Records a failed run.
pub async fn failed(
    pool: &SqlitePool,
    source: &str,
    now_ms: i64,
    duration_ms: i64,
    next_run_ms: i64,
    error: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE source_state SET last_finished_ms = ?, last_duration_ms = ?, last_new = NULL,
            last_changed = NULL, last_error = ?, failures = failures + 1, next_run_ms = ?,
            last_warning = NULL
         WHERE source = ?",
    )
    .bind(now_ms)
    .bind(duration_ms)
    .bind(error)
    .bind(next_run_ms)
    .bind(source)
    .execute(pool)
    .await?;
    Ok(())
}

/// Saves a cursor in the middle of a long run, so an interruption does not start over.
pub async fn save_cursor(pool: &SqlitePool, source: &str, cursor: &str) -> Result<()> {
    sqlx::query("UPDATE source_state SET cursor = ? WHERE source = ?")
        .bind(cursor)
        .bind(source)
        .execute(pool)
        .await?;
    Ok(())
}

/// Switches a source on or off and sets its interval. A source switched on that has never run is due.
pub async fn configure(
    pool: &SqlitePool,
    source: &str,
    enabled: bool,
    interval_secs: i64,
) -> Result<()> {
    sqlx::query("UPDATE source_state SET enabled = ?, interval_secs = ? WHERE source = ?")
        .bind(enabled)
        .bind(interval_secs)
        .bind(source)
        .execute(pool)
        .await?;
    Ok(())
}

/// `next_run_ms` of a source someone asked to fetch now. A fresh row starts at 0 (due for a
/// scheduling instance); only this marker makes an instance without the scheduler run a source.
pub const REQUESTED: i64 = -1;

/// Makes a source due now.
pub async fn due_now(pool: &SqlitePool, source: &str) -> Result<()> {
    sqlx::query("UPDATE source_state SET next_run_ms = ? WHERE source = ?")
        .bind(REQUESTED)
        .bind(source)
        .execute(pool)
        .await?;
    Ok(())
}

/// Forgets the validators and cursor, so the next run loads everything again.
pub async fn reset(pool: &SqlitePool, source: &str) -> Result<()> {
    sqlx::query(
        "UPDATE source_state SET etag = NULL, last_modified = NULL, cursor = NULL WHERE source = ?",
    )
    .bind(source)
    .execute(pool)
    .await?;
    Ok(())
}
