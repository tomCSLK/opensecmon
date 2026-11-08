//! SQLite storage: connection pool (WAL mode) and migrations.

pub mod advisories;
pub mod advisory_list;
pub mod agents;
pub mod alerts;
pub mod assets;
pub mod audit;
pub mod cve_list;
pub mod cves;
pub mod distros;
pub mod inventory;
pub mod items;
pub mod mail;
pub mod matches;
pub mod packed;
pub mod prio;
pub mod retention;
pub mod sources;
pub mod users;

use std::path::Path;
use std::time::Duration;

use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};

use crate::error::Result;

/// Opens (and creates, if missing) the database in WAL mode.
pub async fn connect(path: &Path) -> Result<SqlitePool> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        tokio::fs::create_dir_all(parent).await?;
    }
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5))
        // The first import of the sources writes gigabytes through the WAL; without a limit the file keeps
        // its largest size after the checkpoint.
        .pragma("journal_size_limit", "67108864");
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?;
    Ok(pool)
}

/// Applies all pending migrations from `migrations/` (embedded at compile time).
pub async fn migrate(pool: &SqlitePool) -> Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

/// Writes a consistent copy of the database to `target` (SQLite `VACUUM INTO`); safe while the server runs.
/// The file is created with mode 0600 and an existing non-empty file is never overwritten.
/// It contains the encrypted secrets (SMTP password, later SSH key) but not the key file, which is backed up separately.
pub async fn backup_to(pool: &SqlitePool, target: &Path) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let target = std::path::absolute(target)?;
    let text = target.to_str().ok_or_else(|| {
        crate::error::Error::invalid(crate::i18n::Msg::new("backup-path-not-utf8"))
    })?;
    // SQLite accepts a missing or an empty target; create it ourselves so the mode is right from the start.
    let mut created = false;
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&target)
    {
        Ok(_) => created = true,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Only an empty regular file (not a link, not a device like /dev/null).
            let meta = std::fs::symlink_metadata(&target)?;
            if !meta.is_file() || meta.len() > 0 {
                return Err(crate::error::Error::invalid(
                    crate::i18n::Msg::new("backup-exists")
                        .with("path", target.display().to_string()),
                ));
            }
        }
        Err(e) => return Err(e.into()),
    }
    let done = sqlx::query("VACUUM INTO ?").bind(text).execute(pool).await;
    if done.is_err() && created {
        let _ = std::fs::remove_file(&target); // do not leave a half-made backup behind
    }
    done?;
    Ok(())
}

/// Cheap liveness check for the health endpoint.
pub async fn ping(pool: &SqlitePool) -> Result<()> {
    sqlx::query("SELECT 1").execute(pool).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn backup_is_a_consistent_private_copy_and_never_overwrites() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let pool = connect(&dir.path().join("live.db")).await.unwrap();
        migrate(&pool).await.unwrap();
        sqlx::query("INSERT INTO meta (key, value) VALUES ('k1', 'Keller')")
            .execute(&pool)
            .await
            .unwrap();

        // Links and devices are never written to (nor removed after a failure).
        let empty = dir.path().join("empty");
        std::fs::write(&empty, b"").unwrap();
        let link = dir.path().join("link.db");
        std::os::unix::fs::symlink(&empty, &link).unwrap();
        for target in [link.as_path(), Path::new("/dev/null")] {
            let err = backup_to(&pool, target).await.unwrap_err();
            assert!(matches!(err, crate::error::Error::Invalid(_)), "{err:?}");
        }
        assert!(link.exists() && Path::new("/dev/null").exists());

        let target = dir.path().join("backup.db");
        backup_to(&pool, &target).await.unwrap();
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let copy = connect(&target).await.unwrap();
        let names: Vec<String> = sqlx::query_scalar("SELECT value FROM meta WHERE key = 'k1'")
            .fetch_all(&copy)
            .await
            .unwrap();
        assert_eq!(names, ["Keller"]);
        copy.close().await;

        // A second run must not touch the first backup.
        sqlx::query("INSERT INTO meta (key, value) VALUES ('k2', 'Büro')")
            .execute(&pool)
            .await
            .unwrap();
        let err = backup_to(&pool, &target).await.unwrap_err();
        assert!(matches!(err, crate::error::Error::Invalid(_)), "{err:?}");
        let copy = connect(&target).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta WHERE key LIKE 'k%'")
            .fetch_one(&copy)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn a_failed_backup_leaves_no_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let pool = connect(&dir.path().join("live.db")).await.unwrap();
        let missing_dir = dir.path().join("nope").join("backup.db");
        assert!(backup_to(&pool, &missing_dir).await.is_err());
        assert!(!missing_dir.exists());
    }

    #[tokio::test]
    async fn connect_enables_wal_and_migrations_apply() {
        let dir = tempfile::tempdir().unwrap();
        let pool = connect(&dir.path().join("nested").join("test.db"))
            .await
            .unwrap();
        migrate(&pool).await.unwrap();
        // Running again must be a no-op.
        migrate(&pool).await.unwrap();

        let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(mode, "wal");

        let fk: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(fk, 1);

        let created: String = sqlx::query_scalar("SELECT value FROM meta WHERE key = 'created_at'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(created.ends_with('Z'));
        ping(&pool).await.unwrap();
    }
}
