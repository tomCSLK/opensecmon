//! User and session persistence. Every user is an administrator; users are managed on the command line.

use sqlx::{FromRow, SqlitePool};

use crate::error::{Error, Result};
use crate::i18n::{Lang, Msg};

#[derive(Debug, Clone)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    /// Chosen language; `None` follows the browser.
    pub language: Option<Lang>,
}

#[derive(FromRow)]
struct UserRow {
    id: i64,
    username: String,
    password_hash: String,
    language: Option<String>,
}

impl From<UserRow> for User {
    fn from(row: UserRow) -> Self {
        Self {
            id: row.id,
            username: row.username,
            password_hash: row.password_hash,
            language: row.language.as_deref().and_then(Lang::parse),
        }
    }
}

/// Columns of [`UserRow`].
const USER_COLUMNS: &str = "id, username, password_hash, language";

/// Inserts a user; usernames are unique case-insensitively.
pub async fn create_user(
    pool: &SqlitePool,
    username: &str,
    password_hash: &str,
    language: Option<Lang>,
) -> Result<i64> {
    let result =
        sqlx::query("INSERT INTO users (username, password_hash, language) VALUES (?, ?, ?)")
            .bind(username)
            .bind(password_hash)
            .bind(language.map(Lang::code))
            .execute(pool)
            .await;
    match result {
        Ok(done) => Ok(done.last_insert_rowid()),
        Err(e)
            if e.as_database_error()
                .is_some_and(|d| d.is_unique_violation()) =>
        {
            Err(Error::conflict(Msg::new("username-taken")))
        }
        Err(e) => Err(e.into()),
    }
}

pub async fn find_by_username(pool: &SqlitePool, username: &str) -> Result<Option<User>> {
    Ok(sqlx::query_as::<_, UserRow>(&format!(
        "SELECT {USER_COLUMNS} FROM users WHERE username = ?"
    ))
    .bind(username)
    .fetch_optional(pool)
    .await?
    .map(User::from))
}

pub async fn get_user(pool: &SqlitePool, id: i64) -> Result<Option<User>> {
    Ok(
        sqlx::query_as::<_, UserRow>(&format!("SELECT {USER_COLUMNS} FROM users WHERE id = ?"))
            .bind(id)
            .fetch_optional(pool)
            .await?
            .map(User::from),
    )
}

pub async fn list_users(pool: &SqlitePool) -> Result<Vec<User>> {
    Ok(sqlx::query_as::<_, UserRow>(&format!(
        "SELECT {USER_COLUMNS} FROM users ORDER BY username"
    ))
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(User::from)
    .collect())
}

pub async fn count_users(pool: &SqlitePool) -> Result<i64> {
    Ok(sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?)
}

/// Deletes a user by name (sessions go with it); returns false if the user does not exist.
pub async fn delete_user(pool: &SqlitePool, username: &str) -> Result<bool> {
    let done = sqlx::query("DELETE FROM users WHERE username = ?")
        .bind(username)
        .execute(pool)
        .await?;
    Ok(done.rows_affected() > 0)
}

/// Sets a new password hash; returns false if the user does not exist.
pub async fn set_password_hash(pool: &SqlitePool, username: &str, hash: &str) -> Result<bool> {
    let done = sqlx::query("UPDATE users SET password_hash = ? WHERE username = ?")
        .bind(hash)
        .bind(username)
        .execute(pool)
        .await?;
    Ok(done.rows_affected() > 0)
}

/// Sets a new password hash and ends the user's sessions except `keep` (the hash of the session
/// that made the change, so users changing their own password stay signed in).
pub async fn change_password(
    pool: &SqlitePool,
    id: i64,
    hash: &str,
    keep: Option<&str>,
) -> Result<()> {
    let mut tx = pool.begin().await?;
    let done = sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
        .bind(hash)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    if done.rows_affected() == 0 {
        return Err(Error::NotFound);
    }
    sqlx::query("DELETE FROM sessions WHERE user_id = ? AND id IS NOT ?")
        .bind(id)
        .bind(keep)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Sets the language of a user (`None`: follow the browser).
pub async fn set_language(pool: &SqlitePool, id: i64, language: Option<Lang>) -> Result<()> {
    let done = sqlx::query("UPDATE users SET language = ? WHERE id = ?")
        .bind(language.map(Lang::code))
        .bind(id)
        .execute(pool)
        .await?;
    if done.rows_affected() == 0 {
        return Err(Error::NotFound);
    }
    Ok(())
}

/// The user and CSRF token behind a valid session.
#[derive(Debug, Clone, FromRow)]
pub struct SessionUser {
    pub user_id: i64,
    pub username: String,
    #[sqlx(try_from = "Option<String>")]
    pub language: LangColumn,
    pub csrf_token: String,
    /// Last activity (Unix seconds).
    pub last_seen_at: i64,
}

/// A stored language choice (`NULL` or an unknown code: follow the browser).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LangColumn(pub Option<Lang>);

// sqlx's `try_from` takes the `TryFrom` that every `From` brings along.
impl From<Option<String>> for LangColumn {
    fn from(code: Option<String>) -> Self {
        Self(code.as_deref().and_then(Lang::parse))
    }
}

pub async fn create_session(
    pool: &SqlitePool,
    token_hash: &str,
    user_id: i64,
    csrf_token: &str,
    now: i64,
    expires_at: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO sessions (id, user_id, csrf_token, created_at, expires_at, last_seen_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?4)",
    )
    .bind(token_hash)
    .bind(user_id)
    .bind(csrf_token)
    .bind(now)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Looks up a session within its lifetime by the hash of its cookie token; the idle limit is up to the caller.
pub async fn find_session(
    pool: &SqlitePool,
    token_hash: &str,
    now: i64,
) -> Result<Option<SessionUser>> {
    Ok(sqlx::query_as::<_, SessionUser>(
        "SELECT u.id AS user_id, u.username, u.language, s.csrf_token, s.last_seen_at \
         FROM sessions s JOIN users u ON u.id = s.user_id \
         WHERE s.id = ? AND s.expires_at > ?",
    )
    .bind(token_hash)
    .bind(now)
    .fetch_optional(pool)
    .await?)
}

/// Records activity of a session.
pub async fn touch_session(pool: &SqlitePool, token_hash: &str, now: i64) -> Result<()> {
    sqlx::query("UPDATE sessions SET last_seen_at = ? WHERE id = ?")
        .bind(now)
        .bind(token_hash)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_session(pool: &SqlitePool, token_hash: &str) -> Result<()> {
    sqlx::query("DELETE FROM sessions WHERE id = ?")
        .bind(token_hash)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_sessions_of_user(pool: &SqlitePool, username: &str) -> Result<()> {
    sqlx::query("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE username = ?)")
        .bind(username)
        .execute(pool)
        .await?;
    Ok(())
}

/// Deletes sessions past their lifetime or, with an idle limit (`idle_secs`), unused for longer.
pub async fn purge_expired_sessions(
    pool: &SqlitePool,
    now: i64,
    idle_secs: Option<i64>,
) -> Result<()> {
    sqlx::query(
        "DELETE FROM sessions WHERE expires_at <= ?1 OR (?2 IS NOT NULL AND last_seen_at <= ?1 - ?2)",
    )
    .bind(now)
    .bind(idle_secs)
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage;

    async fn pool() -> (SqlitePool, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pool = storage::connect(&dir.path().join("u.db")).await.unwrap();
        storage::migrate(&pool).await.unwrap();
        (pool, dir)
    }

    #[tokio::test]
    async fn usernames_are_unique_case_insensitively() {
        let (pool, _dir) = pool().await;
        create_user(&pool, "Admin", "hash", None).await.unwrap();
        let err = create_user(&pool, "admin", "hash", None).await.unwrap_err();
        assert!(matches!(err, Error::Conflict(_)));
        assert_eq!(count_users(&pool).await.unwrap(), 1);
        let found = find_by_username(&pool, "ADMIN").await.unwrap().unwrap();
        assert_eq!(found.username, "Admin");
        assert_eq!(list_users(&pool).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn sessions_expire_and_cascade() {
        let (pool, _dir) = pool().await;
        let id = create_user(&pool, "anna", "hash", Some(Lang::En))
            .await
            .unwrap();
        create_session(&pool, "h1", id, "csrf", 100, 200)
            .await
            .unwrap();

        let s = find_session(&pool, "h1", 150).await.unwrap().unwrap();
        assert_eq!(s.username, "anna");
        assert_eq!(s.language, LangColumn(Some(Lang::En)));
        assert!(find_session(&pool, "h1", 200).await.unwrap().is_none());
        assert!(find_session(&pool, "other", 150).await.unwrap().is_none());

        purge_expired_sessions(&pool, 200, None).await.unwrap();
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(left, 0);

        create_session(&pool, "h2", id, "csrf", 100, 900)
            .await
            .unwrap();
        delete_sessions_of_user(&pool, "anna").await.unwrap();
        assert!(find_session(&pool, "h2", 150).await.unwrap().is_none());

        create_session(&pool, "h3", id, "csrf", 100, 900)
            .await
            .unwrap();
        assert!(delete_user(&pool, "anna").await.unwrap());
        assert!(!delete_user(&pool, "anna").await.unwrap());
        assert!(find_session(&pool, "h3", 150).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn idle_sessions_are_purged() {
        let (pool, _dir) = pool().await;
        let anna = create_user(&pool, "anna", "h", None).await.unwrap();
        create_session(&pool, "a1", anna, "c", 1000, 9000)
            .await
            .unwrap();
        create_session(&pool, "a2", anna, "c", 1000, 9000)
            .await
            .unwrap();
        touch_session(&pool, "a2", 1500).await.unwrap();
        let a2 = find_session(&pool, "a2", 1600).await.unwrap().unwrap();
        assert_eq!(a2.last_seen_at, 1500);

        // 30 minutes after 1000: a1 is idle, a2 was active later.
        let now = 1000 + 1800;
        purge_expired_sessions(&pool, now, Some(1800))
            .await
            .unwrap();
        assert!(find_session(&pool, "a1", now).await.unwrap().is_none());
        assert!(find_session(&pool, "a2", now).await.unwrap().is_some());
        // The lifetime applies without an idle limit as well.
        purge_expired_sessions(&pool, 9000, None).await.unwrap();
        assert!(find_session(&pool, "a2", 8999).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn set_password_hash_reports_missing_user() {
        let (pool, _dir) = pool().await;
        create_user(&pool, "anna", "old", None).await.unwrap();
        assert!(set_password_hash(&pool, "anna", "new").await.unwrap());
        assert!(!set_password_hash(&pool, "nobody", "new").await.unwrap());
        let u = find_by_username(&pool, "anna").await.unwrap().unwrap();
        assert_eq!(u.password_hash, "new");
    }

    #[tokio::test]
    async fn changing_a_password_ends_all_sessions_but_the_kept_one() {
        let (pool, _dir) = pool().await;
        let a = create_user(&pool, "anna", "old", None).await.unwrap();
        for token in ["s1", "s2", "s3"] {
            create_session(&pool, token, a, "c", 0, 100).await.unwrap();
        }
        change_password(&pool, a, "new", Some("s2")).await.unwrap();
        assert!(find_session(&pool, "s1", 1).await.unwrap().is_none());
        assert!(find_session(&pool, "s2", 1).await.unwrap().is_some());
        assert_eq!(
            get_user(&pool, a).await.unwrap().unwrap().password_hash,
            "new"
        );
        change_password(&pool, a, "newer", None).await.unwrap();
        assert!(find_session(&pool, "s2", 1).await.unwrap().is_none());
        assert!(matches!(
            change_password(&pool, 99, "x", None).await,
            Err(Error::NotFound)
        ));
        set_language(&pool, a, Some(Lang::En)).await.unwrap();
        assert_eq!(
            get_user(&pool, a).await.unwrap().unwrap().language,
            Some(Lang::En)
        );
    }
}
