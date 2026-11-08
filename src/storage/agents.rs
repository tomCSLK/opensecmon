//! The computers of the agent API: created on the page, enrolled with a one-time code, then known by the hash
//! of their token. Codes and tokens are stored as SHA-256 hashes; the code is kept encrypted as well, so the
//! page can show it again while it is valid.

use sqlx::SqlitePool;

use crate::agent;
use crate::auth::token_hash;
use crate::crypto::SecretBox;
use crate::error::Result;
use crate::inventory::listing::Listing;
use crate::storage::inventory::{self, PackageSync};

const CODE_CONTEXT: &str = "agent.code";

/// How often a computer is asked to report (the same as the SSH hosts are read).
pub const REPORT_INTERVAL_SECS: i64 = crate::storage::inventory::INTERVAL_SECS;

/// A computer of the agent API.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct AgentDevice {
    pub id: i64,
    pub name: String,
    pub token_hash: String,
    pub code_hash: String,
    pub code_secret: Option<Vec<u8>>,
    pub code_expires_ms: Option<i64>,
    pub revoked: bool,
    pub hostname: String,
    pub agent_name: String,
    pub agent_version: String,
    pub os_name: String,
    pub distro: String,
    pub release: String,
    pub packages: i64,
    pub report_hash: String,
    pub enrolled_ms: Option<i64>,
    pub last_seen_ms: Option<i64>,
    pub last_report_ms: Option<i64>,
    pub last_error: String,
    pub created_ms: i64,
    pub pro_mode: String,
    pub pro_detected: bool,
    /// The running kernel and the highest installed one, from the last report (see migration 0019).
    pub kernel: String,
    pub kernel_installed: String,
    pub reboot_required: bool,
    /// The architecture the computer reports (`os.arch`, see migration 0021).
    pub arch: String,
    /// Its agent can install updates offered by opensecmon (`agent.updates`).
    pub can_update: bool,
    /// The version of opensecagent the user asked for ('' none), when, and when it was first offered.
    pub update_version: String,
    pub update_requested_ms: Option<i64>,
    pub update_sent_ms: Option<i64>,
    /// Why the agent could not install the update ('' none).
    pub update_error: String,
}

impl AgentDevice {
    pub fn pro_mode(&self) -> inventory::ProMode {
        inventory::ProMode::parse(&self.pro_mode).unwrap_or_default()
    }

    /// The reference of the assets this computer reports.
    pub fn origin_ref(&self) -> String {
        format!("agent:{}", self.id)
    }

    /// The computer holds a valid token.
    pub fn enrolled(&self) -> bool {
        !self.token_hash.is_empty()
    }

    /// The computer runs Windows (by its agent or its last report).
    pub fn windows(&self) -> bool {
        self.agent_name.ends_with(".ps1") || self.os_name.starts_with("Windows")
    }

    /// A one-time code is waiting to be used.
    pub fn code_valid(&self, now_ms: i64) -> bool {
        !self.code_hash.is_empty() && self.code_expires_ms.is_some_and(|e| e > now_ms)
    }
}

/// What a computer says about itself at the enrollment (already checked for length).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnrollInfo {
    pub hostname: String,
    pub agent_name: String,
    pub agent_version: String,
}

pub async fn devices(pool: &SqlitePool) -> Result<Vec<AgentDevice>> {
    Ok(
        sqlx::query_as("SELECT * FROM agent_devices ORDER BY name COLLATE NOCASE")
            .fetch_all(pool)
            .await?,
    )
}

pub async fn device(pool: &SqlitePool, id: i64) -> Result<Option<AgentDevice>> {
    Ok(sqlx::query_as("SELECT * FROM agent_devices WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await?)
}

/// Whether a host read over SSH or a computer (other than `except`) already has this name: both are hosts of
/// the assets, and two sources under one name would mix their packages.
pub async fn name_taken(
    pool: &SqlitePool,
    name: &str,
    except_ssh: Option<i64>,
    except_agent: Option<i64>,
) -> Result<bool> {
    let n: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM ssh_hosts WHERE name = ?1 AND id != ?2)
              + (SELECT COUNT(*) FROM agent_devices WHERE name = ?1 AND id != ?3)",
    )
    .bind(name)
    .bind(except_ssh.unwrap_or(-1))
    .bind(except_agent.unwrap_or(-1))
    .fetch_one(pool)
    .await?;
    Ok(n > 0)
}

/// Stores a new computer (the name is checked already); `None` if the name is taken.
pub async fn add(pool: &SqlitePool, name: &str, now_ms: i64) -> Result<Option<i64>> {
    if name_taken(pool, name, None, None).await? {
        return Ok(None);
    }
    let r = sqlx::query(
        "INSERT INTO agent_devices (name, created_ms) VALUES (?, ?) ON CONFLICT (name) DO NOTHING",
    )
    .bind(name)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok((r.rows_affected() > 0).then(|| r.last_insert_rowid()))
}

/// Gives a computer another name; its assets follow. False if the name is taken.
pub async fn rename(pool: &SqlitePool, d: &AgentDevice, name: &str) -> Result<bool> {
    if name_taken(pool, name, None, Some(d.id)).await? {
        return Ok(false);
    }
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE agent_devices SET name = ? WHERE id = ?")
        .bind(name)
        .bind(d.id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE assets SET host = ? WHERE origin_ref = ?")
        .bind(name)
        .bind(d.origin_ref())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

/// Makes a new one-time code for a computer (the previous one is no longer valid) and returns it as shown.
pub async fn new_code(
    pool: &SqlitePool,
    secrets: &SecretBox,
    id: i64,
    now_ms: i64,
) -> Result<String> {
    // 40 random bits: a code that another computer holds right now is next to impossible, but the unique
    // index would refuse it, so try again.
    let mut last_error = None;
    for _ in 0..3 {
        let code = agent::new_code();
        let plain = agent::normalize_code(&code).unwrap_or_default();
        let secret = secrets.encrypt(&code, CODE_CONTEXT)?;
        match sqlx::query(
            "UPDATE agent_devices SET code_hash = ?, code_secret = ?, code_expires_ms = ? WHERE id = ?",
        )
        .bind(token_hash(&plain))
        .bind(secret)
        .bind(now_ms + agent::CODE_VALID_MS)
        .bind(id)
        .execute(pool)
        .await
        {
            Ok(_) => return Ok(code),
            Err(e) if is_unique_violation(&e) => last_error = Some(e),
            Err(e) => return Err(e.into()),
        }
    }
    Err(last_error.map_or_else(
        || crate::error::Error::Internal("no free one-time code".to_owned()),
        Into::into,
    ))
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(d) if d.is_unique_violation())
}

/// The code of a computer as shown, while it is valid.
pub fn shown_code(secrets: &SecretBox, d: &AgentDevice, now_ms: i64) -> Option<String> {
    if !d.code_valid(now_ms) {
        return None;
    }
    secrets
        .decrypt(d.code_secret.as_deref()?, CODE_CONTEXT)
        .ok()
}

/// Uses a one-time code (`plain`: as from [`agent::normalize_code`]): the computer gets the token with the hash
/// `new_token_hash` (an earlier token stops working), is no longer revoked, and the code is gone. `None` if no
/// computer has this code or it has expired. A code can be used once, even by requests at the same time.
pub async fn enroll(
    pool: &SqlitePool,
    plain: &str,
    new_token_hash: &str,
    info: &EnrollInfo,
    now_ms: i64,
) -> Result<Option<AgentDevice>> {
    let code_hash = token_hash(plain);
    let r = sqlx::query_as(
        "UPDATE agent_devices
            SET token_hash = ?, code_hash = '', code_secret = NULL, code_expires_ms = NULL, revoked = 0,
                hostname = ?, agent_name = ?, agent_version = ?, enrolled_ms = ?, last_seen_ms = ?
          WHERE code_hash = ? AND code_expires_ms > ?
         RETURNING *",
    )
    .bind(new_token_hash)
    .bind(&info.hostname)
    .bind(&info.agent_name)
    .bind(&info.agent_version)
    .bind(now_ms)
    .bind(now_ms)
    .bind(&code_hash)
    .bind(now_ms)
    .fetch_optional(pool)
    .await?;
    Ok(r)
}

/// The computer that holds this token (not revoked).
pub async fn by_token(pool: &SqlitePool, token: &str) -> Result<Option<AgentDevice>> {
    Ok(sqlx::query_as(
        "SELECT * FROM agent_devices WHERE token_hash = ? AND token_hash != '' AND revoked = 0",
    )
    .bind(token_hash(token))
    .fetch_optional(pool)
    .await?)
}

/// Notes that the computer was in touch.
pub async fn touch(pool: &SqlitePool, id: i64, now_ms: i64) -> Result<()> {
    sqlx::query("UPDATE agent_devices SET last_seen_ms = ? WHERE id = ?")
        .bind(now_ms)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// What a full report says beside its packages; `None` keeps what is stored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReportInfo {
    /// SHA-256 (hex) of the body after decompression, for the short form.
    pub hash: String,
    pub hostname: Option<String>,
    pub agent_name: Option<String>,
    pub agent_version: Option<String>,
    /// `os.arch`, `agent.updates` and `agent.update_error` of a JSON report.
    pub arch: Option<String>,
    pub can_update: Option<bool>,
    pub update_error: Option<String>,
}

/// After a full report: a requested update ends when the agent reports that version, or with the error it
/// reports (then it is no longer offered until the user asks again).
async fn settle_update(tx: &mut sqlx::SqliteConnection, id: i64, info: &ReportInfo) -> Result<()> {
    sqlx::query(
        "UPDATE agent_devices SET arch = COALESCE(?, arch), can_update = COALESCE(?, can_update) WHERE id = ?",
    )
    .bind(&info.arch)
    .bind(info.can_update)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    // Done when the agent reports this version or a higher one (opensecmon may bring a newer package meanwhile).
    let (wanted, running): (String, String) =
        sqlx::query_as("SELECT update_version, agent_version FROM agent_devices WHERE id = ?")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    if !wanted.is_empty()
        && crate::version::is_version(crate::version::Scheme::Generic, &running)
        && crate::version::compare(crate::version::Scheme::Generic, &running, &wanted).is_ge()
    {
        sqlx::query(
            "UPDATE agent_devices
                SET update_version = '', update_requested_ms = NULL, update_sent_ms = NULL, update_error = ''
              WHERE id = ?",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
        return Ok(());
    }
    if let Some(error) = info.update_error.as_deref().filter(|e| !e.is_empty()) {
        sqlx::query(
            "UPDATE agent_devices
                SET update_error = ?, update_version = '', update_requested_ms = NULL, update_sent_ms = NULL
              WHERE id = ? AND update_version != ''",
        )
        .bind(error)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    }
    Ok(())
}

/// Asks for an update of the computer's agent to `version` (an earlier error is forgotten).
pub async fn request_update(pool: &SqlitePool, id: i64, version: &str, now_ms: i64) -> Result<()> {
    sqlx::query(
        "UPDATE agent_devices
            SET update_version = ?, update_requested_ms = ?, update_sent_ms = NULL, update_error = ''
          WHERE id = ?",
    )
    .bind(version)
    .bind(now_ms)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Takes a request for an update back (and forgets an error).
pub async fn cancel_update(pool: &SqlitePool, id: i64) -> Result<()> {
    sqlx::query(
        "UPDATE agent_devices
            SET update_version = '', update_requested_ms = NULL, update_sent_ms = NULL, update_error = ''
          WHERE id = ?",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Notes when the update was first offered to the agent.
pub async fn update_offered(pool: &SqlitePool, id: i64, now_ms: i64) -> Result<()> {
    sqlx::query(
        "UPDATE agent_devices SET update_sent_ms = ? WHERE id = ? AND update_sent_ms IS NULL AND update_version != ''",
    )
    .bind(now_ms)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Stores a full report: the packages as the computer's assets (as for a host read over SSH), its system, and
/// as entries the snaps and Flatpaks of the listing and the `items` of the report (assets by the rules).
/// `None` if the token was revoked or the computer removed in the meantime (nothing is stored then).
pub async fn store_report(
    pool: &SqlitePool,
    d: &AgentDevice,
    listing: &Listing,
    entries: &[crate::inventory::items::Item],
    info: &ReportInfo,
    now_ms: i64,
) -> Result<Option<PackageSync>> {
    let Some(distro) = listing.distro else {
        return Ok(Some(PackageSync::default()));
    };
    let mut tx = pool.begin().await?;
    let r = sqlx::query(
        "UPDATE agent_devices
            SET os_name = ?, distro = ?, release = ?, packages = ?, report_hash = ?, last_report_ms = ?,
                last_seen_ms = ?, last_error = '', hostname = COALESCE(?, hostname),
                agent_name = COALESCE(?, agent_name), agent_version = COALESCE(?, agent_version),
                pro_detected = ?, kernel = ?, kernel_installed = ?, reboot_required = ?
          WHERE id = ? AND token_hash = ? AND token_hash != '' AND revoked = 0",
    )
    .bind(&listing.os_name)
    .bind(distro.as_str())
    .bind(&listing.release)
    .bind(listing.sources.len() as i64)
    .bind(&info.hash)
    .bind(now_ms)
    .bind(now_ms)
    .bind(&info.hostname)
    .bind(&info.agent_name)
    .bind(&info.agent_version)
    .bind(listing.pro)
    .bind(&listing.kernel)
    .bind(&listing.kernel_installed)
    .bind(listing.reboot)
    .bind(d.id)
    .bind(&d.token_hash)
    .execute(&mut *tx)
    .await?;
    if r.rows_affected() == 0 {
        return Ok(None);
    }
    settle_update(&mut tx, d.id, info).await?;
    let pro = d.pro_mode().effective(listing.pro, listing.distro);
    let mut sync = inventory::sync_packages(
        &mut tx,
        "agent",
        &d.origin_ref(),
        &d.name,
        listing,
        pro,
        now_ms,
    )
    .await?;
    let all: Vec<crate::inventory::items::Item> =
        listing.items.iter().chain(entries).cloned().collect();
    crate::storage::items::replace(&mut tx, &d.origin_ref(), &all).await?;
    let software =
        crate::storage::items::sync_origin(&mut tx, &d.origin_ref(), &d.name, now_ms).await?;
    sync.merge(software);
    tx.commit().await?;
    Ok(Some(sync))
}

/// Stores a full report of a Windows computer: its system (an entry of type `os`, always the asset of Windows) and
/// its programs as entries, which become assets by the rules. Packages of an earlier Linux on the computer go.
/// `None` if the token was revoked or the computer removed in the meantime (nothing is stored then).
pub async fn store_windows(
    pool: &SqlitePool,
    d: &AgentDevice,
    system: &crate::inventory::windows::WindowsSystem,
    entries: &[crate::inventory::items::Item],
    info: &ReportInfo,
    now_ms: i64,
) -> Result<Option<PackageSync>> {
    let mut tx = pool.begin().await?;
    let r = sqlx::query(
        "UPDATE agent_devices
            SET os_name = ?, distro = '', release = ?, packages = 1, report_hash = ?, last_report_ms = ?,
                last_seen_ms = ?, last_error = '', hostname = COALESCE(?, hostname),
                agent_name = COALESCE(?, agent_name), agent_version = COALESCE(?, agent_version),
                pro_detected = 0, kernel = '', kernel_installed = '', reboot_required = 0
          WHERE id = ? AND token_hash = ? AND token_hash != '' AND revoked = 0",
    )
    .bind(&system.os_name)
    .bind(&system.release)
    .bind(&info.hash)
    .bind(now_ms)
    .bind(now_ms)
    .bind(&info.hostname)
    .bind(&info.agent_name)
    .bind(&info.agent_version)
    .bind(d.id)
    .bind(&d.token_hash)
    .execute(&mut *tx)
    .await?;
    if r.rows_affected() == 0 {
        return Ok(None);
    }
    settle_update(&mut tx, d.id, info).await?;
    let removed = sqlx::query("DELETE FROM assets WHERE origin_ref = ? AND kind = 'package'")
        .bind(d.origin_ref())
        .execute(&mut *tx)
        .await?
        .rows_affected();
    let mut list = Vec::with_capacity(entries.len() + 1);
    list.push(crate::inventory::items::Item::os(system));
    list.extend(entries.iter().cloned());
    crate::storage::items::replace(&mut tx, &d.origin_ref(), &list).await?;
    let mut sync =
        crate::storage::items::sync_origin(&mut tx, &d.origin_ref(), &d.name, now_ms).await?;
    sync.removed += removed as usize;
    sqlx::query("UPDATE agent_devices SET packages = (SELECT COUNT(*) FROM assets WHERE origin_ref = ?) WHERE id = ?")
        .bind(d.origin_ref())
        .bind(d.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Some(sync))
}

/// Notes a report that equals the last one (full or short form).
pub async fn note_unchanged(pool: &SqlitePool, id: i64, now_ms: i64) -> Result<()> {
    sqlx::query(
        "UPDATE agent_devices SET last_report_ms = ?, last_seen_ms = ?, last_error = '' WHERE id = ?",
    )
    .bind(now_ms)
    .bind(now_ms)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Notes a report that could not be used (the id of the text, a tab and a detail, as for the SSH hosts).
pub async fn record_error(pool: &SqlitePool, id: i64, text: &str, now_ms: i64) -> Result<()> {
    sqlx::query("UPDATE agent_devices SET last_error = ?, last_seen_ms = ? WHERE id = ?")
        .bind(text)
        .bind(now_ms)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Revokes the token and any open code at once; the assets stay.
pub async fn revoke(pool: &SqlitePool, id: i64) -> Result<()> {
    sqlx::query(
        "UPDATE agent_devices SET token_hash = '', revoked = 1, code_hash = '', code_secret = NULL,
             code_expires_ms = NULL
         WHERE id = ?",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Removes a computer with the assets it reported (and their matches).
pub async fn delete(pool: &SqlitePool, id: i64) -> Result<Option<AgentDevice>> {
    let Some(d) = device(pool, id).await? else {
        return Ok(None);
    };
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM assets WHERE origin_ref = ?")
        .bind(d.origin_ref())
        .execute(&mut *tx)
        .await?;
    crate::storage::items::delete_all(&mut tx, &d.origin_ref()).await?;
    sqlx::query("DELETE FROM agent_devices WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Some(d))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage;
    use crate::storage::inventory::{self, HostInput};

    async fn pool() -> (SqlitePool, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pool = storage::connect(&dir.path().join("t.db")).await.unwrap();
        storage::migrate(&pool).await.unwrap();
        (pool, dir)
    }

    fn info(hostname: &str) -> EnrollInfo {
        EnrollInfo {
            hostname: hostname.to_owned(),
            agent_name: "curl-script".to_owned(),
            agent_version: "1".to_owned(),
        }
    }

    #[tokio::test]
    async fn a_code_enrolls_a_computer_once_and_its_token_finds_it() {
        let (pool, _dir) = pool().await;
        let secrets = SecretBox::from_key([3u8; 32]);
        let id = add(&pool, "laptop", 1_000).await.unwrap().unwrap();
        let d = device(&pool, id).await.unwrap().unwrap();
        assert!(!d.enrolled() && !d.code_valid(1_000));

        let code = new_code(&pool, &secrets, id, 1_000).await.unwrap();
        let d = device(&pool, id).await.unwrap().unwrap();
        assert!(d.code_valid(1_000));
        assert_ne!(d.code_hash, code, "only the hash");
        assert_eq!(
            shown_code(&secrets, &d, 2_000).as_deref(),
            Some(code.as_str())
        );
        assert_eq!(shown_code(&secrets, &d, 1_000 + agent::CODE_VALID_MS), None);

        let plain = agent::normalize_code(&code.to_lowercase()).unwrap();
        let token = agent::new_token();
        let got = enroll(&pool, &plain, &token_hash(&token), &info("zorin"), 5_000)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((got.id, got.hostname.as_str()), (id, "zorin"));
        assert!(got.enrolled() && !got.code_valid(5_000));
        assert_eq!(got.code_secret, None);
        assert_eq!(by_token(&pool, &token).await.unwrap().unwrap().id, id);

        // Used once: the same code again does nothing.
        let other = agent::new_token();
        assert_eq!(
            enroll(&pool, &plain, &token_hash(&other), &info("x"), 6_000)
                .await
                .unwrap(),
            None
        );
        assert!(by_token(&pool, &other).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn an_expired_or_replaced_code_does_not_enroll() {
        let (pool, _dir) = pool().await;
        let secrets = SecretBox::from_key([3u8; 32]);
        let id = add(&pool, "pc", 0).await.unwrap().unwrap();
        let old = new_code(&pool, &secrets, id, 0).await.unwrap();
        let new = new_code(&pool, &secrets, id, 10).await.unwrap();
        let plain = |c: &str| agent::normalize_code(c).unwrap();
        let t = token_hash(&agent::new_token());
        assert_eq!(
            enroll(&pool, &plain(&old), &t, &info(""), 20)
                .await
                .unwrap(),
            None
        );
        let late = 10 + agent::CODE_VALID_MS;
        assert_eq!(
            enroll(&pool, &plain(&new), &t, &info(""), late)
                .await
                .unwrap(),
            None
        );
        assert!(
            enroll(&pool, &plain(&new), &t, &info(""), late - 1)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn revoking_stops_the_token_and_a_new_code_enrolls_again() {
        let (pool, _dir) = pool().await;
        let secrets = SecretBox::from_key([3u8; 32]);
        let id = add(&pool, "pc", 0).await.unwrap().unwrap();
        let code = new_code(&pool, &secrets, id, 0).await.unwrap();
        let token = agent::new_token();
        let plain = agent::normalize_code(&code).unwrap();
        enroll(&pool, &plain, &token_hash(&token), &info(""), 1)
            .await
            .unwrap()
            .unwrap();
        // An asset reported by this computer stays when it is revoked.
        sqlx::query(
            "INSERT INTO assets (kind, vendor, product, vendor_name, product_name, version, host, origin,
                 origin_ref, created_ms, updated_ms, matched_ms)
             VALUES ('package', 'ubuntu', 'bash', 'Ubuntu', 'bash', '5.2', 'pc', 'agent', ?, 0, 0, 0)",
        )
        .bind(format!("agent:{id}"))
        .execute(&pool)
        .await
        .unwrap();

        revoke(&pool, id).await.unwrap();
        assert!(by_token(&pool, &token).await.unwrap().is_none());
        let d = device(&pool, id).await.unwrap().unwrap();
        assert!(d.revoked && !d.enrolled());

        let code = new_code(&pool, &secrets, id, 2).await.unwrap();
        let token2 = agent::new_token();
        let plain = agent::normalize_code(&code).unwrap();
        let d = enroll(&pool, &plain, &token_hash(&token2), &info(""), 3)
            .await
            .unwrap()
            .unwrap();
        assert!(!d.revoked && d.enrolled());
        assert!(
            by_token(&pool, &token).await.unwrap().is_none(),
            "the old token stays invalid"
        );
        assert!(by_token(&pool, &token2).await.unwrap().is_some());

        // Renaming moves the assets along, deleting removes them.
        assert!(rename(&pool, &d, "pc-neu").await.unwrap());
        let host: String = sqlx::query_scalar("SELECT host FROM assets")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(host, "pc-neu");
        assert!(delete(&pool, id).await.unwrap().is_some());
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM assets")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
        assert!(device(&pool, id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn computers_and_ssh_hosts_share_their_names() {
        let (pool, _dir) = pool().await;
        let host = HostInput {
            name: "server".to_owned(),
            address: "192.0.2.2".to_owned(),
            port: "22".to_owned(),
            username: "inv".to_owned(),
        }
        .check()
        .unwrap();
        inventory::add_host(&pool, &host, 0).await.unwrap().unwrap();
        assert_eq!(add(&pool, "server", 0).await.unwrap(), None);
        let id = add(&pool, "laptop", 0).await.unwrap().unwrap();
        assert_eq!(add(&pool, "laptop", 0).await.unwrap(), None);
        let laptop = device(&pool, id).await.unwrap().unwrap();
        assert!(!rename(&pool, &laptop, "server").await.unwrap());
        assert!(
            rename(&pool, &laptop, "laptop").await.unwrap(),
            "its own name"
        );

        // The other way round: an SSH host cannot take the name of a computer.
        let same = HostInput {
            name: "laptop".to_owned(),
            ..HostInput::default()
        };
        let same = inventory::CheckedHost {
            name: same.name,
            ..host.clone()
        };
        assert_eq!(inventory::add_host(&pool, &same, 0).await.unwrap(), None);
        let server = inventory::hosts(&pool).await.unwrap().remove(0);
        assert!(!inventory::update_host(&pool, &server, &same).await.unwrap());
    }
}
