//! Storage of phase 6: the hosts read over SSH, the app's SSH key, the link to opennetmon and its devices,
//! and the package assets that follow a host.

use std::collections::HashMap;

use sqlx::SqlitePool;

use crate::crypto::{Secret, SecretBox};
use crate::error::Result;
use crate::inventory::listing::Listing;
use crate::inventory::ssh;
use crate::storage::assets::{Checked, Distro, Kind};

const KEY_CONTEXT: &str = "ssh.key";
const TOKEN_CONTEXT: &str = "opennetmon.token";

/// How often a host is read.
pub const INTERVAL_SECS: i64 = 6 * 3600;

/// Ubuntu Pro of a host or computer: as the reading finds it (a source version with "esm"), or set by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProMode {
    #[default]
    Auto,
    Yes,
    No,
}

impl ProMode {
    pub const ALL: [Self; 3] = [Self::Auto, Self::Yes, Self::No];

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.as_str() == s)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Yes => "yes",
            Self::No => "no",
        }
    }

    pub fn label_id(self) -> &'static str {
        match self {
            Self::Auto => "pro-mode-auto",
            Self::Yes => "pro-mode-yes",
            Self::No => "pro-mode-no",
        }
    }

    /// Whether the packages count as getting Ubuntu Pro (only Ubuntu has it).
    pub fn effective(self, detected: bool, distro: Option<Distro>) -> bool {
        distro == Some(Distro::Ubuntu)
            && match self {
                Self::Auto => detected,
                Self::Yes => true,
                Self::No => false,
            }
    }
}

/// The table of a host or computer with a setting for Ubuntu Pro.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProOwner {
    Ssh,
    Agent,
}

impl ProOwner {
    fn table(self) -> &'static str {
        match self {
            Self::Ssh => "ssh_hosts",
            Self::Agent => "agent_devices",
        }
    }

    fn origin_ref(self, id: i64) -> String {
        match self {
            Self::Ssh => format!("ssh:{id}"),
            Self::Agent => format!("agent:{id}"),
        }
    }
}

/// Sets how a host or computer gets Ubuntu Pro and makes its package assets follow at once; the ids of the
/// assets that changed (to match them again).
pub async fn set_pro_mode(
    pool: &SqlitePool,
    owner: ProOwner,
    id: i64,
    mode: ProMode,
    now_ms: i64,
) -> Result<Vec<i64>> {
    let mut tx = pool.begin().await?;
    let sql = format!(
        "UPDATE {} SET pro_mode = ? WHERE id = ? RETURNING pro_detected, distro",
        owner.table()
    );
    let Some((detected, distro)): Option<(bool, String)> = sqlx::query_as(&sql)
        .bind(mode.as_str())
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
    else {
        return Ok(Vec::new());
    };
    let pro = mode.effective(detected, Distro::parse(&distro));
    let changed: Vec<i64> = sqlx::query_scalar(
        "UPDATE assets SET pro = ?, updated_ms = ?
          WHERE origin_ref = ? AND kind = 'package' AND pro != ? RETURNING id",
    )
    .bind(pro)
    .bind(now_ms)
    .bind(owner.origin_ref(id))
    .bind(pro)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(changed)
}

/// A host whose packages are read over SSH.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct SshHost {
    pub id: i64,
    pub name: String,
    pub address: String,
    pub port: i64,
    pub username: String,
    pub host_key: String,
    pub seen_key: String,
    pub os_name: String,
    pub distro: String,
    pub release: String,
    pub packages: i64,
    pub enabled: bool,
    pub last_ms: Option<i64>,
    pub last_ok_ms: Option<i64>,
    pub last_error: String,
    pub failures: i64,
    pub created_ms: i64,
    pub pro_mode: String,
    pub pro_detected: bool,
    /// The running kernel and the highest installed one, from the last reading (see migration 0019).
    pub kernel: String,
    pub kernel_installed: String,
    pub reboot_required: bool,
}

impl SshHost {
    pub fn pro_mode(&self) -> ProMode {
        ProMode::parse(&self.pro_mode).unwrap_or_default()
    }

    /// The reference of the assets that follow this host.
    pub fn origin_ref(&self) -> String {
        format!("ssh:{}", self.id)
    }

    pub fn target(&self) -> ssh::Target {
        ssh::Target {
            address: self.address.clone(),
            port: u16::try_from(self.port).unwrap_or(22),
            username: self.username.clone(),
        }
    }

    /// When the host is to be read next (`None`: not at all: off, or the key is not confirmed).
    pub fn next_ms(&self) -> Option<i64> {
        if !self.enabled || self.host_key.is_empty() {
            return None;
        }
        let Some(last) = self.last_ms else {
            return Some(0);
        };
        // After failures the back-off of the sources; else the interval, spread over 10 minutes by host so
        // that several hosts are not read at once (fixed per host, so the shown time does not jump).
        let delay = if self.failures > 0 {
            crate::sources::next_delay_secs(INTERVAL_SECS, self.failures)
        } else {
            INTERVAL_SECS + (self.id * 137).rem_euclid(600)
        };
        Some(last + delay * 1000)
    }
}

/// The connection details of a host as entered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostInput {
    pub name: String,
    pub address: String,
    pub port: String,
    pub username: String,
}

/// Checked connection details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedHost {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub username: String,
}

impl HostInput {
    /// Checks the details; the error is the id of a text.
    pub fn check(&self) -> std::result::Result<CheckedHost, &'static str> {
        let name = self.name.trim();
        if !valid_host_name(name) {
            return Err("ssh-error-name");
        }
        let address = self.address.trim();
        if address.is_empty()
            || address.len() > 253
            || address.starts_with('-')
            || !address
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'_'))
        {
            return Err("ssh-error-address");
        }
        let port = match self.port.trim() {
            "" => 22,
            p => p
                .parse::<u16>()
                .ok()
                .filter(|p| *p > 0)
                .ok_or("ssh-error-port")?,
        };
        let username = self.username.trim();
        if username.is_empty()
            || username.len() > 32
            || !username.starts_with(|c: char| c.is_ascii_lowercase() || c == '_')
            || !username
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
        {
            return Err("ssh-error-username");
        }
        Ok(CheckedHost {
            name: name.to_owned(),
            address: address.to_owned(),
            port,
            username: username.to_owned(),
        })
    }
}

/// The rule for the name of a host (SSH host or computer of the agent API): letters, digits, `.`, `-` and `_`,
/// at most 100 characters.
pub fn valid_host_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().count() <= 100
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

pub async fn hosts(pool: &SqlitePool) -> Result<Vec<SshHost>> {
    Ok(
        sqlx::query_as("SELECT * FROM ssh_hosts ORDER BY name COLLATE NOCASE")
            .fetch_all(pool)
            .await?,
    )
}

pub async fn host(pool: &SqlitePool, id: i64) -> Result<Option<SshHost>> {
    Ok(sqlx::query_as("SELECT * FROM ssh_hosts WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await?)
}

/// Stores a new host; `None` if the name is taken (by a host or a computer of the agent API).
pub async fn add_host(pool: &SqlitePool, h: &CheckedHost, now_ms: i64) -> Result<Option<i64>> {
    if crate::storage::agents::name_taken(pool, &h.name, None, None).await? {
        return Ok(None);
    }
    let r = sqlx::query(
        "INSERT INTO ssh_hosts (name, address, port, username, created_ms) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (name) DO NOTHING",
    )
    .bind(&h.name)
    .bind(&h.address)
    .bind(i64::from(h.port))
    .bind(&h.username)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok((r.rows_affected() > 0).then(|| r.last_insert_rowid()))
}

/// Changes the connection details; false if the name is taken by another host or a computer. A new address
/// or port forgets the confirmed host key (it belongs to the old machine). The packages follow the new name.
pub async fn update_host(pool: &SqlitePool, old: &SshHost, h: &CheckedHost) -> Result<bool> {
    if crate::storage::agents::name_taken(pool, &h.name, Some(old.id), None).await? {
        return Ok(false);
    }
    let moved = old.address != h.address || old.port != i64::from(h.port);
    let mut tx = pool.begin().await?;
    sqlx::query(
        "UPDATE ssh_hosts SET name = ?, address = ?, port = ?, username = ?,
             host_key = CASE WHEN ? THEN '' ELSE host_key END,
             seen_key = CASE WHEN ? THEN '' ELSE seen_key END
         WHERE id = ?",
    )
    .bind(&h.name)
    .bind(&h.address)
    .bind(i64::from(h.port))
    .bind(&h.username)
    .bind(moved)
    .bind(moved)
    .bind(old.id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE assets SET host = ? WHERE origin_ref = ?")
        .bind(&h.name)
        .bind(old.origin_ref())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

/// Removes a host with its packages (and their matches).
pub async fn delete_host(pool: &SqlitePool, id: i64) -> Result<Option<SshHost>> {
    let Some(h) = host(pool, id).await? else {
        return Ok(None);
    };
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM assets WHERE origin_ref = ?")
        .bind(h.origin_ref())
        .execute(&mut *tx)
        .await?;
    crate::storage::items::delete_all(&mut tx, &h.origin_ref()).await?;
    sqlx::query("DELETE FROM ssh_hosts WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Some(h))
}

pub async fn set_enabled(pool: &SqlitePool, id: i64, enabled: bool) -> Result<()> {
    sqlx::query("UPDATE ssh_hosts SET enabled = ? WHERE id = ?")
        .bind(enabled)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Remembers the key the host presented (not trusted until confirmed).
pub async fn set_seen_key(pool: &SqlitePool, id: i64, key: &str) -> Result<()> {
    sqlx::query("UPDATE ssh_hosts SET seen_key = ? WHERE id = ?")
        .bind(key)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Trusts the key the host presented; false if it is not the expected one any more.
pub async fn confirm_key(pool: &SqlitePool, id: i64, seen_key: &str) -> Result<bool> {
    let r = sqlx::query(
        "UPDATE ssh_hosts SET host_key = seen_key, failures = 0, last_error = ''
         WHERE id = ? AND seen_key = ? AND seen_key != ''",
    )
    .bind(id)
    .bind(seen_key)
    .execute(pool)
    .await?;
    Ok(r.rows_affected() > 0)
}

/// Notes a failed reading (`text` for the list of hosts).
pub async fn record_error(pool: &SqlitePool, id: i64, text: &str, now_ms: i64) -> Result<()> {
    sqlx::query(
        "UPDATE ssh_hosts SET last_ms = ?, last_error = ?, failures = failures + 1 WHERE id = ?",
    )
    .bind(now_ms)
    .bind(text.chars().take(500).collect::<String>())
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// What a reading changed in the assets of a host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackageSync {
    /// New or changed assets, to be matched.
    pub changed: Vec<i64>,
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
}

impl PackageSync {
    /// Adds what another sync of the same source changed.
    pub fn merge(&mut self, other: Self) {
        self.changed.extend(other.changed);
        self.added += other.added;
        self.updated += other.updated;
        self.removed += other.removed;
    }
}

/// Stores a successful reading: the host's system and its packages as assets (new ones added,
/// changed versions updated, removed packages deleted with their matches), its snaps and Flatpaks as entries
/// that become assets by the rules (`storage::items`).
pub async fn apply_listing(
    pool: &SqlitePool,
    h: &SshHost,
    listing: &Listing,
    now_ms: i64,
) -> Result<PackageSync> {
    let Some(distro) = listing.distro else {
        return Ok(PackageSync::default());
    };
    // Writes from the start: it reads first, and the matching of another host may write in between.
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    let pro = h.pro_mode().effective(listing.pro, listing.distro);
    let mut sync = sync_packages(
        &mut tx,
        "ssh",
        &h.origin_ref(),
        &h.name,
        listing,
        pro,
        now_ms,
    )
    .await?;
    crate::storage::items::replace(&mut tx, &h.origin_ref(), &listing.items).await?;
    sync.merge(
        crate::storage::items::sync_origin(&mut tx, &h.origin_ref(), &h.name, now_ms).await?,
    );
    sqlx::query(
        "UPDATE ssh_hosts SET os_name = ?, distro = ?, release = ?, packages = ?, last_ms = ?,
             last_ok_ms = ?, last_error = '', failures = 0, pro_detected = ?, kernel = ?,
             kernel_installed = ?, reboot_required = ?
         WHERE id = ?",
    )
    .bind(&listing.os_name)
    .bind(distro.as_str())
    .bind(&listing.release)
    .bind(listing.sources.len() as i64)
    .bind(now_ms)
    .bind(now_ms)
    .bind(listing.pro)
    .bind(&listing.kernel)
    .bind(&listing.kernel_installed)
    .bind(listing.reboot)
    .bind(h.id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(sync)
}

/// Makes the package assets of one source (`origin` 'ssh' or 'agent', `origin_ref` the host or computer) match a
/// listing: new packages added, changed versions updated, packages no longer listed deleted with their matches.
/// Other assets of the source (the software a computer reports beside its packages) stay.
/// `pro` is the effective Ubuntu Pro of the host (its setting, see [`ProMode`]), not what the listing detected.
/// Nothing happens for a listing without a distribution.
#[allow(clippy::too_many_arguments)]
pub async fn sync_packages(
    tx: &mut sqlx::SqliteConnection,
    origin: &str,
    origin_ref: &str,
    host: &str,
    listing: &Listing,
    pro: bool,
    now_ms: i64,
) -> Result<PackageSync> {
    let Some(distro) = listing.distro else {
        return Ok(PackageSync::default());
    };
    let existing: Vec<(i64, String, String, String, String, bool)> = sqlx::query_as(
        "SELECT id, product, version, distro, release, pro FROM assets WHERE origin_ref = ? AND kind = 'package'",
    )
    .bind(origin_ref)
    .fetch_all(&mut *tx)
    .await?;
    let mut known: HashMap<String, (i64, String, String, String, bool)> = existing
        .into_iter()
        .map(|(id, p, v, d, r, pro)| (p, (id, v, d, r, pro)))
        .collect();
    let mut sync = PackageSync::default();
    for (package, version) in &listing.sources {
        let checked = Checked {
            kind: Kind::Package,
            vendor: distro.as_str().to_owned(),
            product: package.clone(),
            vendor_name: distro.name().to_owned(),
            product_name: package.clone(),
            version: version.clone(),
            host: host.to_owned(),
            cpe: String::new(),
            distro: distro.as_str().to_owned(),
            release: listing.release.clone(),
            pro,
            note: String::new(),
        };
        match known.remove(package) {
            Some((id, v, d, r, had_pro)) => {
                if v != *version || d != distro.as_str() || r != listing.release || had_pro != pro {
                    crate::storage::assets::update(&mut *tx, id, &checked, now_ms).await?;
                    sync.changed.push(id);
                    sync.updated += 1;
                }
            }
            None => {
                let id = crate::storage::assets::add_from(
                    &mut *tx, &checked, origin, origin_ref, now_ms,
                )
                .await?;
                let min_prio = crate::storage::assets::default_min_prio(Kind::Package, package);
                if min_prio > 0 {
                    crate::storage::assets::set_min_prio(&mut *tx, id, min_prio).await?;
                }
                sync.changed.push(id);
                sync.added += 1;
            }
        }
    }
    for (id, ..) in known.into_values() {
        sqlx::query("DELETE FROM assets WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sync.removed += 1;
    }
    Ok(sync)
}

/// The app's SSH key; made and stored (encrypted) on first use.
pub async fn ssh_key(pool: &SqlitePool, secrets: &SecretBox) -> Result<russh::keys::PrivateKey> {
    let stored: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT ssh_key FROM inventory_settings WHERE id = 1")
            .fetch_one(pool)
            .await?;
    if let Some(blob) = stored {
        let text = secrets.decrypt(&blob, KEY_CONTEXT)?;
        if let Some(key) = ssh::decode_key(&text) {
            return Ok(key);
        }
        tracing::warn!("the stored SSH key cannot be read, a new one is made");
    }
    let key = ssh::generate_key();
    let blob = secrets.encrypt(&ssh::encode_key(&key), KEY_CONTEXT)?;
    sqlx::query("UPDATE inventory_settings SET ssh_key = ?, ssh_public = ? WHERE id = 1")
        .bind(blob)
        .bind(ssh::public_line(&key))
        .execute(pool)
        .await?;
    Ok(key)
}

/// The link to opennetmon.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OnmSettings {
    pub url: String,
    /// Fingerprint of the accepted certificate (`AB:CD:…`), empty for one from a known authority.
    pub cert_sha256: String,
    pub has_token: bool,
    pub last_ms: Option<i64>,
    pub error: String,
}

pub async fn onm_settings(pool: &SqlitePool) -> Result<OnmSettings> {
    type Row = (String, String, Option<Vec<u8>>, Option<i64>, String);
    let (url, cert_sha256, token, last_ms, error): Row = sqlx::query_as(
        "SELECT onm_url, onm_cert_sha256, onm_token, onm_last_ms, onm_error FROM inventory_settings WHERE id = 1",
    )
    .fetch_one(pool)
    .await?;
    Ok(OnmSettings {
        url,
        cert_sha256,
        has_token: token.is_some(),
        last_ms,
        error,
    })
}

/// The token for opennetmon, decrypted.
pub async fn onm_token(pool: &SqlitePool, secrets: &SecretBox) -> Result<Option<Secret>> {
    let token: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT onm_token FROM inventory_settings WHERE id = 1")
            .fetch_one(pool)
            .await?;
    Ok(token
        .map(|blob| secrets.decrypt(&blob, TOKEN_CONTEXT).map(Secret::new))
        .transpose()?)
}

/// Stores the address of opennetmon, the fingerprint of its certificate (empty = from a known authority)
/// and, if given, a new token (an empty address removes all three).
pub async fn save_onm(
    pool: &SqlitePool,
    secrets: &SecretBox,
    url: &str,
    cert_sha256: &str,
    token: Option<&Secret>,
) -> Result<()> {
    if url.is_empty() {
        sqlx::query(
            "UPDATE inventory_settings SET onm_url = '', onm_cert_sha256 = '', onm_token = NULL, onm_error = '' \
             WHERE id = 1",
        )
        .execute(pool)
        .await?;
        return Ok(());
    }
    match token {
        Some(t) => {
            let blob = secrets.encrypt(t.expose(), TOKEN_CONTEXT)?;
            sqlx::query(
                "UPDATE inventory_settings SET onm_url = ?, onm_cert_sha256 = ?, onm_token = ? WHERE id = 1",
            )
            .bind(url)
            .bind(cert_sha256)
            .bind(blob)
                .execute(pool)
                .await?;
        }
        None => {
            sqlx::query(
                "UPDATE inventory_settings SET onm_url = ?, onm_cert_sha256 = ? WHERE id = 1",
            )
            .bind(url)
            .bind(cert_sha256)
            .execute(pool)
            .await?;
        }
    }
    Ok(())
}

pub async fn record_onm(pool: &SqlitePool, error: &str, now_ms: i64) -> Result<()> {
    sqlx::query("UPDATE inventory_settings SET onm_last_ms = ?, onm_error = ? WHERE id = 1")
        .bind(now_ms)
        .bind(error.chars().take(500).collect::<String>())
        .execute(pool)
        .await?;
    Ok(())
}

/// A device of opennetmon with the product the rules suggest.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct OnmDevice {
    pub id: i64,
    pub name: String,
    pub address: String,
    pub sys_descr: String,
    pub sys_object_id: String,
    pub vendor_name: String,
    pub product_name: String,
    pub version: String,
    pub kind: String,
    pub rule: String,
    pub sure: bool,
    pub state: String,
    pub asset_id: Option<i64>,
    pub seen_ms: i64,
}

pub async fn onm_devices(pool: &SqlitePool) -> Result<Vec<OnmDevice>> {
    Ok(
        sqlx::query_as("SELECT * FROM onm_devices ORDER BY name COLLATE NOCASE, id")
            .fetch_all(pool)
            .await?,
    )
}

pub async fn onm_device(pool: &SqlitePool, id: i64) -> Result<Option<OnmDevice>> {
    Ok(sqlx::query_as("SELECT * FROM onm_devices WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await?)
}

/// Stores the devices of a reading: new ones with their suggestion, known ones with fresh details
/// (their decision stays), devices that are gone are removed (an asset taken from them stays).
pub async fn store_onm_devices(
    pool: &SqlitePool,
    devices: &[OnmDevice],
    now_ms: i64,
) -> Result<()> {
    let mut tx = pool.begin().await?;
    for d in devices {
        sqlx::query(
            "INSERT INTO onm_devices (id, name, address, sys_descr, sys_object_id, vendor_name, product_name,
                 version, kind, rule, sure, seen_ms)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT (id) DO UPDATE SET name = excluded.name, address = excluded.address,
                 sys_descr = excluded.sys_descr, sys_object_id = excluded.sys_object_id,
                 vendor_name = excluded.vendor_name, product_name = excluded.product_name,
                 version = excluded.version, kind = excluded.kind, rule = excluded.rule,
                 sure = excluded.sure, seen_ms = excluded.seen_ms",
        )
        .bind(d.id)
        .bind(&d.name)
        .bind(&d.address)
        .bind(&d.sys_descr)
        .bind(&d.sys_object_id)
        .bind(&d.vendor_name)
        .bind(&d.product_name)
        .bind(&d.version)
        .bind(&d.kind)
        .bind(&d.rule)
        .bind(d.sure)
        .bind(now_ms)
        .execute(&mut *tx)
        .await?;
    }
    // Taken devices stay while their asset exists; the page marks them as no longer in opennetmon.
    sqlx::query(
        "DELETE FROM onm_devices WHERE seen_ms < ? AND NOT (state = 'taken' AND asset_id IS NOT NULL)",
    )
        .bind(now_ms)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn set_onm_state(
    pool: &SqlitePool,
    id: i64,
    state: &str,
    asset_id: Option<i64>,
) -> Result<()> {
    sqlx::query("UPDATE onm_devices SET state = ?, asset_id = ? WHERE id = ?")
        .bind(state)
        .bind(asset_id)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::listing;

    async fn pool() -> (SqlitePool, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pool = crate::storage::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        crate::storage::migrate(&pool).await.unwrap();
        (pool, dir)
    }

    #[test]
    fn host_input_is_checked() {
        let ok = HostInput {
            name: "server01".into(),
            address: "192.168.1.2".into(),
            port: String::new(),
            username: "opensecmon".into(),
        };
        assert_eq!(ok.check().unwrap().port, 22);
        let with = |f: &dyn Fn(&mut HostInput)| {
            let mut i = ok.clone();
            f(&mut i);
            i.check().unwrap_err()
        };
        assert_eq!(with(&|i| i.name = "a b".into()), "ssh-error-name");
        assert_eq!(
            with(&|i| i.address = "-oProxyCommand=x".into()),
            "ssh-error-address"
        );
        assert_eq!(with(&|i| i.address = "host;rm".into()), "ssh-error-address");
        assert_eq!(with(&|i| i.port = "70000".into()), "ssh-error-port");
        assert_eq!(with(&|i| i.username = "Root".into()), "ssh-error-username");
        let mut v6 = ok.clone();
        v6.address = "fd00::2".into();
        assert!(v6.check().is_ok());
    }

    #[tokio::test]
    async fn kernel_packages_start_muted_below_high() {
        let (pool, _dir) = pool().await;
        let input = HostInput {
            name: "pi01".into(),
            address: "127.0.0.1".into(),
            port: "22".into(),
            username: "opensecmon".into(),
        };
        let id = add_host(&pool, &input.check().unwrap(), 1)
            .await
            .unwrap()
            .unwrap();
        let h = host(&pool, id).await.unwrap().unwrap();
        let listing = listing::parse(
            "ID=debian\nVERSION_ID=13\n---\n\
             ii \tbash\t5.2.37-2\tbash\t5.2.37-2\n\
             ii \tlinux-image-6.12.38+deb13-amd64\t6.12.38-1\tlinux-signed-amd64\t6.12.38-1\n\
             ii \tlinux-image-amd64\t6.12.38-1\tlinux\t6.12.38-1\n\
             ii \tfirmware-linux-free\t20241210-2\tlinux-firmware\t20241210-2\n",
        )
        .unwrap();
        apply_listing(&pool, &h, &listing, 10).await.unwrap();
        let rows: Vec<(String, i64)> =
            sqlx::query_as("SELECT product, min_prio FROM assets ORDER BY product")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(
            rows,
            vec![
                ("bash".to_owned(), 0),
                ("linux".to_owned(), 65),
                ("linux-firmware".to_owned(), 0),
                ("linux-signed-amd64".to_owned(), 65),
            ]
        );
    }

    #[tokio::test]
    async fn the_pro_setting_of_a_host_outlasts_its_readings() {
        let (pool, _dir) = pool().await;
        let id = add_host(
            &pool,
            &HostInput {
                name: "server01".into(),
                address: "127.0.0.1".into(),
                port: "22".into(),
                username: "opensecmon".into(),
            }
            .check()
            .unwrap(),
            1,
        )
        .await
        .unwrap()
        .unwrap();
        let ubuntu = |zlib: &str| {
            listing::parse(&format!(
                "ID=ubuntu\nVERSION_ID=\"26.04\"\n---\n\
                 ii \tbash\t5.2.37-2ubuntu1\tbash\t5.2.37-2ubuntu1\n\
                 ii \tzlib1g\t{zlib}\tzlib\t{zlib}\n"
            ))
            .unwrap()
        };
        let pro = || async {
            sqlx::query_scalar::<_, bool>("SELECT pro FROM assets ORDER BY product")
                .fetch_all(&pool)
                .await
                .unwrap()
        };
        let h = host(&pool, id).await.unwrap().unwrap();
        apply_listing(&pool, &h, &ubuntu("1:1.3-1"), 10)
            .await
            .unwrap();
        assert_eq!(pro().await, [false, false]);
        // Set by hand: at once, and the next reading keeps it.
        let changed = set_pro_mode(&pool, ProOwner::Ssh, id, ProMode::Yes, 20)
            .await
            .unwrap();
        assert_eq!(changed.len(), 2);
        assert_eq!(pro().await, [true, true]);
        let h = host(&pool, id).await.unwrap().unwrap();
        assert_eq!(h.pro_mode(), ProMode::Yes);
        let s = apply_listing(&pool, &h, &ubuntu("1:1.3-1"), 30)
            .await
            .unwrap();
        assert!(s.changed.is_empty(), "nothing to match again");
        assert_eq!(pro().await, [true, true]);
        // The same mode again changes nothing.
        let changed = set_pro_mode(&pool, ProOwner::Ssh, id, ProMode::Yes, 40)
            .await
            .unwrap();
        assert!(changed.is_empty());
        // Automatic follows what the reading found.
        set_pro_mode(&pool, ProOwner::Ssh, id, ProMode::Auto, 50)
            .await
            .unwrap();
        assert_eq!(pro().await, [false, false]);
        let h = host(&pool, id).await.unwrap().unwrap();
        apply_listing(&pool, &h, &ubuntu("1:1.3-1+esm1"), 60)
            .await
            .unwrap();
        assert_eq!(pro().await, [true, true]);
        let h = host(&pool, id).await.unwrap().unwrap();
        assert!(h.pro_detected);
        set_pro_mode(&pool, ProOwner::Ssh, id, ProMode::No, 70)
            .await
            .unwrap();
        assert_eq!(pro().await, [false, false]);
        // Unknown hosts are left alone.
        assert!(
            set_pro_mode(&pool, ProOwner::Ssh, 99, ProMode::Yes, 80)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn only_ubuntu_gets_pro() {
        assert!(ProMode::Yes.effective(false, Some(Distro::Ubuntu)));
        assert!(!ProMode::Yes.effective(true, Some(Distro::Debian)));
        assert!(ProMode::Auto.effective(true, Some(Distro::Ubuntu)));
        assert!(!ProMode::No.effective(true, Some(Distro::Ubuntu)));
        assert!(!ProMode::Yes.effective(true, None));
        for m in ProMode::ALL {
            assert_eq!(ProMode::parse(m.as_str()), Some(m));
        }
        assert_eq!(ProMode::parse("maybe"), None);
    }

    #[tokio::test]
    async fn a_listing_becomes_package_assets_that_follow_the_host() {
        let (pool, _dir) = pool().await;
        let id = add_host(
            &pool,
            &HostInput {
                name: "server01".into(),
                address: "127.0.0.1".into(),
                port: "22".into(),
                username: "opensecmon".into(),
            }
            .check()
            .unwrap(),
            1,
        )
        .await
        .unwrap()
        .unwrap();
        let h = host(&pool, id).await.unwrap().unwrap();
        assert_eq!(h.next_ms(), None, "no confirmed key yet");
        let first = listing::parse(
            "ID=debian\nVERSION_ID=13\nPRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\n---\n\
             ii \tbash\t5.2.37-2\tbash\t5.2.37-2\n\
             ii \topenssh-server\t1:10.0p1-7\topenssh\t1:10.0p1-7\n\
             ii \tlibssl3t64\t3.5.1-1\topenssl\t3.5.1-1\n",
        )
        .unwrap();
        let s = apply_listing(&pool, &h, &first, 10).await.unwrap();
        assert_eq!(
            (s.added, s.updated, s.removed, s.changed.len()),
            (3, 0, 0, 3)
        );
        let second = listing::parse(
            "ID=debian\nVERSION_ID=13\n---\n\
             ii \tbash\t5.2.37-2\tbash\t5.2.37-2\n\
             ii \topenssh-server\t1:10.0p1-8\topenssh\t1:10.0p1-8\n",
        )
        .unwrap();
        let s = apply_listing(&pool, &h, &second, 20).await.unwrap();
        assert_eq!(
            (s.added, s.updated, s.removed, s.changed.len()),
            (0, 1, 1, 1)
        );
        let rows: Vec<(String, String, String, String)> =
            sqlx::query_as("SELECT product, version, host, origin FROM assets ORDER BY product")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(
            rows,
            [
                (
                    "bash".into(),
                    "5.2.37-2".into(),
                    "server01".into(),
                    "ssh".into()
                ),
                (
                    "openssh".into(),
                    "1:10.0p1-8".into(),
                    "server01".into(),
                    "ssh".into()
                ),
            ]
        );
        let h = host(&pool, id).await.unwrap().unwrap();
        assert_eq!(
            (h.distro.as_str(), h.release.as_str(), h.packages),
            ("debian", "13", 2)
        );
        // Renaming moves the packages along; a new address forgets the key.
        set_seen_key(&pool, id, "ssh-ed25519 AAAA").await.unwrap();
        assert!(confirm_key(&pool, id, "ssh-ed25519 AAAA").await.unwrap());
        let mut input = HostInput {
            name: "server02".into(),
            address: "127.0.0.1".into(),
            port: "22".into(),
            username: "opensecmon".into(),
        };
        assert!(
            update_host(&pool, &h, &input.check().unwrap())
                .await
                .unwrap()
        );
        let h = host(&pool, id).await.unwrap().unwrap();
        assert_eq!(h.host_key, "ssh-ed25519 AAAA");
        assert_eq!(h.next_ms(), Some(20 + (INTERVAL_SECS + 137) * 1000));
        input.address = "127.0.0.2".into();
        update_host(&pool, &h, &input.check().unwrap())
            .await
            .unwrap();
        let h = host(&pool, id).await.unwrap().unwrap();
        assert_eq!(h.host_key, "");
        let hosts: Vec<String> = sqlx::query_scalar("SELECT DISTINCT host FROM assets")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(hosts, ["server02"]);
        delete_host(&pool, id).await.unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM assets")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn snaps_of_a_host_become_assets_by_the_rules_and_go_with_it() {
        let (pool, _dir) = pool().await;
        let input = |name: &str| HostInput {
            name: name.into(),
            address: "127.0.0.1".into(),
            port: "22".into(),
            username: "opensecmon".into(),
        };
        let id = add_host(&pool, &input("server01").check().unwrap(), 1)
            .await
            .unwrap()
            .unwrap();
        let h = host(&pool, id).await.unwrap().unwrap();
        let reading = |lxd: &str| {
            listing::parse(&format!(
                "ID=ubuntu\nVERSION_ID=24.04\n---\n\
                 ii \tbash\t5.2.21-2ubuntu4\tbash\t5.2.21-2ubuntu4\n\
                 --- snap\n\
                 Name    Version   Rev    Tracking       Publisher   Notes\n\
                 core22  20250923  2139   latest/stable  canonical** base\n\
                 lxd     {lxd}     33110  5.21/stable    canonical** -\n\
                 mytool  1.2       7      latest/stable  someone     -\n"
            ))
            .unwrap()
        };
        let s = apply_listing(&pool, &h, &reading("5.21.3-c5ae129"), 10)
            .await
            .unwrap();
        assert_eq!((s.added, s.changed.len()), (2, 2), "bash and LXD");
        let software = || async {
            sqlx::query_as::<_, (String, String, String, String, String)>(
                "SELECT vendor_name, product_name, version, host, origin FROM assets
                 WHERE kind = 'software'",
            )
            .fetch_all(&pool)
            .await
            .unwrap()
        };
        assert_eq!(
            software().await,
            [(
                "Canonical".into(),
                "LXD".into(),
                "5.21.3".into(),
                "server01".into(),
                "ssh".into()
            )]
        );
        // The base snap is ignored, the unknown one waits for an assignment.
        let (all, per_origin) = crate::storage::items::unassigned_counts(&pool)
            .await
            .unwrap();
        assert_eq!(all, 1);
        assert_eq!(per_origin.get(&h.origin_ref()), Some(&1));
        let g = crate::storage::items::unassigned(&pool).await.unwrap();
        assert_eq!(
            (g[0].key.as_str(), g[0].computers.as_slice()),
            ("mytool", &["server01".to_owned()][..])
        );
        // A new version keeps the asset (and its matches).
        let before: i64 = sqlx::query_scalar("SELECT id FROM assets WHERE kind = 'software'")
            .fetch_one(&pool)
            .await
            .unwrap();
        let s = apply_listing(&pool, &h, &reading("5.21.4-1a2b3c4"), 20)
            .await
            .unwrap();
        assert_eq!((s.added, s.updated, s.removed), (0, 1, 0));
        let after: (i64, String) =
            sqlx::query_as("SELECT id, version FROM assets WHERE kind = 'software'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(after, (before, "5.21.4".into()));
        // A rule of the user applies to the host as to the computers.
        crate::storage::items::set_rule(
            &pool,
            crate::inventory::items::ItemType::Snap,
            "mytool",
            &crate::inventory::items::Resolution::Asset {
                vendor_name: "Someone".into(),
                product_name: "My Tool".into(),
            },
            30,
        )
        .await
        .unwrap();
        let origins = crate::storage::items::origins_with(
            &pool,
            crate::inventory::items::ItemType::Snap,
            "mytool",
        )
        .await
        .unwrap();
        assert_eq!(origins, [h.origin_ref()]);
        let changed = crate::storage::items::resync(&pool, &origins, 30)
            .await
            .unwrap();
        assert_eq!(changed.len(), 1);
        assert_eq!(software().await.len(), 2);
        // Removing the host removes its entries with its assets.
        delete_host(&pool, id).await.unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_items")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
        assert!(software().await.is_empty());
    }

    #[tokio::test]
    async fn the_key_and_the_token_are_kept_encrypted() {
        let (pool, _dir) = pool().await;
        let secrets = SecretBox::from_key([7; 32]);
        let key = ssh_key(&pool, &secrets).await.unwrap();
        let again = ssh_key(&pool, &secrets).await.unwrap();
        assert_eq!(ssh::public_line(&key), ssh::public_line(&again));
        let raw: Vec<u8> = sqlx::query_scalar("SELECT ssh_key FROM inventory_settings")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("OPENSSH"));
        save_onm(
            &pool,
            &secrets,
            "https://onm.example",
            "AB:CD",
            Some(&Secret::new("tok-123")),
        )
        .await
        .unwrap();
        assert_eq!(
            onm_token(&pool, &secrets).await.unwrap().unwrap().expose(),
            "tok-123"
        );
        save_onm(&pool, &secrets, "https://onm2.example", "", None)
            .await
            .unwrap();
        let s = onm_settings(&pool).await.unwrap();
        assert_eq!(
            (s.url.as_str(), s.cert_sha256.as_str(), s.has_token),
            ("https://onm2.example", "", true)
        );
        save_onm(&pool, &secrets, "https://onm2.example", "AB:CD", None)
            .await
            .unwrap();
        assert_eq!(onm_settings(&pool).await.unwrap().cert_sha256, "AB:CD");
        save_onm(&pool, &secrets, "", "AB:CD", None).await.unwrap();
        assert!(onm_token(&pool, &secrets).await.unwrap().is_none());
        assert_eq!(onm_settings(&pool).await.unwrap().cert_sha256, "");
    }
}
