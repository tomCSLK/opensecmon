//! Reading the hosts: on demand (wizard, "read now") and in the background every 6 hours, one host at a
//! time; after a reading the new and changed packages are matched. opennetmon is read in the same loop.

use std::sync::Arc;
use std::time::Duration;

use sqlx::SqlitePool;
use tokio::task::JoinHandle;

use super::listing;
use super::ssh::SshError;
use crate::crypto::SecretBox;
use crate::error::Result;
use crate::sources::now_ms;
use crate::storage::inventory::{self, PackageSync};
use crate::storage::matches::Synced;

/// How often the loop looks for due hosts.
const TICK: Duration = Duration::from_secs(60);

/// One reading at a time (the loop and the web pages).
static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// What reading a host gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Read and stored.
    Read { sync: PackageSync, matched: Synced },
    /// The host presented a key that is to be confirmed first (stored as `seen_key`).
    KeyToConfirm,
    /// Failed; the error as stored with the host ([`error_text`]).
    Failed(String),
}

/// An error for the host's row: the id of the text, a tab and the detail (the page shows both).
pub fn error_text(id: &str, detail: &str) -> String {
    if detail.is_empty() {
        id.to_owned()
    } else {
        format!("{id}\t{detail}")
    }
}

/// Reads one host now.
pub async fn read_host(pool: &SqlitePool, secrets: &SecretBox, id: i64) -> Result<Outcome> {
    let _guard = LOCK.lock().await;
    let Some(h) = inventory::host(pool, id).await? else {
        return Err(crate::error::Error::NotFound);
    };
    let key = inventory::ssh_key(pool, secrets).await?;
    let confirmed = (!h.host_key.is_empty()).then_some(h.host_key.as_str());
    let started = std::time::Instant::now();
    let read = super::ssh::read(&h.target(), &key, confirmed).await;
    let now = now_ms();
    let output = match read {
        Ok(output) => output,
        Err(SshError::HostKeyUnknown(seen)) => {
            inventory::set_seen_key(pool, id, &seen).await?;
            return Ok(Outcome::KeyToConfirm);
        }
        Err(e) => {
            if let Some(seen) = e.host_key() {
                inventory::set_seen_key(pool, id, seen).await?;
            }
            let text = error_text(e.text_id(), e.detail());
            tracing::warn!(host = %h.name, error = %e, "reading the host failed");
            inventory::record_error(pool, id, &text, now).await?;
            return Ok(Outcome::Failed(text));
        }
    };
    let listing = match listing::parse(&output) {
        Ok(l) => l,
        Err(e) => {
            let text = error_text(e.text_id(), "");
            tracing::warn!(host = %h.name, error = %e, "the host's output cannot be read");
            inventory::record_error(pool, id, &text, now).await?;
            return Ok(Outcome::Failed(text));
        }
    };
    let sync = inventory::apply_listing(pool, &h, &listing, now).await?;
    let matched = crate::matching::match_assets(pool, &sync.changed, now).await?;
    tracing::info!(
        host = %h.name,
        packages = listing.sources.len(),
        added = sync.added,
        updated = sync.updated,
        removed = sync.removed,
        ms = started.elapsed().as_millis(),
        "host read"
    );
    Ok(Outcome::Read { sync, matched })
}

/// Matches assets that a computer reported, after the response went out; one matching at a time with the
/// readings of the hosts. The handle is for the tests.
pub fn match_in_background(pool: SqlitePool, changed: Vec<i64>, device: String) -> JoinHandle<()> {
    tokio::spawn(async move {
        if changed.is_empty() {
            return;
        }
        let _guard = LOCK.lock().await;
        let started = std::time::Instant::now();
        match crate::matching::match_assets(&pool, &changed, now_ms()).await {
            Ok(m) => tracing::info!(
                device = %device,
                assets = changed.len(),
                new = m.new,
                ms = started.elapsed().as_millis(),
                "report matched"
            ),
            Err(e) => tracing::error!(device = %device, error = %e, "matching a report failed"),
        }
    })
}

/// Reads the hosts that are due.
async fn run_due(pool: &SqlitePool, secrets: &SecretBox) -> Result<()> {
    let now = now_ms();
    for h in inventory::hosts(pool).await? {
        if h.next_ms().is_some_and(|next| next <= now)
            && let Err(e) = read_host(pool, secrets, h.id).await
        {
            tracing::error!(host = %h.name, error = %e, "reading the host failed");
        }
    }
    if let Err(e) = super::opennetmon::run_due(pool, secrets).await {
        tracing::error!(error = %e, "reading opennetmon failed");
    }
    Ok(())
}

/// The background loop; [`Runner::stop`] ends it.
pub struct Runner {
    task: JoinHandle<()>,
}

impl Runner {
    pub fn spawn(pool: SqlitePool, secrets: Arc<SecretBox>) -> Self {
        let task = tokio::spawn(async move {
            let mut tick = tokio::time::interval(TICK);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                if let Err(e) = run_due(&pool, &secrets).await {
                    tracing::error!(error = %e, "reading the hosts failed");
                }
            }
        });
        Self { task }
    }

    pub async fn stop(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::ssh::{public_line, testserver};
    use crate::storage::inventory::HostInput;

    #[tokio::test]
    async fn a_host_is_learned_confirmed_read_and_matched() {
        let dir = tempfile::tempdir().unwrap();
        let pool = crate::storage::connect(&dir.path().join("r.db"))
            .await
            .unwrap();
        crate::storage::migrate(&pool).await.unwrap();
        let secrets = SecretBox::from_key([3; 32]);
        let key = inventory::ssh_key(&pool, &secrets).await.unwrap();
        // An OSV record that the package hits.
        sqlx::raw_sql(
            "INSERT INTO osv_records (seq, source, id, kind, summary, modified, modified_ms, fetched_ms)
               VALUES (1, 'debian', 'DSA-6000-1', 'advisory', 'openssh security update', '2026-01-01', 0, 0);
             INSERT INTO osv_affected (record_seq, ecosystem, release, package, introduced, fixed)
               VALUES (1, 'Debian:13', '13', 'openssh', '0', '1:10.0p1-8');
             INSERT INTO osv_cves (record_seq, cve_id) VALUES (1, 'CVE-2026-10001');",
        )
        .execute(&pool)
        .await
        .unwrap();
        let server = testserver::start(
            &public_line(&key),
            testserver::Reply::Output(
                "ID=debian\nVERSION_ID=13\n---\nii \topenssh-server\t1:10.0p1-7\topenssh\t1:10.0p1-7\n",
            ),
        )
        .await;
        let id = inventory::add_host(
            &pool,
            &HostInput {
                name: "pi01".into(),
                address: "127.0.0.1".into(),
                port: server.port.to_string(),
                username: "opensecmon".into(),
            }
            .check()
            .unwrap(),
            1,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            read_host(&pool, &secrets, id).await.unwrap(),
            Outcome::KeyToConfirm
        );
        let h = inventory::host(&pool, id).await.unwrap().unwrap();
        assert!(
            inventory::confirm_key(&pool, id, &h.seen_key)
                .await
                .unwrap()
        );
        let Outcome::Read { sync, matched } = read_host(&pool, &secrets, id).await.unwrap() else {
            panic!("not read");
        };
        assert_eq!(sync.added, 1);
        assert_eq!(matched.new, 1);
        let vuln: String = sqlx::query_scalar("SELECT vuln FROM matches")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(vuln, "CVE-2026-10001");
        // The host now presents another key: the reading stops, the new key waits for a confirmation.
        sqlx::query("UPDATE ssh_hosts SET host_key = ? WHERE id = ?")
            .bind(public_line(&crate::inventory::ssh::generate_key()))
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        let Outcome::Failed(text) = read_host(&pool, &secrets, id).await.unwrap() else {
            panic!("read with a changed key");
        };
        assert_eq!(text, "ssh-error-key-changed");
        let h = inventory::host(&pool, id).await.unwrap().unwrap();
        assert_eq!(
            (h.failures, h.last_error.as_str()),
            (1, "ssh-error-key-changed")
        );
    }
}
