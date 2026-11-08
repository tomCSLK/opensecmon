//! Hourly housekeeping: removes audit entries and closed matches older than the retention and expired sessions,
//! opens inbox matches whose "later" date has come, stores the open vulnerabilities of the day for the page
//! "Situation" and measures the size of the database once a day. The sources have their own scheduler
//! (`crate::sources`).

use std::time::Duration;

use jiff::tz::TimeZone;
use sqlx::SqlitePool;
use tokio::task::JoinHandle;

use crate::auth::now_secs;
use crate::storage::{audit, matches, retention, users};

const INTERVAL: Duration = Duration::from_secs(3600);

/// The running housekeeping task; [`Maintenance::stop`] ends it.
pub struct Maintenance {
    task: JoinHandle<()>,
}

impl Maintenance {
    /// Starts the task; the first run follows right away.
    pub fn spawn(
        pool: SqlitePool,
        audit_days: u32,
        session_idle_secs: Option<i64>,
        tz: TimeZone,
    ) -> Self {
        let task = tokio::spawn(async move {
            let mut tick = tokio::time::interval(INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                run_once(&pool, audit_days, session_idle_secs, now_secs()).await;
                if let Err(e) =
                    crate::situation::record_today(&pool, &tz, now_secs().saturating_mul(1000))
                        .await
                {
                    tracing::error!(error = %e, "storing the counts of the day failed");
                }
                if let Err(e) =
                    retention::measure_if_due(&pool, now_secs().saturating_mul(1000)).await
                {
                    tracing::error!(error = %e, "measuring the database failed");
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

/// One round; failures are logged and retried in the next round. `audit_days` is the configured retention of
/// the audit log, which the page "Retention" may override.
pub async fn run_once(
    pool: &SqlitePool,
    audit_days: u32,
    session_idle_secs: Option<i64>,
    now: i64,
) {
    let settings = match retention::settings(pool).await {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::error!(error = %e, "reading the retention failed");
            None
        }
    };
    let audit_days = settings
        .and_then(|s| s.audit_days)
        .unwrap_or(i64::from(audit_days));
    let cutoff_ms = now
        .saturating_sub(audit_days.saturating_mul(86_400))
        .saturating_mul(1000);
    match audit::apply_retention(pool, cutoff_ms).await {
        Ok(0) => {}
        Ok(removed) => tracing::info!(removed, "old audit entries removed"),
        Err(e) => tracing::error!(error = %e, "removing old audit entries failed"),
    }
    if let Err(e) = users::purge_expired_sessions(pool, now, session_idle_secs).await {
        tracing::error!(error = %e, "removing expired sessions failed");
    }
    if let Some(s) = settings {
        match matches::apply_retention(pool, s.closed_days, now.saturating_mul(1000)).await {
            Ok(0) => {}
            Ok(removed) => tracing::info!(removed, "old closed matches removed"),
            Err(e) => tracing::error!(error = %e, "removing old closed matches failed"),
        }
    }
    match matches::wake_later(pool, now.saturating_mul(1000)).await {
        Ok(0) => {}
        Ok(woken) => tracing::info!(woken, "postponed matches are open again"),
        Err(e) => tracing::error!(error = %e, "opening postponed matches failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{Action, Kind};
    use crate::i18n::Msg;
    use crate::storage;

    #[tokio::test]
    async fn a_round_removes_only_entries_past_the_retention() {
        let dir = tempfile::tempdir().unwrap();
        let pool = storage::connect(&dir.path().join("m.db")).await.unwrap();
        storage::migrate(&pool).await.unwrap();
        let now = 100 * 86_400;
        let detail = Msg::List(Vec::new());
        for days_ago in [40, 10] {
            let entry = audit::NewEntry {
                ts_ms: (now - days_ago * 86_400) * 1000,
                user: "anna",
                address: None,
                action: Action::SignedIn,
                kind: Kind::Session,
                object_id: None,
                object_name: "",
                detail: &detail,
            };
            audit::insert(&pool, &entry).await.unwrap();
        }
        run_once(&pool, 30, None, now).await;
        let left = audit::list(&pool, 10).await.unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].ts_ms, (now - 10 * 86_400) * 1000);
    }

    #[tokio::test]
    async fn closed_matches_go_some_time_after_they_stopped_applying() {
        use crate::storage::matches::{Confidence, Found, Method, Subject};
        let dir = tempfile::tempdir().unwrap();
        let pool = storage::connect(&dir.path().join("m.db")).await.unwrap();
        storage::migrate(&pool).await.unwrap();
        sqlx::raw_sql(
            "INSERT INTO assets (kind, product, product_name, host, created_ms, updated_ms)
               VALUES ('software', 'a', 'A', 'h1', 0, 0);",
        )
        .execute(&pool)
        .await
        .unwrap();
        let found = |vulns: &[&str]| -> Vec<Found> {
            vulns
                .iter()
                .map(|v| Found {
                    vuln: (*v).to_owned(),
                    title: String::new(),
                    confidence: Confidence::High,
                    method: Method::Nvd,
                    fixed: String::new(),
                    evidence: Vec::new(),
                    base_prio: 0,
                    rating: crate::storage::matches::Rating::None,
                })
                .collect()
        };
        const DAY: i64 = 86_400;
        let t0 = 1000 * DAY;
        matches::sync(
            &pool,
            Subject::Asset(1),
            &found(&["CVE-1", "CVE-2", "CVE-3"]),
            t0 * 1000,
        )
        .await
        .unwrap();
        // CVE-2 ignored, CVE-3 done by hand; then only CVE-1 and CVE-3 apply any more.
        sqlx::raw_sql(
            "UPDATE matches SET state = 'ignored' WHERE vuln = 'CVE-2';
             UPDATE matches SET state = 'done' WHERE vuln = 'CVE-3';",
        )
        .execute(&pool)
        .await
        .unwrap();
        matches::sync(
            &pool,
            Subject::Asset(1),
            &found(&["CVE-3"]),
            (t0 + DAY) * 1000,
        )
        .await
        .unwrap();
        let gone: Vec<(String, String, Option<i64>)> =
            sqlx::query_as("SELECT vuln, state, gone_ms FROM matches ORDER BY vuln")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(
            gone,
            vec![
                (
                    "CVE-1".to_owned(),
                    "done".to_owned(),
                    Some((t0 + DAY) * 1000)
                ),
                (
                    "CVE-2".to_owned(),
                    "ignored".to_owned(),
                    Some((t0 + DAY) * 1000)
                ),
                ("CVE-3".to_owned(), "done".to_owned(), None),
            ]
        );
        // Found again: no longer gone.
        matches::sync(
            &pool,
            Subject::Asset(1),
            &found(&["CVE-2", "CVE-3"]),
            (t0 + 2 * DAY) * 1000,
        )
        .await
        .unwrap();
        matches::sync(
            &pool,
            Subject::Asset(1),
            &found(&["CVE-3"]),
            (t0 + 3 * DAY) * 1000,
        )
        .await
        .unwrap();

        run_once(&pool, 730, None, t0 + 300 * DAY).await;
        assert_eq!(
            matches::rows(&pool, &crate::situation::ALL_STATES)
                .await
                .unwrap()
                .len(),
            3
        );
        run_once(&pool, 730, None, t0 + 367 * DAY).await;
        let mut left: Vec<String> = matches::rows(&pool, &crate::situation::ALL_STATES)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.vuln)
            .collect();
        left.sort();
        assert_eq!(
            left,
            vec!["CVE-2".to_owned(), "CVE-3".to_owned()],
            "CVE-2 was found again later"
        );
    }
}
