//! Settings of the instant mail and the daily report (one row) and the state the notifier keeps between rounds.

use sqlx::{FromRow, SqlitePool};

use crate::error::Result;
use crate::storage::matches::Confidence;

/// What the settings pages edit.
#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub instant: bool,
    pub on_kev: bool,
    pub prio_on: bool,
    pub prio_min: i64,
    pub cvss_on: bool,
    pub cvss_min: f64,
    pub epss_on: bool,
    /// Percent (0–100).
    pub epss_min: f64,
    pub min_confidence: Confidence,
    pub bundle: bool,
    pub once_per_vuln: bool,
    /// Address of the interface for links in the mails, without a trailing slash; empty: no links.
    pub public_url: String,
    pub report: bool,
    /// Minutes after midnight (local time).
    pub report_minute: i64,
    pub report_new: bool,
    pub report_open: bool,
    pub report_sources: bool,
    pub report_due: bool,
    pub report_skip_empty: bool,
}

impl Default for Settings {
    /// The defaults of the migration.
    fn default() -> Self {
        Self {
            instant: true,
            on_kev: true,
            prio_on: true,
            prio_min: 85,
            cvss_on: false,
            cvss_min: 9.0,
            epss_on: false,
            epss_min: 10.0,
            min_confidence: Confidence::Medium,
            bundle: true,
            once_per_vuln: true,
            public_url: String::new(),
            report: true,
            report_minute: 7 * 60,
            report_new: true,
            report_open: true,
            report_sources: true,
            report_due: false,
            report_skip_empty: true,
        }
    }
}

impl Settings {
    /// Describes the conditions of the instant mail; a change means "take what qualifies now as known".
    pub fn alert_key(&self, mail_enabled: bool) -> String {
        if !(mail_enabled && self.instant) {
            return "off".to_owned();
        }
        let on = |b: bool| if b { "1" } else { "0" };
        format!(
            "kev={}|prio={}:{}|cvss={}:{}|epss={}:{}|conf={}",
            on(self.on_kev),
            on(self.prio_on),
            self.prio_min,
            on(self.cvss_on),
            self.cvss_min,
            on(self.epss_on),
            self.epss_min,
            self.min_confidence.as_str()
        )
    }

    /// Describes when the report goes out; a change means "do not catch up a time that has passed".
    pub fn report_key(&self, mail_enabled: bool) -> String {
        if mail_enabled && self.report {
            format!("at={}", self.report_minute)
        } else {
            "off".to_owned()
        }
    }
}

/// What the notifier remembers.
#[derive(Debug, Clone, Default, PartialEq, Eq, FromRow)]
pub struct State {
    pub alert_key: String,
    pub pending_since_ms: Option<i64>,
    pub alert_failures: i64,
    pub alert_retry_ms: i64,
    pub last_alert_ms: Option<i64>,
    pub report_key: String,
    /// The report time that was dealt with last (sent, skipped or not caught up).
    pub report_slot_ms: i64,
    pub report_failures: i64,
    pub report_retry_ms: i64,
    /// When the last report went out (its "new since" starts here).
    pub last_report_ms: Option<i64>,
}

#[derive(FromRow)]
struct Row {
    instant: bool,
    on_kev: bool,
    prio_on: bool,
    prio_min: i64,
    cvss_on: bool,
    cvss_min: f64,
    epss_on: bool,
    epss_min: f64,
    min_confidence: String,
    bundle: bool,
    once_per_vuln: bool,
    public_url: String,
    report: bool,
    report_minute: i64,
    report_new: bool,
    report_open: bool,
    report_sources: bool,
    report_due: bool,
    report_skip_empty: bool,
}

pub async fn settings(pool: &SqlitePool) -> Result<Settings> {
    let r: Row = sqlx::query_as(
        "SELECT instant, on_kev, prio_on, prio_min, cvss_on, cvss_min, epss_on, epss_min, min_confidence,
             bundle, once_per_vuln, public_url, report, report_minute, report_new, report_open, report_sources,
             report_due, report_skip_empty
         FROM alert_settings WHERE id = 1",
    )
    .fetch_one(pool)
    .await?;
    Ok(Settings {
        instant: r.instant,
        on_kev: r.on_kev,
        prio_on: r.prio_on,
        prio_min: r.prio_min,
        cvss_on: r.cvss_on,
        cvss_min: r.cvss_min,
        epss_on: r.epss_on,
        epss_min: r.epss_min,
        min_confidence: Confidence::parse(&r.min_confidence),
        bundle: r.bundle,
        once_per_vuln: r.once_per_vuln,
        public_url: r.public_url,
        report: r.report,
        report_minute: r.report_minute,
        report_new: r.report_new,
        report_open: r.report_open,
        report_sources: r.report_sources,
        report_due: r.report_due,
        report_skip_empty: r.report_skip_empty,
    })
}

/// Stores the settings (validated by the caller).
pub async fn save(pool: &SqlitePool, s: &Settings, now_ms: i64) -> Result<()> {
    sqlx::query(
        "UPDATE alert_settings SET instant = ?, on_kev = ?, prio_on = ?, prio_min = ?, cvss_on = ?, cvss_min = ?,
             epss_on = ?, epss_min = ?, min_confidence = ?, bundle = ?, once_per_vuln = ?, public_url = ?,
             report = ?, report_minute = ?, report_new = ?, report_open = ?, report_sources = ?, report_due = ?,
             report_skip_empty = ?, updated_ms = ?
         WHERE id = 1",
    )
    .bind(s.instant)
    .bind(s.on_kev)
    .bind(s.prio_on)
    .bind(s.prio_min)
    .bind(s.cvss_on)
    .bind(s.cvss_min)
    .bind(s.epss_on)
    .bind(s.epss_min)
    .bind(s.min_confidence.as_str())
    .bind(s.bundle)
    .bind(s.once_per_vuln)
    .bind(&s.public_url)
    .bind(s.report)
    .bind(s.report_minute)
    .bind(s.report_new)
    .bind(s.report_open)
    .bind(s.report_sources)
    .bind(s.report_due)
    .bind(s.report_skip_empty)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn state(pool: &SqlitePool) -> Result<State> {
    Ok(sqlx::query_as(
        "SELECT alert_key, pending_since_ms, alert_failures, alert_retry_ms, last_alert_ms, report_key,
             report_slot_ms, report_failures, report_retry_ms, last_report_ms
         FROM alert_settings WHERE id = 1",
    )
    .fetch_one(pool)
    .await?)
}

/// Stores the state of the instant mail.
pub async fn save_alert_state(pool: &SqlitePool, s: &State) -> Result<()> {
    sqlx::query(
        "UPDATE alert_settings SET alert_key = ?, pending_since_ms = ?, alert_failures = ?, alert_retry_ms = ?,
             last_alert_ms = ?
         WHERE id = 1",
    )
    .bind(&s.alert_key)
    .bind(s.pending_since_ms)
    .bind(s.alert_failures)
    .bind(s.alert_retry_ms)
    .bind(s.last_alert_ms)
    .execute(pool)
    .await?;
    Ok(())
}

/// Stores the state of the daily report.
pub async fn save_report_state(pool: &SqlitePool, s: &State) -> Result<()> {
    sqlx::query(
        "UPDATE alert_settings SET report_key = ?, report_slot_ms = ?, report_failures = ?, report_retry_ms = ?,
             last_report_ms = ?
         WHERE id = 1",
    )
    .bind(&s.report_key)
    .bind(s.report_slot_ms)
    .bind(s.report_failures)
    .bind(s.report_retry_ms)
    .bind(s.last_report_ms)
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{connect, migrate};

    async fn db() -> (tempfile::TempDir, SqlitePool) {
        let dir = tempfile::tempdir().unwrap();
        let pool = connect(&dir.path().join("a.db")).await.unwrap();
        migrate(&pool).await.unwrap();
        (dir, pool)
    }

    #[tokio::test]
    async fn the_defaults_match_the_migration_and_settings_round_trip() {
        let (_dir, pool) = db().await;
        assert_eq!(settings(&pool).await.unwrap(), Settings::default());
        let s = Settings {
            instant: false,
            cvss_on: true,
            cvss_min: 8.5,
            epss_min: 2.5,
            min_confidence: Confidence::High,
            public_url: "https://secmon.example.org".to_owned(),
            report_minute: 22 * 60 + 30,
            report_due: true,
            ..Settings::default()
        };
        save(&pool, &s, 1).await.unwrap();
        assert_eq!(settings(&pool).await.unwrap(), s);
    }

    #[tokio::test]
    async fn the_state_round_trips_in_two_halves() {
        let (_dir, pool) = db().await;
        assert_eq!(state(&pool).await.unwrap(), State::default());
        let s = State {
            alert_key: "a".to_owned(),
            pending_since_ms: Some(5),
            alert_failures: 2,
            alert_retry_ms: 9,
            last_alert_ms: Some(7),
            report_key: "r".to_owned(),
            report_slot_ms: 11,
            report_failures: 1,
            report_retry_ms: 12,
            last_report_ms: Some(13),
        };
        save_alert_state(&pool, &s).await.unwrap();
        let half = state(&pool).await.unwrap();
        assert_eq!(half.alert_key, "a");
        assert_eq!(half.report_key, "");
        save_report_state(&pool, &s).await.unwrap();
        assert_eq!(state(&pool).await.unwrap(), s);
    }

    #[test]
    fn the_keys_change_with_what_matters() {
        let s = Settings::default();
        assert_eq!(s.alert_key(false), "off");
        assert_eq!(s.report_key(false), "off");
        let on = s.alert_key(true);
        assert_ne!(on, "off");
        let other = Settings {
            prio_min: 80,
            ..s.clone()
        };
        assert_ne!(other.alert_key(true), on);
        let bundled = Settings {
            bundle: false,
            public_url: "https://x".to_owned(),
            ..s.clone()
        };
        assert_eq!(
            bundled.alert_key(true),
            on,
            "bundling and links do not re-baseline"
        );
        let later = Settings {
            report_minute: 8 * 60,
            ..s
        };
        assert_ne!(later.report_key(true), Settings::default().report_key(true));
    }
}
