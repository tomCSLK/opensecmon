//! The numbers of the page "Situation": open vulnerabilities by band, now and on past days.
//!
//! "Open" is what the inbox shows by default: matches that are new or seen. A vulnerability counts once, in the
//! band of its highest priority among its open matches. The housekeeping stores the counts of the current day
//! (`situation_days`); a day without an entry is worked out from the matches as they are now (when they were
//! found, when their state last changed), which misses matches of deleted assets and uses today's priorities.

use std::collections::HashMap;

use jiff::civil::Date;
use jiff::tz::TimeZone;
use sqlx::SqlitePool;

use crate::error::Result;
use crate::storage::cve_list::Band;
use crate::storage::matches::{self, Row, State};

/// Open vulnerabilities of one day by band; `kev` counts those in CISA KEV (also part of their band).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, sqlx::FromRow)]
pub struct Counts {
    pub crit: i64,
    pub high: i64,
    pub med: i64,
    pub low: i64,
    pub kev: i64,
}

impl Counts {
    pub fn total(&self) -> i64 {
        self.crit + self.high + self.med + self.low
    }

    pub fn of_band(&self, band: Band) -> i64 {
        match band {
            Band::Crit => self.crit,
            Band::High => self.high,
            Band::Med => self.med,
            Band::Low | Band::None => self.low,
        }
    }

    fn add(&mut self, prio: i64, kev: bool) {
        match Band::of_prio(prio) {
            Band::Crit => self.crit += 1,
            Band::High => self.high += 1,
            Band::Med => self.med += 1,
            Band::Low | Band::None => self.low += 1,
        }
        if kev {
            self.kev += 1;
        }
    }
}

/// All states, for the rows the page and the reconstruction need.
pub const ALL_STATES: [State; 5] = [
    State::New,
    State::Seen,
    State::Later,
    State::Done,
    State::Ignored,
];

/// Whether a match is open now (new or seen).
pub fn open_now(r: &Row) -> bool {
    matches!(r.state(), State::New | State::Seen)
}

/// Whether a match was open at the instant `at_ms`, as far as its row tells: found before, and still open or
/// closed (postponed, done, ignored) only after it.
fn open_at(r: &Row, at_ms: i64) -> bool {
    r.first_seen_ms <= at_ms && (open_now(r) || r.state_ms > at_ms)
}

/// Counts the vulnerabilities of the matches that pass `open` (each in the band of its highest priority); muted
/// matches (below the priority from which their asset shows matches) do not count.
pub fn count(rows: &[Row], open: impl Fn(&Row) -> bool) -> Counts {
    let mut by_vuln: HashMap<&str, (i64, bool)> = HashMap::new();
    for r in rows.iter().filter(|r| !r.muted() && open(r)) {
        let e = by_vuln.entry(r.vuln.as_str()).or_insert((0, false));
        e.0 = e.0.max(r.prio());
        e.1 |= r.kev;
    }
    let mut c = Counts::default();
    for (prio, kev) in by_vuln.into_values() {
        c.add(prio, kev);
    }
    c
}

/// The local date of an instant.
pub fn local_day(tz: &TimeZone, ms: i64) -> Date {
    jiff::Timestamp::from_millisecond(ms)
        .unwrap_or(jiff::Timestamp::UNIX_EPOCH)
        .to_zoned(tz.clone())
        .date()
}

/// The last millisecond of a local day.
fn day_end_ms(tz: &TimeZone, day: Date) -> i64 {
    day.tomorrow()
        .ok()
        .and_then(|d| d.to_zoned(tz.clone()).ok())
        .map_or(i64::MAX, |z| z.timestamp().as_millisecond() - 1)
}

/// One day of the trend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Day {
    pub day: Date,
    pub counts: Counts,
    /// Worked out from the matches instead of stored.
    pub derived: bool,
}

/// The last `days` days up to today: stored counts where there are some, the others worked out from `rows`;
/// today always from the current state.
pub async fn trend(
    pool: &SqlitePool,
    rows: &[Row],
    tz: &TimeZone,
    now_ms: i64,
    days: i32,
) -> Result<Vec<Day>> {
    let today = local_day(tz, now_ms);
    let first = today
        .checked_sub(jiff::Span::new().days(days - 1))
        .unwrap_or(today);
    let stored: Vec<(String, i64, i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT day, crit, high, med, low, kev FROM situation_days WHERE day >= ? AND day < ?",
    )
    .bind(first.to_string())
    .bind(today.to_string())
    .fetch_all(pool)
    .await?;
    let stored: HashMap<String, Counts> = stored
        .into_iter()
        .map(|(day, crit, high, med, low, kev)| {
            (
                day,
                Counts {
                    crit,
                    high,
                    med,
                    low,
                    kev,
                },
            )
        })
        .collect();
    let mut out = Vec::new();
    let mut day = first;
    while day <= today {
        let entry = if day == today {
            Day {
                day,
                counts: count(rows, open_now),
                derived: false,
            }
        } else if let Some(c) = stored.get(&day.to_string()) {
            Day {
                day,
                counts: *c,
                derived: false,
            }
        } else {
            let end = day_end_ms(tz, day);
            Day {
                day,
                counts: count(rows, |r| open_at(r, end)),
                derived: true,
            }
        };
        out.push(entry);
        let Ok(next) = day.tomorrow() else { break };
        day = next;
    }
    Ok(out)
}

/// How long the stored days are kept.
const KEEP_DAYS: i32 = 400;

/// Stores the counts of the current day (the housekeeping, every hour) and removes days past the retention.
pub async fn record_today(pool: &SqlitePool, tz: &TimeZone, now_ms: i64) -> Result<Counts> {
    let rows = matches::rows(pool, &[State::New, State::Seen]).await?;
    let c = count(&rows, open_now);
    let today = local_day(tz, now_ms);
    sqlx::query(
        "INSERT INTO situation_days (day, crit, high, med, low, kev) VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT (day) DO UPDATE SET crit = excluded.crit, high = excluded.high, med = excluded.med,
             low = excluded.low, kev = excluded.kev",
    )
    .bind(today.to_string())
    .bind(c.crit)
    .bind(c.high)
    .bind(c.med)
    .bind(c.low)
    .bind(c.kev)
    .execute(pool)
    .await?;
    if let Ok(oldest) = today.checked_sub(jiff::Span::new().days(KEEP_DAYS)) {
        sqlx::query("DELETE FROM situation_days WHERE day < ?")
            .bind(oldest.to_string())
            .execute(pool)
            .await?;
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::matches::{Confidence, Found, Method, Subject};
    use crate::storage::{connect, migrate};

    const DAY: i64 = 86_400_000;
    /// 2026-11-06 12:00 UTC.
    const NOW: i64 = 1_793_966_400_000;

    async fn db() -> (tempfile::TempDir, SqlitePool) {
        let dir = tempfile::tempdir().unwrap();
        let pool = connect(&dir.path().join("s.db")).await.unwrap();
        migrate(&pool).await.unwrap();
        sqlx::raw_sql(
            "INSERT INTO cves (id, state, title, prio, kev_added) VALUES
               ('CVE-1', 'published', 'one', 90, '2026-01-01'),
               ('CVE-2', 'published', 'two', 70, NULL),
               ('CVE-3', 'published', 'three', 30, NULL);
             INSERT INTO assets (kind, product, product_name, host, created_ms, updated_ms)
               VALUES ('software', 'a', 'A', 'h1', 0, 0), ('software', 'b', 'B', 'h2', 0, 0);",
        )
        .execute(&pool)
        .await
        .unwrap();
        (dir, pool)
    }

    async fn found(pool: &SqlitePool, asset: i64, vulns: &[&str], at: i64) {
        let f: Vec<Found> = vulns
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
            .collect();
        matches::sync(pool, Subject::Asset(asset), &f, at)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_vulnerability_counts_once_in_the_band_of_its_open_matches() {
        let (_dir, pool) = db().await;
        found(&pool, 1, &["CVE-1", "CVE-2", "CVE-3"], NOW - 10 * DAY).await;
        found(&pool, 2, &["CVE-1"], NOW - 2 * DAY).await;
        let rows = matches::rows(&pool, &ALL_STATES).await.unwrap();
        let c = count(&rows, open_now);
        assert_eq!(
            c,
            Counts {
                crit: 1,
                high: 1,
                med: 0,
                low: 1,
                kev: 1
            }
        );
        assert_eq!(c.total(), 3);
    }

    #[tokio::test]
    async fn past_days_are_worked_out_unless_stored_and_today_is_live() {
        let (_dir, pool) = db().await;
        let tz = TimeZone::get("Europe/Berlin").unwrap();
        found(&pool, 1, &["CVE-1", "CVE-2"], NOW - 10 * DAY).await;
        found(&pool, 2, &["CVE-3"], NOW - 3 * DAY).await;
        // CVE-2 was closed four days ago: open before, not after.
        sqlx::query("UPDATE matches SET state = 'done', state_ms = ? WHERE vuln = 'CVE-2'")
            .bind(NOW - 4 * DAY)
            .execute(&pool)
            .await
            .unwrap();
        let rows = matches::rows(&pool, &ALL_STATES).await.unwrap();
        let days = trend(&pool, &rows, &tz, NOW, 30).await.unwrap();
        assert_eq!(days.len(), 30);
        assert_eq!(days[29].day.to_string(), "2026-11-06");
        assert!(!days[29].derived);
        let total = |i: usize| days[i].counts.total();
        assert_eq!(total(29), 2, "CVE-1 and CVE-3 today");
        assert_eq!(total(29 - 3), 2, "CVE-3 found on that day");
        assert_eq!(total(29 - 4), 1, "CVE-2 closed that day");
        assert_eq!(total(29 - 5), 2);
        assert_eq!(total(29 - 11), 0, "nothing found yet");
        assert!(days[29 - 5].derived);

        // A stored day wins over the reconstruction.
        let c = record_today(&pool, &tz, NOW - 5 * DAY).await.unwrap();
        assert_eq!(c.total(), 2, "stores what is open now");
        let days = trend(&pool, &rows, &tz, NOW, 30).await.unwrap();
        assert!(!days[29 - 5].derived);
        assert_eq!(days[29 - 5].counts.kev, 1);
    }

    #[tokio::test]
    async fn stored_days_past_the_retention_are_removed() {
        let (_dir, pool) = db().await;
        let tz = TimeZone::UTC;
        record_today(&pool, &tz, NOW - 500 * DAY).await.unwrap();
        record_today(&pool, &tz, NOW).await.unwrap();
        let days: Vec<String> = sqlx::query_scalar("SELECT day FROM situation_days")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(days, vec!["2026-11-06".to_owned()]);
    }
}
