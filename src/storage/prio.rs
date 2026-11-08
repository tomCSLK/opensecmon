//! The weights of the priority (one row, page "Priority"). The SQL of the CVE priority reads them through
//! subqueries (`storage::cves::PRIO_SQL`), the priority of a match in Rust ([`Weights::match_prio`]).

use sqlx::SqlitePool;

use crate::error::Result;
use crate::storage::matches::{Confidence, Rating};

#[derive(Debug, Clone, Copy, PartialEq, sqlx::FromRow)]
pub struct Weights {
    pub cvss_weight: f64,
    pub epss_weight: f64,
    pub kev_floor: i64,
    pub penalty_medium: i64,
    pub penalty_low: i64,
    /// What a distribution's "unimportant" / "negligible" takes off.
    pub penalty_unimportant: i64,
    /// What "low", "no-dsa", "postponed" and "ignored" take off.
    pub penalty_minor: i64,
}

impl Default for Weights {
    /// The defaults of the migration (the formula of phases 2–7).
    fn default() -> Self {
        Self {
            cvss_weight: 7.0,
            epss_weight: 20.0,
            kev_floor: 90,
            penalty_medium: 10,
            penalty_low: 25,
            penalty_unimportant: 30,
            penalty_minor: 10,
        }
    }
}

impl Weights {
    /// What the confidence of a match takes off.
    pub fn penalty(&self, c: Confidence) -> i64 {
        match c {
            Confidence::High => 0,
            Confidence::Medium => self.penalty_medium,
            Confidence::Low => self.penalty_low,
        }
    }

    /// What the rating of the distribution takes off.
    pub fn rating_penalty(&self, r: Rating) -> i64 {
        match r {
            Rating::None => 0,
            Rating::Unimportant | Rating::Negligible => self.penalty_unimportant,
            Rating::Low | Rating::NoDsa | Rating::Postponed | Rating::Ignored => self.penalty_minor,
        }
    }

    /// The priority of a CVE (as `PRIO_SQL` computes it).
    pub fn cve_prio(&self, cvss: Option<f64>, epss_percentile: Option<f64>, kev: bool) -> i64 {
        let sum = (cvss.unwrap_or(0.0) * self.cvss_weight
            + epss_percentile.unwrap_or(0.0) * self.epss_weight)
            .min(100.0);
        let floor = if kev { self.kev_floor as f64 } else { 0.0 };
        sum.max(floor).round() as i64
    }

    /// The priority of a match: that of its vulnerability less what the confidence and the rating of the
    /// distribution take off; a match of medium or high confidence of a KEV CVE stays at the KEV floor.
    /// Describes the weights for the key of the instant mail (a change takes the current matches as known).
    pub fn key(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}:{}",
            self.cvss_weight,
            self.epss_weight,
            self.kev_floor,
            self.penalty_medium,
            self.penalty_low,
            self.penalty_unimportant,
            self.penalty_minor
        )
    }

    pub fn match_prio(&self, base: i64, kev: bool, confidence: Confidence, rating: Rating) -> i64 {
        let penalty = self.penalty(confidence) + self.rating_penalty(rating);
        self.floored(base, penalty, kev, confidence)
    }

    /// `base` less `penalty`, at least 0, and for a KEV CVE of medium or high confidence at least the floor.
    pub fn floored(&self, base: i64, penalty: i64, kev: bool, confidence: Confidence) -> i64 {
        let p = (base - penalty).max(0);
        if kev && confidence >= Confidence::Medium {
            p.max(self.kev_floor)
        } else {
            p
        }
    }
}

pub async fn load(pool: &SqlitePool) -> Result<Weights> {
    Ok(sqlx::query_as(
        "SELECT cvss_weight, epss_weight, kev_floor, penalty_medium, penalty_low, penalty_unimportant,
                penalty_minor
           FROM prio_settings WHERE id = 1",
    )
    .fetch_one(pool)
    .await?)
}

/// Whether the CVE priorities still have to follow new weights.
pub async fn pending(pool: &SqlitePool) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT recompute = 1 FROM prio_settings WHERE id = 1")
            .fetch_one(pool)
            .await?,
    )
}

/// Stores the weights (checked by the caller) and marks the CVE priorities for [`recompute`].
pub async fn save(pool: &SqlitePool, w: &Weights, now_ms: i64) -> Result<()> {
    sqlx::query(
        "UPDATE prio_settings SET cvss_weight = ?, epss_weight = ?, kev_floor = ?, penalty_medium = ?,
             penalty_low = ?, penalty_unimportant = ?, penalty_minor = ?, updated_ms = ?, recompute = 1
         WHERE id = 1",
    )
    .bind(w.cvss_weight)
    .bind(w.epss_weight)
    .bind(w.kev_floor)
    .bind(w.penalty_medium)
    .bind(w.penalty_low)
    .bind(w.penalty_unimportant)
    .bind(w.penalty_minor)
    .bind(now_ms)
    .execute(pool)
    .await?;
    Ok(())
}

/// Brings every CVE priority to the current weights (in slices, see `cves::in_batches`) and clears the mark,
/// unless the weights changed again meanwhile (then the next run follows). Returns the changed rows.
pub async fn recompute(pool: &SqlitePool) -> Result<u64> {
    let started: i64 = sqlx::query_scalar("SELECT updated_ms FROM prio_settings WHERE id = 1")
        .fetch_one(pool)
        .await?;
    let changed = crate::storage::cves::refresh_all_prios(pool).await?;
    sqlx::query("UPDATE prio_settings SET recompute = 0 WHERE id = 1 AND updated_ms = ?")
        .bind(started)
        .execute(pool)
        .await?;
    Ok(changed)
}

/// Starts [`recompute`] in the background (after saving, and on start when it was interrupted).
pub fn spawn_recompute(pool: SqlitePool) {
    tokio::spawn(async move {
        let started = std::time::Instant::now();
        match recompute(&pool).await {
            Ok(changed) => tracing::info!(
                changed,
                secs = started.elapsed().as_secs(),
                "priorities follow the new weights"
            ),
            Err(e) => tracing::error!(error = %e, "recomputing the priorities failed"),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{connect, migrate};

    #[tokio::test]
    async fn the_defaults_match_the_migration_and_the_sql() {
        let dir = tempfile::tempdir().unwrap();
        let pool = connect(&dir.path().join("p.db")).await.unwrap();
        migrate(&pool).await.unwrap();
        assert_eq!(load(&pool).await.unwrap(), Weights::default());
        sqlx::raw_sql(
            "INSERT INTO cves (id, state, cvss_score, epss_percentile, kev_added) VALUES
               ('CVE-1', 'published', 7.8, 0.82, NULL),
               ('CVE-2', 'published', 5.0, 0.1, '2026-01-01'),
               ('CVE-3', 'published', NULL, NULL, NULL);",
        )
        .execute(&pool)
        .await
        .unwrap();
        let check = |w: Weights| {
            let pool = pool.clone();
            async move {
                save(&pool, &w, 1).await.unwrap();
                assert!(pending(&pool).await.unwrap());
                recompute(&pool).await.unwrap();
                assert!(!pending(&pool).await.unwrap());
                let rows: Vec<(Option<f64>, Option<f64>, bool, i64)> = sqlx::query_as(
                    "SELECT cvss_score, epss_percentile, kev_added IS NOT NULL, prio FROM cves ORDER BY id",
                )
                .fetch_all(&pool)
                .await
                .unwrap();
                for (cvss, pct, kev, prio) in rows {
                    assert_eq!(w.cve_prio(cvss, pct, kev), prio, "{w:?} {cvss:?}");
                }
            }
        };
        check(Weights::default()).await;
        check(Weights {
            cvss_weight: 10.0,
            epss_weight: 50.0,
            kev_floor: 95,
            ..Weights::default()
        })
        .await;
        assert_eq!(
            Weights::default().cve_prio(Some(7.8), Some(0.82), false),
            71
        );
    }

    #[test]
    fn the_confidence_takes_off_and_kev_keeps_its_floor() {
        let w = Weights::default();
        assert_eq!(w.match_prio(80, false, Confidence::High, Rating::None), 80);
        assert_eq!(
            w.match_prio(80, false, Confidence::Medium, Rating::None),
            70
        );
        assert_eq!(w.match_prio(80, false, Confidence::Low, Rating::None), 55);
        assert_eq!(w.match_prio(90, true, Confidence::Medium, Rating::None), 90);
        assert_eq!(w.match_prio(90, true, Confidence::Low, Rating::None), 65);
        let w = Weights {
            penalty_medium: 0,
            kev_floor: 100,
            ..w
        };
        assert_eq!(
            w.match_prio(60, true, Confidence::Medium, Rating::None),
            100
        );
    }
}
