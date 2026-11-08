//! The matches between the own assets (or watchlist keywords) and the vulnerabilities: written by the
//! matching (`crate::matching`), read and changed by the inbox.

use std::collections::{HashMap, HashSet};

use sqlx::SqlitePool;

use crate::error::Result;

/// How sure a match is (see migrations/0007_assets.sql).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "high" => Self::High,
            "medium" => Self::Medium,
            _ => Self::Low,
        }
    }

    pub fn label_id(self) -> &'static str {
        match self {
            Self::High => "match-confidence-high",
            Self::Medium => "match-confidence-medium",
            Self::Low => "match-confidence-low",
        }
    }
}

/// How a match was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    Distro,
    Nvd,
    Cna,
    Csaf,
    Watch,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Distro => "distro",
            Self::Nvd => "nvd",
            Self::Cna => "cna",
            Self::Csaf => "csaf",
            Self::Watch => "watch",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "distro" => Self::Distro,
            "nvd" => Self::Nvd,
            "cna" => Self::Cna,
            "csaf" => Self::Csaf,
            _ => Self::Watch,
        }
    }

    pub fn label_id(self) -> &'static str {
        match self {
            Self::Distro => "match-method-distro",
            Self::Nvd => "match-method-nvd",
            Self::Cna => "match-method-cna",
            Self::Csaf => "match-method-csaf",
            Self::Watch => "match-method-watch",
        }
    }
}

/// How the distribution rates a match of a package: Debian's Security Tracker ("unimportant", no DSA planned
/// with the reason "postponed" or "ignored", urgency "low") or Ubuntu's priority ("negligible", "low"). It takes
/// off from the priority (page "Priority"), see migration 0018.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Rating {
    #[default]
    None,
    Unimportant,
    Negligible,
    Low,
    NoDsa,
    Postponed,
    Ignored,
}

impl Rating {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "",
            Self::Unimportant => "unimportant",
            Self::Negligible => "negligible",
            Self::Low => "low",
            Self::NoDsa => "no-dsa",
            Self::Postponed => "postponed",
            Self::Ignored => "ignored",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "unimportant" => Self::Unimportant,
            "negligible" => Self::Negligible,
            "low" => Self::Low,
            "no-dsa" => Self::NoDsa,
            "postponed" => Self::Postponed,
            "ignored" => Self::Ignored,
            _ => Self::None,
        }
    }

    /// The rating of the Debian Security Tracker for one package and release (`urgency`, the no-DSA text and
    /// its reason); the strongest word wins.
    pub fn of_debian(urgency: &str, nodsa: &str, nodsa_reason: &str) -> Self {
        if urgency == "unimportant" {
            Self::Unimportant
        } else if nodsa_reason == "ignored" {
            Self::Ignored
        } else if nodsa_reason == "postponed" {
            Self::Postponed
        } else if !nodsa.is_empty() || !nodsa_reason.is_empty() {
            Self::NoDsa
        } else if urgency.starts_with("low") {
            Self::Low
        } else {
            Self::None
        }
    }

    /// Ubuntu's priority of a CVE.
    pub fn of_ubuntu(priority: &str) -> Self {
        match priority.to_ascii_lowercase().as_str() {
            "negligible" => Self::Negligible,
            "low" => Self::Low,
            _ => Self::None,
        }
    }

    /// The text of the rating (`None` for no rating).
    pub fn label_id(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Unimportant => Some("rating-unimportant"),
            Self::Negligible => Some("rating-negligible"),
            Self::Low => Some("rating-low"),
            Self::NoDsa => Some("rating-no-dsa"),
            Self::Postponed => Some("rating-postponed"),
            Self::Ignored => Some("rating-ignored"),
        }
    }
}

/// The priority of a report without a CVE from its severity word (critical, high, medium, low …).
pub fn severity_prio(severity: &str) -> i64 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" | "kritisch" => 90,
        "high" | "hoch" => 70,
        "medium" | "mittel" | "moderate" => 50,
        "low" | "niedrig" => 30,
        "negligible" | "unimportant" => 10,
        _ => 40,
    }
}

/// The state of a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum State {
    New,
    Seen,
    Later,
    Done,
    Ignored,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Seen => "seen",
            Self::Later => "later",
            Self::Done => "done",
            Self::Ignored => "ignored",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "new" => Self::New,
            "seen" => Self::Seen,
            "later" => Self::Later,
            "done" => Self::Done,
            "ignored" => Self::Ignored,
            _ => return None,
        })
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::New | Self::Seen)
    }
}

/// Who is affected: an asset or a watchlist keyword.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subject {
    Asset(i64),
    Watch(i64),
}

impl Subject {
    pub fn key(self) -> String {
        match self {
            Self::Asset(id) => format!("a:{id}"),
            Self::Watch(id) => format!("w:{id}"),
        }
    }
}

/// A match the matching found (not yet stored).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub vuln: String,
    pub title: String,
    pub confidence: Confidence,
    pub method: Method,
    pub fixed: String,
    pub evidence: Vec<String>,
    pub base_prio: i64,
    /// How the distribution rates it (only for matches of packages with a CVE).
    pub rating: Rating,
}

/// What [`sync`] changed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Synced {
    pub new: u64,
    pub reopened: u64,
    pub resolved: u64,
}

/// Rows per transaction of [`sync`].
const CHUNK: usize = 500;

/// Stores what the matching found for `subject`: new matches start as "new", known ones get the new
/// details, matches that were closed automatically open again, and open matches that were not found any
/// more are closed automatically (the asset was updated). Ignored and done ones stay as they are.
pub async fn sync(
    pool: &SqlitePool,
    subject: Subject,
    found: &[Found],
    now_ms: i64,
) -> Result<Synced> {
    let key = subject.key();
    let known: Vec<(i64, String, String, bool, bool)> = sqlx::query_as(
        "SELECT id, vuln, state, auto, gone_ms IS NOT NULL FROM matches WHERE subject = ?",
    )
    .bind(&key)
    .fetch_all(pool)
    .await?;
    let known: HashMap<String, (i64, String, bool, bool)> = known
        .into_iter()
        .map(|(id, vuln, state, auto, gone)| (vuln, (id, state, auto, gone)))
        .collect();
    let (asset_id, watch_id) = match subject {
        Subject::Asset(id) => (Some(id), None),
        Subject::Watch(id) => (None, Some(id)),
    };
    let mut out = Synced::default();
    let mut seen = HashSet::new();
    for chunk in found.chunks(CHUNK) {
        let mut tx = pool.begin().await?;
        for f in chunk {
            if !seen.insert(f.vuln.as_str()) {
                continue;
            }
            let evidence = f.evidence.join(",");
            match known.get(&f.vuln) {
                Some((id, state, auto, _)) => {
                    let reopen = state == "done" && *auto;
                    if reopen {
                        out.reopened += 1;
                    }
                    sqlx::query(
                        "UPDATE matches SET title = ?, confidence = ?, method = ?, fixed = ?, evidence = ?,
                             base_prio = ?, updated_ms = ?, gone_ms = NULL,
                             state = CASE WHEN ?8 THEN 'new' ELSE state END,
                             auto = CASE WHEN ?8 THEN 0 ELSE auto END,
                             state_ms = CASE WHEN ?8 THEN ?7 ELSE state_ms END,
                             rating = ?10
                         WHERE id = ?9",
                    )
                    .bind(&f.title)
                    .bind(f.confidence.as_str())
                    .bind(f.method.as_str())
                    .bind(&f.fixed)
                    .bind(&evidence)
                    .bind(f.base_prio)
                    .bind(now_ms)
                    .bind(reopen)
                    .bind(id)
                    .bind(f.rating.as_str())
                    .execute(&mut *tx)
                    .await?;
                }
                None => {
                    out.new += 1;
                    sqlx::query(
                        "INSERT INTO matches (subject, asset_id, watch_id, vuln, title, confidence, method,
                             fixed, evidence, base_prio, first_seen_ms, updated_ms, state_ms, rating)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    )
                    .bind(&key)
                    .bind(asset_id)
                    .bind(watch_id)
                    .bind(&f.vuln)
                    .bind(&f.title)
                    .bind(f.confidence.as_str())
                    .bind(f.method.as_str())
                    .bind(&f.fixed)
                    .bind(&evidence)
                    .bind(f.base_prio)
                    .bind(now_ms)
                    .bind(now_ms)
                    .bind(now_ms)
                    .bind(f.rating.as_str())
                    .execute(&mut *tx)
                    .await?;
                }
            }
        }
        tx.commit().await?;
    }
    // Matches no longer found: open ones are done by themselves; every one notes since when it is gone (the
    // retention removes closed matches some time after that).
    let gone: Vec<(i64, bool)> = known
        .iter()
        .filter(|(vuln, (_, state, _, gone))| {
            !seen.contains(vuln.as_str())
                && (!gone || matches!(state.as_str(), "new" | "seen" | "later"))
        })
        .map(|(_, (id, state, _, _))| (*id, matches!(state.as_str(), "new" | "seen" | "later")))
        .collect();
    for chunk in gone.chunks(CHUNK) {
        let mut tx = pool.begin().await?;
        for (id, open) in chunk {
            if *open {
                sqlx::query(
                    "UPDATE matches SET state = 'done', auto = 1, until_ms = NULL, state_ms = ?1, updated_ms = ?1,
                         gone_ms = COALESCE(gone_ms, ?1)
                     WHERE id = ?2",
                )
                .bind(now_ms)
                .bind(id)
                .execute(&mut *tx)
                .await?;
                out.resolved += 1;
            } else {
                sqlx::query("UPDATE matches SET gone_ms = ? WHERE id = ? AND gone_ms IS NULL")
                    .bind(now_ms)
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        tx.commit().await?;
    }
    Ok(out)
}

/// Removes done and ignored matches that have not been found for `days` days (0 keeps them); returns how many.
/// Matches that are still found stay whatever their state, or they would come back as new.
pub async fn apply_retention(pool: &SqlitePool, days: i64, now_ms: i64) -> Result<u64> {
    if days <= 0 {
        return Ok(0);
    }
    let before = now_ms.saturating_sub(days.saturating_mul(86_400_000));
    Ok(sqlx::query(
        "DELETE FROM matches WHERE state IN ('done', 'ignored') AND gone_ms IS NOT NULL AND gone_ms < ?",
    )
    .bind(before)
    .execute(pool)
    .await?
    .rows_affected())
}

/// Opens matches whose "later" date has come; returns how many.
pub async fn wake_later(pool: &SqlitePool, now_ms: i64) -> Result<u64> {
    Ok(sqlx::query(
        "UPDATE matches SET state = 'seen', until_ms = NULL, state_ms = ?1
         WHERE state = 'later' AND until_ms <= ?1",
    )
    .bind(now_ms)
    .execute(pool)
    .await?
    .rows_affected())
}

/// [`wake_later`] for pages: skipped while the database is being compacted (it would wait for the lock), a
/// failure is only logged; the housekeeping wakes them as well.
pub async fn wake_later_for_page(pool: &SqlitePool, now_ms: i64) {
    if crate::storage::retention::vacuum_state(pool)
        .await
        .is_ok_and(|v| v.running())
    {
        return;
    }
    if let Err(e) = wake_later(pool, now_ms).await {
        tracing::warn!(error = %e, "opening postponed matches failed");
    }
}

/// One match with what the inbox shows of it.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct Row {
    pub id: i64,
    pub vuln: String,
    pub asset_id: Option<i64>,
    pub watch_id: Option<i64>,
    pub confidence: String,
    pub method: String,
    pub fixed: String,
    pub evidence: String,
    pub state: String,
    pub until_ms: Option<i64>,
    pub reason: String,
    pub note: String,
    pub auto: bool,
    pub first_seen_ms: i64,
    pub state_ms: i64,
    pub title: String,
    pub kev: bool,
    pub base: i64,
    pub published_ms: Option<i64>,
    pub cvss_score: Option<f64>,
    /// EPSS probability (0–1).
    pub epss: Option<f64>,
    /// Instant mail: '', 'sent' or 'quiet' (see migration 0009).
    pub alert: String,
    pub alert_ms: Option<i64>,
    /// What the confidence of this match takes off and the KEV floor (from `prio_settings`).
    pub penalty: i64,
    pub kev_floor: i64,
    pub kind: Option<String>,
    pub vendor_name: Option<String>,
    pub product_name: Option<String>,
    pub version: Option<String>,
    pub host: Option<String>,
    pub distro: Option<String>,
    pub release: Option<String>,
    pub pro: Option<bool>,
    pub keyword: Option<String>,
    /// The priority from which the asset shows its matches (0: all; keywords always).
    pub min_prio: i64,
    /// How the distribution rates the match (see [`Rating`]) and what that takes off (part of `penalty`).
    pub rating: String,
    pub rating_penalty: i64,
}

impl Row {
    pub fn confidence(&self) -> Confidence {
        Confidence::parse(&self.confidence)
    }

    pub fn state(&self) -> State {
        State::parse(&self.state).unwrap_or(State::Seen)
    }

    pub fn rating(&self) -> Rating {
        Rating::parse(&self.rating)
    }

    /// The priority of the match with the weights of `prio_settings` (read with the row).
    pub fn prio(&self) -> i64 {
        let w = crate::storage::prio::Weights {
            kev_floor: self.kev_floor,
            ..crate::storage::prio::Weights::default()
        };
        w.floored(self.base, self.penalty, self.kev, self.confidence())
    }

    /// Below the priority from which its asset shows matches: left out of the inbox (unless filtered by the
    /// asset), the counts, the page "Situation" and the mails.
    pub fn muted(&self) -> bool {
        self.min_prio > 0 && self.prio() < self.min_prio
    }
}

/// What the confidence of a match `m` takes off with the weights `p` (SQL, as `Weights::penalty`).
macro_rules! confidence_penalty_sql {
    () => {
        "(CASE m.confidence WHEN 'medium' THEN p.penalty_medium WHEN 'low' THEN p.penalty_low ELSE 0 END)"
    };
}

/// What the distribution's rating of a match `m` takes off with the weights `p` (SQL, as
/// `Weights::rating_penalty`).
macro_rules! rating_penalty_sql {
    () => {
        "(CASE WHEN m.rating IN ('unimportant', 'negligible') THEN p.penalty_unimportant
               WHEN m.rating IN ('low', 'no-dsa', 'postponed', 'ignored') THEN p.penalty_minor ELSE 0 END)"
    };
}

const ROW_SQL: &str = concat!(
    "SELECT m.id, m.vuln, m.asset_id, m.watch_id, m.confidence, m.method, m.fixed, m.evidence,
        m.state, m.until_ms, m.reason, m.note, m.auto, m.first_seen_ms, m.state_ms,
        COALESCE(NULLIF(c.title, ''), m.title) AS title, c.kev_added IS NOT NULL AS kev,
        COALESCE(c.prio, m.base_prio) AS base, c.published_ms, c.cvss_score, c.epss, m.alert, m.alert_ms, ",
    confidence_penalty_sql!(),
    " + ",
    rating_penalty_sql!(),
    " AS penalty, p.kev_floor,
        a.kind, a.vendor_name, a.product_name, a.version, a.host, a.distro, a.release, a.pro, w.keyword,
        COALESCE(a.min_prio, 0) AS min_prio, m.rating, ",
    rating_penalty_sql!(),
    " AS rating_penalty
     FROM matches m
     LEFT JOIN cves c ON c.id = m.vuln
     LEFT JOIN assets a ON a.id = m.asset_id
     LEFT JOIN watchlist w ON w.id = m.watch_id
     CROSS JOIN prio_settings p"
);

/// The matches in the given states.
pub async fn rows(pool: &SqlitePool, states: &[State]) -> Result<Vec<Row>> {
    let marks = vec!["?"; states.len().max(1)].join(",");
    let sql = format!("{ROW_SQL} WHERE m.state IN ({marks})");
    let mut q = sqlx::query_as(&sql);
    if states.is_empty() {
        q = q.bind("");
    }
    for s in states {
        q = q.bind(s.as_str());
    }
    Ok(q.fetch_all(pool).await?)
}

/// Open matches that have not gone out by instant mail yet (for the notifier).
pub async fn unalerted(pool: &SqlitePool) -> Result<Vec<Row>> {
    Ok(sqlx::query_as(&format!(
        "{ROW_SQL} WHERE m.alert = '' AND m.state IN ('new', 'seen') ORDER BY m.id"
    ))
    .fetch_all(pool)
    .await?)
}

/// Marks matches as sent by instant mail (`sent`) or as known without a mail (`quiet`).
pub async fn set_alert(pool: &SqlitePool, ids: &[i64], sent: bool, now_ms: i64) -> Result<()> {
    for chunk in ids.chunks(CHUNK) {
        let mut tx = pool.begin().await?;
        for id in chunk {
            sqlx::query("UPDATE matches SET alert = ?, alert_ms = ? WHERE id = ?")
                .bind(if sent { "sent" } else { "quiet" })
                .bind(now_ms)
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
    }
    Ok(())
}

/// The vulnerabilities among `vulns` that already went out by instant mail.
pub async fn mailed_vulns(pool: &SqlitePool, vulns: &[String]) -> Result<HashSet<String>> {
    let mut out = HashSet::new();
    for chunk in vulns.chunks(CHUNK) {
        let marks = vec!["?"; chunk.len()].join(",");
        let sql =
            format!("SELECT DISTINCT vuln FROM matches WHERE alert = 'sent' AND vuln IN ({marks})");
        let mut q = sqlx::query_scalar::<_, String>(&sql);
        for v in chunk {
            q = q.bind(v);
        }
        out.extend(q.fetch_all(pool).await?);
    }
    Ok(out)
}

/// Matches found since `since_ms` that are still open (for the daily report).
pub async fn new_since(pool: &SqlitePool, since_ms: i64) -> Result<Vec<Row>> {
    Ok(sqlx::query_as(&format!(
        "{ROW_SQL} WHERE m.state IN ('new', 'seen') AND m.first_seen_ms > ? ORDER BY m.id"
    ))
    .bind(since_ms)
    .fetch_all(pool)
    .await?)
}

/// Postponed matches that open again before `until_ms` (for the daily report).
pub async fn due_before(pool: &SqlitePool, until_ms: i64) -> Result<Vec<Row>> {
    Ok(sqlx::query_as(&format!(
        "{ROW_SQL} WHERE m.state = 'later' AND m.until_ms <= ? ORDER BY m.until_ms, m.id"
    ))
    .bind(until_ms)
    .fetch_all(pool)
    .await?)
}

/// All matches of one vulnerability (any state).
pub async fn for_vuln(pool: &SqlitePool, vuln: &str) -> Result<Vec<Row>> {
    Ok(
        sqlx::query_as(&format!("{ROW_SQL} WHERE m.vuln = ? ORDER BY m.id"))
            .bind(vuln)
            .fetch_all(pool)
            .await?,
    )
}

/// Vulnerabilities per state (a vulnerability with matches in two states counts in both).
pub async fn counts(pool: &SqlitePool) -> Result<HashMap<String, i64>> {
    let rows: Vec<(String, i64)> =
        sqlx::query_as("SELECT state, COUNT(DISTINCT vuln) FROM matches GROUP BY state")
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().collect())
}

/// The number of vulnerabilities with open matches (for the navigation).
pub async fn open_count(pool: &SqlitePool) -> Result<i64> {
    Ok(sqlx::query_scalar(&format!(
        "SELECT COUNT(DISTINCT m.vuln) FROM matches m
         LEFT JOIN assets a ON a.id = m.asset_id
         LEFT JOIN cves c ON c.id = m.vuln
         CROSS JOIN prio_settings p
         WHERE m.state IN ('new', 'seen') AND (COALESCE(a.min_prio, 0) = 0 OR {MATCH_PRIO_SQL} >= a.min_prio)"
    ))
    .fetch_one(pool)
    .await?)
}

/// The priority of a match in SQL, as [`Row::prio`] computes it (`m` the match, `c` its CVE, `p` the weights).
const MATCH_PRIO_SQL: &str = concat!(
    "max(max(COALESCE(c.prio, m.base_prio) - ",
    confidence_penalty_sql!(),
    " - ",
    rating_penalty_sql!(),
    ", 0),
        CASE WHEN c.kev_added IS NOT NULL AND m.confidence != 'low' THEN p.kev_floor ELSE 0 END)"
);

/// The open matches of one asset (muted ones left out).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpenOfAsset {
    pub count: i64,
    /// The highest priority among them.
    pub prio: i64,
    /// Their vulnerabilities, to count each once per host (two packages often share a CVE).
    pub vulns: Vec<String>,
}

/// Open matches per asset (for the asset list).
pub async fn open_per_asset(pool: &SqlitePool) -> Result<HashMap<i64, OpenOfAsset>> {
    let rows = rows(pool, &[State::New, State::Seen]).await?;
    let mut out: HashMap<i64, OpenOfAsset> = HashMap::new();
    for r in rows.iter().filter(|r| !r.muted()) {
        if let Some(id) = r.asset_id {
            let e = out.entry(id).or_default();
            e.count += 1;
            e.prio = e.prio.max(r.prio());
            e.vulns.push(r.vuln.clone());
        }
    }
    Ok(out)
}

/// Per host read over SSH or computer that reports (`origin_ref`): the packages with open matches and the
/// different vulnerabilities among them. Muted matches do not count, as in the asset list.
pub async fn open_per_origin(pool: &SqlitePool) -> Result<HashMap<String, (i64, i64)>> {
    let rows: Vec<(String, i64, i64)> = sqlx::query_as(&format!(
        "SELECT a.origin_ref, COUNT(DISTINCT a.id), COUNT(DISTINCT m.vuln)
         FROM matches m JOIN assets a ON a.id = m.asset_id
         LEFT JOIN cves c ON c.id = m.vuln
         CROSS JOIN prio_settings p
         WHERE a.origin IN ('ssh', 'agent') AND m.state IN ('new', 'seen')
           AND (a.min_prio = 0 OR {MATCH_PRIO_SQL} >= a.min_prio)
         GROUP BY a.origin_ref"
    ))
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(o, p, v)| (o, (p, v))).collect())
}

/// Open matches per keyword of the watchlist.
pub async fn open_per_watch(pool: &SqlitePool) -> Result<HashMap<i64, i64>> {
    let rows: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT watch_id, COUNT(*) FROM matches
         WHERE watch_id IS NOT NULL AND state IN ('new', 'seen') GROUP BY watch_id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().collect())
}

/// The vulnerabilities that have a match (any state), for the filter "only mine" of "All CVEs".
pub const MINE_SQL: &str = "SELECT vuln FROM matches WHERE state != 'ignored'";

/// A change of state the inbox asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub state: State,
    pub until_ms: Option<i64>,
    pub reason: String,
    pub note: String,
}

/// Sets the state of matches; returns how many changed. "seen" only applies to new matches (opening the
/// detail), everything else to any match.
pub async fn set_state(
    pool: &SqlitePool,
    ids: &[i64],
    change: &Change,
    now_ms: i64,
) -> Result<u64> {
    let mut done = 0;
    for chunk in ids.chunks(CHUNK) {
        let marks = vec!["?"; chunk.len()].join(",");
        let only_new = if change.state == State::Seen {
            " AND state = 'new'"
        } else {
            ""
        };
        let sql = format!(
            "UPDATE matches SET state = ?, until_ms = ?, reason = ?, note = ?, auto = 0, state_ms = ?
             WHERE id IN ({marks}){only_new}"
        );
        let mut q = sqlx::query(&sql)
            .bind(change.state.as_str())
            .bind(change.until_ms)
            .bind(&change.reason)
            .bind(&change.note)
            .bind(now_ms);
        for id in chunk {
            q = q.bind(id);
        }
        done += q.execute(pool).await?.rows_affected();
    }
    Ok(done)
}

/// Marks the new matches of a vulnerability as seen (the detail was opened).
pub async fn mark_seen(pool: &SqlitePool, vuln: &str, now_ms: i64) -> Result<u64> {
    Ok(sqlx::query(
        "UPDATE matches SET state = 'seen', state_ms = ? WHERE vuln = ? AND state = 'new'",
    )
    .bind(now_ms)
    .bind(vuln)
    .execute(pool)
    .await?
    .rows_affected())
}

/// The ids of the matches of these vulnerabilities in the given states.
pub async fn ids_of(pool: &SqlitePool, vulns: &[String], states: &[State]) -> Result<Vec<i64>> {
    let mut out = Vec::new();
    for chunk in vulns.chunks(CHUNK) {
        let marks = vec!["?"; chunk.len()].join(",");
        let state_marks = vec!["?"; states.len().max(1)].join(",");
        let sql = format!(
            "SELECT id FROM matches WHERE vuln IN ({marks}) AND state IN ({state_marks}) ORDER BY id"
        );
        let mut q = sqlx::query_scalar::<_, i64>(&sql);
        for v in chunk {
            q = q.bind(v);
        }
        if states.is_empty() {
            q = q.bind("");
        }
        for s in states {
            q = q.bind(s.as_str());
        }
        out.extend(q.fetch_all(pool).await?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ratings_of_debian_and_ubuntu() {
        assert_eq!(
            Rating::of_debian("unimportant", "Minor issue", "ignored"),
            Rating::Unimportant
        );
        assert_eq!(
            Rating::of_debian("not yet assigned", "x", "ignored"),
            Rating::Ignored
        );
        assert_eq!(
            Rating::of_debian("not yet assigned", "x", "postponed"),
            Rating::Postponed
        );
        assert_eq!(
            Rating::of_debian("not yet assigned", "Minor issue", ""),
            Rating::NoDsa
        );
        assert_eq!(Rating::of_debian("low**", "", ""), Rating::Low);
        assert_eq!(Rating::of_debian("not yet assigned", "", ""), Rating::None);
        assert_eq!(Rating::of_debian("end-of-life", "", ""), Rating::None);
        assert_eq!(Rating::of_ubuntu("Negligible"), Rating::Negligible);
        assert_eq!(Rating::of_ubuntu("low"), Rating::Low);
        assert_eq!(Rating::of_ubuntu("medium"), Rating::None);
        for r in [
            Rating::None,
            Rating::Unimportant,
            Rating::Negligible,
            Rating::Low,
            Rating::NoDsa,
            Rating::Postponed,
            Rating::Ignored,
        ] {
            assert_eq!(Rating::parse(r.as_str()), r);
            if let Some(id) = r.label_id() {
                for t in crate::i18n::Lang::ALL {
                    assert_ne!(t.get(id), id, "{id} is missing");
                }
            }
        }
    }

    fn found(vuln: &str) -> Found {
        Found {
            vuln: vuln.to_owned(),
            title: format!("about {vuln}"),
            confidence: Confidence::High,
            method: Method::Distro,
            fixed: "1.1".into(),
            evidence: vec!["USN-1-1".into()],
            base_prio: 0,
            rating: crate::storage::matches::Rating::None,
        }
    }

    async fn pool() -> (SqlitePool, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pool = crate::storage::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        crate::storage::migrate(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO assets (id, kind, product, product_name, created_ms, updated_ms)
             VALUES (1, 'software', 'x', 'X', 0, 0)",
        )
        .execute(&pool)
        .await
        .unwrap();
        (pool, dir)
    }

    async fn state_of(pool: &SqlitePool, vuln: &str) -> (String, bool) {
        sqlx::query_as("SELECT state, auto FROM matches WHERE vuln = ?")
            .bind(vuln)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[test]
    fn the_priority_follows_the_confidence() {
        let w = crate::storage::prio::Weights::default();
        assert_eq!(w.match_prio(70, false, Confidence::High, Rating::None), 70);
        assert_eq!(
            w.match_prio(70, false, Confidence::Medium, Rating::None),
            60
        );
        assert_eq!(w.match_prio(70, true, Confidence::Medium, Rating::None), 90);
        assert_eq!(w.match_prio(95, true, Confidence::Low, Rating::None), 70);
        assert_eq!(w.match_prio(5, false, Confidence::Low, Rating::None), 0);
        assert_eq!(severity_prio("Critical"), 90);
        assert_eq!(severity_prio("?"), 40);
    }

    #[tokio::test]
    async fn matches_open_close_and_open_again() {
        let (pool, _dir) = pool().await;
        let s = Subject::Asset(1);
        let r = sync(&pool, s, &[found("CVE-2026-1"), found("CVE-2026-2")], 10)
            .await
            .unwrap();
        assert_eq!(r.new, 2);
        assert_eq!(open_count(&pool).await.unwrap(), 2);

        // The user ignores one; the asset is updated and the other disappears.
        let ids = ids_of(&pool, &["CVE-2026-2".into()], &[State::New])
            .await
            .unwrap();
        let ignore = Change {
            state: State::Ignored,
            until_ms: None,
            reason: "not used".into(),
            note: String::new(),
        };
        assert_eq!(set_state(&pool, &ids, &ignore, 11).await.unwrap(), 1);
        let r = sync(&pool, s, &[], 12).await.unwrap();
        assert_eq!(r.resolved, 1);
        assert_eq!(state_of(&pool, "CVE-2026-1").await, ("done".into(), true));
        assert_eq!(
            state_of(&pool, "CVE-2026-2").await,
            ("ignored".into(), false)
        );

        // It comes back (older version): open again; the ignored one stays ignored.
        let r = sync(&pool, s, &[found("CVE-2026-1"), found("CVE-2026-2")], 13)
            .await
            .unwrap();
        assert_eq!((r.new, r.reopened), (0, 1));
        assert_eq!(state_of(&pool, "CVE-2026-1").await, ("new".into(), false));
        assert_eq!(
            state_of(&pool, "CVE-2026-2").await,
            ("ignored".into(), false)
        );
        assert_eq!(counts(&pool).await.unwrap().get("ignored"), Some(&1));

        // Seen only touches new matches; later wakes up.
        assert_eq!(mark_seen(&pool, "CVE-2026-1", 14).await.unwrap(), 1);
        let later = Change {
            state: State::Later,
            until_ms: Some(20),
            reason: String::new(),
            note: String::new(),
        };
        let ids = ids_of(&pool, &["CVE-2026-1".into()], &[State::Seen])
            .await
            .unwrap();
        set_state(&pool, &ids, &later, 15).await.unwrap();
        assert_eq!(wake_later(&pool, 19).await.unwrap(), 0);
        assert_eq!(wake_later(&pool, 20).await.unwrap(), 1);
        let rows = rows(&pool, &[State::Seen]).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].title, "about CVE-2026-1");
        assert_eq!(rows[0].product_name.as_deref(), Some("X"));

        // Deleting the asset removes its matches.
        crate::storage::assets::delete(&pool, 1).await.unwrap();
        assert!(counts(&pool).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_open_count_leaves_out_muted_matches_as_the_rows_do() {
        let dir = tempfile::tempdir().unwrap();
        let pool = crate::storage::connect(&dir.path().join("m.db"))
            .await
            .unwrap();
        crate::storage::migrate(&pool).await.unwrap();
        sqlx::raw_sql(
            "INSERT INTO cves (id, state, prio, kev_added) VALUES
               ('CVE-1', 'published', 90, NULL), ('CVE-2', 'published', 70, NULL),
               ('CVE-3', 'published', 40, '2026-01-01'), ('CVE-4', 'published', 60, NULL);
             INSERT INTO assets (id, kind, product, product_name, min_prio, created_ms, updated_ms) VALUES
               (1, 'package', 'linux', 'linux', 65, 0, 0), (2, 'software', 'b', 'B', 0, 0, 0);",
        )
        .execute(&pool)
        .await
        .unwrap();
        let found = |vuln: &str, confidence| Found {
            vuln: vuln.to_owned(),
            title: String::new(),
            confidence,
            method: Method::Distro,
            fixed: String::new(),
            evidence: Vec::new(),
            base_prio: 0,
            rating: crate::storage::matches::Rating::None,
        };
        // On the kernel: 90 shows, 70 medium (60) is muted, KEV 40 high is lifted to 90, 60 is muted.
        sync(
            &pool,
            Subject::Asset(1),
            &[
                found("CVE-1", Confidence::High),
                found("CVE-2", Confidence::Medium),
                found("CVE-3", Confidence::High),
                found("CVE-4", Confidence::High),
            ],
            1,
        )
        .await
        .unwrap();
        let rows = rows(&pool, &[State::New, State::Seen]).await.unwrap();
        let mut shown: Vec<&str> = rows
            .iter()
            .filter(|r| !r.muted())
            .map(|r| r.vuln.as_str())
            .collect();
        shown.sort_unstable();
        assert_eq!(shown, ["CVE-1", "CVE-3"]);
        assert_eq!(open_count(&pool).await.unwrap(), 2);
        // The same CVE on an asset without a minimum counts.
        sync(
            &pool,
            Subject::Asset(2),
            &[found("CVE-4", Confidence::Low)],
            1,
        )
        .await
        .unwrap();
        assert_eq!(open_count(&pool).await.unwrap(), 3);
        let per_asset = open_per_asset(&pool).await.unwrap();
        assert_eq!(per_asset.get(&1).map(|o| (o.count, o.prio)), Some((2, 90)));
    }
}
