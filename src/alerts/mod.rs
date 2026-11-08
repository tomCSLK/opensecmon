//! Notifications: the instant mail for new matches and the daily report.
//!
//! A task checks once a minute. A match goes out by instant mail when it is open, has not gone out yet and meets
//! the conditions (see [`reasons`]). When the conditions change (or mail is switched on), whatever meets them at
//! that moment is taken as known instead of being mailed, so switching on does not send the whole backlog.
//! The daily report goes out once at the configured local time; a time that passed while it was switched off
//! is not caught up.

pub mod compose;

use std::sync::Arc;
use std::time::Duration;

use jiff::tz::TimeZone;
use sqlx::SqlitePool;
use tokio::task::JoinHandle;

use crate::crypto::SecretBox;
use crate::error::Result;
use crate::i18n::{Lang, Msg};
use crate::mail::{self, MailConfig};
use crate::sources::{SourceId, now_ms};
use crate::storage::alerts::{self as store, Settings};
use crate::storage::mail::{self as mail_store, Kind};
use crate::storage::matches::{self, Row, State};
use crate::storage::sources as source_store;
use compose::{FailedSource, Links, Reason};

const TICK: Duration = Duration::from_secs(60);
/// How long the first match of a bundle waits for others.
pub const BUNDLE_MS: i64 = 10 * 60_000;
const RETRY_FIRST_MS: i64 = 15 * 60_000;
const RETRY_MAX_MS: i64 = 2 * 3_600_000;
const DAY_MS: i64 = 86_400_000;
/// Priority from which an open match counts as critical in the report (the band of the drafts).
const CRITICAL: i64 = 85;

/// Why a match qualifies for the instant mail; empty: it does not.
pub fn reasons(s: &Settings, r: &Row) -> Vec<Reason> {
    let mut out = Vec::new();
    if r.confidence() < s.min_confidence || r.muted() {
        return out;
    }
    if s.on_kev && r.kev {
        out.push(Reason::Kev);
    }
    let prio = r.prio();
    if s.prio_on && prio >= s.prio_min {
        out.push(Reason::Prio(prio, s.prio_min));
    }
    if s.cvss_on
        && let Some(score) = r.cvss_score
        && score >= s.cvss_min
    {
        out.push(Reason::Cvss(score, s.cvss_min));
    }
    if s.epss_on
        && let Some(epss) = r.epss
        && epss * 100.0 >= s.epss_min
    {
        out.push(Reason::Epss(epss * 100.0, s.epss_min));
    }
    out
}

/// The wait after `failures` failed attempts: 15 min, doubling, at most 2 h.
fn retry_delay(failures: i64) -> i64 {
    let shift = u32::try_from(failures.clamp(1, 8) - 1).unwrap_or(0);
    (RETRY_FIRST_MS << shift).min(RETRY_MAX_MS)
}

fn civil_time(minute: i64) -> jiff::civil::Time {
    let h = i8::try_from(minute.clamp(0, 1439) / 60).unwrap_or(0);
    let m = i8::try_from(minute.clamp(0, 1439) % 60).unwrap_or(0);
    jiff::civil::Time::new(h, m, 0, 0).unwrap_or_default()
}

fn at(tz: &TimeZone, date: jiff::civil::Date, minute: i64) -> Option<i64> {
    date.to_datetime(civil_time(minute))
        .to_zoned(tz.clone())
        .ok()
        .map(|z| z.timestamp().as_millisecond())
}

/// The most recent report time at or before `now_ms` (local `minute` after midnight in `tz`).
pub fn slot_ms(tz: &TimeZone, now_ms: i64, minute: i64) -> i64 {
    let Ok(now) = jiff::Timestamp::from_millisecond(now_ms) else {
        return 0;
    };
    let today = now.to_zoned(tz.clone()).date();
    match at(tz, today, minute) {
        Some(ms) if ms <= now_ms => ms,
        _ => today
            .yesterday()
            .ok()
            .and_then(|d| at(tz, d, minute))
            .unwrap_or(0),
    }
}

/// The next report time after `now_ms`.
pub fn next_slot_ms(tz: &TimeZone, now_ms: i64, minute: i64) -> i64 {
    let Ok(now) = jiff::Timestamp::from_millisecond(now_ms) else {
        return 0;
    };
    let today = now.to_zoned(tz.clone()).date();
    match at(tz, today, minute) {
        Some(ms) if ms > now_ms => ms,
        _ => today
            .tomorrow()
            .ok()
            .and_then(|d| at(tz, d, minute))
            .unwrap_or(0),
    }
}

fn links(settings: &Settings) -> Links<'_> {
    Links((!settings.public_url.is_empty()).then_some(settings.public_url.as_str()))
}

/// What a round of the instant mail did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Instant {
    /// Off (no mail or no instant mail).
    Off,
    /// The conditions changed: this many matches were taken as known.
    Baseline(usize),
    /// Nothing new.
    Idle,
    /// Matches wait (bundle or retry after an error).
    Waiting(usize),
    /// A mail with this many vulnerabilities went out.
    Sent(usize),
    Failed,
}

/// Matches that meet the conditions and have not gone out yet; with "once per vulnerability" those whose
/// vulnerability was mailed before are taken as known here.
async fn candidates(pool: &SqlitePool, s: &Settings, now: i64) -> Result<Vec<Row>> {
    let rows: Vec<Row> = matches::unalerted(pool)
        .await?
        .into_iter()
        .filter(|r| !reasons(s, r).is_empty())
        .collect();
    if !s.once_per_vuln || rows.is_empty() {
        return Ok(rows);
    }
    let mut vulns: Vec<String> = rows.iter().map(|r| r.vuln.clone()).collect();
    vulns.sort();
    vulns.dedup();
    let mailed = matches::mailed_vulns(pool, &vulns).await?;
    let (known, rest): (Vec<Row>, Vec<Row>) =
        rows.into_iter().partition(|r| mailed.contains(&r.vuln));
    let ids: Vec<i64> = known.iter().map(|r| r.id).collect();
    matches::set_alert(pool, &ids, false, now).await?;
    Ok(rest)
}

/// One round of the instant mail.
pub async fn instant_round(pool: &SqlitePool, secrets: &SecretBox, now: i64) -> Result<Instant> {
    let config = mail_store::load_config(pool, secrets).await?;
    let settings = store::settings(pool).await?;
    let mut state = store::state(pool).await?;
    // While the priorities follow new weights, they are half old, half new: wait.
    if crate::storage::prio::pending(pool).await? {
        return Ok(Instant::Idle);
    }
    let mut key = settings.alert_key(config.enabled);
    if key != "off" {
        // New weights change which matches meet the priority condition: no mail for those either.
        key.push_str("|w=");
        key.push_str(&crate::storage::prio::load(pool).await?.key());
    }
    if key != state.alert_key {
        let mut known = 0;
        if key != "off" {
            let rows: Vec<i64> = matches::unalerted(pool)
                .await?
                .iter()
                .filter(|r| !reasons(&settings, r).is_empty())
                .map(|r| r.id)
                .collect();
            known = rows.len();
            matches::set_alert(pool, &rows, false, now).await?;
            tracing::info!(
                known,
                "instant mail: conditions changed, current matches taken as known"
            );
        }
        state.alert_key = key;
        state.pending_since_ms = None;
        state.alert_failures = 0;
        state.alert_retry_ms = 0;
        store::save_alert_state(pool, &state).await?;
        return Ok(if known == 0 && state.alert_key == "off" {
            Instant::Off
        } else {
            Instant::Baseline(known)
        });
    }
    if key == "off" {
        return Ok(Instant::Off);
    }
    let rows = candidates(pool, &settings, now).await?;
    if rows.is_empty() {
        if state.pending_since_ms.is_some() {
            state.pending_since_ms = None;
            store::save_alert_state(pool, &state).await?;
        }
        return Ok(Instant::Idle);
    }
    let since = *state.pending_since_ms.get_or_insert(now);
    if (settings.bundle && now - since < BUNDLE_MS) || now < state.alert_retry_ms {
        store::save_alert_state(pool, &state).await?;
        return Ok(Instant::Waiting(rows.len()));
    }
    let items = compose::group(&rows, |r| reasons(&settings, r));
    let message = compose::instant(config.language, &items, &links(&settings));
    let outcome = deliver(pool, &config, Kind::Match, &message, now).await?;
    if outcome.is_ok() {
        let ids: Vec<i64> = rows.iter().map(|r| r.id).collect();
        matches::set_alert(pool, &ids, true, now).await?;
        state.pending_since_ms = None;
        state.alert_failures = 0;
        state.alert_retry_ms = 0;
        state.last_alert_ms = Some(now);
    } else {
        state.alert_failures += 1;
        state.alert_retry_ms = now + retry_delay(state.alert_failures);
    }
    store::save_alert_state(pool, &state).await?;
    Ok(match outcome {
        Ok(()) => Instant::Sent(items.len()),
        Err(_) => Instant::Failed,
    })
}

/// Sends a mail and records the attempt.
async fn deliver(
    pool: &SqlitePool,
    config: &MailConfig,
    kind: Kind,
    message: &compose::Mail,
    now: i64,
) -> Result<std::result::Result<(), Msg>> {
    let outcome = mail::send(config, &message.subject, &message.body)
        .await
        .map_err(|e| e.user_message());
    match &outcome {
        Ok(()) => tracing::info!(?kind, subject = %message.subject, "mail sent"),
        Err(e) => tracing::warn!(?kind, error = %e, "sending the mail failed"),
    }
    mail_store::record_notification(
        pool,
        now,
        kind,
        &message.subject,
        &config.recipients,
        outcome.as_ref().err(),
    )
    .await?;
    Ok(outcome)
}

/// The matches without those below the priority from which their asset shows matches.
fn unmuted(rows: Vec<Row>) -> Vec<Row> {
    rows.into_iter().filter(|r| !r.muted()).collect()
}

/// The content of the daily report as of `now`, in language `t`.
pub async fn build_report(
    pool: &SqlitePool,
    settings: &Settings,
    t: Lang,
    now: i64,
    last_report_ms: Option<i64>,
) -> Result<compose::Report> {
    let since_ms = last_report_ms.unwrap_or(now - DAY_MS);
    let no_reasons = |_: &Row| Vec::new();
    let new = if settings.report_new {
        Some(compose::group(
            &unmuted(matches::new_since(pool, since_ms).await?),
            no_reasons,
        ))
    } else {
        None
    };
    let open = if settings.report_open {
        let rows: Vec<Row> = matches::rows(pool, &[State::New, State::Seen])
            .await?
            .into_iter()
            .filter(|r| !r.muted() && (r.kev || r.prio() >= CRITICAL))
            .collect();
        Some(compose::group(&rows, no_reasons))
    } else {
        None
    };
    let due = if settings.report_due {
        Some(compose::group(
            &unmuted(matches::due_before(pool, now + DAY_MS).await?),
            no_reasons,
        ))
    } else {
        None
    };
    let sources = if settings.report_sources {
        Some(
            source_store::all(pool)
                .await?
                .into_iter()
                .filter(|s| s.enabled && s.failures > 0)
                .map(|s| FailedSource {
                    name: SourceId::parse(&s.source)
                        .map_or_else(|| s.source.clone(), |id| t.get(id.label_id())),
                    error: s.last_error.unwrap_or_default(),
                    last_success_ms: s.last_success_ms,
                })
                .collect(),
        )
    } else {
        None
    };
    let open_total = usize::try_from(matches::open_count(pool).await?).unwrap_or(0);
    Ok(compose::Report {
        now_ms: now,
        since_ms,
        new,
        open,
        due,
        sources,
        open_total,
    })
}

/// What a round of the daily report did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Report {
    Off,
    /// Switched on or moved: the next time counts.
    Armed,
    NotYet,
    /// Nothing to report and "skip empty" is on.
    Skipped,
    Sent,
    Failed,
}

/// One round of the daily report.
pub async fn report_round(
    pool: &SqlitePool,
    secrets: &SecretBox,
    tz: &TimeZone,
    now: i64,
) -> Result<Report> {
    let config = mail_store::load_config(pool, secrets).await?;
    let settings = store::settings(pool).await?;
    let mut state = store::state(pool).await?;
    let key = settings.report_key(config.enabled);
    let slot = if key == "off" {
        0
    } else {
        slot_ms(tz, now, settings.report_minute)
    };
    if key != state.report_key {
        state.report_key = key;
        state.report_slot_ms = slot;
        state.report_failures = 0;
        state.report_retry_ms = 0;
        store::save_report_state(pool, &state).await?;
        return Ok(if slot == 0 {
            Report::Off
        } else {
            Report::Armed
        });
    }
    if key == "off" {
        return Ok(Report::Off);
    }
    if slot <= state.report_slot_ms || now < state.report_retry_ms {
        return Ok(Report::NotYet);
    }
    let data = build_report(pool, &settings, config.language, now, state.last_report_ms).await?;
    if settings.report_skip_empty && data.is_empty() {
        tracing::info!("daily report: nothing to report");
        state.report_slot_ms = slot;
        store::save_report_state(pool, &state).await?;
        return Ok(Report::Skipped);
    }
    let message = compose::report(config.language, tz, &data, &links(&settings));
    let outcome = deliver(pool, &config, Kind::Report, &message, now).await?;
    if outcome.is_ok() {
        state.report_slot_ms = slot;
        state.report_failures = 0;
        state.report_retry_ms = 0;
        state.last_report_ms = Some(now);
    } else {
        state.report_failures += 1;
        state.report_retry_ms = now + retry_delay(state.report_failures);
    }
    store::save_report_state(pool, &state).await?;
    Ok(if outcome.is_ok() {
        Report::Sent
    } else {
        Report::Failed
    })
}

/// "Send now" on the settings page: the report as of now, also when it is empty or switched off.
/// Returns the recipients, or why it failed.
pub async fn send_report_now(
    pool: &SqlitePool,
    secrets: &SecretBox,
    tz: &TimeZone,
    now: i64,
) -> Result<std::result::Result<Vec<String>, Msg>> {
    let config = mail_store::load_config(pool, secrets).await?;
    let settings = store::settings(pool).await?;
    let mut state = store::state(pool).await?;
    let data = build_report(pool, &settings, config.language, now, state.last_report_ms).await?;
    let message = compose::report(config.language, tz, &data, &links(&settings));
    let outcome = deliver(pool, &config, Kind::Report, &message, now).await?;
    if outcome.is_ok() {
        state.last_report_ms = Some(now);
        store::save_report_state(pool, &state).await?;
    }
    Ok(outcome.map(|()| config.recipients))
}

/// The running notifier; [`Notifier::stop`] ends it.
pub struct Notifier {
    task: JoinHandle<()>,
}

impl Notifier {
    pub fn spawn(pool: SqlitePool, secrets: Arc<SecretBox>, tz: TimeZone) -> Self {
        let task = tokio::spawn(async move {
            let mut tick = tokio::time::interval(TICK);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let now = now_ms();
                if let Err(e) = instant_round(&pool, &secrets, now).await {
                    tracing::error!(error = %e, "instant mail round failed");
                }
                if let Err(e) = report_round(&pool, &secrets, &tz, now).await {
                    tracing::error!(error = %e, "daily report round failed");
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
mod tests;
