//! The OSV records of Debian and Ubuntu from `osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/`.
//!
//! Debian publishes its advisories (DSA, DLA, DTSA) and one record per CVE (DEBIAN-CVE-…), Ubuntu its
//! notices (USN, LSN) and one record per CVE (UBUNTU-CVE-…). Every record names the affected source
//! packages per release with ranges of versions ("introduced 0, fixed 1.26.3-3+deb13u2").
//!
//! The first run loads `all.zip` (Debian about 80 MB, Ubuntu about 800 MB). After that `modified_id.csv`
//! (one line `<modified>,<id>` per record, newest first, a few MB, asked for with its validators) says which
//! records changed since the cursor (the newest `modified` we applied); those are fetched one by one over
//! kept-alive connections. Too many changes at once start over with `all.zip`, which also removes the
//! records OSV no longer has.

use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, anyhow, bail};
use jiff::Timestamp;
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::http_client::{self, Get, HttpError, Outcome, Session};
use crate::sources::cve5::{clip, is_cve_id};
use crate::sources::{Context, parse_time_ms};
use crate::storage::cves::Upserted;
use crate::storage::distros;
use crate::storage::sources::{SourceState, Success};

const MAX_CSV: u64 = 64 << 20;
const CSV_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_ZIP: u64 = 4 << 30;
const ZIP_TIMEOUT: Duration = Duration::from_secs(2 * 3600);
/// Largest single record (Ubuntu's kernel records list thousands of versions).
const MAX_RECORD: u64 = 32 << 20;
const RECORD_TIMEOUT: Duration = Duration::from_secs(120);
const RECORD_IDLE: Duration = Duration::from_secs(15);
const MAX_ENTRIES: usize = 1_000_000;
/// More changed records than this load `all.zip` again instead of one request per record.
const FULL_THRESHOLD: usize = 10_000;
/// Records written per transaction.
const BATCH: usize = 500;
const PARALLEL: usize = if cfg!(test) { 1 } else { 4 };
/// Most affected rows kept of one record.
const MAX_AFFECTED: usize = 20_000;
const MAX_CVES: usize = 2_000;

/// The two distributions OSV has for us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Distro {
    Debian,
    Ubuntu,
}

impl Distro {
    /// The value of `osv_records.source`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Debian => "debian",
            Self::Ubuntu => "ubuntu",
        }
    }

    /// The directory at OSV and the first part of every ecosystem ("Debian:13").
    pub fn dir(self) -> &'static str {
        match self {
            Self::Debian => "Debian",
            Self::Ubuntu => "Ubuntu",
        }
    }

    /// The source state row.
    fn source(self) -> &'static str {
        match self {
            Self::Debian => "osv_debian",
            Self::Ubuntu => "osv_ubuntu",
        }
    }
}

/// An advisory of the distribution or its view of one CVE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Advisory,
    Cve,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Advisory => "advisory",
            Self::Cve => "cve",
        }
    }
}

/// One OSV record, reduced to what we keep.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub id: String,
    pub distro: Distro,
    pub kind: Kind,
    pub summary: String,
    pub details: String,
    pub priority: String,
    pub url: String,
    pub published_ms: Option<i64>,
    pub modified: String,
    pub modified_ms: i64,
    pub withdrawn_ms: Option<i64>,
    pub cves: Vec<String>,
    pub affected: Vec<Affected>,
}

/// One range of an affected source package in one release.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Affected {
    pub ecosystem: String,
    pub release: String,
    pub package: String,
    pub introduced: String,
    pub fixed: String,
    pub last_affected: String,
    pub urgency: String,
}

#[derive(Deserialize)]
struct Raw {
    id: String,
    modified: String,
    #[serde(default)]
    published: Option<String>,
    #[serde(default)]
    withdrawn: Option<String>,
    #[serde(default)]
    aliases: Option<Vec<String>>,
    #[serde(default)]
    upstream: Option<Vec<String>>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    severity: Option<Vec<RawSeverity>>,
    #[serde(default)]
    affected: Option<Vec<RawAffected>>,
    #[serde(default)]
    references: Option<Vec<RawRef>>,
}

#[derive(Deserialize)]
struct RawSeverity {
    #[serde(rename = "type")]
    kind: String,
    score: String,
}

#[derive(Deserialize)]
struct RawAffected {
    #[serde(default)]
    package: Option<RawPackage>,
    #[serde(default)]
    ranges: Option<Vec<RawRange>>,
    #[serde(default)]
    ecosystem_specific: Option<RawSpecific>,
}

#[derive(Deserialize)]
struct RawPackage {
    ecosystem: String,
    name: String,
}

#[derive(Deserialize)]
struct RawRange {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    events: Vec<RawEvent>,
}

#[derive(Deserialize)]
struct RawEvent {
    #[serde(default)]
    introduced: Option<String>,
    #[serde(default)]
    fixed: Option<String>,
    #[serde(default)]
    last_affected: Option<String>,
}

#[derive(Deserialize)]
struct RawSpecific {
    #[serde(default)]
    urgency: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct RawRef {
    #[serde(rename = "type")]
    kind: String,
    url: String,
}

/// Checks an OSV id before it becomes part of a URL or a file name: letters, digits, `-`, `.`, `_`.
pub fn valid_id(id: &str) -> bool {
    (1..=80).contains(&id.len())
        && id.as_bytes()[0].is_ascii_alphanumeric()
        && !id.contains("..")
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
}

/// Reads one record of `distro`.
pub fn parse(bytes: &[u8], distro: Distro) -> Result<Record, String> {
    let raw: Raw = serde_json::from_slice(bytes).map_err(|e| format!("not an OSV record: {e}"))?;
    if !valid_id(&raw.id) {
        return Err("invalid id".to_owned());
    }
    let modified_ms = parse_time_ms(&raw.modified).ok_or("invalid modified time")?;
    let kind = if ["DEBIAN-CVE-", "UBUNTU-CVE-", "CVE-"]
        .iter()
        .any(|p| raw.id.starts_with(p))
    {
        Kind::Cve
    } else {
        Kind::Advisory
    };

    let mut cves: Vec<String> = raw
        .upstream
        .iter()
        .flatten()
        .chain(raw.aliases.iter().flatten())
        .chain(std::iter::once(&raw.id))
        .filter_map(|id| {
            let id = id
                .strip_prefix("DEBIAN-")
                .or_else(|| id.strip_prefix("UBUNTU-"))
                .unwrap_or(id);
            is_cve_id(id).then(|| id.to_owned())
        })
        .collect();
    cves.sort();
    cves.dedup();
    cves.truncate(MAX_CVES);

    let affected = affected_rows(raw.affected.unwrap_or_default(), distro);

    let priority = raw
        .severity
        .iter()
        .flatten()
        .find(|s| s.kind == "Ubuntu")
        .map(|s| clip(&s.score.trim().to_lowercase(), 30))
        .unwrap_or_default();

    let (url, details) = match kind {
        Kind::Cve => (String::new(), String::new()),
        Kind::Advisory => {
            let url = raw
                .references
                .iter()
                .flatten()
                .find(|r| {
                    r.kind == "ADVISORY" && r.url.starts_with("https://") && r.url.len() < 500
                })
                .map(|r| r.url.clone())
                .unwrap_or_else(|| match distro {
                    Distro::Debian => {
                        format!("https://security-tracker.debian.org/tracker/{}", raw.id)
                    }
                    Distro::Ubuntu => format!("https://ubuntu.com/security/notices/{}", raw.id),
                });
            (
                url,
                clip(raw.details.as_deref().unwrap_or_default(), 20_000),
            )
        }
    };

    Ok(Record {
        distro,
        kind,
        summary: clip(raw.summary.as_deref().unwrap_or_default().trim(), 500),
        details,
        priority,
        url,
        published_ms: raw.published.as_deref().and_then(parse_time_ms),
        modified: clip(raw.modified.trim(), 64),
        modified_ms,
        withdrawn_ms: raw.withdrawn.as_deref().and_then(parse_time_ms),
        cves,
        affected,
        id: raw.id,
    })
}

/// The affected source packages of the distribution, one row per range.
fn affected_rows(entries: Vec<RawAffected>, distro: Distro) -> Vec<Affected> {
    let mut rows = Vec::new();
    let mut seen = HashSet::new();
    for entry in entries {
        let Some(package) = entry.package else {
            continue;
        };
        let mut parts = package.ecosystem.split(':');
        if parts.next() != Some(distro.dir()) {
            continue;
        }
        let release = parts
            .find(|p| p.starts_with(|c: char| c.is_ascii_digit()))
            .unwrap_or_default();
        let name = package.name.trim();
        if name.is_empty() || name.chars().any(char::is_control) {
            continue;
        }
        let urgency = entry
            .ecosystem_specific
            .and_then(|s| s.urgency)
            .and_then(|u| u.as_str().map(|s| clip(s.trim(), 40)))
            .unwrap_or_default();
        let row = |introduced: Option<String>, fixed: &str, last: &str| Affected {
            ecosystem: clip(&package.ecosystem, 60),
            release: clip(release, 20),
            package: clip(name, 200),
            introduced: clip(introduced.as_deref().unwrap_or_default(), 200),
            fixed: clip(fixed, 200),
            last_affected: clip(last, 200),
            urgency: urgency.clone(),
        };
        let mut found = Vec::new();
        for range in entry.ranges.iter().flatten() {
            if range.kind != "ECOSYSTEM" {
                continue;
            }
            let mut open: Option<String> = None;
            for event in &range.events {
                if let Some(v) = &event.introduced {
                    if let Some(prev) = open.replace(v.clone()) {
                        found.push(row(Some(prev), "", ""));
                    }
                } else if let Some(v) = &event.fixed {
                    found.push(row(open.take(), v, ""));
                } else if let Some(v) = &event.last_affected {
                    found.push(row(open.take(), "", v));
                }
            }
            if let Some(prev) = open {
                found.push(row(Some(prev), "", ""));
            }
        }
        if found.is_empty() {
            // Affected without a usable range: the package is named, the versions are unknown.
            found.push(row(None, "", ""));
        }
        for r in found {
            if rows.len() >= MAX_AFFECTED {
                return rows;
            }
            if seen.insert(r.clone()) {
                rows.push(r);
            }
        }
    }
    rows
}

/// One line of `modified_id.csv`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub modified: Timestamp,
    pub id: String,
}

/// The records of `modified_id.csv` changed after `after` (all without a cursor), oldest first.
/// Lines that cannot be read are left out.
pub fn parse_modified(text: &[u8], after: Option<Timestamp>) -> Vec<Change> {
    let text = String::from_utf8_lossy(text);
    let mut changes: Vec<Change> = text
        .lines()
        .filter_map(|line| {
            let (time, id) = line.trim().split_once(',')?;
            let modified: Timestamp = time.trim().parse().ok()?;
            let id = id.trim();
            (valid_id(id) && after.is_none_or(|a| modified > a)).then(|| Change {
                modified,
                id: id.to_owned(),
            })
        })
        .collect();
    changes.sort_by(|a, b| a.modified.cmp(&b.modified).then_with(|| a.id.cmp(&b.id)));
    changes.dedup_by(|a, b| a.id == b.id);
    changes
}

#[derive(Debug, Default)]
struct Totals {
    new: i64,
    changed: i64,
    removed: u64,
    skipped: u64,
    failed: u64,
}

pub async fn run(ctx: &Context, distro: Distro, state: &SourceState) -> anyhow::Result<Success> {
    let base = format!(
        "{}/{}",
        ctx.endpoints.osv.trim_end_matches('/'),
        distro.dir()
    );
    let cursor: Option<Timestamp> = state.cursor.as_deref().and_then(|c| c.parse().ok());
    let csv_url = format!("{base}/modified_id.csv");
    // The validators only count with a cursor: without one, the list must be read. A run that could not
    // fetch every record keeps its cursor before them; they are fetched again once the list changes
    // (OSV rewrites it several times a day).
    let get = Get::new(&csv_url, MAX_CSV, CSV_TIMEOUT)
        .accept("text/csv")
        .conditional(
            cursor.and(state.etag.as_deref()),
            cursor.and(state.last_modified.as_deref()),
        );
    let fetched = match http_client::get_bytes(&get).await? {
        Outcome::NotModified => return Ok(Success::default()),
        Outcome::Fresh(fetched) => fetched,
    };

    let mut totals = Totals::default();
    let mut reached = cursor;
    let mut changes = parse_modified(&fetched.body, reached);
    if reached.is_none() || changes.len() > FULL_THRESHOLD {
        tracing::info!(
            distro = distro.as_str(),
            changes = changes.len(),
            "OSV: loading all records"
        );
        let newest = import_full(ctx, distro, &base, &mut totals).await?;
        reached = newest.or(reached);
        if let Some(r) = reached {
            crate::storage::sources::save_cursor(&ctx.pool, distro.source(), &r.to_string())
                .await?;
        }
        changes = parse_modified(&fetched.body, reached);
    }
    if !changes.is_empty()
        && let Some(r) = apply_changes(ctx, distro, &base, changes, &mut totals).await?
    {
        reached = Some(r);
    }

    let count = distros::count(&ctx.pool, distro.as_str()).await?;
    let mut warnings = Vec::new();
    if totals.skipped > 0 {
        warnings.push(format!("{} records could not be read", totals.skipped));
    }
    if totals.failed > 0 {
        warnings.push(format!(
            "{} records could not be fetched (tried again with the next list)",
            totals.failed
        ));
    }
    if totals.removed > 0 {
        tracing::info!(
            distro = distro.as_str(),
            removed = totals.removed,
            "OSV: records removed"
        );
    }
    Ok(Success {
        etag: fetched.etag,
        last_modified: fetched.last_modified,
        cursor: reached.map(|r| r.to_string()),
        version: reached.map(|r| r.strftime("%Y-%m-%d %H:%MZ").to_string()),
        item_count: Some(count),
        new: totals.new,
        changed: totals.changed,
        warning: (!warnings.is_empty()).then(|| warnings.join("; ")),
    })
}

/// Loads `all.zip` and replaces the records of `distro`; returns the newest `modified` it contained.
async fn import_full(
    ctx: &Context,
    distro: Distro,
    base: &str,
    totals: &mut Totals,
) -> anyhow::Result<Option<Timestamp>> {
    let path = ctx.download_path(&format!("osv-{}.zip", distro.as_str()));
    let url = format!("{base}/all.zip");
    let get = Get::new(&url, MAX_ZIP, ZIP_TIMEOUT).accept("application/zip");
    let downloaded = http_client::get_file(&get, &path).await;
    let result = match downloaded {
        Ok(Outcome::Fresh(_)) => ingest_archive(ctx, distro, path.clone(), totals).await,
        Ok(Outcome::NotModified) => Err(anyhow!("unexpected 304 for {url}")),
        Err(e) => Err(e.into()),
    };
    let _ = tokio::fs::remove_file(&path).await;
    result
}

/// Reads all records of the archive in a worker thread, stores them in batches and removes the records
/// the archive no longer has.
async fn ingest_archive(
    ctx: &Context,
    distro: Distro,
    path: PathBuf,
    totals: &mut Totals,
) -> anyhow::Result<Option<Timestamp>> {
    let before = distros::ids(&ctx.pool, distro.as_str()).await?;
    let (sender, mut batches) = mpsc::channel::<Vec<Record>>(4);
    let reader = tokio::task::spawn_blocking(move || read_archive(&path, distro, &sender));
    let mut seen: HashSet<String> = HashSet::with_capacity(before.len());
    let mut newest: Option<Timestamp> = None;
    let stored: anyhow::Result<()> = async {
        while let Some(batch) = batches.recv().await {
            write_records(ctx, &batch, totals).await?;
            for r in batch {
                if let Ok(t) = r.modified.parse::<Timestamp>() {
                    newest = newest.max(Some(t));
                }
                seen.insert(r.id);
            }
        }
        Ok(())
    }
    .await;
    drop(batches);
    let read = reader
        .await
        .map_err(|e| anyhow!("reading the archive stopped: {e}"))?;
    stored?;
    totals.skipped += read?;
    // A short archive must not empty the table.
    if seen.len() * 2 < before.len() {
        bail!(
            "the archive has only {} records, {} are stored; nothing removed",
            seen.len(),
            before.len()
        );
    }
    let gone: Vec<String> = before.into_iter().filter(|id| !seen.contains(id)).collect();
    totals.removed += distros::delete(&ctx.pool, &gone).await?;
    Ok(newest)
}

async fn write_records(ctx: &Context, batch: &[Record], totals: &mut Totals) -> anyhow::Result<()> {
    let now = crate::sources::now_ms();
    let mut tx = ctx.pool.begin().await?;
    for record in batch {
        match distros::upsert(&mut tx, record, now).await? {
            Upserted::New => totals.new += 1,
            Upserted::Changed => totals.changed += 1,
            Upserted::Unchanged => {}
        }
    }
    tx.commit().await?;
    ctx.progress.add(batch.len() as u64);
    Ok(())
}

/// Sends the records of the archive in batches; returns how many entries could not be read.
fn read_archive(
    path: &Path,
    distro: Distro,
    sender: &mpsc::Sender<Vec<Record>>,
) -> anyhow::Result<u64> {
    let mut archive = super::open_archive(path, MAX_ENTRIES)?;
    let mut batch = Vec::with_capacity(BATCH);
    let mut skipped = 0;
    let mut buf = Vec::new();
    for i in 0..archive.len() {
        // Stop when the run was given up (time limit): nobody stores the records any more.
        if sender.is_closed() {
            bail!("storing stopped");
        }
        let mut entry = archive.by_index(i)?;
        let name = entry.name().map(|n| n.into_owned()).unwrap_or_default();
        if !entry.is_file() || !name.ends_with(".json") {
            continue;
        }
        buf.clear();
        (&mut entry).take(MAX_RECORD + 1).read_to_end(&mut buf)?;
        if buf.len() as u64 > MAX_RECORD {
            skipped += 1;
            continue;
        }
        match parse(&buf, distro) {
            Ok(record) => batch.push(record),
            Err(e) => {
                tracing::debug!(entry = %name, error = %e, "OSV: record skipped");
                skipped += 1;
            }
        }
        if batch.len() == BATCH {
            let full = std::mem::replace(&mut batch, Vec::with_capacity(BATCH));
            sender
                .blocking_send(full)
                .map_err(|_| anyhow!("storing stopped"))?;
        }
    }
    if !batch.is_empty() {
        sender
            .blocking_send(batch)
            .map_err(|_| anyhow!("storing stopped"))?;
    }
    Ok(skipped)
}

/// What fetching one record gave.
enum Fetched {
    Record(Box<Record>),
    /// Removed since the list was written, or unreadable: nothing to retry.
    Gone,
    Unreadable,
    Failed(String),
}

/// Fetches the changed records (oldest first) and stores them; returns the cursor to keep: the newest
/// time before the first record that could not be fetched.
async fn apply_changes(
    ctx: &Context,
    distro: Distro,
    base: &str,
    changes: Vec<Change>,
    totals: &mut Totals,
) -> anyhow::Result<Option<Timestamp>> {
    let mut first_failed: Option<Timestamp> = None;
    let times: Vec<Timestamp> = changes.iter().map(|c| c.modified).collect();
    let mut queue = changes.into_iter();
    let mut running = JoinSet::new();
    let mut sessions: Vec<Session> = Vec::with_capacity(PARALLEL);
    let mut done: Vec<Record> = Vec::with_capacity(BATCH);
    let mut attempts = 0u64;
    loop {
        while running.len() < PARALLEL {
            let Some(change) = queue.next() else { break };
            let url = format!("{base}/{}.json", change.id);
            let mut session = sessions.pop().unwrap_or_default();
            running.spawn(async move {
                let result = fetch_record(&mut session, &url, distro).await;
                (change, result, session)
            });
        }
        let Some(joined) = running.join_next().await else {
            break;
        };
        let (change, result, session) = joined.context("a download task failed")?;
        sessions.push(session);
        attempts += 1;
        match result {
            Fetched::Record(r) => done.push(*r),
            Fetched::Gone => {}
            Fetched::Unreadable => totals.skipped += 1,
            Fetched::Failed(e) => {
                tracing::debug!(id = %change.id, error = %e, "OSV: record not fetched");
                totals.failed += 1;
                first_failed =
                    Some(first_failed.map_or(change.modified, |f| f.min(change.modified)));
            }
        }
        if done.len() >= BATCH {
            write_records(ctx, &done, totals).await?;
            done.clear();
        }
    }
    write_records(ctx, &done, totals).await?;
    if totals.failed >= 10 && totals.failed == attempts {
        bail!("no record could be fetched");
    }
    Ok(match first_failed {
        None => times.last().copied(),
        Some(failed) => times.iter().copied().filter(|t| *t < failed).max(),
    })
}

async fn fetch_record(session: &mut Session, url: &str, distro: Distro) -> Fetched {
    let get = Get::new(url, MAX_RECORD, RECORD_TIMEOUT)
        .accept("application/json")
        .idle(RECORD_IDLE);
    let first = session.get_bytes(&get).await;
    let answer = match first {
        Err(HttpError::Timeout | HttpError::Connect(_) | HttpError::Closed) => {
            session.get_bytes(&get).await
        }
        other => other,
    };
    match answer {
        Ok(Outcome::Fresh(f)) => match parse(&f.body, distro) {
            Ok(r) => Fetched::Record(Box::new(r)),
            Err(_) => Fetched::Unreadable,
        },
        Ok(Outcome::NotModified) => Fetched::Failed("unexpected 304".to_owned()),
        Err(HttpError::Status(404 | 410)) => Fetched::Gone,
        Err(HttpError::TooLarge(_)) => Fetched::Unreadable,
        Err(e) => Fetched::Failed(e.to_string()),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::http_client::testserver::{listen, ok, ok_with, serve_on, status};
    use crate::sources::testutil::{context, state};
    use crate::sources::{SourceId, Sources};
    use std::io::Write;

    pub(crate) const DSA: &str = r#"{"id": "DSA-6189-1", "summary": "libpng1.6 - security update",
      "schema_version": "1.7.3", "published": "2026-03-27T00:00:00Z", "modified": "2026-11-05T21:39:16.716389Z",
      "upstream": ["CVE-2026-33416", "CVE-2026-33636", "DEBIAN-CVE-2026-33416", "DEBIAN-CVE-2026-33636"],
      "affected": [{"package": {"ecosystem": "Debian:12", "name": "libpng1.6",
          "purl": "pkg:deb/debian/libpng1.6?arch=source"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.6.39-2+deb12u4"}]}],
        "versions": ["1.6.39-2", "1.6.39-2+deb12u1"]},
       {"package": {"ecosystem": "Debian:13", "name": "libpng1.6"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.6.48-1+deb13u4"}]}]}]}"#;

    pub(crate) const DEBIAN_CVE: &str = r#"{"schema_version": "1.9.2", "id": "DEBIAN-CVE-2026-33416",
      "published": "2026-03-20T15:17:41.590Z", "modified": "2026-11-06T11:00:08.619771263Z",
      "upstream": ["CVE-2026-33416"], "details": "A long description that is not kept.",
      "references": [{"type": "ADVISORY", "url": "https://security-tracker.debian.org/tracker/CVE-2026-33416"}],
      "affected": [
       {"package": {"name": "libpng1.6", "ecosystem": "Debian:12"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.6.39-2+deb12u4"}]}],
        "ecosystem_specific": {"urgency": "medium"}},
       {"package": {"name": "libpng1.6", "ecosystem": "Debian:14"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
        "ecosystem_specific": {"urgency": "not yet assigned"}},
       {"package": {"name": "libpng1.6", "ecosystem": "Ubuntu:26.04:LTS"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}"#;

    pub(crate) const UBUNTU_CVE: &str = r#"{"id": "UBUNTU-CVE-2026-97205", "modified": "2026-11-06T01:11:58.823517344Z",
      "published": "2026-10-15T00:00:00Z", "related": ["USN-8955-1"], "upstream": ["CVE-2026-97205"],
      "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                   {"type": "Ubuntu", "score": "Medium"}],
      "affected": [
       {"package": {"name": "nginx", "ecosystem": "Ubuntu:26.04:LTS"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.28.0-1ubuntu1.2"}]}],
        "ecosystem_specific": {"binaries": [{"binary_name": "nginx", "binary_version": "1.28.0-1ubuntu1.2"}]}},
       {"package": {"name": "nginx", "ecosystem": "Ubuntu:Pro:20.04:LTS"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.18.0-0ubuntu1.7+esm2"}]}],
        "ecosystem_specific": {"availability": "Available with Ubuntu Pro: https://ubuntu.com/pro"}},
       {"package": {"name": "nginx", "ecosystem": "Ubuntu:26.10"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}"#;

    const USN: &str = r#"{"id": "USN-8955-1", "summary": "nginx <vulnerabilities>",
      "details": "It was discovered that nginx incorrectly handled certain things.",
      "published": "2026-11-04T14:40:26Z", "modified": "2026-11-06T01:13:08.896367466Z",
      "upstream": ["CVE-2026-97205", "UBUNTU-CVE-2026-97205"],
      "references": [{"type": "REPORT", "url": "https://ubuntu.com/security/CVE-2026-97205"},
                     {"type": "ADVISORY", "url": "https://ubuntu.com/security/notices/USN-8955-1"}],
      "affected": [{"package": {"name": "nginx", "ecosystem": "Ubuntu:26.04:LTS"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.28.0-1ubuntu1.2"}]}]}]}"#;

    #[test]
    fn advisories_keep_their_cves_ranges_and_page() {
        let r = parse(DSA.as_bytes(), Distro::Debian).unwrap();
        assert_eq!(r.kind, Kind::Advisory);
        assert_eq!(r.cves, ["CVE-2026-33416", "CVE-2026-33636"]);
        assert_eq!(r.summary, "libpng1.6 - security update");
        assert_eq!(
            r.url,
            "https://security-tracker.debian.org/tracker/DSA-6189-1"
        );
        assert_eq!(r.affected.len(), 2);
        assert_eq!(r.affected[0].release, "12");
        assert_eq!(r.affected[0].introduced, "0");
        assert_eq!(r.affected[0].fixed, "1.6.39-2+deb12u4");
        assert_eq!(r.published_ms, parse_time_ms("2026-03-27T00:00:00Z"));

        let u = parse(USN.as_bytes(), Distro::Ubuntu).unwrap();
        assert_eq!(u.url, "https://ubuntu.com/security/notices/USN-8955-1");
        assert_eq!(u.cves, ["CVE-2026-97205"]);
        assert!(u.details.starts_with("It was discovered"));
    }

    #[test]
    fn cve_records_keep_urgency_priority_and_open_ranges_of_their_own_distribution() {
        let d = parse(DEBIAN_CVE.as_bytes(), Distro::Debian).unwrap();
        assert_eq!(d.kind, Kind::Cve);
        assert_eq!(d.cves, ["CVE-2026-33416"]);
        assert!(d.details.is_empty() && d.url.is_empty());
        // The Ubuntu entry of a Debian record is not ours.
        assert_eq!(d.affected.len(), 2);
        assert_eq!(d.affected[0].urgency, "medium");
        assert_eq!(d.affected[1].release, "14");
        assert!(d.affected[1].fixed.is_empty() && d.affected[1].last_affected.is_empty());
        assert_eq!(d.modified, "2026-11-06T11:00:08.619771263Z");

        let u = parse(UBUNTU_CVE.as_bytes(), Distro::Ubuntu).unwrap();
        assert_eq!(u.priority, "medium");
        let eco: Vec<_> = u
            .affected
            .iter()
            .map(|a| (a.ecosystem.as_str(), a.release.as_str()))
            .collect();
        assert_eq!(
            eco,
            [
                ("Ubuntu:26.04:LTS", "26.04"),
                ("Ubuntu:Pro:20.04:LTS", "20.04"),
                ("Ubuntu:26.10", "26.10")
            ]
        );
    }

    #[test]
    fn ranges_with_several_events_become_several_rows() {
        let json = r#"{"id": "DSA-1-1", "modified": "2026-01-01T00:00:00Z", "affected": [
          {"package": {"name": "p", "ecosystem": "Debian:13"},
           "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "1.2"},
              {"introduced": "2.0"}, {"last_affected": "2.3"}, {"introduced": "3.0"}]},
             {"type": "GIT", "events": [{"introduced": "abc"}]}]},
          {"package": {"name": "q", "ecosystem": "Debian:13"}, "versions": ["1"]},
          {"package": {"name": "q", "ecosystem": "Debian:13"}, "versions": ["1"]}]}"#;
        let r = parse(json.as_bytes(), Distro::Debian).unwrap();
        let rows: Vec<_> = r
            .affected
            .iter()
            .map(|a| {
                (
                    a.package.as_str(),
                    a.introduced.as_str(),
                    a.fixed.as_str(),
                    a.last_affected.as_str(),
                )
            })
            .collect();
        assert_eq!(
            rows,
            [
                ("p", "1.0", "1.2", ""),
                ("p", "2.0", "", "2.3"),
                ("p", "3.0", "", ""),
                ("q", "", "", "")
            ]
        );
    }

    #[test]
    fn bad_records_and_ids_are_refused() {
        assert!(parse(b"[]", Distro::Debian).is_err());
        assert!(
            parse(
                br#"{"id": "../x", "modified": "2026-01-01T00:00:00Z"}"#,
                Distro::Debian
            )
            .is_err()
        );
        assert!(
            parse(
                br#"{"id": "DSA-1", "modified": "yesterday"}"#,
                Distro::Debian
            )
            .is_err()
        );
        for good in ["DSA-6189-1", "UBUNTU-CVE-2026-1", "USN-1.2_3"] {
            assert!(valid_id(good), "{good}");
        }
        for bad in ["", "-x", "a/b", "a..b", "a b", "%2e", &"x".repeat(81)] {
            assert!(!valid_id(bad), "{bad}");
        }
    }

    #[test]
    fn the_change_list_gives_the_records_after_the_cursor_oldest_first() {
        let csv = b"2026-11-06T11:00:08.619771263Z,DEBIAN-CVE-2026-1\n\
            2026-11-06T10:06:25.875323872Z,DSA-2-1\n\
            garbage\n\
            2026-11-06T10:06:25.875323872Z,../etc\n\
            2026-11-05T09:00:00Z,DLA-3-1\n";
        let all = parse_modified(csv, None);
        assert_eq!(
            all.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            ["DLA-3-1", "DSA-2-1", "DEBIAN-CVE-2026-1"]
        );
        let after: Timestamp = "2026-11-06T10:06:25.875323872Z".parse().unwrap();
        let newer = parse_modified(csv, Some(after));
        assert_eq!(newer.len(), 1);
        assert_eq!(newer[0].id, "DEBIAN-CVE-2026-1");
    }

    fn zip_of(files: &[(&str, &str)]) -> Vec<u8> {
        let mut out = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut out);
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            for (name, body) in files {
                zip.start_file(*name, opts).unwrap();
                zip.write_all(body.as_bytes()).unwrap();
            }
            zip.finish().unwrap();
        }
        out.into_inner()
    }

    async fn record_count(ctx: &Context) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM osv_records")
            .fetch_one(&ctx.pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn the_first_run_loads_all_zip_then_applies_newer_changes() {
        let (listener, addr) = listen().await;
        let base = format!("http://{addr}");
        let (ctx, _dir) = context(&base).await;
        let sources = Sources::new(
            ctx.pool.clone(),
            ctx.work_dir.clone(),
            (*ctx.endpoints).clone(),
            false,
        );
        let zip = zip_of(&[
            ("DSA-6189-1.json", DSA),
            ("DEBIAN-CVE-2026-33416.json", DEBIAN_CVE),
            ("broken.json", "{"),
        ]);
        let newer = DEBIAN_CVE
            .replace("2026-11-06T11:00:08.619771263Z", "2026-11-06T12:00:00Z")
            .replace("\"medium\"", "\"high\"");
        let csv = "2026-11-06T12:00:00Z,DEBIAN-CVE-2026-33416\n\
                   2026-11-05T21:39:16.716389Z,DSA-6189-1\n";
        serve_on(
            listener,
            vec![
                ok_with("ETag: \"c1\"\r\n", csv.as_bytes()),
                ok(&zip),
                ok(newer.as_bytes()),
                status(304, ""),
            ],
        );
        sources.run(SourceId::OsvDebian).await;
        let s = state(&ctx, SourceId::OsvDebian).await;
        assert_eq!(s.last_error, None);
        assert_eq!(s.cursor.as_deref(), Some("2026-11-06T12:00:00Z"));
        assert_eq!(s.etag.as_deref(), Some("\"c1\""));
        assert_eq!(s.item_count, Some(2));
        assert_eq!(s.last_new, Some(2));
        assert_eq!(s.last_changed, Some(1));
        assert!(
            s.last_warning
                .unwrap()
                .contains("1 records could not be read")
        );
        let urgency: String = sqlx::query_scalar(
            "SELECT a.urgency FROM osv_affected a JOIN osv_records r ON r.seq = a.record_seq
             WHERE r.id = 'DEBIAN-CVE-2026-33416' AND a.release = '12'",
        )
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
        assert_eq!(urgency, "high");

        // The list did not change: nothing is fetched.
        sources.run_now(SourceId::OsvDebian).await.unwrap();
        sources.run(SourceId::OsvDebian).await;
        let s = state(&ctx, SourceId::OsvDebian).await;
        assert_eq!(s.last_error, None);
        assert_eq!(s.last_new, Some(0));
        assert_eq!(record_count(&ctx).await, 2);
    }

    #[tokio::test]
    async fn failed_records_keep_the_cursor_before_them() {
        let (listener, addr) = listen().await;
        let base = format!("http://{addr}");
        let (ctx, _dir) = context(&base).await;
        let sources = Sources::new(
            ctx.pool.clone(),
            ctx.work_dir.clone(),
            (*ctx.endpoints).clone(),
            false,
        );
        crate::storage::sources::save_cursor(&ctx.pool, "osv_ubuntu", "2026-11-01T00:00:00Z")
            .await
            .unwrap();
        let csv = "2026-11-06T01:13:08.896367466Z,USN-8955-1\n\
                   2026-11-06T01:11:58.823517344Z,UBUNTU-CVE-2026-97205\n\
                   2026-11-03T00:00:00Z,USN-1-1\n";
        // Oldest first: USN-1-1 is gone (404), the CVE record fails, the USN arrives.
        serve_on(
            listener,
            vec![
                ok(csv.as_bytes()),
                status(404, ""),
                status(500, ""),
                ok(USN.as_bytes()),
            ],
        );
        sources.run(SourceId::OsvUbuntu).await;
        let s = state(&ctx, SourceId::OsvUbuntu).await;
        assert_eq!(s.last_error, None);
        assert_eq!(s.cursor.as_deref(), Some("2026-11-03T00:00:00Z"));
        assert!(
            s.last_warning
                .unwrap()
                .contains("1 records could not be fetched")
        );
        assert_eq!(record_count(&ctx).await, 1);
    }

    #[tokio::test]
    async fn a_full_import_removes_records_that_are_gone() {
        let (ctx, _dir) = context("http://127.0.0.1:9").await;
        let mut totals = Totals::default();
        for (name, records) in [
            (
                "a.zip",
                vec![
                    ("DSA-6189-1.json", DSA),
                    ("DEBIAN-CVE-2026-33416.json", DEBIAN_CVE),
                ],
            ),
            ("b.zip", vec![("DEBIAN-CVE-2026-33416.json", DEBIAN_CVE)]),
        ] {
            let path = ctx.download_path(name);
            std::fs::write(&path, zip_of(&records)).unwrap();
            ingest_archive(&ctx, Distro::Debian, path, &mut totals)
                .await
                .unwrap();
        }
        assert_eq!(totals.new, 2);
        assert_eq!(totals.removed, 1);
        assert_eq!(record_count(&ctx).await, 1);
        let orphans: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM osv_affected WHERE record_seq NOT IN (SELECT seq FROM osv_records)",
        )
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
        assert_eq!(orphans, 0);

        // An archive with less than half of the stored records removes nothing.
        let path = ctx.download_path("c.zip");
        std::fs::write(&path, zip_of(&[])).unwrap();
        let err = ingest_archive(&ctx, Distro::Debian, path, &mut totals)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("nothing removed"), "{err}");
        assert_eq!(record_count(&ctx).await, 1);
    }
}
