//! cvelistV5, the CVE list of the CVE Program, from the releases of `github.com/CVEProject/cvelistV5`.
//!
//! Every hour a release `cve_YYYY-MM-DD_HHMMZ` appears with two assets: the whole list as of midnight
//! (`…_all_CVEs_at_midnight.zip.zip`, about 650 MB, a zip inside a zip) and the records changed since
//! midnight (`…_delta_CVEs_at_HHMMZ.zip`, a few MB). Shortly after midnight a release
//! `cve_YYYY-MM-DD_at_end_of_day` closes the day with all of its changes.
//!
//! The cursor is the last release we applied. A run applies, day by day, the newest delta of every day
//! since then (the end-of-day delta for finished days); only without a cursor, or when a day can no
//! longer be bridged (the list of releases reaches back about two days), it starts over with the full
//! list. Records whose `dateUpdated` we already have are skipped.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, anyhow, bail};
use jiff::civil::Date;
use serde::Deserialize;
use tokio::sync::mpsc;

use crate::http_client::{self, Get, Outcome};
use crate::sources::Context;
use crate::sources::cve5::{self, Cve};
use crate::storage::cves::{Upserted, upsert};
use crate::storage::sources::{SourceState, Success};

/// Releases asked for at once (about two days).
const RELEASES_PER_PAGE: u32 = 60;
const MAX_RELEASE_LIST: u64 = 32 << 20;
const MAX_DELTA: u64 = 512 << 20;
const MAX_FULL: u64 = 3 << 30;
/// Largest inner archive unpacked from the full download.
const MAX_INNER: u64 = 8 << 30;
/// Largest single record (the biggest ones list hundreds of versions).
const MAX_RECORD: u64 = 8 << 20;
/// Most entries an archive may have.
const MAX_ENTRIES: usize = 2_000_000;
const LIST_TIMEOUT: Duration = Duration::from_secs(120);
const DELTA_TIMEOUT: Duration = Duration::from_secs(900);
const FULL_TIMEOUT: Duration = Duration::from_secs(2 * 3600);
/// Records written per transaction.
const BATCH: usize = 500;

/// A point in the sequence of releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Mark {
    pub date: Date,
    pub pos: Pos,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Pos {
    /// Midnight at the start of the day (what the full list contains).
    Start,
    /// An hourly release, `HHMM`.
    Hour(u16),
    EndOfDay,
}

impl Mark {
    /// Reads a release tag: `cve_2026-11-05_2000Z` or `cve_2026-11-04_at_end_of_day`.
    pub fn parse_tag(tag: &str) -> Option<Self> {
        let rest = tag.strip_prefix("cve_")?;
        let (date, pos) = rest.split_at_checked(10)?;
        let date: Date = date.parse().ok()?;
        let pos = match pos {
            "_at_end_of_day" => Pos::EndOfDay,
            "_start" => Pos::Start,
            hour => {
                let hhmm = hour.strip_prefix('_')?.strip_suffix('Z')?;
                if hhmm.len() != 4 || !hhmm.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                Pos::Hour(hhmm.parse().ok()?)
            }
        };
        Some(Self { date, pos })
    }

    /// The tag of this mark (also the stored cursor).
    pub fn tag(self) -> String {
        match self.pos {
            Pos::Start => format!("cve_{}_start", self.date),
            Pos::Hour(h) => format!("cve_{}_{h:04}Z", self.date),
            Pos::EndOfDay => format!("cve_{}_at_end_of_day", self.date),
        }
    }
}

/// A release with the assets we use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub mark: Mark,
    pub delta_url: Option<String>,
    pub full_url: Option<String>,
}

/// What a run does, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Load the whole list as of midnight of `date`.
    Full { url: String, date: Date },
    /// Apply the changes up to `mark`.
    Delta { url: String, mark: Mark },
}

#[derive(Debug, Deserialize)]
struct ApiRelease {
    tag_name: String,
    #[serde(default)]
    assets: Vec<ApiAsset>,
}

#[derive(Debug, Deserialize)]
struct ApiAsset {
    name: String,
    browser_download_url: String,
}

/// Reads the release list of the GitHub API. Download links must point to the cvelistV5 repository
/// (or, in tests, to the host of `endpoint`).
pub fn parse_releases(bytes: &[u8], endpoint: &str) -> anyhow::Result<Vec<Release>> {
    let list: Vec<ApiRelease> =
        serde_json::from_slice(bytes).context("the release list is not valid JSON")?;
    let allowed = |url: &str| {
        url.starts_with("https://github.com/CVEProject/cvelistV5/releases/download/")
            || (!endpoint.starts_with("https://api.github.com/")
                && origin(url).is_some()
                && origin(url) == origin(endpoint))
    };
    let mut releases: Vec<Release> = list
        .into_iter()
        .filter_map(|r| {
            let mark = Mark::parse_tag(&r.tag_name)?;
            let pick = |want: fn(&str) -> bool| {
                r.assets
                    .iter()
                    .find(|a| want(&a.name) && allowed(&a.browser_download_url))
                    .map(|a| a.browser_download_url.clone())
            };
            Some(Release {
                mark,
                delta_url: pick(|n| n.contains("_delta_CVEs_at_") && n.ends_with(".zip")),
                full_url: pick(|n| n.contains("_all_CVEs_at_midnight") && n.ends_with(".zip")),
            })
        })
        .collect();
    releases.sort_by_key(|r| r.mark);
    releases.dedup_by_key(|r| r.mark);
    Ok(releases)
}

/// `scheme://host:port` of a URL.
fn origin(url: &str) -> Option<String> {
    let t = http_client::parse_url(url).ok()?;
    Some(format!(
        "{}://{}",
        if t.tls { "https" } else { "http" },
        t.authority
    ))
}

/// The steps from `cursor` to the newest release.
pub fn plan(cursor: Option<Mark>, releases: &[Release]) -> anyhow::Result<Vec<Step>> {
    let Some(latest) = releases.iter().map(|r| r.mark).max() else {
        bail!("the release list is empty");
    };
    if let Some(cursor) = cursor {
        if cursor >= latest {
            return Ok(Vec::new());
        }
        if let Some(steps) = bridge(cursor, latest, releases) {
            return Ok(steps);
        }
    }
    // Start over: the newest full list, then the changes since its midnight.
    let full = releases
        .iter()
        .rev()
        .find_map(|r| Some((r.full_url.clone()?, r.mark.date)))
        .ok_or_else(|| anyhow!("no release offers the full CVE list"))?;
    let start = Mark {
        date: full.1,
        pos: Pos::Start,
    };
    let mut steps = vec![Step::Full {
        url: full.0,
        date: full.1,
    }];
    steps.extend(
        bridge(start, latest, releases)
            .ok_or_else(|| anyhow!("the changes since the full list are incomplete"))?,
    );
    Ok(steps)
}

/// The deltas that lead from `cursor` to `latest` without a gap; `None` if a day is missing.
fn bridge(cursor: Mark, latest: Mark, releases: &[Release]) -> Option<Vec<Step>> {
    let mut steps = Vec::new();
    let mut day = cursor.date;
    while day <= latest.date {
        let newest = releases
            .iter()
            .filter(|r| r.mark.date == day && r.delta_url.is_some())
            .max_by_key(|r| r.mark);
        let done_with_day = day == cursor.date && cursor.pos == Pos::EndOfDay;
        if !done_with_day {
            let release = newest?;
            // A finished day is only complete with its end-of-day delta.
            if day < latest.date && release.mark.pos != Pos::EndOfDay {
                return None;
            }
            if release.mark > cursor {
                steps.push(Step::Delta {
                    url: release.delta_url.clone()?,
                    mark: release.mark,
                });
            }
        }
        day = day.tomorrow().ok()?;
    }
    Some(steps)
}

pub async fn run(ctx: &Context, state: &SourceState) -> anyhow::Result<Success> {
    let url = format!(
        "{}?per_page={RELEASES_PER_PAGE}",
        ctx.endpoints.cvelist_releases
    );
    let cursor = state.cursor.as_deref().and_then(Mark::parse_tag);
    // The ETag of the release list only counts once we have a cursor: without one, the list must be read.
    let etag = cursor.and(state.etag.as_deref());
    let get = Get::new(&url, MAX_RELEASE_LIST, LIST_TIMEOUT)
        .accept("application/vnd.github+json")
        .conditional(etag, None);
    let fetched = match http_client::get_bytes(&get).await? {
        Outcome::NotModified => return Ok(Success::default()),
        Outcome::Fresh(fetched) => fetched,
    };
    let releases = parse_releases(&fetched.body, &ctx.endpoints.cvelist_releases)?;
    let steps = plan(cursor, &releases)?;
    let (mut new, mut changed) = (0, 0);
    let mut reached = cursor;
    for step in steps {
        let (n, c, mark) = match step {
            Step::Full { url, date } => {
                tracing::info!(%date, "cvelistV5: loading the full CVE list");
                let (n, c) = apply_full(ctx, &url).await?;
                (
                    n,
                    c,
                    Mark {
                        date,
                        pos: Pos::Start,
                    },
                )
            }
            Step::Delta { url, mark } => {
                let (n, c) = apply_delta(ctx, &url).await?;
                (n, c, mark)
            }
        };
        new += n;
        changed += c;
        reached = Some(mark);
        // Keep the progress if a later step fails or the service stops.
        crate::storage::sources::save_cursor(&ctx.pool, "cvelist", &mark.tag()).await?;
    }
    let count = crate::storage::cves::count(&ctx.pool).await?;
    Ok(Success {
        etag: fetched.etag,
        last_modified: None,
        cursor: reached.map(Mark::tag),
        version: reached.map(|m| match m.pos {
            Pos::Start => format!("{} 00:00Z", m.date),
            Pos::Hour(h) => format!("{} {:02}:{:02}Z", m.date, h / 100, h % 100),
            Pos::EndOfDay => format!("{} 24:00Z", m.date),
        }),
        item_count: Some(count),
        new,
        changed,
        warning: None,
    })
}

/// Downloads and applies a delta.
async fn apply_delta(ctx: &Context, url: &str) -> anyhow::Result<(i64, i64)> {
    let path = ctx.download_path("cvelist-delta.zip");
    download(url, &path, MAX_DELTA, DELTA_TIMEOUT).await?;
    let result = ingest_archive(ctx, path.clone()).await;
    let _ = tokio::fs::remove_file(&path).await;
    result
}

/// Downloads the full list, unpacks the inner archive and applies it.
async fn apply_full(ctx: &Context, url: &str) -> anyhow::Result<(i64, i64)> {
    let outer = ctx.download_path("cvelist-full.zip.zip");
    let inner = ctx.download_path("cvelist-full.zip");
    download(url, &outer, MAX_FULL, FULL_TIMEOUT).await?;
    let unpack = {
        let (outer, inner) = (outer.clone(), inner.clone());
        tokio::task::spawn_blocking(move || unpack_inner(&outer, &inner))
    };
    let unpacked = unpack.await.map_err(|e| anyhow!("unpacking stopped: {e}"));
    let _ = tokio::fs::remove_file(&outer).await;
    unpacked??;
    let result = ingest_archive(ctx, inner.clone()).await;
    let _ = tokio::fs::remove_file(&inner).await;
    result
}

async fn download(url: &str, path: &Path, max: u64, timeout: Duration) -> anyhow::Result<()> {
    let get = Get::new(url, max, timeout).accept("application/octet-stream");
    match http_client::get_file(&get, path).await? {
        Outcome::Fresh(_) => Ok(()),
        Outcome::NotModified => bail!("unexpected 304 for {url}"),
    }
}

/// Copies the only `.zip` inside the archive `outer` to `inner`.
fn unpack_inner(outer: &Path, inner: &Path) -> anyhow::Result<()> {
    let file = std::fs::File::open(outer)?;
    let mut archive = zip::ZipArchive::new(std::io::BufReader::new(file))
        .context("the full list is not a zip archive")?;
    let index = (0..archive.len())
        .find(|&i| {
            archive
                .name_for_index(i)
                .is_some_and(|n| n.is_ok_and(|n| n.ends_with(".zip")))
        })
        .ok_or_else(|| anyhow!("the full list contains no inner archive"))?;
    let entry = archive.by_index(index)?;
    let mut out = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(inner)?
    };
    let copied = std::io::copy(&mut entry.take(MAX_INNER + 1), &mut out)?;
    if copied > MAX_INNER {
        bail!("the inner archive is larger than {MAX_INNER} bytes");
    }
    out.sync_all()?;
    Ok(())
}

/// Reads all records of an archive in a worker thread and stores them in batches.
async fn ingest_archive(ctx: &Context, path: PathBuf) -> anyhow::Result<(i64, i64)> {
    let (sender, mut batches) = mpsc::channel::<Vec<Cve>>(4);
    let reader = tokio::task::spawn_blocking(move || read_archive(&path, &sender));
    let (mut new, mut changed) = (0, 0);
    let stored: anyhow::Result<()> = async {
        while let Some(batch) = batches.recv().await {
            let mut tx = ctx.pool.begin().await?;
            for cve in &batch {
                match upsert(&mut tx, cve).await? {
                    Upserted::New => new += 1,
                    Upserted::Changed => changed += 1,
                    Upserted::Unchanged => {}
                }
            }
            tx.commit().await?;
            ctx.progress.add(batch.len() as u64);
        }
        Ok(())
    }
    .await;
    // Dropping the receiver ends the reader early if storing failed.
    drop(batches);
    let read = reader
        .await
        .map_err(|e| anyhow!("reading the archive stopped: {e}"))?;
    stored?;
    let skipped = read?;
    if skipped > 0 {
        tracing::warn!(
            skipped,
            "cvelistV5: records that could not be read were skipped"
        );
    }
    Ok((new, changed))
}

/// Sends the records of the archive in batches; returns how many entries could not be read.
fn read_archive(path: &Path, sender: &mpsc::Sender<Vec<Cve>>) -> anyhow::Result<u64> {
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
        let file_name = name.rsplit('/').next().unwrap_or_default();
        if !entry.is_file() || !file_name.starts_with("CVE-") || !file_name.ends_with(".json") {
            continue;
        }
        buf.clear();
        (&mut entry).take(MAX_RECORD + 1).read_to_end(&mut buf)?;
        if buf.len() as u64 > MAX_RECORD {
            skipped += 1;
            continue;
        }
        match cve5::parse(&buf) {
            Ok(cve) => batch.push(cve),
            Err(e) => {
                tracing::debug!(entry = %name, error = %e, "cvelistV5: record skipped");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_client::testserver::{listen, ok, ok_with, serve_on, status};
    use crate::sources::testutil::{context, state};
    use crate::sources::{SourceId, Sources};
    use std::io::Write;

    fn mark(tag: &str) -> Mark {
        Mark::parse_tag(tag).unwrap()
    }

    fn release(tag: &str) -> Release {
        let m = mark(tag);
        Release {
            mark: m,
            delta_url: Some(format!("delta:{tag}")),
            full_url: (m.pos != Pos::EndOfDay).then(|| format!("full:{}", m.date)),
        }
    }

    fn delta(tag: &str) -> Step {
        Step::Delta {
            url: format!("delta:{tag}"),
            mark: mark(tag),
        }
    }

    #[test]
    fn tags_are_read_and_written() {
        for tag in [
            "cve_2026-11-05_2000Z",
            "cve_2026-11-05_0000Z",
            "cve_2026-11-04_at_end_of_day",
            "cve_2026-11-04_start",
        ] {
            assert_eq!(mark(tag).tag(), tag);
        }
        for bad in [
            "cve_2026-11-05",
            "cve_2026-13-05_2000Z",
            "cve_2026-11-05_20Z",
            "v1.0",
        ] {
            assert_eq!(Mark::parse_tag(bad), None, "{bad}");
        }
        assert!(mark("cve_2026-11-04_2300Z") < mark("cve_2026-11-04_at_end_of_day"));
        assert!(mark("cve_2026-11-04_at_end_of_day") < mark("cve_2026-11-05_0000Z"));
        assert!(mark("cve_2026-11-05_start") < mark("cve_2026-11-05_0000Z"));
    }

    #[test]
    fn the_same_day_needs_only_the_newest_delta() {
        let releases = [
            release("cve_2026-11-05_1800Z"),
            release("cve_2026-11-05_1900Z"),
            release("cve_2026-11-05_2000Z"),
        ];
        let steps = plan(Some(mark("cve_2026-11-05_1800Z")), &releases).unwrap();
        assert_eq!(steps, [delta("cve_2026-11-05_2000Z")]);
        assert!(
            plan(Some(mark("cve_2026-11-05_2000Z")), &releases)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_new_day_first_closes_the_old_one() {
        let releases = [
            release("cve_2026-11-04_2200Z"),
            release("cve_2026-11-04_2300Z"),
            release("cve_2026-11-04_at_end_of_day"),
            release("cve_2026-11-05_0000Z"),
            release("cve_2026-11-05_0100Z"),
        ];
        let steps = plan(Some(mark("cve_2026-11-04_2200Z")), &releases).unwrap();
        assert_eq!(
            steps,
            [
                delta("cve_2026-11-04_at_end_of_day"),
                delta("cve_2026-11-05_0100Z")
            ]
        );
        let steps = plan(Some(mark("cve_2026-11-04_at_end_of_day")), &releases).unwrap();
        assert_eq!(steps, [delta("cve_2026-11-05_0100Z")]);
    }

    #[test]
    fn a_gap_or_no_cursor_starts_over_with_the_full_list() {
        let releases = [
            release("cve_2026-11-04_at_end_of_day"),
            release("cve_2026-11-05_0000Z"),
            release("cve_2026-11-05_0100Z"),
        ];
        let full = Step::Full {
            url: "full:2026-11-05".into(),
            date: "2026-11-05".parse().unwrap(),
        };
        let expected = [full, delta("cve_2026-11-05_0100Z")];
        assert_eq!(plan(None, &releases).unwrap(), expected);
        // The end of 2026-11-02 and all of 2026-11-03 are no longer in the list.
        assert_eq!(
            plan(Some(mark("cve_2026-11-02_1500Z")), &releases).unwrap(),
            expected
        );
        assert!(plan(None, &[]).is_err());
    }

    fn zip_of(entries: &[(&str, String)]) -> Vec<u8> {
        let mut out = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, body) in entries {
            out.start_file(*name, options).unwrap();
            out.write_all(body.as_bytes()).unwrap();
        }
        out.finish().unwrap().into_inner()
    }

    fn record(id: &str, updated: &str, title: &str) -> String {
        format!(
            r#"{{"cveMetadata": {{"cveId": "{id}", "state": "PUBLISHED", "assignerShortName": "example",
                 "datePublished": "2026-11-01T00:00:00Z", "dateUpdated": "{updated}"}},
                "containers": {{"cna": {{"title": "{title}", "descriptions": [{{"lang": "en", "value": "{title} in Widget."}}],
                   "affected": [{{"vendor": "Example", "product": "Widget"}}],
                   "metrics": [{{"cvssV3_1": {{"baseScore": 8.1, "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}}}}]}}}}}}"#
        )
    }

    fn releases_json(base: &str, tags: &[&str]) -> String {
        let list: Vec<String> = tags
            .iter()
            .map(|tag| {
                let day = &tag[4..14];
                format!(
                    r#"{{"tag_name": "{tag}", "body": "ignored", "assets": [
                        {{"name": "{day}_all_CVEs_at_midnight.zip.zip", "browser_download_url": "{base}/full/{tag}"}},
                        {{"name": "{day}_delta_CVEs_at_x.zip", "browser_download_url": "{base}/delta/{tag}"}},
                        {{"name": "evil_delta_CVEs_at_x.zip", "browser_download_url": "https://evil.example/x.zip"}}]}}"#
                )
            })
            .collect();
        format!("[{}]", list.join(","))
    }

    #[test]
    fn foreign_download_links_are_ignored() {
        let json = releases_json("https://elsewhere.example", &["cve_2026-11-05_0100Z"]);
        let releases =
            parse_releases(json.as_bytes(), "https://api.github.com/repos/x/releases").unwrap();
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0].delta_url, None);
        assert_eq!(releases[0].full_url, None);
    }

    #[tokio::test]
    async fn the_first_run_loads_the_full_list_and_later_runs_only_the_changes() {
        let inner = zip_of(&[
            (
                "cves/2026/0xxx/CVE-2026-0001.json",
                record("CVE-2026-0001", "2026-11-01T00:00:00Z", "Old title"),
            ),
            (
                "cves/2026/0xxx/CVE-2026-0002.json",
                record("CVE-2026-0002", "2026-11-01T00:00:00Z", "Second"),
            ),
            ("cves/2026/0xxx/CVE-2026-0003.json", "{broken".to_owned()),
            ("cves/delta.json", "{}".to_owned()),
        ]);
        let mut outer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        outer
            .start_file("cves.zip", zip::write::SimpleFileOptions::default())
            .unwrap();
        outer.write_all(&inner).unwrap();
        let outer = outer.finish().unwrap().into_inner();
        let delta_day = zip_of(&[
            (
                "deltaCves/CVE-2026-0001.json",
                record("CVE-2026-0001", "2026-11-05T09:00:00Z", "New title"),
            ),
            (
                "deltaCves/CVE-2026-0002.json",
                record("CVE-2026-0002", "2026-11-01T00:00:00Z", "Second"),
            ),
        ]);
        let delta_later = zip_of(&[
            (
                "deltaCves/CVE-2026-0001.json",
                record("CVE-2026-0001", "2026-11-05T09:00:00Z", "New title"),
            ),
            (
                "deltaCves/CVE-2026-0004.json",
                record("CVE-2026-0004", "2026-11-05T10:00:00Z", "Fourth"),
            ),
        ]);

        let (listener, addr) = listen().await;
        let base = format!("http://{addr}");
        let first = releases_json(&base, &["cve_2026-11-05_0800Z", "cve_2026-11-05_0900Z"]);
        let second = releases_json(
            &base,
            &[
                "cve_2026-11-05_0800Z",
                "cve_2026-11-05_0900Z",
                "cve_2026-11-05_1000Z",
            ],
        );
        // In order: release list, full list, delta (first run); release list, delta (second run);
        // 304 for the release list (third run).
        let mut requests = serve_on(
            listener,
            vec![
                ok_with("ETag: \"r1\"\r\n", first.as_bytes()),
                ok(&outer),
                ok(&delta_day),
                ok_with("ETag: \"r2\"\r\n", second.as_bytes()),
                ok(&delta_later),
                status(304, ""),
            ],
        );
        let (ctx, _dir) = context(&base).await;
        let sources = Sources::new(
            ctx.pool.clone(),
            ctx.work_dir.clone(),
            (*ctx.endpoints).clone(),
            false,
        );

        sources.run(SourceId::Cvelist).await;
        let s = state(&ctx, SourceId::Cvelist).await;
        assert_eq!(s.last_error, None);
        assert_eq!(s.cursor.as_deref(), Some("cve_2026-11-05_0900Z"));
        assert_eq!(s.version.as_deref(), Some("2026-11-05 09:00Z"));
        assert_eq!(
            (s.last_new, s.last_changed, s.item_count),
            (Some(2), Some(1), Some(2))
        );
        let paths: Vec<String> = (0..3)
            .map(|_| {
                requests
                    .try_recv()
                    .unwrap()
                    .lines()
                    .next()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(
            paths,
            [
                "GET /releases?per_page=60 HTTP/1.1",
                "GET /full/cve_2026-11-05_0900Z HTTP/1.1",
                "GET /delta/cve_2026-11-05_0900Z HTTP/1.1"
            ]
        );
        let (title, prio, products): (String, i64, String) =
            sqlx::query_as("SELECT title, prio, products FROM cves WHERE id = 'CVE-2026-0001'")
                .fetch_one(&ctx.pool)
                .await
                .unwrap();
        assert_eq!(
            (title.as_str(), prio, products.as_str()),
            ("New title", 57, "Example Widget")
        );
        let hits: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM cves_fts WHERE cves_fts MATCH 'widget'")
                .fetch_one(&ctx.pool)
                .await
                .unwrap();
        assert_eq!(hits, 2, "the full-text index follows the table");
        assert_eq!(
            std::fs::read_dir(&ctx.work_dir).unwrap().count(),
            0,
            "downloads are removed"
        );

        sources.run(SourceId::Cvelist).await;
        let s = state(&ctx, SourceId::Cvelist).await;
        assert_eq!(s.last_error, None);
        assert_eq!(s.cursor.as_deref(), Some("cve_2026-11-05_1000Z"));
        assert_eq!(
            (s.last_new, s.last_changed, s.item_count),
            (Some(1), Some(0), Some(3))
        );
        let list = requests.recv().await.unwrap().to_ascii_lowercase();
        assert!(list.contains("if-none-match: \"r1\""), "{list}");

        sources.run(SourceId::Cvelist).await;
        let s = state(&ctx, SourceId::Cvelist).await;
        assert_eq!(s.last_error, None);
        assert_eq!((s.last_new, s.last_changed), (Some(0), Some(0)));
        assert_eq!(s.cursor.as_deref(), Some("cve_2026-11-05_1000Z"));
    }

    #[test]
    fn the_real_delta_can_be_read() {
        // A copy fetched once into dev/cache/ (not in the repository); skipped without it.
        let path = Path::new("dev/cache/delta.zip");
        if !path.exists() {
            return;
        }
        let (sender, mut receiver) = mpsc::channel(10_000);
        let skipped = read_archive(path, &sender).unwrap();
        drop(sender);
        let mut records = 0;
        while let Ok(batch) = receiver.try_recv() {
            records += batch.len();
        }
        assert_eq!(skipped, 0);
        assert!(records > 1000, "{records}");
    }
}
