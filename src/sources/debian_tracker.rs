//! The Debian Security Tracker (`security-tracker.debian.org/tracker/data/json`): every known issue per
//! source package and release, about 90 MB of JSON (asked for with its validators and gzip).
//!
//! OSV already says which version fixes an issue. The tracker adds what OSV leaves out, and only that is
//! kept: issues still open or undetermined in a release, and issues the security team will not fix with a
//! DSA ("no-dsa", with the reason "postponed" or "ignored"). The downloaded file is read package by
//! package, so its descriptions never become structures in memory (only the file itself is held).

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use anyhow::anyhow;
use serde::Deserialize;
use serde::de::{MapAccess, Visitor};

use crate::http_client::{self, Get, Outcome};
use crate::sources::Context;
use crate::sources::cve5::{clip, is_cve_id};
use crate::storage::distros::{self, TrackerRow};
use crate::storage::sources::{SourceState, Success};

/// About four times the size of the file in November 2026.
const MAX_BYTES: u64 = 384 << 20;
const TIMEOUT: Duration = Duration::from_secs(900);
/// Most rows kept (about 30,000 in November 2026).
const MAX_ROWS: usize = 2_000_000;

#[derive(Deserialize)]
struct Issue {
    #[serde(default)]
    releases: HashMap<String, Release>,
}

#[derive(Deserialize)]
struct Release {
    #[serde(default)]
    status: String,
    #[serde(default)]
    urgency: String,
    #[serde(default)]
    nodsa: Option<String>,
    #[serde(default)]
    nodsa_reason: Option<String>,
    #[serde(default)]
    fixed_version: Option<String>,
}

/// The rows to keep, collected while the document is read.
struct Rows(Vec<TrackerRow>);

impl<'de> Deserialize<'de> for Rows {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_map(RowsVisitor)
    }
}

struct RowsVisitor;

impl<'de> Visitor<'de> for RowsVisitor {
    type Value = Rows;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a map of source packages")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Rows, A::Error> {
        let mut rows = Vec::new();
        while let Some(package) = map.next_key::<String>()? {
            let issues: HashMap<String, Issue> = map.next_value()?;
            if !valid_package(&package) {
                continue;
            }
            for (cve, issue) in issues {
                if !is_cve_id(&cve) {
                    continue;
                }
                for (release, r) in issue.releases {
                    let nodsa = r.nodsa.is_some();
                    if (r.status == "resolved" && !nodsa)
                        || !valid_release(&release)
                        || r.status.is_empty()
                    {
                        continue;
                    }
                    if rows.len() >= MAX_ROWS {
                        return Err(serde::de::Error::custom("too many open issues"));
                    }
                    rows.push(TrackerRow {
                        cve_id: cve.clone(),
                        package: package.clone(),
                        release,
                        status: clip(&r.status, 20),
                        urgency: clip(&r.urgency, 40),
                        nodsa: clip(r.nodsa.as_deref().unwrap_or_default().trim(), 200),
                        nodsa_reason: clip(r.nodsa_reason.as_deref().unwrap_or_default(), 40),
                        fixed_version: clip(r.fixed_version.as_deref().unwrap_or_default(), 200),
                    });
                }
            }
        }
        Ok(Rows(rows))
    }
}

fn valid_package(name: &str) -> bool {
    (1..=200).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'+' | b'_'))
}

fn valid_release(name: &str) -> bool {
    (1..=20).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_lowercase())
}

/// Reads the tracker's JSON into the rows to keep.
pub fn parse(bytes: &[u8]) -> Result<Vec<TrackerRow>, String> {
    serde_json::from_slice::<Rows>(bytes)
        .map(|r| r.0)
        .map_err(|e| format!("the tracker data is not valid: {e}"))
}

/// The Debian version of a codename ("13" for trixie); `None` for unknown names and sid.
pub fn version_of(codename: &str) -> Option<&'static str> {
    Some(match codename {
        "buster" => "10",
        "bullseye" => "11",
        "bookworm" => "12",
        "trixie" => "13",
        "forky" => "14",
        "duke" => "15",
        _ => return None,
    })
}

/// The codename of a Debian version ("trixie" for 13).
pub fn codename_of(version: &str) -> Option<&'static str> {
    ["buster", "bullseye", "bookworm", "trixie", "forky", "duke"]
        .into_iter()
        .find(|c| version_of(c) == Some(version))
}

/// When the data was written (its `Last-Modified`, else now), for the sources page.
fn data_time(last_modified: Option<&str>) -> String {
    last_modified
        .and_then(|t| jiff::fmt::rfc2822::parse(t).ok())
        .map(|z| z.timestamp())
        .unwrap_or_else(jiff::Timestamp::now)
        .strftime("%Y-%m-%d %H:%MZ")
        .to_string()
}

pub async fn run(ctx: &Context, state: &SourceState) -> anyhow::Result<Success> {
    let get = Get::new(&ctx.endpoints.debian_tracker, MAX_BYTES, TIMEOUT)
        .accept("application/json")
        .conditional(state.etag.as_deref(), state.last_modified.as_deref());
    let fetched = match http_client::get_bytes(&get).await? {
        Outcome::NotModified => return Ok(Success::default()),
        Outcome::Fresh(fetched) => fetched,
    };
    let body = fetched.body;
    let rows = tokio::task::spawn_blocking(move || parse(&body))
        .await
        .map_err(|e| anyhow!("reading the tracker data stopped: {e}"))?
        .map_err(|e| anyhow!(e))?;
    ctx.progress.add(rows.len() as u64);
    let replaced = distros::replace_tracker(&ctx.pool, rows).await?;
    let count = distros::tracker_count(&ctx.pool).await?;
    let version = data_time(fetched.last_modified.as_deref());
    Ok(Success {
        etag: fetched.etag,
        last_modified: fetched.last_modified,
        cursor: None,
        version: Some(version),
        item_count: Some(count),
        new: replaced.new,
        changed: replaced.changed,
        warning: None,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::http_client::testserver::{gzip, listen, ok_with, serve_on, status};
    use crate::sources::testutil::{context, state};
    use crate::sources::{SourceId, Sources};

    pub(crate) const TRACKER: &str = r#"{
      "389-ds-base": {
        "CVE-2023-1055": {"description": "A flaw <b>was</b> found.", "debianbug": 1034891, "scope": "local",
          "releases": {
            "bookworm": {"status": "open", "repositories": {"bookworm": "2.3.1+dfsg1-1+deb12u1"},
                         "urgency": "not yet assigned", "nodsa": "Minor issue", "nodsa_reason": ""},
            "sid": {"status": "resolved", "repositories": {"sid": "3.3.1-3"}, "fixed_version": "2.3.4+dfsg1-1",
                    "urgency": "not yet assigned"}}},
        "TEMP-0000000-ABCDEF": {"releases": {"trixie": {"status": "open", "urgency": "low"}}}
      },
      "libpng1.6": {
        "CVE-2026-33416": {"releases": {
            "trixie": {"status": "open", "urgency": "medium", "nodsa": "Minor issue", "nodsa_reason": "postponed"},
            "forky": {"status": "undetermined", "urgency": "unimportant"},
            "bookworm": {"status": "resolved", "fixed_version": "1.6.39-2+deb12u4", "urgency": "medium"}}}
      },
      "../evil": {"CVE-2026-1": {"releases": {"trixie": {"status": "open"}}}}
    }"#;

    fn key(r: &TrackerRow) -> (&str, &str, &str, &str, &str) {
        (
            r.package.as_str(),
            r.cve_id.as_str(),
            r.release.as_str(),
            r.status.as_str(),
            r.nodsa_reason.as_str(),
        )
    }

    #[test]
    fn only_open_and_no_dsa_issues_are_kept() {
        let mut rows = parse(TRACKER.as_bytes()).unwrap();
        rows.sort_by(|a, b| key(a).cmp(&key(b)));
        let keys: Vec<_> = rows.iter().map(key).collect();
        assert_eq!(
            keys,
            [
                ("389-ds-base", "CVE-2023-1055", "bookworm", "open", ""),
                ("libpng1.6", "CVE-2026-33416", "forky", "undetermined", ""),
                ("libpng1.6", "CVE-2026-33416", "trixie", "open", "postponed"),
            ]
        );
        assert_eq!(rows[0].nodsa, "Minor issue");
        assert!(parse(b"[1, 2]").is_err());
        assert!(parse(br#"{"p": {"CVE-2026-1": {"releases": {"trixie": "x"}}}}"#).is_err());
    }

    #[test]
    fn the_data_time_comes_from_last_modified() {
        assert_eq!(
            data_time(Some("Thu, 05 Nov 2026 13:30:39 GMT")),
            "2026-11-05 13:30Z"
        );
        assert_eq!(data_time(Some("gestern")).len(), 17);
    }

    #[test]
    fn codenames_and_versions_belong_together() {
        assert_eq!(version_of("trixie"), Some("13"));
        assert_eq!(codename_of("12"), Some("bookworm"));
        assert_eq!(version_of("sid"), None);
        assert_eq!(codename_of("99"), None);
    }

    #[tokio::test]
    async fn a_run_stores_the_rows_and_honours_the_validators() {
        let (listener, addr) = listen().await;
        let (ctx, _dir) = context(&format!("http://{addr}")).await;
        let sources = Sources::new(
            ctx.pool.clone(),
            ctx.work_dir.clone(),
            (*ctx.endpoints).clone(),
            false,
        );
        serve_on(
            listener,
            vec![
                ok_with(
                    "Content-Encoding: gzip\r\nETag: \"t1\"\r\n",
                    &gzip(TRACKER.as_bytes()),
                ),
                status(304, ""),
            ],
        );
        sources.run(SourceId::DebianTracker).await;
        let s = state(&ctx, SourceId::DebianTracker).await;
        assert_eq!(s.last_error, None);
        assert_eq!(s.item_count, Some(3));
        assert_eq!(s.last_new, Some(3));
        assert_eq!(s.etag.as_deref(), Some("\"t1\""));
        sources.run_now(SourceId::DebianTracker).await.unwrap();
        sources.run(SourceId::DebianTracker).await;
        let s = state(&ctx, SourceId::DebianTracker).await;
        assert_eq!(s.last_error, None);
        assert_eq!(s.item_count, Some(3));
    }
}
