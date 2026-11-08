//! The CSAF sources: BSI CERT-Bund (one provider, TLP:WHITE feeds only) and the vendors chosen on the page
//! "Vendor CSAF". Both read the provider metadata, then every public distribution: a ROLIE feed or the
//! `changes.csv` of a directory, each with a conditional GET. Only documents that are new or have a new
//! `updated` time are fetched, a few at a time, with their checksum; refused documents are remembered until
//! the provider publishes a new version. OpenPGP signatures are not checked (yet).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use anyhow::{Context as _, bail};
use tokio::task::JoinSet;

use crate::csaf::document::{self, Advisory};
use crate::csaf::{self as reader, Checksum, DistKind, DocRef};
use crate::http_client::{self, Get, HttpError, Outcome, Session};
use crate::sources::{Context, SourceId, now_ms};
use crate::storage::advisories::{self as store, Origin, Provider};
use crate::storage::sources::{SourceState, Success};

const METADATA_MAX: u64 = 2 << 20;
const METADATA_TIMEOUT: Duration = Duration::from_secs(60);
/// BSI's feeds have 50 MB each and grow by a few MB a year.
const FEED_MAX: u64 = 400 << 20;
const FEED_TIMEOUT: Duration = Duration::from_secs(900);
const DOC_MAX: u64 = 32 << 20;
const DOC_TIMEOUT: Duration = Duration::from_secs(120);
const HASH_MAX: u64 = 4096;
const HASH_TIMEOUT: Duration = Duration::from_secs(30);
/// Documents fetched at the same time from one provider (one in the tests: the test server answers in order).
const PARALLEL: usize = if cfg!(test) { 1 } else { 4 };
/// Documents written per transaction.
const BATCH: usize = 50;
const LISTER_MAX: u64 = 4 << 20;

/// What a run of one provider brought.
#[derive(Debug, Default)]
struct Totals {
    new: i64,
    changed: i64,
    /// Refused documents by reason.
    refused: HashMap<String, usize>,
    /// Documents that could not be fetched (network); tried again on the next run.
    failed: usize,
    first_failure: Option<String>,
}

impl Totals {
    fn add(&mut self, other: Totals) {
        self.new += other.new;
        self.changed += other.changed;
        for (reason, n) in other.refused {
            *self.refused.entry(reason).or_default() += n;
        }
        self.failed += other.failed;
        if self.first_failure.is_none() {
            self.first_failure = other.first_failure;
        }
    }

    /// The warning of the run, if anything was refused or failed.
    fn warning(&self) -> Option<String> {
        let mut parts = Vec::new();
        let refused: usize = self.refused.values().sum();
        if refused > 0 {
            let mut reasons: Vec<_> = self.refused.iter().collect();
            reasons.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
            let top: Vec<String> = reasons
                .iter()
                .take(3)
                .map(|(r, n)| format!("{r}: {n}"))
                .collect();
            parts.push(format!("{refused} documents skipped ({})", top.join("; ")));
        }
        if self.failed > 0 {
            parts.push(format!(
                "{} documents could not be fetched and are tried again ({})",
                self.failed,
                self.first_failure.as_deref().unwrap_or("?")
            ));
        }
        (!parts.is_empty()).then(|| parts.join(". "))
    }
}

/// How fetching one document ended.
enum DocResult {
    Stored(Box<Advisory>, bool),
    /// Refused for good (until the feed names a new version).
    Refused(String),
    /// Not fetched (network, server error); tried again next time.
    Failed(String),
}

pub async fn run(ctx: &Context, source: SourceId, _state: &SourceState) -> anyhow::Result<Success> {
    let (source_name, providers) = match source {
        SourceId::Bsi => (
            "bsi",
            vec![store::bsi_provider(&ctx.pool, &ctx.endpoints.bsi).await?],
        ),
        SourceId::Vendor => (
            "vendor",
            store::providers(&ctx.pool, "vendor")
                .await?
                .into_iter()
                .filter(|p| p.enabled)
                .collect(),
        ),
        _ => bail!("not a CSAF source"),
    };
    let mut totals = Totals::default();
    let mut provider_errors = Vec::new();
    for p in &providers {
        match run_provider(ctx, source_name, p).await {
            Ok(t) => totals.add(t),
            Err(e) => {
                let text = format!("{e:#}");
                tracing::warn!(provider = %p.url, error = %text, "CSAF provider failed");
                store::provider_checked(&ctx.pool, p.id, now_ms(), None, None, Some(&text)).await?;
                provider_errors.push(format!("{}: {text}", display_name(p)));
            }
        }
    }
    // BSI is one provider: its failure is the source's. A vendor failing alone is a warning.
    if !provider_errors.is_empty() && provider_errors.len() == providers.len() {
        bail!("{}", provider_errors.join("; "));
    }
    let mut warning = totals.warning();
    if !provider_errors.is_empty() {
        let errors = provider_errors.join("; ");
        warning = Some(match warning {
            Some(w) => format!("{errors}. {w}"),
            None => errors,
        });
    }
    let version = match source {
        SourceId::Bsi => store::newest_day(&ctx.pool, source_name).await?,
        _ => Some(providers.len().to_string()),
    };
    Ok(Success {
        etag: None,
        last_modified: None,
        cursor: None,
        version,
        item_count: Some(store::count(&ctx.pool, source_name).await?),
        new: totals.new,
        changed: totals.changed,
        warning: warning.map(|w| crate::sources::cve5::clip(&w, 1000)),
    })
}

fn display_name(p: &Provider) -> &str {
    if p.name.is_empty() { &p.url } else { &p.name }
}

/// Reads a provider's metadata (also used when a vendor is added).
pub async fn fetch_metadata(url: &str) -> anyhow::Result<reader::Metadata> {
    let get = Get::new(url, METADATA_MAX, METADATA_TIMEOUT).accept("application/json");
    let fetched = http_client::get_bytes(&get)
        .await
        .context("loading the provider metadata")?
        .fresh()
        .context("the server answered 304 without a condition")?;
    reader::parse_metadata(&fetched.body).map_err(anyhow::Error::msg)
}

/// Loads the provider list of the BSI (CSAF lister).
pub async fn fetch_lister(url: &str) -> anyhow::Result<Vec<reader::Listed>> {
    let get = Get::new(url, LISTER_MAX, METADATA_TIMEOUT).accept("application/json");
    let fetched = http_client::get_bytes(&get)
        .await
        .context("loading the provider list")?
        .fresh()
        .context("the server answered 304 without a condition")?;
    reader::parse_aggregator(&fetched.body).map_err(anyhow::Error::msg)
}

async fn run_provider(ctx: &Context, source: &str, p: &Provider) -> anyhow::Result<Totals> {
    let meta = fetch_metadata(&p.url).await?;
    let skip = p.skip();
    let since = p.since_ms();
    let mut known = store::known(&ctx.pool, p.id).await?;
    let mut seen = HashSet::new();
    let mut totals = Totals::default();
    for dist in meta.distributions.iter().filter(|d| !skip.contains(&d.url)) {
        let feed_url = match dist.kind {
            DistKind::Rolie => dist.url.clone(),
            DistKind::Directory => format!("{}/changes.csv", dist.url),
        };
        let (etag, last_modified) = store::feed_validators(&ctx.pool, &feed_url).await?;
        let get = Get::new(&feed_url, FEED_MAX, FEED_TIMEOUT)
            .accept(match dist.kind {
                DistKind::Rolie => "application/json",
                DistKind::Directory => "text/csv, text/plain",
            })
            .conditional(etag.as_deref(), last_modified.as_deref());
        let fetched = match http_client::get_bytes(&get)
            .await
            .with_context(|| format!("loading {feed_url}"))?
        {
            Outcome::NotModified => continue,
            Outcome::Fresh(f) => f,
        };
        let docs = match dist.kind {
            DistKind::Rolie => reader::parse_rolie(&fetched.body),
            DistKind::Directory => {
                reader::parse_changes(&String::from_utf8_lossy(&fetched.body), &dist.url)
            }
        }
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("reading {feed_url}"))?;
        drop(fetched.body);
        let todo: Vec<DocRef> = docs
            .into_iter()
            .filter(|d| seen.insert(d.url.clone()))
            .filter(|d| known.get(&d.url) != Some(&d.updated))
            .filter(
                |d| match (since, crate::sources::parse_time_ms(&d.updated)) {
                    (Some(since), Some(updated)) => updated >= since,
                    _ => true,
                },
            )
            .collect();
        if !todo.is_empty() {
            tracing::info!(feed = %feed_url, documents = todo.len(), "fetching CSAF documents");
        }
        for d in &todo {
            known.insert(d.url.clone(), d.updated.clone());
        }
        let feed = fetch_documents(ctx, source, p.id, todo).await?;
        // Validators only when every document was handled: a failed one must be tried again next time.
        if feed.failed == 0 {
            store::save_feed(
                &ctx.pool,
                &feed_url,
                p.id,
                fetched.etag.as_deref(),
                fetched.last_modified.as_deref(),
                now_ms(),
            )
            .await?;
        }
        totals.add(feed);
    }
    store::provider_checked(
        &ctx.pool,
        p.id,
        now_ms(),
        Some(&meta.name),
        Some(&meta.distributions),
        None,
    )
    .await?;
    Ok(totals)
}

/// Fetches the documents a few at a time and stores them in batches.
async fn fetch_documents(
    ctx: &Context,
    source: &str,
    provider_id: i64,
    todo: Vec<DocRef>,
) -> anyhow::Result<Totals> {
    let mut totals = Totals::default();
    // Which checksum file a directory provider has (0 unknown, 1 .sha512, 2 .sha256, 3 none), learned on the way.
    let hash_hint = Arc::new(AtomicU8::new(0));
    let mut queue = todo.into_iter();
    let mut running = JoinSet::new();
    let mut done: Vec<(DocRef, DocResult)> = Vec::with_capacity(BATCH);
    // One kept-alive connection per download slot: a slot takes a session, fetches the document
    // and its checksum over it and hands it back.
    let mut sessions: Vec<Session> = Vec::with_capacity(PARALLEL);
    let deadline = std::time::Instant::now() + PROVIDER_BUDGET;
    let mut failures_in_a_row = 0;
    let mut stopped = None;
    loop {
        while running.len() < PARALLEL && stopped.is_none() {
            if failures_in_a_row >= MAX_FAILURES_IN_A_ROW {
                stopped = Some(format!("{failures_in_a_row} documents in a row failed"));
                break;
            }
            if std::time::Instant::now() > deadline {
                stopped = Some(format!(
                    "the time for one run ({} min) is up",
                    PROVIDER_BUDGET.as_secs() / 60
                ));
                break;
            }
            let Some(doc) = queue.next() else { break };
            let hint = Arc::clone(&hash_hint);
            let mut session = sessions.pop().unwrap_or_default();
            running.spawn(async move {
                let result = fetch_document(&mut session, &doc, &hint).await;
                (doc, result, session)
            });
        }
        let Some(joined) = running.join_next().await else {
            break;
        };
        let (doc, result, session) = joined.context("a download task failed")?;
        sessions.push(session);
        if matches!(result, DocResult::Failed(_)) {
            failures_in_a_row += 1;
        } else {
            failures_in_a_row = 0;
        }
        done.push((doc, result));
        if done.len() >= BATCH {
            write_batch(ctx, source, provider_id, &mut done, &mut totals).await?;
        }
    }
    write_batch(ctx, source, provider_id, &mut done, &mut totals).await?;
    if let Some(why) = stopped {
        let left = queue.count();
        if left > 0 {
            tracing::warn!(source, provider_id, left, reason = %why, "CSAF: stopped early, the rest follows");
            totals.failed += left;
            let first = totals.first_failure.take().unwrap_or_default();
            totals.first_failure = Some(format!(
                "stopped early ({why}); {left} documents follow on the next run; first failure: {first}"
            ));
        }
    }
    let stored_or_refused =
        totals.new + totals.changed + totals.refused.values().sum::<usize>() as i64;
    if totals.failed > 0 && stored_or_refused == 0 && totals.failed >= 10 {
        bail!(
            "no document could be fetched ({})",
            totals.first_failure.as_deref().unwrap_or("?")
        );
    }
    Ok(totals)
}

async fn write_batch(
    ctx: &Context,
    source: &str,
    provider_id: i64,
    done: &mut Vec<(DocRef, DocResult)>,
    totals: &mut Totals,
) -> anyhow::Result<()> {
    if done.is_empty() {
        return Ok(());
    }
    let now = now_ms();
    let mut tx = ctx.pool.begin().await?;
    for (doc, result) in done.iter() {
        match result {
            DocResult::Stored(advisory, hash_checked) => {
                let origin = Origin {
                    provider_id,
                    source,
                    url: &doc.url,
                    feed_updated: &doc.updated,
                    hash_checked: *hash_checked,
                    now_ms: now,
                };
                if store::store(&mut tx, &origin, advisory).await? {
                    totals.new += 1;
                } else {
                    totals.changed += 1;
                }
            }
            DocResult::Refused(reason) => {
                store::skip(&mut tx, provider_id, &doc.url, &doc.updated, reason, now).await?;
                *totals.refused.entry(reason.clone()).or_default() += 1;
            }
            DocResult::Failed(reason) => {
                totals.failed += 1;
                if totals.first_failure.is_none() {
                    totals.first_failure = Some(format!("{}: {reason}", doc.url));
                }
            }
        }
    }
    tx.commit().await?;
    ctx.progress.add(done.len() as u64);
    done.clear();
    Ok(())
}

/// A download error: missing for good (404/410) or worth another try.
fn classify(e: &HttpError) -> Result<(), String> {
    match e {
        HttpError::Status(404 | 410) => Ok(()),
        other => Err(other.to_string()),
    }
}

/// Some requests stall (about one in 40 at the BSI): give up a stalled step after this long and
/// try once more right away. What fails twice is tried again on the next run.
const DOC_IDLE: Duration = Duration::from_secs(15);
/// Longest time for the documents of one provider in a run, and most failed documents in a row: a slow or
/// broken provider must not hold up the other sources (the rest is fetched on the next run).
const PROVIDER_BUDGET: Duration = Duration::from_secs(if cfg!(test) { 5 } else { 30 * 60 });
const MAX_FAILURES_IN_A_ROW: usize = 20;

/// One GET of a document or checksum, repeated once after a stall or a refused connection.
async fn get_with_retry(
    session: &mut Session,
    get: &Get<'_>,
) -> Result<Outcome<Vec<u8>>, HttpError> {
    match session.get_bytes(get).await {
        Err(HttpError::Timeout | HttpError::Connect(_) | HttpError::Closed) => {
            session.get_bytes(get).await
        }
        other => other,
    }
}

async fn get_small(session: &mut Session, url: &str) -> Result<Option<Vec<u8>>, String> {
    let get = Get::new(url, HASH_MAX, HASH_TIMEOUT)
        .accept("text/plain")
        .idle(DOC_IDLE);
    match get_with_retry(session, &get).await {
        Ok(Outcome::Fresh(f)) => Ok(Some(f.body)),
        Ok(Outcome::NotModified) => Err("unexpected 304".to_owned()),
        Err(e) => classify(&e).map(|()| None),
    }
}

async fn fetch_document(session: &mut Session, doc: &DocRef, hint: &AtomicU8) -> DocResult {
    let get = Get::new(&doc.url, DOC_MAX, DOC_TIMEOUT)
        .accept("application/json")
        .idle(DOC_IDLE);
    let body = match get_with_retry(session, &get).await {
        Ok(Outcome::Fresh(f)) => f.body,
        Ok(Outcome::NotModified) => return DocResult::Failed("unexpected 304".to_owned()),
        Err(HttpError::TooLarge(n)) => {
            return DocResult::Refused(format!("larger than {} MB", n >> 20));
        }
        Err(e) => {
            return match classify(&e) {
                Ok(()) => DocResult::Refused("document not found".to_owned()),
                Err(e) => DocResult::Failed(e),
            };
        }
    };

    // The checksum: named by the feed, else next to the document.
    let hash_text = if let Some(url) = &doc.hash_url {
        match get_small(session, url).await {
            Ok(Some(text)) => Some(text),
            Ok(None) => return DocResult::Refused("checksum file not found".to_owned()),
            Err(e) => return DocResult::Failed(e),
        }
    } else {
        let order: &[(u8, &str)] = match hint.load(Ordering::Relaxed) {
            2 => &[(2, ".sha256"), (1, ".sha512")],
            3 => &[],
            _ => &[(1, ".sha512"), (2, ".sha256")],
        };
        let mut found = None;
        for (code, suffix) in order {
            match get_small(session, &format!("{}{suffix}", doc.url)).await {
                Ok(Some(text)) => {
                    hint.store(*code, Ordering::Relaxed);
                    found = Some(text);
                    break;
                }
                Ok(None) => {}
                Err(e) => return DocResult::Failed(e),
            }
        }
        if found.is_none() && !order.is_empty() {
            hint.store(3, Ordering::Relaxed);
        }
        found
    };
    let hash_checked = match hash_text {
        Some(text) => match Checksum::parse(&String::from_utf8_lossy(&text)) {
            Some(sum) if sum.matches(&body) => true,
            Some(_) => return DocResult::Refused("checksum does not match".to_owned()),
            None => return DocResult::Refused("checksum file unreadable".to_owned()),
        },
        None => false,
    };
    match document::parse(&body) {
        Ok(advisory) => DocResult::Stored(Box::new(advisory), hash_checked),
        Err(reason) => DocResult::Refused(short_reason(&reason)),
    }
}

/// Groups similar refusals (JSON errors name line and column).
fn short_reason(reason: &str) -> String {
    match reason.split_once(": ") {
        Some((head, _)) if head == "not valid JSON" => head.to_owned(),
        _ => reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csaf::document::tests::BSI_DOC;
    use crate::http_client::testserver::{listen, ok, ok_with, serve_on, status};
    use crate::sources::testutil;
    use sha2::Digest;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn metadata(base: &str) -> String {
        format!(
            r#"{{"canonical_url": "{base}/pm.json", "publisher": {{"name": "BSI"}}, "role": "csaf_trusted_provider",
                "distributions": [{{"rolie": {{"feeds": [
                  {{"tlp_label": "WHITE", "url": "{base}/white/feed.json"}},
                  {{"tlp_label": "GREEN", "url": "{base}/green/feed.json"}}]}}}}]}}"#
        )
    }

    fn feed(base: &str, entries: &[(&str, &str)]) -> String {
        let entries: Vec<String> = entries
            .iter()
            .map(|(name, updated)| {
                format!(
                    r#"{{"updated": "{updated}", "link": [
                         {{"rel": "self", "href": "{base}/white/{name}.json"}},
                         {{"rel": "hash", "href": "{base}/white/{name}.json.sha512"}}],
                       "content": {{"src": "{base}/white/{name}.json"}}}}"#
                )
            })
            .collect();
        format!(r#"{{"feed": {{"entry": [{}]}}}}"#, entries.join(","))
    }

    fn sha512(data: &[u8]) -> Vec<u8> {
        format!("{}  doc.json\n", hex(sha2::Sha512::digest(data).as_slice())).into_bytes()
    }

    #[tokio::test]
    async fn a_broken_provider_is_given_up_after_some_failures_in_a_row() {
        let (listener, addr) = listen().await;
        let base = format!("http://{addr}");
        let names: Vec<String> = (0..25).map(|i| format!("d{i}")).collect();
        let entries: Vec<(&str, &str)> = names
            .iter()
            .map(|n| (n.as_str(), "2026-11-05T10:00:00Z"))
            .collect();
        let feed = feed(&base, &entries);
        // After the metadata and the feed the server is gone: every document fails.
        let _requests = serve_on(
            listener,
            vec![ok(metadata(&base).as_bytes()), ok(feed.as_bytes())],
        );
        let (ctx, _dir) = testutil::context(&base).await;
        let state = testutil::state(&ctx, SourceId::Bsi).await;
        let error = run(&ctx, SourceId::Bsi, &state).await.unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("no document could be fetched"), "{text}");
        assert!(
            text.contains("stopped early (20 documents in a row failed); 5 documents"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn bsi_documents_are_fetched_checked_and_fetched_again_only_when_changed() {
        let (listener, addr) = listen().await;
        let base = format!("http://{addr}");
        let doc_a = BSI_DOC.as_bytes().to_vec();
        let doc_b = BSI_DOC
            .replace("WID-SEC-W-2026-4365", "WID-SEC-W-2026-0001")
            .replace("WID-SEC-2026-4365", "WID-SEC-2026-0001")
            .into_bytes();
        let green = BSI_DOC
            .replace(r#""label": "WHITE""#, r#""label": "GREEN""#)
            .into_bytes();
        let first_feed = feed(
            &base,
            &[
                ("a", "2026-11-05T23:00:00Z"),
                ("b", "2026-11-04T10:00:00Z"),
                ("c", "2026-11-03T10:00:00Z"),
                ("d", "2026-11-02T10:00:00Z"),
                ("e", "2026-11-01T10:00:00Z"),
            ],
        );
        let second_feed = feed(
            &base,
            &[
                ("a", "2026-11-06T08:00:00Z"),
                ("b", "2026-11-04T10:00:00Z"),
                ("c", "2026-11-03T10:00:00Z"),
                ("d", "2026-11-02T10:00:00Z"),
                ("e", "2026-11-01T10:00:00Z"),
            ],
        );
        let mut requests = serve_on(
            listener,
            vec![
                // Run 1: metadata, feed, then document and checksum for a … e.
                ok(metadata(&base).as_bytes()),
                ok_with("ETag: \"f1\"\r\n", first_feed.as_bytes()),
                ok(&doc_a),
                ok(&sha512(&doc_a)),
                ok(&doc_b),
                ok(&sha512(b"something else")),
                ok(&green),
                ok(&sha512(&green)),
                status(404, ""),
                ok(b"{}"),
                status(503, ""),
                // Run 2: the feed has not changed.
                ok(metadata(&base).as_bytes()),
                status(304, ""),
                // Run 3: a new version of a.
                ok(metadata(&base).as_bytes()),
                ok_with("ETag: \"f2\"\r\n", second_feed.as_bytes()),
                ok(&doc_a),
                ok(&sha512(&doc_a)),
                ok(&doc_b),
                ok(&sha512(&doc_b)),
            ],
        );
        let (ctx, _dir) = testutil::context(&base).await;
        let state = testutil::state(&ctx, SourceId::Bsi).await;

        let s = run(&ctx, SourceId::Bsi, &state).await.unwrap();
        assert_eq!((s.new, s.changed), (1, 0));
        assert_eq!(s.item_count, Some(1));
        assert_eq!(s.version.as_deref(), Some("2026-11-05"));
        let warning = s.warning.unwrap();
        assert!(warning.contains("3 documents skipped"), "{warning}");
        assert!(warning.contains("checksum does not match: 1"), "{warning}");
        assert!(
            warning.contains("the document is TLP:GREEN: 1"),
            "{warning}"
        );
        assert!(
            warning.contains("1 documents could not be fetched"),
            "{warning}"
        );
        // The GREEN feed is never asked for; the feed's ETag is not kept because e failed.
        let mut heads = Vec::new();
        while let Ok(h) = requests.try_recv() {
            heads.push(h.lines().next().unwrap_or_default().to_owned());
        }
        assert!(heads.iter().all(|h| !h.contains("/green/")), "{heads:?}");
        assert_eq!(
            store::feed_validators(&ctx.pool, &format!("{base}/white/feed.json"))
                .await
                .unwrap(),
            (None, None)
        );
        let skipped: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM csaf_skipped")
            .fetch_one(&ctx.pool)
            .await
            .unwrap();
        assert_eq!(skipped, 3);

        // Pretend run 1 had kept the validators: the server says 304, nothing is fetched.
        store::save_feed(
            &ctx.pool,
            &format!("{base}/white/feed.json"),
            1,
            Some("\"f1\""),
            None,
            0,
        )
        .await
        .unwrap();
        let s = run(&ctx, SourceId::Bsi, &state).await.unwrap();
        assert_eq!((s.new, s.changed, s.warning), (0, 0, None));
        let head = requests.recv().await.unwrap();
        assert!(head.contains("pm.json"));
        let head = requests.recv().await.unwrap();
        assert!(head.contains("if-none-match: \"f1\""), "{head}");

        // A new version of a: it is replaced. b, c and d (refused, unchanged) are not asked for again; e failed
        // in run 1 and is fetched again (the server hands it b's content, a second advisory).
        let s = run(&ctx, SourceId::Bsi, &state).await.unwrap();
        assert_eq!(
            (s.new, s.changed, s.warning.as_deref()),
            (1, 1, None),
            "{s:?}"
        );
        let provider = store::bsi_provider(&ctx.pool, &format!("{base}/pm.json"))
            .await
            .unwrap();
        assert_eq!(provider.name, "BSI");
        assert_eq!(provider.documents, s.item_count.unwrap());
    }

    #[test]
    fn warnings_name_the_most_frequent_reasons() {
        let mut t = Totals::default();
        t.refused.insert("checksum does not match".into(), 2);
        t.refused.insert("not valid JSON".into(), 5);
        t.failed = 1;
        t.first_failure = Some("https://x/a.json: timed out".into());
        assert_eq!(
            t.warning().unwrap(),
            "7 documents skipped (not valid JSON: 5; checksum does not match: 2). \
             1 documents could not be fetched and are tried again (https://x/a.json: timed out)"
        );
        assert_eq!(Totals::default().warning(), None);
        assert_eq!(
            short_reason("not valid JSON: expected value at line 1"),
            "not valid JSON"
        );
    }
}
