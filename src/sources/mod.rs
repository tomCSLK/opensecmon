//! The sources: what they are, when they run and how a run is recorded.
//!
//! One background task runs the due sources one after another (never two at once: the large imports
//! would only compete for the disk and the database). Every source keeps its validators and a cursor in
//! `source_state`, so a run only downloads what changed. Contents of the sources are data, never
//! instructions: they are parsed strictly, limited in size and escaped when shown.

pub mod csaf;
pub mod cve5;
pub mod cvelist;
pub mod debian_tracker;
pub mod epss;
pub mod kev;
pub mod nvd;
pub mod osv;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::Rng;
use sqlx::SqlitePool;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::storage::sources::{self as store, SourceState, Success};

/// Longest a single run may take (the first import of cvelistV5 and the NVD takes a few minutes).
const RUN_LIMIT: Duration = Duration::from_secs(3 * 3600);
/// Longest sleep of the scheduler between two looks at the table.
const IDLE_CHECK: Duration = Duration::from_secs(60);
/// First wait after a failure; doubles with every further failure, up to the interval.
const BACKOFF_START_SECS: i64 = 300;

/// The sources, in the order they run when several are due.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceId {
    Cvelist,
    Nvd,
    Kev,
    Epss,
    /// BSI CERT-Bund, CSAF (TLP:WHITE).
    Bsi,
    /// The CSAF providers of vendors chosen on the page "Vendor CSAF".
    Vendor,
    /// OSV records of Debian (DSA, DLA, DTSA, DEBIAN-CVE).
    OsvDebian,
    /// OSV records of Ubuntu (USN, LSN, UBUNTU-CVE).
    OsvUbuntu,
    /// The open issues of the Debian Security Tracker.
    DebianTracker,
}

impl SourceId {
    pub const ALL: [Self; 9] = [
        Self::Cvelist,
        Self::Nvd,
        Self::Kev,
        Self::Epss,
        Self::Bsi,
        Self::Vendor,
        Self::OsvDebian,
        Self::OsvUbuntu,
        Self::DebianTracker,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cvelist => "cvelist",
            Self::Nvd => "nvd",
            Self::Kev => "kev",
            Self::Epss => "epss",
            Self::Bsi => "bsi",
            Self::Vendor => "vendor",
            Self::OsvDebian => "osv_debian",
            Self::OsvUbuntu => "osv_ubuntu",
            Self::DebianTracker => "debian_tracker",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|id| id.as_str() == s)
    }

    /// Catalog id of the name.
    pub fn label_id(self) -> &'static str {
        match self {
            Self::Cvelist => "source-cvelist",
            Self::Nvd => "source-nvd",
            Self::Kev => "source-kev",
            Self::Epss => "source-epss",
            Self::Bsi => "source-bsi",
            Self::Vendor => "source-vendor",
            Self::OsvDebian => "source-osv-debian",
            Self::OsvUbuntu => "source-osv-ubuntu",
            Self::DebianTracker => "source-debian-tracker",
        }
    }

    /// Catalog id of the notice on licence and attribution.
    pub fn notice_id(self) -> &'static str {
        match self {
            Self::Cvelist => "source-cvelist-notice",
            Self::Nvd => "source-nvd-notice",
            Self::Kev => "source-kev-notice",
            Self::Epss => "source-epss-notice",
            Self::Bsi => "source-bsi-notice",
            Self::Vendor => "source-vendor-notice",
            Self::OsvDebian => "source-osv-debian-notice",
            Self::OsvUbuntu => "source-osv-ubuntu-notice",
            Self::DebianTracker => "source-debian-tracker-notice",
        }
    }

    /// Catalog id of the line that describes the stored state (`version`, `count`).
    pub fn state_id(self) -> &'static str {
        match self {
            Self::Cvelist => "source-cvelist-state",
            Self::Nvd => "source-nvd-state",
            Self::Kev => "source-kev-state",
            Self::Epss => "source-epss-state",
            Self::Bsi => "source-bsi-state",
            Self::Vendor => "source-vendor-state",
            Self::OsvDebian => "source-osv-debian-state",
            Self::OsvUbuntu => "source-osv-ubuntu-state",
            Self::DebianTracker => "source-debian-tracker-state",
        }
    }

    /// Shortest interval the source may be asked in (the NVD asks for at most one request per two hours
    /// on its feeds; EPSS changes once a day).
    pub fn min_interval_secs(self) -> i64 {
        match self {
            Self::Cvelist
            | Self::Kev
            | Self::Bsi
            | Self::Vendor
            | Self::OsvDebian
            | Self::OsvUbuntu
            | Self::DebianTracker => 3600,
            Self::Nvd => 7200,
            Self::Epss => 86_400,
        }
    }

    /// The intervals that can be chosen.
    pub fn intervals(self) -> Vec<i64> {
        INTERVALS
            .into_iter()
            .filter(|&s| s >= self.min_interval_secs())
            .collect()
    }
}

/// Intervals offered on the sources page.
pub const INTERVALS: [i64; 5] = [3600, 7200, 21_600, 43_200, 86_400];

/// Where the sources are fetched from; the tests point them at a local server.
#[derive(Debug, Clone)]
pub struct Endpoints {
    /// GitHub API: the releases of cvelistV5.
    pub cvelist_releases: String,
    /// Directory of the NVD JSON 2.0 feeds (`…/nvdcve-2.0-modified.meta` etc.).
    pub nvd_feeds: String,
    pub kev: String,
    pub epss: String,
    /// BSI CERT-Bund's provider-metadata.json.
    pub bsi: String,
    /// The BSI's list of CSAF providers (offered on the page "Vendor CSAF").
    pub csaf_lister: String,
    /// The OSV bucket (`…/Debian/all.zip`, `…/Ubuntu/modified_id.csv` …).
    pub osv: String,
    /// The JSON of the Debian Security Tracker.
    pub debian_tracker: String,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            cvelist_releases: "https://api.github.com/repos/CVEProject/cvelistV5/releases".to_owned(),
            nvd_feeds: "https://nvd.nist.gov/feeds/json/cve/2.0".to_owned(),
            kev: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
                .to_owned(),
            epss: "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz".to_owned(),
            bsi: "https://wid.cert-bund.de/.well-known/csaf/provider-metadata.json".to_owned(),
            csaf_lister: "https://wid.cert-bund.de/.well-known/csaf-aggregator/aggregator.json"
                .to_owned(),
            osv: "https://osv-vulnerabilities.storage.googleapis.com".to_owned(),
            debian_tracker: "https://security-tracker.debian.org/tracker/data/json".to_owned(),
        }
    }
}

/// Records processed by the running source, for the progress shown on the sources page.
#[derive(Debug, Clone, Default)]
pub struct Progress(Arc<AtomicU64>);

impl Progress {
    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    fn reset(&self) {
        self.0.store(0, Ordering::Relaxed);
    }
}

/// What a source run gets to work with.
#[derive(Debug, Clone)]
pub struct Context {
    pub pool: SqlitePool,
    pub endpoints: Arc<Endpoints>,
    /// Directory for downloads (created on start, emptied before and after every run).
    pub work_dir: PathBuf,
    pub progress: Progress,
}

impl Context {
    /// A path for a download in the work directory.
    pub fn download_path(&self, name: &str) -> PathBuf {
        self.work_dir.join(name)
    }
}

/// The source that runs right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Running {
    pub source: SourceId,
    pub started_ms: i64,
    pub processed: u64,
}

/// The handle of the sources: start, wake and ask the scheduler. Cheap to clone.
#[derive(Clone)]
pub struct Sources {
    inner: Arc<Inner>,
}

struct Inner {
    ctx: Context,
    scheduled: bool,
    wake: Notify,
    running: Mutex<Option<(SourceId, i64)>>,
    status: Mutex<Status>,
}

/// What the top bar of every page says about the sources (kept in memory, refreshed after every run).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Status {
    /// Whether the state was read at least once (before that the top bar shows nothing).
    pub known: bool,
    /// End of the last run of any source.
    pub checked_ms: Option<i64>,
    /// Switched-on sources whose last run failed.
    pub failing: u32,
    /// The source that runs right now.
    pub running: Option<SourceId>,
}

impl Sources {
    /// `scheduled = false` runs a source only when asked to ("fetch now").
    pub fn new(pool: SqlitePool, work_dir: PathBuf, endpoints: Endpoints, scheduled: bool) -> Self {
        Self {
            inner: Arc::new(Inner {
                ctx: Context {
                    pool,
                    endpoints: Arc::new(endpoints),
                    work_dir,
                    progress: Progress::default(),
                },
                scheduled,
                wake: Notify::new(),
                running: Mutex::new(None),
                status: Mutex::new(Status::default()),
            }),
        }
    }

    /// Starts the scheduler task.
    pub fn spawn(&self) -> Scheduler {
        let this = self.clone();
        Scheduler {
            task: tokio::spawn(async move { this.schedule().await }),
        }
    }

    /// The source that runs right now and how far it got.
    pub fn running(&self) -> Option<Running> {
        let running = *self.inner.running.lock().unwrap_or_else(|e| e.into_inner());
        running.map(|(source, started_ms)| Running {
            source,
            started_ms,
            processed: self.inner.ctx.progress.get(),
        })
    }

    /// Where the sources are fetched from.
    pub fn endpoints(&self) -> &Endpoints {
        &self.inner.ctx.endpoints
    }

    /// Whether the sources run on their own schedule (`fetch_sources`); otherwise only when asked.
    pub fn scheduled(&self) -> bool {
        self.inner.scheduled
    }

    /// What the top bar says about the sources.
    pub fn status(&self) -> Status {
        let mut status = *self.inner.status.lock().unwrap_or_else(|e| e.into_inner());
        status.running = self.running().map(|r| r.source);
        status
    }

    /// Reads the state of the sources again for [`Self::status`].
    pub async fn refresh_status(&self) {
        match store::all(&self.inner.ctx.pool).await {
            Ok(states) => {
                let status = Status {
                    known: true,
                    checked_ms: states.iter().filter_map(|s| s.last_finished_ms).max(),
                    failing: states
                        .iter()
                        .filter(|s| s.enabled && s.failures > 0)
                        .count()
                        .try_into()
                        .unwrap_or(u32::MAX),
                    running: None,
                };
                *self.inner.status.lock().unwrap_or_else(|e| e.into_inner()) = status;
            }
            Err(e) => tracing::error!(error = %e, "reading the state of the sources failed"),
        }
    }

    /// Makes `source` due now and wakes the scheduler.
    pub async fn run_now(&self, source: SourceId) -> crate::error::Result<()> {
        store::due_now(&self.inner.ctx.pool, source.as_str()).await?;
        self.inner.wake.notify_one();
        Ok(())
    }

    /// Wakes the scheduler after a change of the settings.
    pub fn wake(&self) {
        self.inner.wake.notify_one();
    }

    async fn schedule(&self) {
        let ctx = &self.inner.ctx;
        if let Err(e) = prepare_work_dir(&ctx.work_dir).await {
            tracing::error!(dir = %ctx.work_dir.display(), error = %e, "cannot prepare the download directory");
        }
        self.refresh_status().await;
        loop {
            let wait = match self.next_due().await {
                Ok(Next::Run(source)) => {
                    self.run(source).await;
                    continue;
                }
                Ok(Next::Wait(wait)) => wait,
                Err(e) => {
                    tracing::error!(error = %e, "reading the state of the sources failed");
                    IDLE_CHECK
                }
            };
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                () = self.inner.wake.notified() => {}
            }
        }
    }

    /// The first due source, or how long to sleep.
    async fn next_due(&self) -> crate::error::Result<Next> {
        let now = now_ms();
        let states = store::all(&self.inner.ctx.pool).await?;
        let mut wait = IDLE_CHECK;
        for id in SourceId::ALL {
            let Some(state) = states.iter().find(|s| s.source == id.as_str()) else {
                continue;
            };
            // Unscheduled: only what "fetch now" asked for, never a fresh row (0).
            let eligible = if self.inner.scheduled {
                state.enabled
            } else {
                state.next_run_ms == store::REQUESTED
            };
            if !eligible {
                continue;
            }
            if state.next_run_ms <= now {
                return Ok(Next::Run(id));
            }
            let until = Duration::from_millis((state.next_run_ms - now).unsigned_abs());
            wait = wait.min(until);
        }
        Ok(Next::Wait(wait))
    }

    /// Runs one source and records the outcome.
    pub async fn run(&self, source: SourceId) {
        let ctx = &self.inner.ctx;
        let name = source.as_str();
        let Ok(Some(state)) = store::get(&ctx.pool, name).await else {
            tracing::error!(source = name, "the source has no state row");
            return;
        };
        let started_ms = now_ms();
        if let Err(e) = store::started(&ctx.pool, name, started_ms).await {
            tracing::error!(source = name, error = %e, "recording the start failed");
        }
        ctx.progress.reset();
        *self.inner.running.lock().unwrap_or_else(|e| e.into_inner()) = Some((source, started_ms));
        let _ = prepare_work_dir(&ctx.work_dir).await;
        tracing::info!(source = name, "fetching");
        let clock = Instant::now();
        let outcome = match tokio::time::timeout(RUN_LIMIT, run_source(source, ctx, &state)).await {
            Ok(outcome) => outcome,
            Err(_) => Err(anyhow::anyhow!(
                "gave up after {} hours",
                RUN_LIMIT.as_secs() / 3600
            )),
        };
        let duration_ms = i64::try_from(clock.elapsed().as_millis()).unwrap_or(i64::MAX);
        let _ = prepare_work_dir(&ctx.work_dir).await;
        let finished_ms = now_ms();
        let recorded = match &outcome {
            Ok(success) => {
                tracing::info!(
                    source = name,
                    new = success.new,
                    changed = success.changed,
                    seconds = duration_ms / 1000,
                    "fetched"
                );
                let next = finished_ms + next_delay_secs(state.interval_secs, 0) * 1000;
                store::succeeded(&ctx.pool, name, finished_ms, duration_ms, next, success).await
            }
            Err(e) => {
                let text = error_text(e);
                tracing::warn!(source = name, error = %text, "fetching failed");
                let next =
                    finished_ms + next_delay_secs(state.interval_secs, state.failures + 1) * 1000;
                store::failed(&ctx.pool, name, finished_ms, duration_ms, next, &text).await
            }
        };
        if let Err(e) = recorded {
            tracing::error!(source = name, error = %e, "recording the outcome failed");
        }
        // New data: match the assets again (still shown as running, so a second run waits).
        if let Ok(success) = &outcome
            && success.new + success.changed > 0
            && let Err(e) = crate::matching::match_all(&ctx.pool, now_ms()).await
        {
            tracing::error!(source = name, error = %e, "matching the assets failed");
        }
        *self.inner.running.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.refresh_status().await;
    }
}

enum Next {
    Run(SourceId),
    Wait(Duration),
}

async fn run_source(
    source: SourceId,
    ctx: &Context,
    state: &SourceState,
) -> anyhow::Result<Success> {
    match source {
        SourceId::Cvelist => cvelist::run(ctx, state).await,
        SourceId::Nvd => nvd::run(ctx, state).await,
        SourceId::Kev => kev::run(ctx, state).await,
        SourceId::Epss => epss::run(ctx, state).await,
        SourceId::Bsi | SourceId::Vendor => csaf::run(ctx, source, state).await,
        SourceId::OsvDebian => osv::run(ctx, osv::Distro::Debian, state).await,
        SourceId::OsvUbuntu => osv::run(ctx, osv::Distro::Ubuntu, state).await,
        SourceId::DebianTracker => debian_tracker::run(ctx, state).await,
    }
}

/// The running scheduler; [`Scheduler::stop`] ends it (a run in progress is abandoned; its database
/// changes are committed in batches, the cursor marks how far it got).
pub struct Scheduler {
    task: JoinHandle<()>,
}

impl Scheduler {
    pub async fn stop(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

/// Seconds until the next run: the interval plus a random part (up to a tenth, at most ten minutes) after
/// a success; after the `failures`-th failure in a row 5, 10, 20 … minutes, never longer than the interval.
pub fn next_delay_secs(interval_secs: i64, failures: i64) -> i64 {
    if failures > 0 {
        let shift = u32::try_from(failures - 1).unwrap_or(u32::MAX).min(16);
        return BACKOFF_START_SECS
            .saturating_mul(1 << shift)
            .min(interval_secs.max(BACKOFF_START_SECS));
    }
    let spread = (interval_secs / 10).clamp(1, 600);
    interval_secs + rand::rng().random_range(0..spread)
}

/// The error with its causes, on one line and shortened.
fn error_text(e: &anyhow::Error) -> String {
    let text = format!("{e:#}");
    if text.chars().count() > 500 {
        text.chars().take(500).collect::<String>() + "…"
    } else {
        text
    }
}

/// Creates the work directory (mode 0700) and removes what an earlier run left there.
async fn prepare_work_dir(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::create_dir_all(dir).await?;
    tokio::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).await?;
    let mut entries = tokio::fs::read_dir(dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        if entry.file_type().await?.is_file() {
            tokio::fs::remove_file(entry.path()).await?;
        }
    }
    Ok(())
}

/// Unix milliseconds now.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

/// Opens a downloaded ZIP archive: at most `max_entries` entries and none sharing its data with another (an
/// archive of many entries over one compressed block would unpack to terabytes).
pub fn open_archive(
    path: &std::path::Path,
    max_entries: usize,
) -> anyhow::Result<zip::ZipArchive<std::io::BufReader<std::fs::File>>> {
    use anyhow::Context;
    let file = std::fs::File::open(path)?;
    let mut archive =
        zip::ZipArchive::new(std::io::BufReader::new(file)).context("not a zip archive")?;
    if archive.len() > max_entries {
        anyhow::bail!("the archive has more than {max_entries} entries");
    }
    if archive.has_overlapping_files()? {
        anyhow::bail!("the archive has entries that share their data");
    }
    Ok(archive)
}

/// Lower case letters and digits of a vendor or product name: the key under which names from different
/// sources meet ("Red Hat", "redhat", "red_hat" → "redhat").
pub fn name_key(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

/// Parses a timestamp of a source (RFC 3339, also without zone, then UTC) into Unix milliseconds.
pub fn parse_time_ms(text: &str) -> Option<i64> {
    let text = text.trim();
    if let Ok(ts) = text.parse::<jiff::Timestamp>() {
        return Some(ts.as_millisecond());
    }
    if let Ok(dt) = text.parse::<jiff::civil::DateTime>() {
        return dt
            .to_zoned(jiff::tz::TimeZone::UTC)
            .ok()
            .map(|z| z.timestamp().as_millisecond());
    }
    text.parse::<jiff::civil::Date>()
        .ok()
        .and_then(|d| d.to_zoned(jiff::tz::TimeZone::UTC).ok())
        .map(|z| z.timestamp().as_millisecond())
}

#[cfg(test)]
pub(crate) mod testutil {
    use super::*;

    /// A context with a fresh database and the endpoints pointing to `base` (a local test server).
    pub async fn context(base: &str) -> (Context, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pool = crate::storage::connect(&dir.path().join("s.db"))
            .await
            .unwrap();
        crate::storage::migrate(&pool).await.unwrap();
        let work_dir = dir.path().join("downloads");
        std::fs::create_dir_all(&work_dir).unwrap();
        let ctx = Context {
            pool,
            endpoints: Arc::new(Endpoints {
                cvelist_releases: format!("{base}/releases"),
                nvd_feeds: format!("{base}/nvd"),
                kev: format!("{base}/kev.json"),
                epss: format!("{base}/epss.csv.gz"),
                bsi: format!("{base}/pm.json"),
                csaf_lister: format!("{base}/aggregator.json"),
                osv: format!("{base}/osv"),
                debian_tracker: format!("{base}/tracker.json"),
            }),
            work_dir,
            progress: Progress::default(),
        };
        (ctx, dir)
    }

    pub async fn state(ctx: &Context, source: SourceId) -> SourceState {
        store::get(&ctx.pool, source.as_str())
            .await
            .unwrap()
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_round_trip_and_intervals_respect_the_minimum() {
        for id in SourceId::ALL {
            assert_eq!(SourceId::parse(id.as_str()), Some(id));
            assert!(id.intervals().iter().all(|&s| s >= id.min_interval_secs()));
            assert!(!id.intervals().is_empty());
        }
        assert_eq!(SourceId::Epss.intervals(), [86_400]);
        assert_eq!(SourceId::parse("osv"), None);
    }

    #[test]
    fn every_label_exists_in_every_language() {
        for lang in crate::i18n::Lang::ALL {
            for id in SourceId::ALL {
                for key in [id.label_id(), id.notice_id(), id.state_id()] {
                    assert_ne!(lang.get(key), key, "{key} missing in {lang:?}");
                }
            }
        }
    }

    #[test]
    fn delays_spread_after_success_and_back_off_after_failures() {
        for _ in 0..50 {
            let d = next_delay_secs(3600, 0);
            assert!((3600..3960).contains(&d), "{d}");
            let d = next_delay_secs(86_400, 0);
            assert!((86_400..87_000).contains(&d), "{d}");
        }
        assert_eq!(next_delay_secs(21_600, 1), 300);
        assert_eq!(next_delay_secs(21_600, 2), 600);
        assert_eq!(next_delay_secs(21_600, 3), 1200);
        assert_eq!(next_delay_secs(21_600, 30), 21_600);
        assert_eq!(next_delay_secs(3600, 5), 3600);
    }

    #[test]
    fn names_meet_under_one_key() {
        assert_eq!(name_key("Red Hat"), "redhat");
        assert_eq!(name_key("red_hat"), "redhat");
        assert_eq!(name_key("FRITZ!Box 7590"), "fritzbox7590");
        assert_eq!(name_key("n/a"), "na");
    }

    #[test]
    fn times_of_the_sources_are_parsed() {
        assert_eq!(parse_time_ms("1970-01-01T00:00:01.000Z"), Some(1000));
        assert_eq!(parse_time_ms("1970-01-01T00:00:02"), Some(2000));
        assert_eq!(parse_time_ms("1970-01-02"), Some(86_400_000));
        assert_eq!(
            parse_time_ms("2026-11-05T14:00:06-05:00"),
            Some(1_793_905_206_000)
        );
        assert_eq!(parse_time_ms("gestern"), None);
    }

    #[tokio::test]
    async fn without_the_scheduler_only_requested_sources_run() {
        let (ctx, _dir) = testutil::context("http://127.0.0.1:9").await;
        let unscheduled = Sources::new(
            ctx.pool.clone(),
            ctx.work_dir.clone(),
            (*ctx.endpoints).clone(),
            false,
        );
        // A fresh database: every row starts due, but nobody asked for a fetch.
        assert!(matches!(
            unscheduled.next_due().await.unwrap(),
            Next::Wait(_)
        ));
        // A scheduling instance starts the initial import of the fresh rows.
        let scheduled = Sources::new(
            ctx.pool.clone(),
            ctx.work_dir.clone(),
            (*ctx.endpoints).clone(),
            true,
        );
        assert!(matches!(scheduled.next_due().await.unwrap(), Next::Run(_)));
        // "Fetch now" is the only way for an instance without the scheduler.
        store::due_now(&ctx.pool, SourceId::Kev.as_str())
            .await
            .unwrap();
        assert!(matches!(
            unscheduled.next_due().await.unwrap(),
            Next::Run(SourceId::Kev)
        ));
    }

    #[tokio::test]
    async fn work_dirs_are_private_and_emptied() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().join("downloads");
        prepare_work_dir(&work).await.unwrap();
        std::fs::write(work.join("left-over.zip"), b"x").unwrap();
        prepare_work_dir(&work).await.unwrap();
        assert_eq!(std::fs::read_dir(&work).unwrap().count(), 0);
        assert_eq!(
            std::fs::metadata(&work).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}
