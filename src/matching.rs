//! The matching: which vulnerabilities affect the own assets (PLAN.md, "Abgleich").
//!
//! - **Packages** (Debian/Ubuntu source package, release, installed version) are compared with the version
//!   ranges of the distribution's OSV records (DSA/DLA/USN and the per-CVE records): confidence high.
//! - **Products** (vendor/product keys, optionally a CPE) are compared with
//!   - the NVD's CPE configurations (version ranges of the vulnerable CPEs) and the CNA's version ranges
//!     of the CVE record: high when the version lies in a range;
//!   - the CSAF product trees (BSI CERT-Bund, vendors), whose versions are texts such as "<10.6p2": medium.
//!
//!   A product whose version cannot be checked (no version given, the source names no versions) matches
//!   with medium confidence, but only reports published at most 30 days before the asset was added.
//! - **Keywords** of the watchlist are searched in the titles and product names: low.
//!
//! Every run computes the full set of matches of an asset and stores the difference
//! (`storage::matches::sync`). Texts of the sources are only compared, never interpreted.

use std::collections::{BTreeSet, HashMap};
use std::time::Instant;

use serde_json::Value;
use sqlx::SqlitePool;

use crate::error::Result;
use crate::sources::name_key;
use crate::storage::assets::{self, Asset, Distro, Kind, LOOK_BACK_MS, Watch, cpe_keys};
use crate::storage::matches::{
    self, Confidence, Found, Method, Rating, Subject, Synced, severity_prio,
};
use crate::version::{Bound, Range, Scheme, compare, is_version};

/// One run at a time: the scheduler (after a source changed) and the web pages (an asset changed).
static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Most matches per asset; a package far behind its release would otherwise fill the inbox with
/// thousands of old kernel CVEs. The rest is not lost: it shows once the newer ones are handled.
const MAX_PER_ASSET: usize = 2_000;
/// Most results per keyword and table.
const MAX_PER_KEYWORD: i64 = 500;
/// Most evidence ids kept per match.
const MAX_EVIDENCE: usize = 20;

/// The matches found so far, by vulnerability.
#[derive(Default)]
struct Hits(HashMap<String, Found>);

impl Hits {
    fn add(&mut self, f: Found) {
        match self.0.get_mut(&f.vuln) {
            Some(known) => {
                let mut evidence: BTreeSet<String> = known.evidence.drain(..).collect();
                evidence.extend(f.evidence.iter().cloned());
                known.evidence = evidence.into_iter().take(MAX_EVIDENCE).collect();
                if f.confidence > known.confidence
                    || (f.confidence == known.confidence && known.fixed.is_empty())
                {
                    known.confidence = f.confidence;
                    known.method = f.method;
                    if !f.fixed.is_empty() {
                        known.fixed = f.fixed;
                    }
                }
                if known.title.is_empty() {
                    known.title = f.title;
                }
                known.base_prio = known.base_prio.max(f.base_prio);
                if known.rating == Rating::None {
                    known.rating = f.rating;
                }
            }
            None => {
                self.0.insert(f.vuln.clone(), f);
            }
        }
    }

    fn into_vec(self) -> Vec<Found> {
        let mut out: Vec<Found> = self.0.into_values().collect();
        out.sort_by(|a, b| a.vuln.cmp(&b.vuln));
        out
    }
}

/// What a source says about one version of a product.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Affected; `checked`: the version lies in a range the source gives (else: the source names the
    /// product without usable versions, or the asset has no version).
    Affected {
        checked: bool,
        fixed: String,
    },
    NotAffected,
}

/// Products that the NVD and the CNA of the vendor name differently (vendor, then the names): an asset under one
/// name is also matched under the others. Checked against the data: Microsoft writes "Microsoft Edge
/// (Chromium-based)" where the NVD writes `edge_chromium`, Notepad++ "notepad-plus-plus" where the NVD writes
/// `notepad++`.
const SAME_PRODUCT: &[(&str, &[&str])] = &[
    ("microsoft", &["edgechromium", "microsoftedgechromiumbased"]),
    ("notepadplusplus", &["notepad", "notepadplusplus"]),
];

/// The keys under which the sources name a product: its own, the other names of [`SAME_PRODUCT`], for devices
/// also the firmware (NVD writes "er605_firmware" beside "er605"), and for TP-Link the model with and without
/// "omada"/"tl" in front ("er605", "omada_er605", "tl-sg2008").
fn product_keys(kind: Kind, vendor: &str, product: &str) -> Vec<(String, String)> {
    let mut products = vec![product.to_owned()];
    for (v, names) in SAME_PRODUCT {
        if *v == vendor && names.contains(&product) {
            products.extend(
                names
                    .iter()
                    .filter(|n| **n != product)
                    .map(|n| (*n).to_owned()),
            );
        }
    }
    if vendor == "tplink" {
        let base = product
            .strip_prefix("omada")
            .or_else(|| product.strip_prefix("tl"))
            .unwrap_or(product);
        if base.chars().any(|c| c.is_ascii_digit()) {
            for p in [base.to_owned(), format!("omada{base}"), format!("tl{base}")] {
                if !products.contains(&p) {
                    products.push(p);
                }
            }
        }
    }
    if kind == Kind::Hardware {
        for i in 0..products.len() {
            if !products[i].ends_with("firmware") {
                products.push(format!("{}firmware", products[i]));
            }
        }
    }
    products
        .into_iter()
        .filter(|p| !p.is_empty())
        .map(|p| (vendor.to_owned(), p))
        .collect()
}

/// Finds the matches of an asset without storing them (also the preview of the form).
pub async fn find(pool: &SqlitePool, asset: &Asset) -> Result<Vec<Found>> {
    let mut hits = Hits::default();
    match asset.kind() {
        // The kernel of Raspberry Pi OS has no data source: Debian's data would give hundreds of wrong matches.
        Kind::Package if asset.pi_kernel() => {}
        Kind::Package => distro(pool, asset, &mut hits).await?,
        Kind::Software | Kind::Hardware => {
            let since = asset.created_ms - LOOK_BACK_MS;
            let mut keys = product_keys(asset.kind(), &asset.vendor, &asset.product);
            if let Some(k) = cpe_keys(&asset.cpe)
                && !keys.contains(&k)
            {
                keys.push(k);
            }
            for (vendor, product) in &keys {
                nvd(pool, asset, vendor, product, since, &mut hits).await?;
                cna(pool, asset, vendor, product, since, &mut hits).await?;
            }
            csaf(pool, asset, &keys, since, &mut hits).await?;
        }
    }
    let mut found = hits.into_vec();
    if found.len() > MAX_PER_ASSET {
        // Keep the newest CVEs (their ids sort by year and number).
        found.sort_by(|a, b| b.vuln.cmp(&a.vuln));
        found.truncate(MAX_PER_ASSET);
    }
    Ok(found)
}

/// Matches one asset and stores the outcome.
pub async fn match_asset(pool: &SqlitePool, id: i64, now_ms: i64) -> Result<Synced> {
    let _guard = LOCK.lock().await;
    match_asset_locked(pool, id, now_ms).await
}

async fn match_asset_locked(pool: &SqlitePool, id: i64, now_ms: i64) -> Result<Synced> {
    let Some(asset) = assets::get(pool, id).await? else {
        return Ok(Synced::default());
    };
    let found = find(pool, &asset).await?;
    let synced = matches::sync(pool, Subject::Asset(id), &found, now_ms).await?;
    assets::set_matched(pool, id, now_ms).await?;
    Ok(synced)
}

/// Matches several assets (the new and changed packages of a host) under one lock.
pub async fn match_assets(pool: &SqlitePool, ids: &[i64], now_ms: i64) -> Result<Synced> {
    let _guard = LOCK.lock().await;
    let clock = Instant::now();
    let mut total = Synced::default();
    for id in ids {
        add(&mut total, match_asset_locked(pool, *id, now_ms).await?);
    }
    if !ids.is_empty() {
        tracing::info!(
            assets = ids.len(),
            new = total.new,
            reopened = total.reopened,
            resolved = total.resolved,
            ms = clock.elapsed().as_millis(),
            "matched"
        );
    }
    Ok(total)
}

/// Matches one keyword of the watchlist and stores the outcome.
pub async fn match_watch(pool: &SqlitePool, id: i64, now_ms: i64) -> Result<Synced> {
    let _guard = LOCK.lock().await;
    match_watch_locked(pool, id, now_ms).await
}

async fn match_watch_locked(pool: &SqlitePool, id: i64, now_ms: i64) -> Result<Synced> {
    let Some(watch) = assets::get_watch(pool, id).await? else {
        return Ok(Synced::default());
    };
    let found = find_keyword(pool, &watch).await?;
    let synced = matches::sync(pool, Subject::Watch(id), &found, now_ms).await?;
    assets::set_watch_matched(pool, id, now_ms).await?;
    Ok(synced)
}

/// Matches every asset and keyword (after a source brought new data).
pub async fn match_all(pool: &SqlitePool, now_ms: i64) -> Result<Synced> {
    let _guard = LOCK.lock().await;
    let clock = Instant::now();
    let mut total = Synced::default();
    let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM assets ORDER BY id")
        .fetch_all(pool)
        .await?;
    let watch_ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM watchlist ORDER BY id")
        .fetch_all(pool)
        .await?;
    for id in &ids {
        add(&mut total, match_asset_locked(pool, *id, now_ms).await?);
    }
    for id in &watch_ids {
        add(&mut total, match_watch_locked(pool, *id, now_ms).await?);
    }
    matches::wake_later(pool, now_ms).await?;
    tracing::info!(
        assets = ids.len(),
        keywords = watch_ids.len(),
        new = total.new,
        reopened = total.reopened,
        resolved = total.resolved,
        ms = clock.elapsed().as_millis(),
        "matched"
    );
    Ok(total)
}

fn add(total: &mut Synced, s: Synced) {
    total.new += s.new;
    total.reopened += s.reopened;
    total.resolved += s.resolved;
}

// ---------------------------------------------------------------------------------------------------
// Packages: OSV ranges of Debian and Ubuntu

/// Whether `ecosystem` is the plain release (`Debian:13`, `Ubuntu:24.04:LTS`, `Ubuntu:25.10`) or, with
/// `pro`, Ubuntu Pro of it (`Ubuntu:Pro:20.04:LTS`; FIPS and Realtime are other kernels and packages).
fn ecosystem_is(ecosystem: &str, distro: Distro, release: &str, pro: bool) -> bool {
    let parts: Vec<&str> = ecosystem.split(':').collect();
    match (distro, pro, parts.as_slice()) {
        (Distro::Debian, false, ["Debian", r]) => *r == release,
        (Distro::Ubuntu, false, ["Ubuntu", r] | ["Ubuntu", r, "LTS"]) => *r == release,
        (Distro::Ubuntu, true, ["Ubuntu", "Pro", r] | ["Ubuntu", "Pro", r, "LTS"]) => *r == release,
        _ => false,
    }
}

/// The range of an OSV row: from `introduced` ("0" = from the start) up to `fixed` (exclusive) or
/// `last_affected` (inclusive); neither = still open.
fn osv_range(introduced: &str, fixed: &str, last_affected: &str) -> Range {
    let start = (!matches!(introduced, "" | "0")).then(|| Bound {
        version: introduced.to_owned(),
        inclusive: true,
    });
    let end = if !fixed.is_empty() {
        Some(Bound {
            version: fixed.to_owned(),
            inclusive: false,
        })
    } else if !last_affected.is_empty() {
        Some(Bound {
            version: last_affected.to_owned(),
            inclusive: true,
        })
    } else {
        None
    };
    Range { start, end }
}

#[derive(sqlx::FromRow)]
struct OsvRow {
    seq: i64,
    id: String,
    kind: String,
    summary: String,
    priority: String,
    ecosystem: String,
    introduced: String,
    fixed: String,
    last_affected: String,
}

async fn distro(pool: &SqlitePool, asset: &Asset, hits: &mut Hits) -> Result<()> {
    let Some(distro) = asset.distro() else {
        return Ok(());
    };
    let rows: Vec<OsvRow> = sqlx::query_as(
        "SELECT r.seq, r.id, r.kind, r.summary, r.priority, a.ecosystem, a.introduced, a.fixed,
                a.last_affected
         FROM osv_affected a JOIN osv_records r ON r.seq = a.record_seq
         WHERE a.package = ? AND a.release = ? AND r.source = ? AND r.withdrawn_ms IS NULL",
    )
    .bind(&asset.product)
    .bind(&asset.release)
    .bind(distro.as_str())
    .fetch_all(pool)
    .await?;
    // Per record: the rows of Ubuntu Pro if the host has it and the record names Pro, else the plain ones.
    let mut by_record: HashMap<i64, (Vec<&OsvRow>, Vec<&OsvRow>)> = HashMap::new();
    for r in &rows {
        let e = by_record.entry(r.seq).or_default();
        if ecosystem_is(&r.ecosystem, distro, &asset.release, false) {
            e.0.push(r);
        } else if asset.pro && ecosystem_is(&r.ecosystem, distro, &asset.release, true) {
            e.1.push(r);
        }
    }
    let mut affected: Vec<(&OsvRow, String)> = Vec::new();
    for (plain, pro) in by_record.values() {
        let chosen = if pro.is_empty() { plain } else { pro };
        if let Some(r) = chosen.iter().find(|r| {
            osv_range(&r.introduced, &r.fixed, &r.last_affected)
                .contains(Scheme::Deb, &asset.version)
        }) {
            affected.push((r, r.fixed.clone()));
        }
    }
    if affected.is_empty() {
        return Ok(());
    }
    let seqs: Vec<i64> = affected.iter().map(|(r, _)| r.seq).collect();
    let cves = cves_of(pool, "osv_cves", "record_seq", &seqs).await?;
    let tracker = debian_ratings(pool, asset, distro).await?;
    for (r, fixed) in affected {
        let evidence = if r.kind == "advisory" {
            vec![r.id.clone()]
        } else {
            Vec::new()
        };
        let base_prio = severity_prio(&r.priority);
        match cves.get(&r.seq) {
            Some(list) if !list.is_empty() => {
                for cve in list {
                    hits.add(Found {
                        vuln: cve.clone(),
                        title: if r.kind == "advisory" {
                            String::new()
                        } else {
                            r.summary.clone()
                        },
                        confidence: Confidence::High,
                        method: Method::Distro,
                        fixed: fixed.clone(),
                        evidence: evidence.clone(),
                        base_prio,
                        rating: match distro {
                            Distro::Debian => tracker.get(cve).copied().unwrap_or_default(),
                            Distro::Ubuntu => Rating::of_ubuntu(&r.priority),
                        },
                    });
                }
            }
            _ => hits.add(Found {
                vuln: format!("osv:{}", r.id),
                title: r.summary.clone(),
                confidence: Confidence::High,
                method: Method::Distro,
                fixed,
                evidence,
                base_prio,
                rating: Rating::None,
            }),
        }
    }
    Ok(())
}

/// How the Debian Security Tracker rates the CVEs of a Debian package in its release (empty for Ubuntu, or when
/// the release has no code name the tracker knows). Without CVE (`osv:` matches) the severity of the record is
/// already the base priority, so only CVEs get a rating.
async fn debian_ratings(
    pool: &SqlitePool,
    asset: &Asset,
    distro: Distro,
) -> Result<HashMap<String, Rating>> {
    let Some(codename) = (distro == Distro::Debian)
        .then(|| crate::inventory::listing::debian_codename(&asset.release))
        .flatten()
    else {
        return Ok(HashMap::new());
    };
    let rows: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT cve_id, urgency, nodsa, nodsa_reason FROM debian_tracker WHERE package = ? AND release = ?",
    )
    .bind(&asset.product)
    .bind(codename)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(cve, urgency, nodsa, reason)| (cve, Rating::of_debian(&urgency, &nodsa, &reason)))
        .filter(|(_, r)| *r != Rating::None)
        .collect())
}

/// The CVEs of records (`osv_cves` by `record_seq`, `advisory_cves` by `advisory_seq`).
async fn cves_of(
    pool: &SqlitePool,
    table: &str,
    column: &str,
    seqs: &[i64],
) -> Result<HashMap<i64, Vec<String>>> {
    let mut out: HashMap<i64, Vec<String>> = HashMap::new();
    for chunk in seqs.chunks(500) {
        let marks = vec!["?"; chunk.len()].join(",");
        let sql = format!("SELECT {column}, cve_id FROM {table} WHERE {column} IN ({marks})");
        let mut q = sqlx::query_as::<_, (i64, String)>(&sql);
        for s in chunk {
            q = q.bind(s);
        }
        for (seq, cve) in q.fetch_all(pool).await? {
            out.entry(seq).or_default().push(cve);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------------
// Products: NVD CPE configurations

/// What the NVD's configurations say about `version` of the product with these keys.
pub(crate) fn nvd_verdict(configs: &Value, vendor: &str, product: &str, version: &str) -> Verdict {
    let mut checked = false;
    let mut unchecked = false;
    let mut fixed: Option<String> = None;
    let mut hit = false;
    let matches = configs
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| c.get("nodes")?.as_array())
        .flatten()
        .filter_map(|n| n.get("cpeMatch")?.as_array())
        .flatten();
    for m in matches {
        if m.get("vulnerable").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        let Some(criteria) = m.get("criteria").and_then(Value::as_str) else {
            continue;
        };
        let parts: Vec<&str> = criteria.split(':').collect();
        if parts.len() < 7
            || name_key(&parts[3].replace('\\', "")) != vendor
            || name_key(&parts[4].replace('\\', "")) != product
        {
            continue;
        }
        let bound = |key: &str, inclusive: bool| {
            m.get(key).and_then(Value::as_str).map(|v| Bound {
                version: v.to_owned(),
                inclusive,
            })
        };
        let start =
            bound("versionStartIncluding", true).or_else(|| bound("versionStartExcluding", false));
        let end =
            bound("versionEndIncluding", true).or_else(|| bound("versionEndExcluding", false));
        let cpe_version = parts[5].replace('\\', "");
        let update = parts[6];
        let range = if !matches!(cpe_version.as_str(), "*" | "-" | "")
            && start.is_none()
            && end.is_none()
        {
            let full = if matches!(update, "*" | "-" | "") {
                cpe_version
            } else {
                format!("{cpe_version}{update}")
            };
            Some(Range::exact(&full))
        } else if start.is_some() || end.is_some() {
            Some(Range { start, end })
        } else {
            None
        };
        let Some(range) = range.filter(|_| is_version(Scheme::Generic, version)) else {
            unchecked = true;
            continue;
        };
        checked = true;
        if range.contains(Scheme::Generic, version) {
            hit = true;
            if let Some(end) = range
                .end
                .filter(|e| !e.inclusive && range.start.as_ref() != Some(e))
            {
                fixed = Some(end.version);
            }
        }
    }
    if hit {
        Verdict::Affected {
            checked: true,
            fixed: fixed.unwrap_or_default(),
        }
    } else if checked {
        Verdict::NotAffected
    } else if unchecked {
        Verdict::Affected {
            checked: false,
            fixed: String::new(),
        }
    } else {
        Verdict::NotAffected
    }
}

async fn nvd(
    pool: &SqlitePool,
    asset: &Asset,
    vendor: &str,
    product: &str,
    since: i64,
    hits: &mut Hits,
) -> Result<()> {
    let rows: Vec<PackedRow> = sqlx::query_as(
        "SELECT n.cve_id, n.configs, n.configs_z, c.published_ms
         FROM cve_products p
         JOIN nvd_cves n ON n.cve_id = p.cve_id
         LEFT JOIN cves c ON c.id = p.cve_id
         WHERE p.origin = 'nvd' AND p.vendor = ? AND p.product = ? AND COALESCE(c.state, 'published') = 'published'",
    )
    .bind(vendor)
    .bind(product)
    .fetch_all(pool)
    .await?;
    for (cve, configs, configs_z, published) in rows {
        let configs = crate::storage::packed::text(configs, configs_z);
        let configs: Value = serde_json::from_str(&configs).unwrap_or(Value::Null);
        let verdict = nvd_verdict(&configs, vendor, product, &asset.version);
        add_product_hit(hits, &cve, verdict, Method::Nvd, published, since);
    }
    Ok(())
}

/// Adds a CVE match of a product: checked → high, unchecked → medium if recent enough.
fn add_product_hit(
    hits: &mut Hits,
    cve: &str,
    verdict: Verdict,
    method: Method,
    published: Option<i64>,
    since: i64,
) {
    let Verdict::Affected { checked, fixed } = verdict else {
        return;
    };
    let confidence = if checked {
        Confidence::High
    } else if published.is_some_and(|p| p >= since) {
        Confidence::Medium
    } else {
        return;
    };
    hits.add(Found {
        vuln: cve.to_owned(),
        title: String::new(),
        confidence,
        method,
        fixed,
        evidence: Vec::new(),
        base_prio: 0,
        rating: Rating::None,
    });
}

// ---------------------------------------------------------------------------------------------------
/// A CVE with a packed JSON column (text, deflated, see `storage::packed`) and its publication.
type PackedRow = (String, String, Option<Vec<u8>>, Option<i64>);

// Products: the CNA's version ranges (CVE record, `cves.affected`)

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
}

/// What the CNA's `affected` entries say about `version` of the product with these keys.
pub(crate) fn cna_verdict(affected: &Value, vendor: &str, product: &str, version: &str) -> Verdict {
    let mut statuses = Vec::new();
    let mut parseable = false;
    let mut named_affected = false;
    let mut default_affected = false;
    let mut fixed = String::new();
    let entries = affected.as_array().into_iter().flatten().filter(|e| {
        name_key(text(e, "vendor")) == vendor && {
            let p = text(e, "product");
            name_key(if p.is_empty() { text(e, "package") } else { p }) == product
        }
    });
    for e in entries {
        default_affected |= text(e, "default") == "affected";
        for v in e
            .get("versions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let status = text(v, "status");
            named_affected |= status == "affected";
            if text(v, "type") == "git" {
                continue;
            }
            let start = text(v, "version");
            let (lt, lte) = (text(v, "less_than"), text(v, "less_than_or_equal"));
            let range = if !lt.is_empty() || !lte.is_empty() {
                let start = (!matches!(start, "" | "0" | "*")
                    && is_version(Scheme::Generic, start))
                .then(|| Bound {
                    version: start.to_owned(),
                    inclusive: true,
                });
                let end = if lt == "*" || lte == "*" {
                    None
                } else if !lt.is_empty() {
                    Some(Bound {
                        version: lt.to_owned(),
                        inclusive: false,
                    })
                } else {
                    Some(Bound {
                        version: lte.to_owned(),
                        inclusive: true,
                    })
                };
                if end
                    .as_ref()
                    .is_some_and(|b| !is_version(Scheme::Generic, &b.version))
                {
                    continue;
                }
                Range { start, end }
            } else if is_version(Scheme::Generic, start) {
                Range::exact(start)
            } else {
                continue;
            };
            parseable = true;
            if is_version(Scheme::Generic, version) && range.contains(Scheme::Generic, version) {
                statuses.push(status.to_owned());
                if status == "affected" && !lt.is_empty() && lt != "*" {
                    fixed = lt.to_owned();
                }
            }
        }
    }
    if !is_version(Scheme::Generic, version) || !parseable {
        return if named_affected || default_affected {
            Verdict::Affected {
                checked: false,
                fixed: String::new(),
            }
        } else {
            Verdict::NotAffected
        };
    }
    let affected = if statuses.iter().any(|s| s == "affected") {
        true
    } else if statuses.iter().any(|s| s == "unaffected") {
        false
    } else {
        default_affected
    };
    if affected {
        Verdict::Affected {
            checked: true,
            fixed,
        }
    } else {
        Verdict::NotAffected
    }
}

async fn cna(
    pool: &SqlitePool,
    asset: &Asset,
    vendor: &str,
    product: &str,
    since: i64,
    hits: &mut Hits,
) -> Result<()> {
    let rows: Vec<PackedRow> = sqlx::query_as(
        "SELECT c.id, c.affected, c.affected_z, c.published_ms
         FROM cve_products p JOIN cves c ON c.id = p.cve_id
         WHERE p.origin = 'cna' AND p.vendor = ? AND p.product = ? AND c.state = 'published'",
    )
    .bind(vendor)
    .bind(product)
    .fetch_all(pool)
    .await?;
    for (cve, affected, affected_z, published) in rows {
        let affected = crate::storage::packed::text(affected, affected_z);
        let affected: Value = serde_json::from_str(&affected).unwrap_or(Value::Null);
        let verdict = cna_verdict(&affected, vendor, product, &asset.version);
        add_product_hit(hits, &cve, verdict, Method::Cna, published, since);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------
// Products: CSAF product trees

/// A statement of a CSAF product tree about versions.
fn csaf_range(version: &str, is_range: bool) -> Option<Range> {
    let v = version.trim();
    let bound = |s: &str, inclusive: bool| {
        let s = s.trim();
        is_version(Scheme::Generic, s).then(|| Bound {
            version: s.to_owned(),
            inclusive,
        })
    };
    if let Some(rest) = v.strip_prefix("<=") {
        return Some(Range {
            start: None,
            end: Some(bound(rest, true)?),
        });
    }
    if let Some(rest) = v.strip_prefix('<') {
        return Some(Range {
            start: None,
            end: Some(bound(rest, false)?),
        });
    }
    if let Some(rest) = v.strip_prefix(">=") {
        return Some(Range {
            start: Some(bound(rest, true)?),
            end: None,
        });
    }
    if let Some(rest) = v.strip_prefix('>') {
        return Some(Range {
            start: Some(bound(rest, false)?),
            end: None,
        });
    }
    // "6.8p1-9.9p1": a range if both halves are plain versions (every part starts with a digit) in the
    // right order; else a version with a package revision such as "9.9p1-22.el10_2".
    let plain = |s: &str| {
        s.split('.')
            .all(|c| c.starts_with(|c: char| c.is_ascii_digit()))
    };
    if let Some((a, b)) = v.split_once('-')
        && plain(a)
        && plain(b)
        && let (Some(lo), Some(hi)) = (bound(a, true), bound(b, true))
        && compare(Scheme::Generic, a, b).is_lt()
    {
        return Some(Range {
            start: Some(lo),
            end: Some(hi),
        });
    }
    if is_range {
        return None;
    }
    bound(v, true).map(|_| Range::exact(v))
}

#[derive(sqlx::FromRow)]
struct CsafRow {
    advisory_seq: i64,
    vendor: String,
    product: String,
    version: String,
    version_range: bool,
    status: String,
    cpe: String,
    display_id: String,
    title: String,
    severity: String,
    published_ms: Option<i64>,
}

/// The vendor key of a CPE in a CSAF tree (`cpe:/a:openbsd:openssh:…` or CPE 2.3).
fn csaf_cpe_vendor(cpe: &str) -> Option<String> {
    let rest = cpe
        .strip_prefix("cpe:2.3:")
        .or_else(|| cpe.strip_prefix("cpe:/"))?;
    let vendor = rest.split(':').nth(1)?;
    Some(name_key(&vendor.replace('\\', "")))
}

/// The BSI writes one range as two products, ">=5.4" and "<7.1p2" (often only one of them marked as
/// affected). Half-open ranges of both directions are therefore paired into closed ones; a lower bound
/// alone would match every later version.
fn pair_bounds(ranges: Vec<Range>) -> Vec<Range> {
    let (lower, rest): (Vec<Range>, Vec<Range>) = ranges
        .into_iter()
        .partition(|r| r.start.is_some() && r.end.is_none());
    let (upper, mut out): (Vec<Range>, Vec<Range>) = rest
        .into_iter()
        .partition(|r| r.start.is_none() && r.end.is_some());
    if lower.is_empty() || upper.is_empty() {
        out.extend(lower);
        out.extend(upper);
        return out;
    }
    for l in &lower {
        for u in &upper {
            let (Some(start), Some(end)) = (&l.start, &u.end) else {
                continue;
            };
            if compare(Scheme::Generic, &start.version, &end.version).is_lt() {
                out.push(Range {
                    start: Some(start.clone()),
                    end: Some(end.clone()),
                });
            }
        }
    }
    out
}

/// What the rows of one advisory say about `version`.
fn csaf_verdict(rows: &[&CsafRow], version: &str) -> Verdict {
    let affected: Vec<&&CsafRow> = rows
        .iter()
        .filter(|r| r.status == "affected" || (r.status.is_empty() && r.version_range))
        .collect();
    let mut fixed_versions: Vec<&str> = rows
        .iter()
        .filter(|r| r.status == "fixed" || (r.status.is_empty() && !r.version_range))
        .map(|r| r.version.trim())
        .filter(|v| is_version(Scheme::Generic, v))
        .collect();
    fixed_versions.sort_by(|a, b| compare(Scheme::Generic, a, b));
    let ranges = pair_bounds(
        affected
            .iter()
            .filter_map(|r| csaf_range(&r.version, r.version_range))
            .collect(),
    );
    let known = is_version(Scheme::Generic, version);
    let fixed_after = |v: &str| {
        fixed_versions
            .iter()
            .find(|f| compare(Scheme::Generic, f, v).is_gt())
            .map(|f| (*f).to_owned())
            .unwrap_or_default()
    };
    if known && !ranges.is_empty() {
        return if ranges.iter().any(|r| r.contains(Scheme::Generic, version)) {
            Verdict::Affected {
                checked: true,
                fixed: fixed_after(version),
            }
        } else {
            Verdict::NotAffected
        };
    }
    if known && !fixed_versions.is_empty() {
        // Only fixed versions named: affected if older than all of them.
        return if compare(Scheme::Generic, version, fixed_versions[0]).is_lt() {
            Verdict::Affected {
                checked: true,
                fixed: fixed_versions[0].to_owned(),
            }
        } else {
            Verdict::NotAffected
        };
    }
    if affected.is_empty() {
        Verdict::NotAffected
    } else {
        Verdict::Affected {
            checked: false,
            fixed: String::new(),
        }
    }
}

async fn csaf(
    pool: &SqlitePool,
    asset: &Asset,
    keys: &[(String, String)],
    since: i64,
    hits: &mut Hits,
) -> Result<()> {
    // Product keys as CSAF writes them: "openssh", or with the vendor in front ("avmfritzbox").
    let mut products: Vec<String> = Vec::new();
    let mut vendors: Vec<&str> = Vec::new();
    for (vendor, product) in keys {
        products.push(product.clone());
        if !vendor.is_empty() {
            products.push(format!("{vendor}{product}"));
            vendors.push(vendor);
        }
    }
    products.sort();
    products.dedup();
    let marks = vec!["?"; products.len()].join(",");
    let sql = format!(
        "SELECT p.advisory_seq, p.vendor, p.product, p.version, p.version_range, p.status, p.cpe,
                a.display_id, a.title, a.severity, COALESCE(a.published_ms, a.updated_ms) AS published_ms
         FROM advisory_products p JOIN advisories a ON a.seq = p.advisory_seq
         WHERE p.product IN ({marks})"
    );
    let mut q = sqlx::query_as::<_, CsafRow>(&sql);
    for p in &products {
        q = q.bind(p);
    }
    let rows = q.fetch_all(pool).await?;
    let vendor_fits = |r: &CsafRow| {
        vendors.is_empty()
            || vendors.contains(&r.vendor.as_str())
            || matches!(r.vendor.as_str(), "" | "opensource")
            || csaf_cpe_vendor(&r.cpe).is_some_and(|v| vendors.contains(&v.as_str()))
            || vendors.iter().any(|v| r.product.starts_with(*v))
    };
    let mut by_advisory: HashMap<i64, Vec<&CsafRow>> = HashMap::new();
    for r in rows.iter().filter(|r| vendor_fits(r)) {
        by_advisory.entry(r.advisory_seq).or_default().push(r);
    }
    let mut affected = Vec::new();
    for (seq, rows) in &by_advisory {
        let verdict = csaf_verdict(rows, &asset.version);
        let Verdict::Affected { checked, fixed } = verdict else {
            continue;
        };
        let first = rows[0];
        if !checked && first.published_ms.is_none_or(|p| p < since) {
            continue;
        }
        affected.push((*seq, first, fixed));
    }
    let seqs: Vec<i64> = affected.iter().map(|(s, _, _)| *s).collect();
    let cves = cves_of(pool, "advisory_cves", "advisory_seq", &seqs).await?;
    for (seq, r, fixed) in affected {
        let found = |vuln: String, title: String| Found {
            vuln,
            title,
            confidence: Confidence::Medium,
            method: Method::Csaf,
            fixed: fixed.clone(),
            evidence: vec![r.display_id.clone()],
            base_prio: severity_prio(&r.severity),
            rating: Rating::None,
        };
        match cves.get(&seq) {
            Some(list) if !list.is_empty() => {
                for cve in list {
                    hits.add(found(cve.clone(), String::new()));
                }
            }
            _ => hits.add(found(format!("adv:{seq}"), r.title.clone())),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------
// Watchlist

/// The FTS5 query for a keyword: the phrase in the title and product columns.
fn fts_phrase(keyword: &str) -> String {
    format!("{{title products}} : \"{}\"", keyword.replace('"', "\"\""))
}

async fn find_keyword(pool: &SqlitePool, watch: &Watch) -> Result<Vec<Found>> {
    let phrase = fts_phrase(&watch.keyword);
    let mut hits = Hits::default();
    let cves: Vec<(String, String)> = sqlx::query_as(
        // The subquery runs the full-text search once; as a join SQLite would walk the date index and ask
        // the FTS table row by row (seconds instead of milliseconds on a full database).
        "SELECT c.id, c.title FROM cves c
         WHERE c.seq IN (SELECT rowid FROM cves_fts WHERE cves_fts MATCH ?)
           AND c.state = 'published' AND c.published_ms >= ?
         ORDER BY c.published_ms DESC LIMIT ?",
    )
    .bind(&phrase)
    .bind(watch.since_ms)
    .bind(MAX_PER_KEYWORD)
    .fetch_all(pool)
    .await?;
    for (id, title) in cves {
        hits.add(Found {
            vuln: id,
            title,
            confidence: Confidence::Low,
            method: Method::Watch,
            fixed: String::new(),
            evidence: Vec::new(),
            base_prio: 0,
            rating: Rating::None,
        });
    }
    let advisories: Vec<(i64, String, String, String)> = sqlx::query_as(
        "SELECT a.seq, a.display_id, a.title, a.severity FROM advisories a
         WHERE a.seq IN (SELECT rowid FROM advisories_fts WHERE advisories_fts MATCH ?)
           AND COALESCE(a.published_ms, a.updated_ms) >= ?
         ORDER BY a.updated_ms DESC LIMIT ?",
    )
    .bind(&phrase)
    .bind(watch.since_ms)
    .bind(MAX_PER_KEYWORD)
    .fetch_all(pool)
    .await?;
    let seqs: Vec<i64> = advisories.iter().map(|a| a.0).collect();
    let cves = cves_of(pool, "advisory_cves", "advisory_seq", &seqs).await?;
    for (seq, display_id, title, severity) in advisories {
        let found = |vuln: String, title: String| Found {
            vuln,
            title,
            confidence: Confidence::Low,
            method: Method::Watch,
            fixed: String::new(),
            evidence: vec![display_id.clone()],
            base_prio: severity_prio(&severity),
            rating: Rating::None,
        };
        match cves.get(&seq) {
            Some(list) if !list.is_empty() => {
                for cve in list {
                    hits.add(found(cve.clone(), String::new()));
                }
            }
            _ => hits.add(found(format!("adv:{seq}"), title)),
        }
    }
    Ok(hits.into_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::assets::Input;
    use serde_json::json;

    #[test]
    fn ecosystems_are_told_apart() {
        assert!(ecosystem_is("Debian:13", Distro::Debian, "13", false));
        assert!(!ecosystem_is("Debian:13", Distro::Debian, "12", false));
        assert!(ecosystem_is(
            "Ubuntu:24.04:LTS",
            Distro::Ubuntu,
            "24.04",
            false
        ));
        assert!(ecosystem_is("Ubuntu:25.10", Distro::Ubuntu, "25.10", false));
        assert!(ecosystem_is(
            "Ubuntu:Pro:20.04:LTS",
            Distro::Ubuntu,
            "20.04",
            true
        ));
        assert!(!ecosystem_is(
            "Ubuntu:Pro:FIPS:20.04:LTS",
            Distro::Ubuntu,
            "20.04",
            true
        ));
        assert!(!ecosystem_is(
            "Ubuntu:Pro:20.04:LTS",
            Distro::Ubuntu,
            "20.04",
            false
        ));
    }

    #[test]
    fn the_nvd_ranges_decide() {
        let configs = json!([{"nodes": [{"cpeMatch": [
            {"criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "vulnerable": true,
             "versionStartIncluding": "8.5", "versionEndExcluding": "9.8"},
            {"criteria": "cpe:2.3:a:openbsd:openssh:7.0:p1:*:*:*:*:*:*", "vulnerable": true},
            {"criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", "vulnerable": false}
        ]}]}]);
        let v = |version| nvd_verdict(&configs, "openbsd", "openssh", version);
        assert_eq!(
            v("9.6p1"),
            Verdict::Affected {
                checked: true,
                fixed: "9.8".into()
            }
        );
        assert_eq!(v("9.8p1"), Verdict::NotAffected);
        assert_eq!(
            v("7.0p1"),
            Verdict::Affected {
                checked: true,
                fixed: String::new()
            }
        );
        assert_eq!(
            v(""),
            Verdict::Affected {
                checked: false,
                fixed: String::new()
            }
        );
        assert_eq!(
            nvd_verdict(&configs, "linux", "linuxkernel", "6.1"),
            Verdict::NotAffected
        );
        let all = json!([{"nodes": [{"cpeMatch": [
            {"criteria": "cpe:2.3:o:avm:fritz\\!os:*:*:*:*:*:*:*:*", "vulnerable": true}]}]}]);
        assert_eq!(
            nvd_verdict(&all, "avm", "fritzos", "8.20"),
            Verdict::Affected {
                checked: false,
                fixed: String::new()
            }
        );
    }

    #[test]
    fn the_cna_ranges_decide() {
        let affected = json!([
            {"vendor": "OpenBSD", "product": "OpenSSH", "default": "unaffected",
             "versions": [{"version": "8.5p1", "less_than_or_equal": "9.7p1", "status": "affected"}]},
            {"vendor": "Red Hat", "product": "Red Hat Enterprise Linux 9", "default": "affected",
             "versions": [{"version": "0:8.7p1-38.el9", "less_than": "*", "status": "unaffected", "type": "rpm"}]}
        ]);
        let v = |version| cna_verdict(&affected, "openbsd", "openssh", version);
        assert_eq!(
            v("9.6p1"),
            Verdict::Affected {
                checked: true,
                fixed: String::new()
            }
        );
        assert_eq!(v("9.8p1"), Verdict::NotAffected);
        assert_eq!(v("8.4p1"), Verdict::NotAffected);
        let na = json!([{"vendor": "n/a", "product": "Widget", "versions": [{"version": "n/a", "status": "affected"}]}]);
        assert_eq!(
            cna_verdict(&na, "na", "widget", "1.0"),
            Verdict::Affected {
                checked: false,
                fixed: String::new()
            }
        );
        let lt = json!([{"vendor": "Acme", "product": "Widget", "versions": [
            {"version": "0", "less_than": "2.4.1", "status": "affected", "type": "semver"}]}]);
        assert_eq!(
            cna_verdict(&lt, "acme", "widget", "2.4.0"),
            Verdict::Affected {
                checked: true,
                fixed: "2.4.1".into()
            }
        );
    }

    fn csaf_row(version: &str, range: bool, status: &str) -> CsafRow {
        CsafRow {
            advisory_seq: 1,
            vendor: "opensource".into(),
            product: "openssh".into(),
            version: version.into(),
            version_range: range,
            status: status.into(),
            cpe: String::new(),
            display_id: "WID-SEC-2026-1".into(),
            title: "OpenSSH".into(),
            severity: "high".into(),
            published_ms: Some(0),
        }
    }

    #[test]
    fn csaf_product_trees_are_read_as_ranges() {
        assert_eq!(
            csaf_range("<10.6p2", true).unwrap().end.unwrap().version,
            "10.6p2"
        );
        assert!(
            csaf_range("6.8p1-9.9p1", false)
                .unwrap()
                .contains(Scheme::Generic, "9.0")
        );
        assert_eq!(
            csaf_range("9.9p1-22.el10_2", false),
            Some(Range::exact("9.9p1-22.el10_2"))
        );
        assert_eq!(csaf_range("", true), None);
        let rows = [
            csaf_row("<10.6p2", true, "affected"),
            csaf_row("10.6p2", false, ""),
        ];
        let rows: Vec<&CsafRow> = rows.iter().collect();
        assert_eq!(
            csaf_verdict(&rows, "10.0p1"),
            Verdict::Affected {
                checked: true,
                fixed: "10.6p2".into()
            }
        );
        assert_eq!(csaf_verdict(&rows, "10.6p2"), Verdict::NotAffected);
        assert_eq!(
            csaf_verdict(&rows, ""),
            Verdict::Affected {
                checked: false,
                fixed: String::new()
            }
        );
        let only_fixed = [csaf_row("8.20", false, "fixed")];
        let only_fixed: Vec<&CsafRow> = only_fixed.iter().collect();
        assert_eq!(
            csaf_verdict(&only_fixed, "8.10"),
            Verdict::Affected {
                checked: true,
                fixed: "8.20".into()
            }
        );
        assert_eq!(csaf_verdict(&only_fixed, "8.20"), Verdict::NotAffected);
        // One range as the BSI writes it (WID-SEC-2024-1055): ">=5.4" affected, "<7.1p2" without a status.
        let split = [
            csaf_row(">=5.4", true, "affected"),
            csaf_row(">=6.8", true, ""),
            csaf_row("<7.1p2", true, ""),
        ];
        let split: Vec<&CsafRow> = split.iter().collect();
        assert_eq!(csaf_verdict(&split, "9.6p1"), Verdict::NotAffected);
        assert_eq!(csaf_verdict(&split, "5.3"), Verdict::NotAffected);
        assert!(matches!(
            csaf_verdict(&split, "7.0p1"),
            Verdict::Affected { checked: true, .. }
        ));
    }

    #[test]
    fn devices_are_also_found_under_their_firmware_and_other_names() {
        let keys = |kind, vendor, product| {
            product_keys(kind, vendor, product)
                .into_iter()
                .map(|(_, p)| p)
                .collect::<Vec<_>>()
        };
        assert_eq!(keys(Kind::Software, "openbsd", "openssh"), ["openssh"]);
        assert_eq!(
            keys(Kind::Hardware, "avm", "fritzos"),
            ["fritzos", "fritzosfirmware"]
        );
        assert_eq!(
            keys(Kind::Hardware, "tplink", "omadaer605"),
            [
                "omadaer605",
                "er605",
                "tler605",
                "omadaer605firmware",
                "er605firmware",
                "tler605firmware"
            ]
        );
        assert_eq!(
            keys(Kind::Software, "tplink", "omadacontroller"),
            ["omadacontroller"]
        );
        assert_eq!(
            keys(Kind::Software, "microsoft", "edgechromium"),
            ["edgechromium", "microsoftedgechromiumbased"]
        );
        assert_eq!(
            keys(Kind::Software, "microsoft", "microsoftedgechromiumbased"),
            ["microsoftedgechromiumbased", "edgechromium"]
        );
        assert_eq!(
            keys(Kind::Software, "notepadplusplus", "notepad"),
            ["notepad", "notepadplusplus"]
        );
        // Only under the vendor named.
        assert_eq!(keys(Kind::Software, "memono", "notepad"), ["notepad"]);
    }

    #[test]
    fn keywords_become_phrases() {
        assert_eq!(fts_phrase("Huawei 5G"), "{title products} : \"Huawei 5G\"");
        assert_eq!(fts_phrase("a\"b"), "{title products} : \"a\"\"b\"");
    }

    async fn pool() -> (SqlitePool, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pool = crate::storage::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        crate::storage::migrate(&pool).await.unwrap();
        (pool, dir)
    }

    async fn exec(pool: &SqlitePool, sql: &str) {
        sqlx::raw_sql(sql).execute(pool).await.unwrap();
    }

    fn package(release: &str, name: &str, version: &str, pro: bool) -> Input {
        Input {
            kind: "package".into(),
            distro: "ubuntu".into(),
            release: release.into(),
            product_name: name.into(),
            version: version.into(),
            pro,
            ..Input::default()
        }
    }

    #[tokio::test]
    async fn packages_match_the_ranges_of_their_release() {
        let (pool, _dir) = pool().await;
        exec(
            &pool,
            "INSERT INTO osv_records (seq, id, source, kind, summary, priority, modified, modified_ms, fetched_ms) VALUES
               (1, 'USN-8928-1', 'ubuntu', 'advisory', 'OpenSSH vulnerabilities', '', 'x', 0, 0),
               (2, 'UBUNTU-CVE-2026-1', 'ubuntu', 'cve', 'a flaw', 'medium', 'x', 0, 0),
               (3, 'UBUNTU-CVE-2026-2', 'ubuntu', 'cve', 'still open', 'low', 'x', 0, 0),
               (4, 'USN-9000-1', 'ubuntu', 'advisory', 'no cve', 'high', 'x', 0, 0);
             INSERT INTO osv_cves VALUES ('CVE-2026-1', 1), ('CVE-2026-1', 2), ('CVE-2026-2', 3);
             INSERT INTO osv_affected (record_seq, ecosystem, release, package, introduced, fixed, last_affected, urgency) VALUES
               (1, 'Ubuntu:24.04:LTS', '24.04', 'openssh', '0', '1:9.6p1-3ubuntu13.20', '', ''),
               (2, 'Ubuntu:24.04:LTS', '24.04', 'openssh', '0', '1:9.6p1-3ubuntu13.20', '', ''),
               (3, 'Ubuntu:24.04:LTS', '24.04', 'openssh', '0', '', '', ''),
               (3, 'Ubuntu:Pro:24.04:LTS', '24.04', 'openssh', '0', '1:9.6p1-3ubuntu13.19+esm1', '', ''),
               (4, 'Ubuntu:22.04:LTS', '22.04', 'openssh', '0', '1:8.9p1-3ubuntu0.20', '', '');",
        )
        .await;
        let old = package("24.04", "openssh", "1:9.6p1-3ubuntu13.19", false)
            .check()
            .unwrap()
            .as_asset(1, 0);
        let found = find(&pool, &old).await.unwrap();
        let vulns: Vec<&str> = found.iter().map(|f| f.vuln.as_str()).collect();
        assert_eq!(vulns, ["CVE-2026-1", "CVE-2026-2"]);
        assert_eq!(found[0].fixed, "1:9.6p1-3ubuntu13.20");
        assert_eq!(found[0].evidence, ["USN-8928-1"]);
        assert_eq!(found[0].confidence, Confidence::High);
        assert_eq!(found[1].fixed, "");
        // Ubuntu's priority of the CVE (the USN has none): medium is no rating, low is.
        assert_eq!(found[0].rating, Rating::None);
        assert_eq!(found[1].rating, Rating::Low);

        // With Ubuntu Pro the open CVE has a fix that the host has.
        let pro = package("24.04", "openssh", "1:9.6p1-3ubuntu13.19+esm1", true)
            .check()
            .unwrap()
            .as_asset(1, 0);
        let found = find(&pool, &pro).await.unwrap();
        let vulns: Vec<&str> = found.iter().map(|f| f.vuln.as_str()).collect();
        assert_eq!(vulns, ["CVE-2026-1"]);

        let current = package("24.04", "openssh", "1:9.6p1-3ubuntu13.20", false)
            .check()
            .unwrap()
            .as_asset(1, 0);
        assert_eq!(
            find(&pool, &current).await.unwrap().len(),
            1,
            "CVE-2026-2 is open"
        );

        let other = package("22.04", "openssh", "1:8.9p1-3ubuntu0.1", false)
            .check()
            .unwrap()
            .as_asset(1, 0);
        let found = find(&pool, &other).await.unwrap();
        assert_eq!(found[0].vuln, "osv:USN-9000-1");
        assert_eq!(found[0].base_prio, 70);
        assert_eq!(found[0].title, "no cve");
        assert_eq!(
            found[0].rating,
            Rating::None,
            "without CVE the severity is the base"
        );
    }

    #[tokio::test]
    async fn debian_packages_take_the_rating_of_the_tracker() {
        let (pool, _dir) = pool().await;
        exec(
            &pool,
            "INSERT INTO osv_records (seq, id, source, kind, summary, priority, modified, modified_ms, fetched_ms) VALUES
               (1, 'DEBIAN-CVE-2026-1', 'debian', 'cve', '', '', 'x', 0, 0),
               (2, 'DEBIAN-CVE-2026-2', 'debian', 'cve', '', '', 'x', 0, 0),
               (3, 'DEBIAN-CVE-2026-3', 'debian', 'cve', '', '', 'x', 0, 0),
               (4, 'DEBIAN-CVE-2026-4', 'debian', 'cve', '', '', 'x', 0, 0);
             INSERT INTO osv_cves VALUES ('CVE-2026-1', 1), ('CVE-2026-2', 2), ('CVE-2026-3', 3), ('CVE-2026-4', 4);
             INSERT INTO osv_affected (record_seq, ecosystem, release, package, introduced, fixed, last_affected, urgency) VALUES
               (1, 'Debian:13', '13', 'zlib', '0', '', '', ''),
               (2, 'Debian:13', '13', 'zlib', '0', '', '', ''),
               (3, 'Debian:13', '13', 'zlib', '0', '', '', ''),
               (4, 'Debian:13', '13', 'zlib', '0', '', '', '');
             INSERT INTO debian_tracker (cve_id, package, release, status, urgency, nodsa, nodsa_reason, fixed_version) VALUES
               ('CVE-2026-1', 'zlib', 'trixie', 'open', 'unimportant', '', '', ''),
               ('CVE-2026-2', 'zlib', 'trixie', 'open', 'not yet assigned', 'Minor issue', 'postponed', ''),
               ('CVE-2026-3', 'zlib', 'trixie', 'open', 'not yet assigned', 'Minor issue', '', ''),
               ('CVE-2026-4', 'zlib', 'bookworm', 'open', 'unimportant', '', '', ''),
               ('CVE-2026-4', 'zlib', 'trixie', 'open', 'not yet assigned', '', '', '');",
        )
        .await;
        let asset = Input {
            distro: "debian".into(),
            ..package("13", "zlib", "1:1.3.dfsg-1", false)
        }
        .check()
        .unwrap()
        .as_asset(1, 0);
        let found = find(&pool, &asset).await.unwrap();
        let ratings: Vec<(&str, Rating)> =
            found.iter().map(|f| (f.vuln.as_str(), f.rating)).collect();
        assert_eq!(
            ratings,
            [
                ("CVE-2026-1", Rating::Unimportant),
                ("CVE-2026-2", Rating::Postponed),
                ("CVE-2026-3", Rating::NoDsa),
                ("CVE-2026-4", Rating::None),
            ],
            "only the tracker rows of trixie count"
        );
    }

    #[tokio::test]
    async fn the_kernel_of_raspberry_pi_os_is_not_matched_against_debian() {
        let (pool, _dir) = pool().await;
        exec(
            &pool,
            "INSERT INTO osv_records (seq, id, source, kind, summary, priority, modified, modified_ms, fetched_ms) VALUES
               (1, 'DEBIAN-CVE-2026-1', 'debian', 'cve', '', '', 'x', 0, 0),
               (2, 'DEBIAN-CVE-2026-2', 'debian', 'cve', '', '', 'x', 0, 0);
             INSERT INTO osv_cves VALUES ('CVE-2026-1', 1), ('CVE-2026-2', 2);
             INSERT INTO osv_affected (record_seq, ecosystem, release, package, introduced, fixed, last_affected, urgency) VALUES
               (1, 'Debian:13', '13', 'linux', '0', '', '', ''),
               (2, 'Debian:13', '13', 'glibc', '0', '', '', '');",
        )
        .await;
        let found = |product: &'static str, version: &'static str| {
            let pool = pool.clone();
            async move {
                let asset = Input {
                    distro: "debian".into(),
                    ..package("13", product, version, false)
                }
                .check()
                .unwrap()
                .as_asset(1, 0);
                find(&pool, &asset)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|f| f.vuln)
                    .collect::<Vec<_>>()
            }
        };
        assert!(
            found("linux", "1:6.18.60-1+rpt1").await.is_empty(),
            "the kernel of the Pi"
        );
        assert_eq!(
            found("linux", "6.12.57-1").await,
            ["CVE-2026-1"],
            "Debian's kernel"
        );
        assert_eq!(
            found("glibc", "2.41-12+rpt1").await,
            ["CVE-2026-2"],
            "other packages of the Pi are rebuilds of Debian"
        );
    }

    #[tokio::test]
    async fn products_match_nvd_cna_and_csaf() {
        let (pool, _dir) = pool().await;
        let now = 1_800_000_000_000_i64;
        exec(
            &pool,
            &format!(
                "INSERT INTO cves (id, state, title, published_ms, affected) VALUES
                   ('CVE-2024-6387', 'published', 'regreSSHion', 1719000000000, '[]'),
                   ('CVE-2026-9', 'published', 'new one', {recent}, '[{{\"vendor\":\"OpenBSD\",\"product\":\"OpenSSH\",\"versions\":[{{\"version\":\"n/a\",\"status\":\"affected\"}}]}}]'),
                   ('CVE-2020-1', 'published', 'old one', 1580000000000, '[{{\"vendor\":\"OpenBSD\",\"product\":\"OpenSSH\",\"versions\":[{{\"version\":\"n/a\",\"status\":\"affected\"}}]}}]');
                 INSERT INTO cve_products VALUES
                   ('CVE-2024-6387', 'nvd', 'openbsd', 'openssh', 'openbsd', 'openssh'),
                   ('CVE-2026-9', 'cna', 'openbsd', 'openssh', 'OpenBSD', 'OpenSSH'),
                   ('CVE-2020-1', 'cna', 'openbsd', 'openssh', 'OpenBSD', 'OpenSSH');
                 INSERT INTO nvd_cves (cve_id, configs) VALUES ('CVE-2024-6387',
                   '[{{\"nodes\":[{{\"cpeMatch\":[{{\"criteria\":\"cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*\",\"vulnerable\":true,\"versionStartIncluding\":\"8.5\",\"versionEndExcluding\":\"9.8\"}}]}}]}}]');
                 INSERT INTO advisories (seq, provider_id, source, url, tracking_id, display_id, title, severity, published_ms, fetched_ms)
                   VALUES (7, 1, 'bsi', 'u7', 'W-7', 'WID-SEC-2026-7', 'OpenSSH: Schwachstelle', 'high', 0, 0),
                          (8, 1, 'bsi', 'u8', 'W-8', 'WID-SEC-2026-8', 'OpenSSH: ohne CVE', 'medium', 0, 0);
                 INSERT INTO advisory_cves VALUES (7, 'CVE-2026-50');
                 INSERT INTO advisory_products (advisory_seq, product_id, vendor, product, vendor_name, product_name, name, version, version_range, status) VALUES
                   (7, 'P1', 'opensource', 'openssh', 'Open Source', 'OpenSSH', 'x', '<10.6p2', 1, 'affected'),
                   (7, 'P2', 'opensource', 'openssh', 'Open Source', 'OpenSSH', 'x', '10.6p2', 0, ''),
                   (8, 'P1', 'opensource', 'openssh', 'Open Source', 'OpenSSH', 'x', '<9.0', 1, 'affected'),
                   (8, 'P3', 'microsoft', 'windows', 'Microsoft', 'Windows', 'x', '<1', 1, 'affected');",
                recent = now - 86_400_000
            ),
        )
        .await;
        let asset = Input {
            kind: "software".into(),
            vendor_name: "OpenBSD".into(),
            product_name: "OpenSSH".into(),
            version: "9.6p1".into(),
            ..Input::default()
        }
        .check()
        .unwrap()
        .as_asset(1, now);
        let found = find(&pool, &asset).await.unwrap();
        let summary: Vec<(&str, Confidence, Method, &str)> = found
            .iter()
            .map(|f| (f.vuln.as_str(), f.confidence, f.method, f.fixed.as_str()))
            .collect();
        assert_eq!(
            summary,
            [
                ("CVE-2024-6387", Confidence::High, Method::Nvd, "9.8"),
                ("CVE-2026-50", Confidence::Medium, Method::Csaf, "10.6p2"),
                ("CVE-2026-9", Confidence::Medium, Method::Cna, ""),
            ],
            "the old CVE without versions is left out, so is advisory 8 (9.6p1 is not < 9.0)"
        );
        assert_eq!(found[1].evidence, ["WID-SEC-2026-7"]);

        // Stored, then the asset is updated past every fix.
        sqlx::query(
            "INSERT INTO assets (id, kind, vendor, product, vendor_name, product_name, version, created_ms, updated_ms)
             VALUES (1, 'software', 'openbsd', 'openssh', 'OpenBSD', 'OpenSSH', '9.6p1', ?, ?)",
        )
        .bind(now)
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();
        let s = match_asset(&pool, 1, now).await.unwrap();
        assert_eq!(s.new, 3);
        sqlx::query("UPDATE assets SET version = '10.7p1' WHERE id = 1")
            .execute(&pool)
            .await
            .unwrap();
        let s = match_all(&pool, now + 1).await.unwrap();
        assert_eq!((s.new, s.resolved), (0, 2), "the medium CNA match stays");
    }

    #[tokio::test]
    async fn keywords_find_recent_titles() {
        let (pool, _dir) = pool().await;
        exec(
            &pool,
            "INSERT INTO cves (id, state, title, products, published_ms) VALUES
               ('CVE-2026-5', 'published', 'Huawei 5G CPE Pro: buffer overflow', '', 100),
               ('CVE-2019-5', 'published', 'Huawei 5G CPE Pro: old', '', 1);
             INSERT INTO advisories (seq, provider_id, source, url, tracking_id, display_id, title, products, severity, published_ms, fetched_ms)
               VALUES (3, 1, 'bsi', 'u3', 'W-3', 'WID-SEC-2026-3', 'Huawei Router: mehrere Schwachstellen', 'Huawei 5G CPE Pro', 'critical', 100, 0);",
        )
        .await;
        let id = assets::add_watch(&pool, "Huawei 5G CPE", 50 + LOOK_BACK_MS)
            .await
            .unwrap()
            .unwrap();
        let s = match_watch(&pool, id, 200).await.unwrap();
        assert_eq!(s.new, 2);
        let rows = matches::rows(&pool, &[matches::State::New]).await.unwrap();
        let mut vulns: Vec<&str> = rows.iter().map(|r| r.vuln.as_str()).collect();
        vulns.sort_unstable();
        assert_eq!(vulns, ["CVE-2026-5", "adv:3"]);
        let adv = rows.iter().find(|r| r.vuln == "adv:3").unwrap();
        assert_eq!(adv.prio(), 65, "critical 90 less 25 for the low confidence");
    }
}
