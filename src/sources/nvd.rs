//! NVD JSON 2.0 feeds: what NIST adds to a CVE (its own CVSS score, the CPE configurations, the status of
//! the analysis). The first run loads the yearly feeds (`nvdcve-2.0-2002.json.gz` … this year); after that
//! only `nvdcve-2.0-modified.json.gz` (changes of the last eight days), and only when its `.meta` names a
//! new SHA-256. Every feed is checked against that hash before it is read. The NVD asks not to fetch the
//! feeds more often than every two hours.
//!
//! The feeds are large (the yearly ones unpack to a few hundred MB), so they are read as a stream.

use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, anyhow, bail};
use serde::de::{DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use crate::http_client::{self, Get};
use crate::sources::cve5::{Metric, Product, clip, is_cve_id, metric};
use crate::sources::{Context, now_ms};
use crate::storage::cves::{refresh_derived, replace_metrics, replace_products};
use crate::storage::sources::{SourceState, Success, save_cursor};

/// The first yearly feed (it also holds all older CVEs).
const FIRST_YEAR: i16 = 2002;
const MAX_META: u64 = 4 << 10;
const MAX_GZ: u64 = 512 << 20;
const MAX_UNPACKED: u64 = 4 << 30;
const META_TIMEOUT: Duration = Duration::from_secs(60);
const FEED_TIMEOUT: Duration = Duration::from_secs(1800);
/// The modified feed covers eight days; after a longer pause the yearly feeds are loaded again.
const MODIFIED_SPAN_MS: i64 = 7 * 86_400_000;
const BATCH: usize = 500;
const MAX_CONFIGS: usize = 50;
const MAX_MATCHES: usize = 2_000;

/// What the cursor remembers: the yearly feeds already loaded and the hash of the last modified feed.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
struct Cursor {
    #[serde(default)]
    years: Vec<i16>,
    #[serde(default)]
    modified_sha256: String,
}

/// The `.meta` file of a feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    pub last_modified: String,
    pub sha256: String,
    pub size: u64,
}

pub fn parse_meta(text: &str) -> anyhow::Result<Meta> {
    let mut last_modified = String::new();
    let mut sha256 = String::new();
    let mut size = 0;
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "lastModifiedDate" => last_modified = clip(value, 40),
            "sha256" => sha256 = value.to_ascii_lowercase(),
            "size" => size = value.parse().unwrap_or(0),
            _ => {}
        }
    }
    if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("the .meta file has no valid sha256");
    }
    Ok(Meta {
        last_modified,
        sha256,
        size,
    })
}

/// What we keep of one NVD entry.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub id: String,
    pub status: String,
    pub last_modified: String,
    pub configs_json: String,
    pub metrics: Vec<Metric>,
    pub products: Vec<Product>,
}

#[derive(Debug, Deserialize)]
struct Item {
    cve: RawCve,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCve {
    id: String,
    #[serde(default)]
    vuln_status: String,
    #[serde(default)]
    last_modified: String,
    #[serde(default)]
    metrics: RawMetrics,
    #[serde(default)]
    configurations: Vec<Value>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawMetrics {
    #[serde(rename = "cvssMetricV40")]
    v40: Vec<RawMetric>,
    #[serde(rename = "cvssMetricV31")]
    v31: Vec<RawMetric>,
    #[serde(rename = "cvssMetricV30")]
    v30: Vec<RawMetric>,
    #[serde(rename = "cvssMetricV2")]
    v2: Vec<RawMetric>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawMetric {
    #[serde(default)]
    source: String,
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    cvss_data: Value,
    #[serde(default)]
    base_severity: Option<String>,
}

impl RawCve {
    fn into_record(self) -> Option<Record> {
        if !is_cve_id(&self.id) {
            return None;
        }
        let mut metrics = Vec::new();
        for (list, version) in [
            (&self.metrics.v40, "4.0"),
            (&self.metrics.v31, "3.1"),
            (&self.metrics.v30, "3.0"),
            (&self.metrics.v2, "2.0"),
        ] {
            // Only NIST's own assessment; the secondary ones repeat what the CNA said in cvelistV5.
            for m in list.iter().filter(|m| m.kind == "Primary") {
                let mut data = m.cvss_data.clone();
                if let (Some(severity), Some(obj)) = (&m.base_severity, data.as_object_mut()) {
                    obj.entry("baseSeverity")
                        .or_insert_with(|| Value::String(severity.clone()));
                }
                if let Some(metric) = metric(&data, "nvd", &m.source, version) {
                    metrics.push(metric);
                }
            }
        }
        let mut products = Vec::new();
        let configs: Vec<Value> = self
            .configurations
            .iter()
            .take(MAX_CONFIGS)
            .map(|c| config(c, &mut products))
            .collect();
        products.sort();
        products.dedup_by(|a, b| a.vendor == b.vendor && a.product == b.product);
        Some(Record {
            id: self.id,
            status: clip(&self.vuln_status, 40),
            last_modified: clip(&self.last_modified, 40),
            configs_json: Value::Array(configs).to_string(),
            metrics,
            products,
        })
    }
}

/// A configuration, reduced to the operators and the CPE matches; collects the named products.
fn config(c: &Value, products: &mut Vec<Product>) -> Value {
    let nodes: Vec<Value> = c
        .get("nodes")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
        .iter()
        .take(MAX_CONFIGS)
        .map(|node| {
            let matches: Vec<Value> = node
                .get("cpeMatch")
                .and_then(Value::as_array)
                .map_or(&[][..], Vec::as_slice)
                .iter()
                .take(MAX_MATCHES)
                .filter_map(|m| {
                    let criteria = m.get("criteria")?.as_str()?;
                    if criteria.len() > 300 || !criteria.starts_with("cpe:2.3:") {
                        return None;
                    }
                    if let Some((vendor, product)) = cpe_vendor_product(criteria)
                        && let Some(p) = Product::new(&vendor, &product)
                    {
                        products.push(p);
                    }
                    let mut out = serde_json::Map::new();
                    out.insert("criteria".into(), Value::String(criteria.to_owned()));
                    out.insert(
                        "vulnerable".into(),
                        Value::Bool(
                            m.get("vulnerable")
                                .and_then(Value::as_bool)
                                .unwrap_or(false),
                        ),
                    );
                    for key in [
                        "versionStartIncluding",
                        "versionStartExcluding",
                        "versionEndIncluding",
                        "versionEndExcluding",
                    ] {
                        if let Some(v) = m.get(key).and_then(Value::as_str) {
                            out.insert(key.into(), Value::String(clip(v, 100)));
                        }
                    }
                    Some(Value::Object(out))
                })
                .collect();
            json!({
                "operator": node.get("operator").and_then(Value::as_str).unwrap_or("OR"),
                "negate": node.get("negate").and_then(Value::as_bool).unwrap_or(false),
                "cpeMatch": matches,
            })
        })
        .collect();
    json!({
        "operator": c.get("operator").and_then(Value::as_str).unwrap_or("OR"),
        "nodes": nodes,
    })
}

/// Vendor and product of a CPE 2.3 name (`cpe:2.3:a:vendor:product:version:…`), unescaped.
pub fn cpe_vendor_product(cpe: &str) -> Option<(String, String)> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut chars = cpe.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => current.extend(chars.next()),
            ':' => fields.push(std::mem::take(&mut current)),
            c => current.push(c),
        }
        if fields.len() > 5 {
            break;
        }
    }
    fields.push(current);
    let vendor = fields.get(3)?;
    let product = fields.get(4)?;
    if fields.first().map(String::as_str) != Some("cpe")
        || ["*", "-", ""].contains(&vendor.as_str())
        || ["*", "-", ""].contains(&product.as_str())
    {
        return None;
    }
    Some((vendor.clone(), product.clone()))
}

/// Reads a feed (`{…, "vulnerabilities": [{"cve": {…}}, …]}`) and hands every entry to `each`.
pub fn read_feed<R: Read>(
    reader: R,
    each: &mut dyn FnMut(Record) -> Result<(), String>,
) -> anyhow::Result<u64> {
    let mut de = serde_json::Deserializer::from_reader(reader);
    let count = FeedSeed { each }
        .deserialize(&mut de)
        .context("the feed cannot be read")?;
    de.end().context("the feed has trailing data")?;
    Ok(count)
}

struct FeedSeed<'a> {
    each: &'a mut dyn FnMut(Record) -> Result<(), String>,
}

impl<'de> DeserializeSeed<'de> for FeedSeed<'_> {
    type Value = u64;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<u64, D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for FeedSeed<'_> {
    type Value = u64;
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("an NVD feed")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<u64, A::Error> {
        let mut count = 0;
        while let Some(key) = map.next_key::<String>()? {
            if key == "vulnerabilities" {
                count += map.next_value_seed(ItemsSeed {
                    each: &mut *self.each,
                })?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(count)
    }
}

struct ItemsSeed<'a> {
    each: &'a mut dyn FnMut(Record) -> Result<(), String>,
}

impl<'de> DeserializeSeed<'de> for ItemsSeed<'_> {
    type Value = u64;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<u64, D::Error> {
        d.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for ItemsSeed<'_> {
    type Value = u64;
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a list of NVD entries")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<u64, A::Error> {
        use serde::de::Error;
        let mut count = 0;
        // An entry that does not fit the expected shape is skipped, not fatal.
        while let Some(item) = seq.next_element::<Option<Value>>()? {
            let Some(item) = item else { continue };
            let Ok(item) = serde_json::from_value::<Item>(item) else {
                continue;
            };
            if let Some(record) = item.cve.into_record() {
                (self.each)(record).map_err(A::Error::custom)?;
                count += 1;
            }
        }
        Ok(count)
    }
}

pub async fn run(ctx: &Context, state: &SourceState) -> anyhow::Result<Success> {
    let mut cursor: Cursor = state
        .cursor
        .as_deref()
        .and_then(|c| serde_json::from_str(c).ok())
        .unwrap_or_default();
    // After a long pause the modified feed no longer covers the gap: load the yearly feeds again.
    let stale = state
        .last_success_ms
        .is_some_and(|ms| now_ms() - ms > MODIFIED_SPAN_MS);
    if stale {
        cursor.years.clear();
    }
    let this_year = jiff::Zoned::now().year();
    let (mut new, mut changed) = (0, 0);
    for year in FIRST_YEAR..=this_year {
        if cursor.years.contains(&year) {
            continue;
        }
        let name = format!("nvdcve-2.0-{year}");
        let (n, c, _) = apply_feed(ctx, &name, None).await?;
        new += n;
        changed += c;
        cursor.years.push(year);
        save_cursor(&ctx.pool, "nvd", &serde_json::to_string(&cursor)?).await?;
    }
    let (n, c, meta) =
        apply_feed(ctx, "nvdcve-2.0-modified", Some(&cursor.modified_sha256)).await?;
    new += n;
    changed += c;
    let version = meta.as_ref().map(|m| m.last_modified.clone());
    if let Some(meta) = meta {
        cursor.modified_sha256 = meta.sha256;
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nvd_cves")
        .fetch_one(&ctx.pool)
        .await?;
    Ok(Success {
        etag: None,
        last_modified: None,
        cursor: Some(serde_json::to_string(&cursor)?),
        version,
        item_count: Some(count),
        new,
        changed,
        warning: None,
    })
}

/// Loads one feed unless its hash equals `known_sha256`. Returns new and changed entries and the meta of
/// a loaded feed.
async fn apply_feed(
    ctx: &Context,
    name: &str,
    known_sha256: Option<&str>,
) -> anyhow::Result<(i64, i64, Option<Meta>)> {
    let base = &ctx.endpoints.nvd_feeds;
    let meta_url = format!("{base}/{name}.meta");
    let fetched = http_client::get_bytes(&Get::new(&meta_url, MAX_META, META_TIMEOUT))
        .await?
        .fresh()
        .ok_or_else(|| anyhow!("unexpected 304 for {name}.meta"))?;
    let meta = parse_meta(&String::from_utf8_lossy(&fetched.body))
        .with_context(|| format!("{name}.meta"))?;
    if known_sha256 == Some(meta.sha256.as_str()) {
        return Ok((0, 0, None));
    }
    if meta.size > MAX_UNPACKED {
        bail!("{name} is larger than {MAX_UNPACKED} bytes");
    }
    let path = ctx.download_path(&format!("{name}.json.gz"));
    let feed_url = format!("{base}/{name}.json.gz");
    // No specific Accept: the NVD answers `application/gzip` with 406.
    let get = Get::new(&feed_url, MAX_GZ, FEED_TIMEOUT);
    if http_client::get_file(&get, &path).await?.fresh().is_none() {
        bail!("unexpected 304 for {name}.json.gz");
    }
    let result = ingest(ctx, path.clone(), meta.sha256.clone())
        .await
        .with_context(|| format!("{name}.json.gz"));
    let _ = tokio::fs::remove_file(&path).await;
    let (new, changed) = result?;
    Ok((new, changed, Some(meta)))
}

/// Checks the hash of the unpacked feed, then reads it in a worker thread and stores it in batches.
async fn ingest(ctx: &Context, path: PathBuf, sha256: String) -> anyhow::Result<(i64, i64)> {
    let (sender, mut batches) = mpsc::channel::<Vec<Record>>(4);
    let reader = tokio::task::spawn_blocking(move || -> anyhow::Result<u64> {
        let actual = unpacked_sha256(&path)?;
        if actual != sha256 {
            bail!("SHA-256 does not match the .meta file");
        }
        let mut batch = Vec::with_capacity(BATCH);
        let mut each = |record: Record| -> Result<(), String> {
            batch.push(record);
            if batch.len() == BATCH {
                let full = std::mem::replace(&mut batch, Vec::with_capacity(BATCH));
                sender
                    .blocking_send(full)
                    .map_err(|_| "storing stopped".to_owned())?;
            }
            Ok(())
        };
        let count = read_feed(gz_reader(&path)?, &mut each)?;
        if !batch.is_empty() {
            sender
                .blocking_send(batch)
                .map_err(|_| anyhow!("storing stopped"))?;
        }
        Ok(count)
    });
    let (mut new, mut changed) = (0, 0);
    let stored: anyhow::Result<()> = async {
        while let Some(batch) = batches.recv().await {
            let mut tx = ctx.pool.begin().await?;
            for record in &batch {
                match store(&mut tx, record).await? {
                    Some(true) => new += 1,
                    Some(false) => changed += 1,
                    None => {}
                }
            }
            tx.commit().await?;
            ctx.progress.add(batch.len() as u64);
        }
        Ok(())
    }
    .await;
    drop(batches);
    let read = reader
        .await
        .map_err(|e| anyhow!("reading the feed stopped: {e}"))?;
    stored?;
    read?;
    Ok((new, changed))
}

fn gz_reader(path: &Path) -> anyhow::Result<impl Read> {
    let file = std::fs::File::open(path)?;
    Ok(BufReader::with_capacity(
        1 << 20,
        flate2::read::MultiGzDecoder::new(BufReader::with_capacity(1 << 20, file))
            .take(MAX_UNPACKED + 1),
    ))
}

/// SHA-256 (lower-case hex) of the unpacked content of a `.gz` file.
fn unpacked_sha256(path: &Path) -> anyhow::Result<String> {
    let mut reader = gz_reader(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf).context("cannot unpack the feed")?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > MAX_UNPACKED {
            bail!("the feed unpacks to more than {MAX_UNPACKED} bytes");
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// Stores one entry. `Some(true)` new, `Some(false)` changed, `None` unchanged.
async fn store(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    record: &Record,
) -> crate::error::Result<Option<bool>> {
    let known: Option<String> =
        sqlx::query_scalar("SELECT last_modified FROM nvd_cves WHERE cve_id = ?")
            .bind(&record.id)
            .fetch_optional(&mut **tx)
            .await?;
    if known.as_deref() == Some(record.last_modified.as_str()) {
        return Ok(None);
    }
    let (configs, configs_z) = crate::storage::packed::pack(&record.configs_json);
    sqlx::query(
        "INSERT INTO nvd_cves (cve_id, status, last_modified, configs, configs_z) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (cve_id) DO UPDATE SET status = excluded.status,
            last_modified = excluded.last_modified, configs = excluded.configs, configs_z = excluded.configs_z",
    )
    .bind(&record.id)
    .bind(&record.status)
    .bind(&record.last_modified)
    .bind(configs)
    .bind(configs_z)
    .execute(&mut **tx)
    .await?;
    replace_metrics(tx, &record.id, &["nvd"], &record.metrics).await?;
    replace_products(tx, &record.id, "nvd", &record.products).await?;
    refresh_derived(tx, &record.id).await?;
    Ok(Some(known.is_none()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::http_client::testserver::{gzip, ok, serve_and_record};
    use crate::sources::testutil::{context, state};
    use crate::sources::{SourceId, Sources};

    pub(crate) const FEED: &str = r#"{"resultsPerPage": 2, "format": "NVD_CVE", "version": "2.0",
      "vulnerabilities": [
        {"cve": {"id": "CVE-2026-0001", "vulnStatus": "Analyzed", "lastModified": "2026-11-05T10:00:00.000",
          "metrics": {
            "cvssMetricV31": [
              {"source": "nvd@nist.gov", "type": "Primary",
               "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseScore": 9.8, "baseSeverity": "CRITICAL"}},
              {"source": "cna@example.org", "type": "Secondary",
               "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseScore": 8.4}}],
            "cvssMetricV2": [{"source": "nvd@nist.gov", "type": "Primary", "baseSeverity": "HIGH",
               "cvssData": {"version": "2.0", "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P", "baseScore": 7.5}}]},
          "configurations": [{"operator": "AND", "nodes": [
            {"operator": "OR", "negate": false, "cpeMatch": [
              {"vulnerable": true, "criteria": "cpe:2.3:o:avm:fritz\\!os:*:*:*:*:*:*:*:*",
               "versionEndExcluding": "8.20", "matchCriteriaId": "X"}]},
            {"operator": "OR", "negate": false, "cpeMatch": [
              {"vulnerable": false, "criteria": "cpe:2.3:h:avm:fritz\\!box_7590:-:*:*:*:*:*:*:*"}]}]}]}},
        {"cve": {"id": "not-a-cve"}},
        {"cve": 42},
        {"cve": {"id": "CVE-2026-0002", "vulnStatus": "Deferred", "lastModified": "2026-11-05T11:00:00.000"}}
      ], "timestamp": "2026-11-05T14:00:03"}"#;

    fn sha256_hex(data: &[u8]) -> String {
        Sha256::digest(data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn meta(data: &[u8]) -> String {
        format!(
            "lastModifiedDate:2026-11-05T14:00:06-05:00\r\nsize:{}\r\ngzSize:1\r\nsha256:{}\r\n",
            data.len(),
            sha256_hex(data).to_uppercase()
        )
    }

    #[test]
    fn meta_files_are_read() {
        let m = parse_meta(&meta(b"abc")).unwrap();
        assert_eq!(m.last_modified, "2026-11-05T14:00:06-05:00");
        assert_eq!(m.size, 3);
        assert_eq!(m.sha256, sha256_hex(b"abc"));
        assert!(parse_meta("sha256:xyz").is_err());
    }

    #[test]
    fn cpe_names_give_vendor_and_product() {
        assert_eq!(
            cpe_vendor_product("cpe:2.3:o:avm:fritz\\!os:*:*:*:*:*:*:*:*"),
            Some(("avm".into(), "fritz!os".into()))
        );
        assert_eq!(
            cpe_vendor_product("cpe:2.3:a:openbsd:openssh:9.7:p1:*:*:*:*:*:*"),
            Some(("openbsd".into(), "openssh".into()))
        );
        assert_eq!(cpe_vendor_product("cpe:2.3:a:*:*:*:*:*:*:*:*:*:*"), None);
        assert_eq!(cpe_vendor_product("cpe:/a:x:y"), None);
    }

    #[test]
    fn a_feed_is_read_as_a_stream_and_bad_entries_are_skipped() {
        let mut records = Vec::new();
        let count = read_feed(FEED.as_bytes(), &mut |r| {
            records.push(r);
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 2);
        let r = &records[0];
        assert_eq!(r.status, "Analyzed");
        assert_eq!(
            r.metrics
                .iter()
                .map(|m| (m.version.as_str(), m.score, m.severity.as_str()))
                .collect::<Vec<_>>(),
            [("3.1", 9.8, "CRITICAL"), ("2.0", 7.5, "HIGH")],
            "only NIST's primary scores"
        );
        assert_eq!(
            r.products
                .iter()
                .map(|p| (p.vendor.as_str(), p.product.as_str()))
                .collect::<Vec<_>>(),
            [("avm", "fritzbox7590"), ("avm", "fritzos")]
        );
        let configs: Value = serde_json::from_str(&r.configs_json).unwrap();
        assert_eq!(configs[0]["operator"], "AND");
        assert_eq!(
            configs[0]["nodes"][0]["cpeMatch"][0]["versionEndExcluding"],
            "8.20"
        );
        assert!(
            configs[0]["nodes"][0]["cpeMatch"][0]
                .get("matchCriteriaId")
                .is_none()
        );
        assert!(read_feed(&b"{\"vulnerabilities\": [}"[..], &mut |_| Ok(())).is_err());
    }

    #[test]
    fn the_real_modified_feed_can_be_read() {
        // A copy fetched once into dev/cache/ (not in the repository); skipped without it.
        let path = Path::new("dev/cache/nvd-modified.json.gz");
        if !path.exists() {
            return;
        }
        let text = std::fs::read_to_string("dev/cache/nvd-modified.meta").unwrap();
        assert_eq!(
            unpacked_sha256(path).unwrap(),
            parse_meta(&text).unwrap().sha256
        );
        let mut n = 0;
        read_feed(gz_reader(path).unwrap(), &mut |_| {
            n += 1;
            Ok(())
        })
        .unwrap();
        assert!(n > 1000, "{n}");
    }

    #[tokio::test]
    async fn the_first_run_loads_every_year_then_only_changes() {
        let gz = gzip(FEED.as_bytes());
        let empty = br#"{"vulnerabilities": []}"#;
        let empty_gz = gzip(empty);
        let this_year = jiff::Zoned::now().year();
        let years = usize::try_from(this_year - FIRST_YEAR + 1).unwrap();
        let mut responses = Vec::new();
        // Yearly feeds: the first has the entries, the others are empty.
        for i in 0..years {
            let (data, packed) = if i == 0 {
                (FEED.as_bytes(), &gz)
            } else {
                (&empty[..], &empty_gz)
            };
            responses.push(ok(meta(data).as_bytes()));
            responses.push(ok(packed));
        }
        // Modified feed: the same entries again (unchanged), then the same .meta (nothing to do).
        responses.push(ok(meta(FEED.as_bytes()).as_bytes()));
        responses.push(ok(&gz));
        responses.push(ok(meta(FEED.as_bytes()).as_bytes()));
        // A broken download: the hash does not match.
        responses.push(ok(meta(b"something else").as_bytes()));
        responses.push(ok(&gz));
        let (addr, mut requests) = serve_and_record(responses).await;
        let (ctx, _dir) = context(&format!("http://{addr}")).await;
        sqlx::query("INSERT INTO cves (id, state, record_updated) VALUES ('CVE-2026-0001', 'published', 'x')")
            .execute(&ctx.pool)
            .await
            .unwrap();
        let sources = Sources::new(
            ctx.pool.clone(),
            ctx.work_dir.clone(),
            (*ctx.endpoints).clone(),
            false,
        );

        sources.run(SourceId::Nvd).await;
        let s = state(&ctx, SourceId::Nvd).await;
        assert_eq!(s.last_error, None);
        assert_eq!(
            (s.last_new, s.last_changed, s.item_count),
            (Some(2), Some(0), Some(2))
        );
        assert_eq!(s.version.as_deref(), Some("2026-11-05T14:00:06-05:00"));
        assert_eq!(
            requests.recv().await.unwrap().lines().next().unwrap(),
            "GET /nvd/nvdcve-2.0-2002.meta HTTP/1.1"
        );
        let (score, source, prio): (Option<f64>, Option<String>, i64) = sqlx::query_as(
            "SELECT cvss_score, cvss_source, prio FROM cves WHERE id = 'CVE-2026-0001'",
        )
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
        assert_eq!(
            (score, source.as_deref(), prio),
            (Some(9.8), Some("nvd:nvd@nist.gov"), 69)
        );

        sources.run(SourceId::Nvd).await;
        let s = state(&ctx, SourceId::Nvd).await;
        assert_eq!(s.last_error, None);
        assert_eq!((s.last_new, s.last_changed), (Some(0), Some(0)));

        // The modified feed changed, but the download does not match its hash.
        sources.run(SourceId::Nvd).await;
        let s = state(&ctx, SourceId::Nvd).await;
        assert!(
            s.last_error
                .as_deref()
                .unwrap_or_default()
                .contains("SHA-256"),
            "{s:?}"
        );
    }
}
