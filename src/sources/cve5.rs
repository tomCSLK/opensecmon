//! Reads one CVE record in the CVE JSON 5 format of cvelistV5 (`CVE-2026-12345.json`) into what we store.
//!
//! Records come from many CNAs and are not always tidy, so the reader is lenient about shapes (a missing
//! list, a number written as a string) and strict about sizes: texts and lists are cut to fixed limits.

use serde_json::{Value, json};

use crate::sources::{name_key, parse_time_ms};

/// Longest description kept (characters).
const MAX_DESCRIPTION: usize = 8_000;
/// Longest title kept; a title made from the description is cut earlier.
const MAX_TITLE: usize = 300;
const MAX_DERIVED_TITLE: usize = 140;
const MAX_REFS: usize = 200;
const MAX_AFFECTED: usize = 200;
const MAX_CWES: usize = 20;
const MAX_VERSIONS: usize = 500;
const MAX_CPES: usize = 50;
const MAX_NAME: usize = 200;
const MAX_URL: usize = 2_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CveState {
    Published,
    Rejected,
}

/// A CVSS score of one provider.
#[derive(Debug, Clone, PartialEq)]
pub struct Metric {
    /// `cna`, `adp` or `nvd`.
    pub provider: &'static str,
    /// The organisation (CNA/ADP short name, NVD source identifier).
    pub source: String,
    /// `4.0`, `3.1`, `3.0`, `2.0`.
    pub version: String,
    pub score: f64,
    pub vector: String,
    pub severity: String,
}

/// A vendor/product pair a CVE names.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Product {
    /// [`name_key`] of the vendor.
    pub vendor: String,
    pub product: String,
    pub vendor_name: String,
    pub product_name: String,
}

impl Product {
    pub fn new(vendor_name: &str, product_name: &str) -> Option<Self> {
        let vendor_name = clip(vendor_name.trim(), MAX_NAME);
        let product_name = clip(product_name.trim(), MAX_NAME);
        let vendor = name_key(&vendor_name);
        let product = name_key(&product_name);
        let vendor = if PLACEHOLDERS.contains(&vendor.as_str()) {
            String::new()
        } else {
            vendor
        };
        if product.is_empty() || PLACEHOLDERS.contains(&product.as_str()) {
            return None;
        }
        Some(Self {
            vendor,
            product,
            vendor_name,
            product_name,
        })
    }
}

/// Keys that stand for "no name".
const PLACEHOLDERS: [&str; 5] = ["na", "unknown", "unspecified", "none", "notapplicable"];

/// What we keep of a CVE record.
#[derive(Debug, Clone, PartialEq)]
pub struct Cve {
    pub id: String,
    pub state: CveState,
    /// Short name of the CNA (`redhat`, `GitHub_M` …).
    pub assigner: String,
    pub title: String,
    pub description: String,
    pub published_ms: Option<i64>,
    pub updated_ms: Option<i64>,
    /// `dateUpdated` as written: equal means unchanged.
    pub record_updated: String,
    pub cwes: Vec<String>,
    /// `[{"url": …, "tags": […]}]`
    pub refs_json: String,
    /// The CNA's `affected` entries, reduced (see [`affected_entry`]).
    pub affected_json: String,
    pub metrics: Vec<Metric>,
    pub products: Vec<Product>,
}

/// Checks that `id` looks like a CVE id (`CVE-YYYY-NNNN…`).
pub fn is_cve_id(id: &str) -> bool {
    let mut parts = id.split('-');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some("CVE"), Some(year), Some(num), None)
            if year.len() == 4 && year.bytes().all(|b| b.is_ascii_digit())
                && (4..=9).contains(&num.len()) && num.bytes().all(|b| b.is_ascii_digit())
    )
}

/// Reads one record.
pub fn parse(bytes: &[u8]) -> Result<Cve, String> {
    let record: Value = serde_json::from_slice(bytes).map_err(|e| format!("not JSON: {e}"))?;
    let meta = record.get("cveMetadata").ok_or("no cveMetadata")?;
    let id = text(meta, "cveId").ok_or("no cveId")?;
    if !is_cve_id(id) {
        return Err(format!("not a CVE id: {}", clip(id, 40)));
    }
    let state = match text(meta, "state") {
        Some("PUBLISHED") => CveState::Published,
        Some("REJECTED") => CveState::Rejected,
        other => return Err(format!("{id}: unknown state {other:?}")),
    };
    let containers = record.get("containers").unwrap_or(&Value::Null);
    let cna = containers.get("cna").unwrap_or(&Value::Null);
    let adps = list(containers, "adp");
    let assigner = clip(
        text(meta, "assignerShortName").unwrap_or_default(),
        MAX_NAME,
    );
    let record_updated = clip(text(meta, "dateUpdated").unwrap_or_default(), 40);

    let description = match state {
        CveState::Published => english(list(cna, "descriptions")),
        CveState::Rejected => english(list(cna, "rejectedReasons")),
    };
    let description = clip(description.trim(), MAX_DESCRIPTION);
    let title = match text(cna, "title").map(str::trim).filter(|t| !t.is_empty()) {
        Some(title) => clip(&one_line(title), MAX_TITLE),
        None => derived_title(&description),
    };

    let mut cwes: Vec<String> = Vec::new();
    for container in std::iter::once(cna).chain(adps.iter()) {
        for problem in list(container, "problemTypes") {
            for d in list(problem, "descriptions") {
                if cwes.len() < MAX_CWES
                    && let Some(cwe) = text(d, "cweId").map(str::trim)
                    && cwe.starts_with("CWE-")
                    && cwe.len() <= 16
                    && !cwes.iter().any(|c| c == cwe)
                {
                    cwes.push(cwe.to_owned());
                }
            }
        }
    }

    let mut refs: Vec<Value> = Vec::new();
    let mut seen_urls = std::collections::HashSet::new();
    for container in std::iter::once(cna).chain(adps.iter()) {
        for r in list(container, "references") {
            let Some(url) = text(r, "url").map(str::trim) else {
                continue;
            };
            if url.len() > MAX_URL || !(url.starts_with("https://") || url.starts_with("http://")) {
                continue;
            }
            if refs.len() < MAX_REFS && seen_urls.insert(url.to_owned()) {
                let tags: Vec<String> = list(r, "tags")
                    .iter()
                    .filter_map(Value::as_str)
                    .take(10)
                    .map(|t| clip(t, 40))
                    .collect();
                refs.push(json!({ "url": url, "tags": tags }));
            }
        }
    }

    let affected: Vec<Value> = list(cna, "affected")
        .iter()
        .take(MAX_AFFECTED)
        .map(affected_entry)
        .collect();
    let mut products: Vec<Product> = list(cna, "affected")
        .iter()
        .take(MAX_AFFECTED)
        .filter_map(|a| {
            Product::new(
                text(a, "vendor").unwrap_or_default(),
                text(a, "product").or_else(|| text(a, "packageName"))?,
            )
        })
        .collect();
    products.sort();
    products.dedup_by(|a, b| a.vendor == b.vendor && a.product == b.product);

    let cna_source = text(
        cna.get("providerMetadata").unwrap_or(&Value::Null),
        "shortName",
    )
    .unwrap_or(&assigner)
    .to_owned();
    let mut metrics = metrics_of(cna, "cna", &cna_source);
    for adp in adps {
        let source = text(
            adp.get("providerMetadata").unwrap_or(&Value::Null),
            "shortName",
        )
        .unwrap_or("ADP");
        metrics.extend(metrics_of(adp, "adp", source));
    }

    Ok(Cve {
        id: id.to_owned(),
        state,
        assigner,
        title,
        description,
        published_ms: text(meta, "datePublished").and_then(parse_time_ms),
        updated_ms: text(meta, "dateUpdated").and_then(parse_time_ms),
        record_updated,
        cwes,
        refs_json: Value::Array(refs).to_string(),
        affected_json: Value::Array(affected).to_string(),
        metrics,
        products,
    })
}

/// The CVSS scores of a container (`metrics: [{"cvssV3_1": {…}}, …]`).
fn metrics_of(container: &Value, provider: &'static str, source: &str) -> Vec<Metric> {
    let mut out = Vec::new();
    for entry in list(container, "metrics") {
        for (key, version) in [
            ("cvssV4_0", "4.0"),
            ("cvssV3_1", "3.1"),
            ("cvssV3_0", "3.0"),
            ("cvssV2_0", "2.0"),
        ] {
            let Some(cvss) = entry.get(key) else {
                continue;
            };
            if let Some(metric) = metric(cvss, provider, source, version) {
                out.push(metric);
            }
        }
    }
    out
}

/// One CVSS block (`baseScore`, `vectorString`, `baseSeverity`), checked.
pub fn metric(cvss: &Value, provider: &'static str, source: &str, version: &str) -> Option<Metric> {
    let score = number(cvss.get("baseScore")?)?;
    if !(0.0..=10.0).contains(&score) {
        return None;
    }
    let vector = text(cvss, "vectorString")?.trim();
    if vector.is_empty() || vector.len() > 200 || !vector.is_ascii() {
        return None;
    }
    Some(Metric {
        provider,
        source: clip(source, MAX_NAME),
        version: version.to_owned(),
        score,
        vector: vector.to_owned(),
        severity: clip(text(cvss, "baseSeverity").unwrap_or_default(), 20).to_ascii_uppercase(),
    })
}

/// An `affected` entry, reduced to what the detail page and the matching (phase 5) need.
fn affected_entry(a: &Value) -> Value {
    let s = |key: &str| clip(text(a, key).unwrap_or_default().trim(), MAX_NAME);
    let versions: Vec<Value> = list(a, "versions")
        .iter()
        .take(MAX_VERSIONS)
        .map(|v| {
            let mut out = serde_json::Map::new();
            for (from, to) in [
                ("version", "version"),
                ("lessThan", "less_than"),
                ("lessThanOrEqual", "less_than_or_equal"),
                ("status", "status"),
                ("versionType", "type"),
            ] {
                if let Some(value) = v.get(from).and_then(scalar_text) {
                    out.insert(to.to_owned(), Value::String(clip(&value, 100)));
                }
            }
            Value::Object(out)
        })
        .collect();
    let strings = |key: &str, max: usize| -> Vec<String> {
        list(a, key)
            .iter()
            .filter_map(Value::as_str)
            .take(max)
            .map(|c| clip(c.trim(), MAX_NAME))
            .collect()
    };
    json!({
        "vendor": s("vendor"),
        "product": s("product"),
        "package": s("packageName"),
        "collection": s("collectionURL"),
        "default": s("defaultStatus"),
        "cpes": strings("cpes", MAX_CPES),
        "platforms": strings("platforms", 20),
        "versions": versions,
    })
}

/// The English text of a list of `{lang, value}` (else the first one).
fn english(items: &[Value]) -> String {
    let pick = items
        .iter()
        .find(|d| text(d, "lang").is_some_and(|l| l.to_ascii_lowercase().starts_with("en")))
        .or_else(|| items.first());
    pick.and_then(|d| text(d, "value"))
        .unwrap_or_default()
        .to_owned()
}

/// A title from the description: its first sentence, shortened.
fn derived_title(description: &str) -> String {
    let line = one_line(description);
    let sentence = match line.find(". ") {
        Some(end) => &line[..=end],
        None => line.as_str(),
    };
    let sentence = sentence.trim().trim_end_matches('.');
    if sentence.chars().count() > MAX_DERIVED_TITLE {
        let cut: String = sentence.chars().take(MAX_DERIVED_TITLE - 1).collect();
        format!("{}…", cut.trim_end())
    } else {
        sentence.to_owned()
    }
}

/// Whitespace (newlines, tabs, runs of spaces) folded into single spaces.
fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn text<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key)?.as_str()
}

fn list<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v.get(key)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// A number, also when written as a string.
fn number(v: &Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_str()?.trim().parse().ok())
}

/// A string or number as text.
fn scalar_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// At most `max` characters of `s`.
pub fn clip(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((end, _)) => s[..end].to_owned(),
        None => s.to_owned(),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const RECORD: &str = r#"{
      "dataType": "CVE_RECORD", "dataVersion": "5.2",
      "cveMetadata": {"cveId": "CVE-2026-0001", "state": "PUBLISHED", "assignerShortName": "example",
        "datePublished": "2026-01-02T03:04:05.000Z", "dateUpdated": "2026-01-03T00:00:00.000Z"},
      "containers": {
        "cna": {
          "providerMetadata": {"shortName": "example"},
          "descriptions": [{"lang": "de", "value": "Deutsch"},
                           {"lang": "en", "value": "A heap overflow in\nWidget Server allows remote code execution. More text."}],
          "affected": [
            {"vendor": "Example Corp", "product": "Widget Server", "defaultStatus": "unaffected",
             "versions": [{"version": "2.0", "lessThan": "2.4.1", "status": "affected", "versionType": "semver"},
                          {"version": 3, "status": "affected"}],
             "cpes": ["cpe:2.3:a:example:widget_server:*:*:*:*:*:*:*:*"]},
            {"vendor": "n/a", "product": "n/a"},
            {"vendor": "Example Corp", "product": "Widget Server"}
          ],
          "metrics": [{"cvssV3_1": {"version": "3.1", "baseScore": "9.8", "baseSeverity": "critical",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
                      {"cvssV4_0": {"baseScore": 11, "vectorString": "CVSS:4.0/AV:N"}},
                      {"other": {"type": "x"}}],
          "problemTypes": [{"descriptions": [{"cweId": "CWE-122", "description": "x"}]}],
          "references": [{"url": "https://example.org/advisory", "tags": ["vendor-advisory"]},
                         {"url": "javascript:alert(1)"}]
        },
        "adp": [{"providerMetadata": {"shortName": "CISA-ADP"},
                 "metrics": [{"cvssV3_1": {"baseScore": 7.5, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}}],
                 "problemTypes": [{"descriptions": [{"cweId": "CWE-122"}, {"cweId": "CWE-787"}]}],
                 "references": [{"url": "https://example.org/advisory"}, {"url": "https://other.example/x"}]}]
      }
    }"#;

    #[test]
    fn a_published_record_is_read_completely() {
        let cve = parse(RECORD.as_bytes()).unwrap();
        assert_eq!(cve.id, "CVE-2026-0001");
        assert_eq!(cve.state, CveState::Published);
        assert_eq!(cve.assigner, "example");
        assert_eq!(
            cve.description,
            "A heap overflow in\nWidget Server allows remote code execution. More text."
        );
        assert_eq!(
            cve.title,
            "A heap overflow in Widget Server allows remote code execution"
        );
        assert_eq!(cve.published_ms, Some(1_767_323_045_000));
        assert_eq!(cve.record_updated, "2026-01-03T00:00:00.000Z");
        assert_eq!(cve.cwes, ["CWE-122", "CWE-787"]);
        let refs: Value = serde_json::from_str(&cve.refs_json).unwrap();
        assert_eq!(refs.as_array().unwrap().len(), 2, "{refs}");
        assert_eq!(refs[0]["tags"][0], "vendor-advisory");
        assert_eq!(
            cve.metrics,
            [
                Metric {
                    provider: "cna",
                    source: "example".into(),
                    version: "3.1".into(),
                    score: 9.8,
                    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into(),
                    severity: "CRITICAL".into(),
                },
                Metric {
                    provider: "adp",
                    source: "CISA-ADP".into(),
                    version: "3.1".into(),
                    score: 7.5,
                    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H".into(),
                    severity: String::new(),
                },
            ],
            "the CVSS 4.0 score of 11 is out of range"
        );
        assert_eq!(cve.products.len(), 1);
        assert_eq!(cve.products[0].vendor, "examplecorp");
        assert_eq!(cve.products[0].product, "widgetserver");
        let affected: Value = serde_json::from_str(&cve.affected_json).unwrap();
        assert_eq!(affected[0]["versions"][0]["less_than"], "2.4.1");
        assert_eq!(affected[0]["versions"][1]["version"], "3");
        assert_eq!(affected[0]["default"], "unaffected");
    }

    #[test]
    fn a_rejected_record_keeps_its_reason() {
        let record = r#"{"cveMetadata": {"cveId": "CVE-2020-99999", "state": "REJECTED",
            "dateUpdated": "2020-01-01T00:00:00"},
          "containers": {"cna": {"rejectedReasons": [{"lang": "en", "value": "Duplicate of CVE-2020-1."}]}}}"#;
        let cve = parse(record.as_bytes()).unwrap();
        assert_eq!(cve.state, CveState::Rejected);
        assert_eq!(cve.description, "Duplicate of CVE-2020-1.");
        assert_eq!(cve.title, "Duplicate of CVE-2020-1");
        assert!(cve.metrics.is_empty() && cve.products.is_empty());
        assert_eq!(cve.refs_json, "[]");
    }

    #[test]
    fn broken_records_are_refused() {
        for bad in [
            "",
            "[]",
            r#"{"cveMetadata": {}}"#,
            r#"{"cveMetadata": {"cveId": "../../etc/passwd", "state": "PUBLISHED"}}"#,
            r#"{"cveMetadata": {"cveId": "CVE-2026-1234", "state": "RESERVED"}}"#,
        ] {
            assert!(parse(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn long_texts_are_cut() {
        let long = "x".repeat(20_000);
        let record = format!(
            r#"{{"cveMetadata": {{"cveId": "CVE-2026-0002", "state": "PUBLISHED"}},
               "containers": {{"cna": {{"title": "{long}", "descriptions": [{{"lang": "en", "value": "{long}"}}]}}}}}}"#
        );
        let cve = parse(record.as_bytes()).unwrap();
        assert_eq!(cve.title.chars().count(), MAX_TITLE);
        assert_eq!(cve.description.chars().count(), MAX_DESCRIPTION);
    }

    #[test]
    fn cve_ids_are_recognised() {
        assert!(is_cve_id("CVE-2026-1234"));
        assert!(is_cve_id("CVE-2021-44228"));
        assert!(!is_cve_id("CVE-26-1234"));
        assert!(!is_cve_id("CVE-2026-12"));
        assert!(!is_cve_id("cve-2026-1234"));
        assert!(!is_cve_id("CVE-2026-1234-x"));
    }

    #[test]
    fn titles_are_made_from_long_descriptions() {
        let title = derived_title(&"word ".repeat(100));
        assert!(title.ends_with('…'));
        assert!(title.chars().count() <= MAX_DERIVED_TITLE);
    }
}
