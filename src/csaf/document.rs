//! A CSAF 2.0 document, read into what opensecmon keeps of it: the advisory (ids, title, summary,
//! severity, dates, notes, references), the CVEs and the products of the product tree with their status.
//!
//! Only the fields used are read, every one of them leniently (a wrong type gives an empty value, not a
//! rejected document), and everything is cut to size. Documents not labelled TLP:WHITE or TLP:CLEAR are
//! refused.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use super::{RawPublisher, lenient, list, nullable, public_tlp, with_budget};
use crate::sources::cve5::{clip, is_cve_id};
use crate::sources::parse_time_ms;

/// Most products kept of one document (Red Hat's VEX documents name tens of thousands).
pub const MAX_PRODUCTS: usize = 5_000;
/// Most list elements (branches, products, notes, ids …) built while reading one document.
const MAX_ELEMENTS: usize = 200_000;
const MAX_CVES: usize = 5_000;
const MAX_NOTES: usize = 20;
const MAX_REFS: usize = 200;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Note {
    pub category: String,
    pub title: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reference {
    pub category: String,
    pub summary: String,
    pub url: String,
}

/// A product of the product tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Product {
    pub id: String,
    pub vendor_name: String,
    pub product_name: String,
    /// The full name the document gives.
    pub name: String,
    pub version: String,
    /// The version is a range such as `<10.6p2` (`product_version_range`).
    pub version_range: bool,
    pub cpe: String,
    pub purl: String,
    /// `affected`, `fixed`, `not_affected`, `investigating`, `recommended` or empty.
    pub status: &'static str,
}

/// What opensecmon keeps of a document.
#[derive(Debug, Clone, PartialEq)]
pub struct Advisory {
    pub tracking_id: String,
    pub display_id: String,
    pub publisher: String,
    pub title: String,
    pub summary: String,
    pub lang: String,
    pub tlp: String,
    /// `critical`, `high`, `medium`, `low` or empty.
    pub severity: &'static str,
    pub severity_text: String,
    pub cvss_score: Option<f64>,
    pub status: String,
    pub version: String,
    pub published_ms: Option<i64>,
    pub updated_ms: Option<i64>,
    /// The publisher's own page of the advisory (BSI: the portal), if it names one.
    pub web_url: String,
    pub notes: Vec<Note>,
    pub refs: Vec<Reference>,
    pub cves: Vec<String>,
    pub products: Vec<Product>,
    /// Products of the tree beyond [`MAX_PRODUCTS`], left out.
    pub products_cut: usize,
}

impl Advisory {
    /// The vendor and product names for the full-text search ("OpenSSH, Alpine Linux, …").
    pub fn products_text(&self) -> String {
        let mut seen = HashSet::new();
        let mut names = Vec::new();
        for p in &self.products {
            let name = if p.product_name.is_empty() {
                p.name.trim()
            } else {
                p.product_name.trim()
            };
            let full = if p.vendor_name.is_empty() || name.starts_with(p.vendor_name.trim()) {
                name.to_owned()
            } else {
                format!("{} {}", p.vendor_name.trim(), name)
            };
            if !full.is_empty() && seen.insert(full.to_lowercase()) {
                names.push(full);
            }
        }
        clip(&names.join(", "), 4000)
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawDoc {
    #[serde(deserialize_with = "nullable")]
    document: RawDocument,
    #[serde(deserialize_with = "nullable")]
    product_tree: RawProductTree,
    #[serde(deserialize_with = "list")]
    vulnerabilities: Vec<RawVuln>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawDocument {
    #[serde(deserialize_with = "lenient")]
    csaf_version: String,
    #[serde(deserialize_with = "lenient")]
    lang: String,
    #[serde(deserialize_with = "lenient")]
    title: String,
    #[serde(deserialize_with = "nullable")]
    publisher: RawPublisher,
    #[serde(deserialize_with = "nullable")]
    aggregate_severity: RawSeverity,
    #[serde(deserialize_with = "nullable")]
    distribution: RawDistribution,
    #[serde(deserialize_with = "list")]
    notes: Vec<RawNote>,
    #[serde(deserialize_with = "list")]
    references: Vec<RawRef>,
    #[serde(deserialize_with = "nullable")]
    tracking: RawTracking,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawSeverity {
    #[serde(deserialize_with = "lenient")]
    text: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawDistribution {
    #[serde(deserialize_with = "nullable")]
    tlp: RawTlp,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawTlp {
    #[serde(deserialize_with = "lenient")]
    label: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawNote {
    #[serde(deserialize_with = "lenient")]
    category: String,
    #[serde(deserialize_with = "lenient")]
    title: String,
    #[serde(deserialize_with = "lenient")]
    text: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawRef {
    #[serde(deserialize_with = "lenient")]
    category: String,
    #[serde(deserialize_with = "lenient")]
    summary: String,
    #[serde(deserialize_with = "lenient")]
    url: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawTracking {
    #[serde(deserialize_with = "lenient")]
    id: String,
    #[serde(deserialize_with = "lenient")]
    status: String,
    #[serde(deserialize_with = "lenient")]
    version: String,
    #[serde(deserialize_with = "lenient")]
    initial_release_date: String,
    #[serde(deserialize_with = "lenient")]
    current_release_date: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawProductTree {
    #[serde(deserialize_with = "list")]
    branches: Vec<RawBranch>,
    #[serde(deserialize_with = "list")]
    full_product_names: Vec<RawFullName>,
    #[serde(deserialize_with = "list")]
    relationships: Vec<RawRelationship>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawBranch {
    #[serde(deserialize_with = "lenient")]
    category: String,
    #[serde(deserialize_with = "lenient")]
    name: String,
    #[serde(deserialize_with = "list")]
    branches: Vec<RawBranch>,
    #[serde(deserialize_with = "nullable")]
    product: Option<RawFullName>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawFullName {
    #[serde(deserialize_with = "lenient")]
    name: String,
    #[serde(deserialize_with = "lenient")]
    product_id: String,
    #[serde(deserialize_with = "nullable")]
    product_identification_helper: RawHelper,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawHelper {
    #[serde(deserialize_with = "lenient")]
    cpe: String,
    #[serde(deserialize_with = "lenient")]
    purl: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawRelationship {
    #[serde(deserialize_with = "lenient")]
    product_reference: String,
    #[serde(deserialize_with = "nullable")]
    full_product_name: RawFullName,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawVuln {
    #[serde(deserialize_with = "lenient")]
    cve: String,
    #[serde(deserialize_with = "nullable")]
    product_status: RawStatus,
    #[serde(deserialize_with = "list")]
    scores: Vec<RawScore>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawStatus {
    #[serde(deserialize_with = "ids")]
    first_affected: Vec<String>,
    #[serde(deserialize_with = "ids")]
    known_affected: Vec<String>,
    #[serde(deserialize_with = "ids")]
    last_affected: Vec<String>,
    #[serde(deserialize_with = "ids")]
    under_investigation: Vec<String>,
    #[serde(deserialize_with = "ids")]
    first_fixed: Vec<String>,
    #[serde(deserialize_with = "ids")]
    fixed: Vec<String>,
    #[serde(deserialize_with = "ids")]
    recommended: Vec<String>,
    #[serde(deserialize_with = "ids")]
    known_not_affected: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawScore {
    #[serde(deserialize_with = "nullable")]
    cvss_v3: RawCvss,
    #[serde(deserialize_with = "nullable")]
    cvss_v2: RawCvss,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawCvss {
    #[serde(rename = "baseScore")]
    base_score: Option<f64>,
}

/// A list of product ids: strings only, anything else is dropped.
fn ids<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    Ok(super::list::<D, MaybeId>(d)?
        .into_iter()
        .filter_map(|m| m.0)
        .collect())
}

/// A product id, or anything else in its place (skipped without building it).
struct MaybeId(Option<String>);

impl<'de> Deserialize<'de> for MaybeId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::{IgnoredAny, MapAccess, SeqAccess, Visitor};
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = MaybeId;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a product id")
            }
            fn visit_str<E>(self, v: &str) -> Result<MaybeId, E> {
                Ok(MaybeId(Some(v.to_owned())))
            }
            fn visit_string<E>(self, v: String) -> Result<MaybeId, E> {
                Ok(MaybeId(Some(v)))
            }
            fn visit_bool<E>(self, _: bool) -> Result<MaybeId, E> {
                Ok(MaybeId(None))
            }
            fn visit_i64<E>(self, _: i64) -> Result<MaybeId, E> {
                Ok(MaybeId(None))
            }
            fn visit_u64<E>(self, _: u64) -> Result<MaybeId, E> {
                Ok(MaybeId(None))
            }
            fn visit_f64<E>(self, _: f64) -> Result<MaybeId, E> {
                Ok(MaybeId(None))
            }
            fn visit_unit<E>(self) -> Result<MaybeId, E> {
                Ok(MaybeId(None))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<MaybeId, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(MaybeId(None))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<MaybeId, A::Error> {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(MaybeId(None))
            }
        }
        d.deserialize_any(V)
    }
}

/// The severity band of the publisher's word (German or English), if it is one we know.
pub fn band_of_text(text: &str) -> Option<&'static str> {
    match text.trim().to_lowercase().as_str() {
        "kritisch" | "critical" => Some("critical"),
        "hoch" | "high" | "important" | "wichtig" => Some("high"),
        "mittel" | "medium" | "moderate" => Some("medium"),
        "niedrig" | "low" | "gering" => Some("low"),
        _ => None,
    }
}

/// The severity band of a CVSS score (the CVSS 3 bands).
pub fn band_of_score(score: f64) -> &'static str {
    match score {
        s if s >= 9.0 => "critical",
        s if s >= 7.0 => "high",
        s if s >= 4.0 => "medium",
        s if s > 0.0 => "low",
        _ => "",
    }
}

/// Status rank: when several vulnerabilities give one product different statuses, the strongest wins.
fn rank(status: &str) -> u8 {
    match status {
        "affected" => 5,
        "investigating" => 4,
        "fixed" => 3,
        "recommended" => 2,
        "not_affected" => 1,
        _ => 0,
    }
}

/// Vendor and product from a CPE (`cpe:2.3:a:vendor:product:…` or `cpe:/a:vendor:product:…`).
pub fn cpe_names(cpe: &str) -> Option<(String, String)> {
    let rest = cpe
        .strip_prefix("cpe:2.3:")
        .or_else(|| cpe.strip_prefix("cpe:/"))?;
    let mut parts = rest.split(':');
    let _part = parts.next()?;
    let vendor = parts.next()?.replace('\\', "");
    let product = parts.next()?.replace('\\', "");
    let real = |s: &str| !s.is_empty() && s != "*" && s != "-";
    (real(&vendor) && real(&product)).then_some((vendor, product))
}

/// Where a branch of the product tree stands: the names collected on the way down.
#[derive(Debug, Clone, Default)]
struct Path {
    vendor: String,
    family: String,
    product: String,
    version: String,
    range: bool,
}

fn product_of(full: &RawFullName, path: &Path) -> Option<Product> {
    let id = full.product_id.trim();
    if id.is_empty() {
        return None;
    }
    let helper = &full.product_identification_helper;
    let cpe = clip(helper.cpe.trim(), 500);
    let mut vendor = path.vendor.trim().to_owned();
    let mut product = if path.product.trim().is_empty() {
        path.family.trim().to_owned()
    } else {
        path.product.trim().to_owned()
    };
    if (vendor.is_empty() || product.is_empty())
        && let Some((v, p)) = cpe_names(&cpe)
    {
        if vendor.is_empty() {
            vendor = v;
        }
        if product.is_empty() {
            product = p;
        }
    }
    let name = clip(full.name.trim(), 500);
    if product.is_empty() {
        product.clone_from(&name);
    }
    Some(Product {
        id: clip(id, 200),
        vendor_name: clip(&vendor, 200),
        product_name: clip(&product, 300),
        name,
        version: clip(path.version.trim(), 200),
        version_range: path.range,
        cpe,
        purl: clip(helper.purl.trim(), 500),
        status: "",
    })
}

fn walk(branch: &RawBranch, path: &Path, out: &mut Vec<Product>, seen: &mut HashSet<String>) {
    let mut path = path.clone();
    let name = branch.name.trim();
    match branch.category.as_str() {
        "vendor" => path.vendor = name.to_owned(),
        "product_family" => path.family = name.to_owned(),
        "product_name" => path.product = name.to_owned(),
        "product_version" => (path.version, path.range) = (name.to_owned(), false),
        "product_version_range" => (path.version, path.range) = (name.to_owned(), true),
        _ => {}
    }
    if let Some(product) = branch.product.as_ref().and_then(|f| product_of(f, &path))
        && seen.insert(product.id.clone())
    {
        out.push(product);
    }
    for b in &branch.branches {
        walk(b, &path, out, seen);
    }
}

/// Reads a CSAF document. The error says why it was refused (shown on the sources page).
pub fn parse(bytes: &[u8]) -> Result<Advisory, String> {
    let raw: RawDoc = with_budget(MAX_ELEMENTS, || serde_json::from_slice(bytes))
        .map_err(|e| format!("not valid JSON: {e}"))?;
    let doc = raw.document;
    if !doc.csaf_version.trim().starts_with("2.") {
        return Err("not a CSAF 2 document".to_owned());
    }
    let tracking_id = clip(doc.tracking.id.trim(), 200);
    if tracking_id.is_empty() {
        return Err("the document has no tracking id".to_owned());
    }
    let tlp = doc.distribution.tlp.label.trim().to_ascii_uppercase();
    if !public_tlp(&tlp) {
        return Err(if tlp.is_empty() {
            "the document carries no TLP label".to_owned()
        } else {
            format!("the document is TLP:{}", clip(&tlp, 20))
        });
    }

    // References: BSI names its portal page "WID-SEC-2026-4365 - Portal Version"; its id is what people use.
    let refs: Vec<Reference> = doc
        .references
        .iter()
        .filter(|r| {
            let url = r.url.trim();
            url.starts_with("https://") || url.starts_with("http://")
        })
        .take(MAX_REFS)
        .map(|r| Reference {
            category: clip(r.category.trim(), 40),
            summary: clip(r.summary.trim(), 500),
            url: clip(r.url.trim(), 1000),
        })
        .collect();
    let portal = refs.iter().find_map(|r| {
        let id = r.summary.strip_suffix("- Portal Version")?.trim();
        (r.category == "self" && !id.is_empty() && id.len() <= 100)
            .then(|| (id.to_owned(), r.url.clone()))
    });
    let (display_id, web_url) = match portal {
        Some((id, url)) => (id, url),
        None => {
            let page = refs
                .iter()
                .find(|r| {
                    r.category == "self"
                        && r.url.starts_with("https://")
                        && !r.url.to_ascii_lowercase().ends_with(".json")
                })
                .map(|r| r.url.clone())
                .unwrap_or_default();
            (tracking_id.clone(), page)
        }
    };

    let note = |category: &str| {
        doc.notes
            .iter()
            .find(|n| n.category == category && !n.text.trim().is_empty())
            .map(|n| clip(n.text.trim(), 4000))
    };
    let summary = note("summary")
        .or_else(|| note("description"))
        .unwrap_or_default();
    let notes = doc
        .notes
        .iter()
        .filter(|n| n.category != "legal_disclaimer" && !n.text.trim().is_empty())
        .take(MAX_NOTES)
        .map(|n| Note {
            category: clip(n.category.trim(), 40),
            title: clip(n.title.trim(), 200),
            text: clip(n.text.trim(), 20_000),
        })
        .collect();

    // Products: the branches, the full product names and the relationships (component on platform).
    let tree = raw.product_tree;
    let mut products = Vec::new();
    let mut seen = HashSet::new();
    for b in &tree.branches {
        walk(b, &Path::default(), &mut products, &mut seen);
    }
    for f in &tree.full_product_names {
        if let Some(p) = product_of(f, &Path::default())
            && seen.insert(p.id.clone())
        {
            products.push(p);
        }
    }
    let by_id: HashMap<String, usize> = products
        .iter()
        .enumerate()
        .map(|(i, p)| (p.id.clone(), i))
        .collect();
    for r in &tree.relationships {
        let full = &r.full_product_name;
        let Some(base) = by_id
            .get(r.product_reference.trim())
            .map(|&i| products[i].clone())
        else {
            continue;
        };
        let Some(mut p) = product_of(full, &Path::default()) else {
            continue;
        };
        if !seen.insert(p.id.clone()) {
            continue;
        }
        p.vendor_name = base.vendor_name;
        p.product_name = base.product_name;
        p.version = base.version;
        p.version_range = base.version_range;
        if p.cpe.is_empty() {
            p.cpe = base.cpe;
        }
        if p.purl.is_empty() {
            p.purl = base.purl;
        }
        products.push(p);
    }

    // Vulnerabilities: CVEs, the status of every product, the highest CVSS score.
    let mut status: HashMap<&str, &'static str> = HashMap::new();
    let mut cves = Vec::new();
    let mut cve_seen = HashSet::new();
    let (mut v3, mut v2): (Option<f64>, Option<f64>) = (None, None);
    for v in &raw.vulnerabilities {
        let cve = v.cve.trim();
        if is_cve_id(cve) && cves.len() < MAX_CVES && cve_seen.insert(cve.to_owned()) {
            cves.push(cve.to_owned());
        }
        let s = &v.product_status;
        for (list, name) in [
            (&s.first_affected, "affected"),
            (&s.known_affected, "affected"),
            (&s.last_affected, "affected"),
            (&s.under_investigation, "investigating"),
            (&s.first_fixed, "fixed"),
            (&s.fixed, "fixed"),
            (&s.recommended, "recommended"),
            (&s.known_not_affected, "not_affected"),
        ] {
            for id in list {
                let entry = status.entry(id.trim()).or_insert(name);
                if rank(name) > rank(entry) {
                    *entry = name;
                }
            }
        }
        for score in &v.scores {
            let valid = |s: Option<f64>| s.filter(|s| (0.0..=10.0).contains(s));
            if let Some(s) = valid(score.cvss_v3.base_score) {
                v3 = Some(v3.map_or(s, |m| m.max(s)));
            }
            if let Some(s) = valid(score.cvss_v2.base_score) {
                v2 = Some(v2.map_or(s, |m| m.max(s)));
            }
        }
    }
    for p in &mut products {
        if let Some(s) = status.get(p.id.as_str()) {
            p.status = s;
        }
    }
    // Keep the products with a status first when there are too many.
    let products_cut = products.len().saturating_sub(MAX_PRODUCTS);
    if products_cut > 0 {
        products.sort_by_key(|p| std::cmp::Reverse(rank(p.status)));
        products.truncate(MAX_PRODUCTS);
    }

    let cvss_score = v3.or(v2);
    let severity_text = clip(doc.aggregate_severity.text.trim(), 60);
    let severity = band_of_text(&severity_text)
        .or_else(|| cvss_score.map(band_of_score))
        .unwrap_or("");
    let published_ms = parse_time_ms(&doc.tracking.initial_release_date);
    let updated_ms = parse_time_ms(&doc.tracking.current_release_date).or(published_ms);
    Ok(Advisory {
        tracking_id,
        display_id: clip(&display_id, 100),
        publisher: clip(doc.publisher.name.trim(), 200),
        title: clip(doc.title.trim(), 500),
        summary,
        lang: clip(doc.lang.trim(), 20),
        tlp,
        severity,
        severity_text,
        cvss_score,
        status: clip(doc.tracking.status.trim(), 20),
        version: clip(doc.tracking.version.trim(), 40),
        published_ms,
        updated_ms,
        web_url,
        notes,
        refs,
        cves,
        products,
        products_cut,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A shortened BSI document (WID-SEC-W-2026-4365), as the feed delivers it.
    pub const BSI_DOC: &str = r#"{
      "document": {
        "aggregate_severity": {"text": "hoch"},
        "category": "csaf_base", "csaf_version": "2.0",
        "distribution": {"tlp": {"label": "WHITE", "url": "https://www.first.org/tlp/"}},
        "lang": "de-DE",
        "notes": [
          {"category": "legal_disclaimer", "text": "Das BSI ist als Anbieter …"},
          {"category": "description", "text": "OpenSSH ist eine Open Source Implementierung des Secure Shell Protokolls.", "title": "Produktbeschreibung"},
          {"category": "summary", "text": "Ein entfernter, anonymer Angreifer kann eine Schwachstelle in OpenSSH ausnutzen, um beliebigen Programmcode auszuführen.", "title": "Angriff"},
          {"category": "general", "text": "- Linux", "title": null}
        ],
        "publisher": {"category": "other", "name": "Bundesamt für Sicherheit in der Informationstechnik", "namespace": "https://www.bsi.bund.de"},
        "references": [
          {"category": "self", "summary": "WID-SEC-W-2026-4365 - CSAF Version", "url": "https://wid.cert-bund.de/.well-known/csaf/white/2026/wid-sec-w-2026-4365.json"},
          {"category": "self", "summary": "WID-SEC-2026-4365 - Portal Version", "url": "https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4365"},
          {"category": "external", "summary": "OpenSSH Release Notes vom 2026-11-05", "url": "https://www.openssh.org/releasenotes.html#10.6p2"},
          {"category": "external", "summary": "kaputt", "url": "javascript:alert(1)"}
        ],
        "source_lang": "en-US",
        "title": "OpenSSH: Schwachstelle ermöglicht Codeausführung",
        "tracking": {
          "current_release_date": "2026-11-05T23:00:00.000+00:00",
          "id": "WID-SEC-W-2026-4365",
          "initial_release_date": "2026-11-05T23:00:00.000+00:00",
          "status": "final", "version": "1"
        }
      },
      "product_tree": {
        "branches": [{"category": "vendor", "name": "Open Source", "branches": [
          {"category": "product_name", "name": "Open Source Alpine Linux",
           "product": {"name": "Open Source Alpine Linux", "product_id": "T062555"}},
          {"category": "product_name", "name": "OpenSSH", "branches": [
            {"category": "product_version_range", "name": "<10.6p2",
             "product": {"name": "Open Source OpenSSH <10.6p2", "product_id": "T062554"}},
            {"category": "product_version", "name": "10.6p2",
             "product": {"name": "Open Source OpenSSH 10.6p2", "product_id": "T062554-fixed",
                         "product_identification_helper": {"cpe": "cpe:/a:openbsd:openssh:10.6p2"}}}
          ]}
        ]}]
      },
      "vulnerabilities": [
        {"cve": "CVE-2026-123158", "product_status": {"known_affected": ["T062554", "T062555"]},
         "release_date": "2026-11-05T23:00:00.000+00:00", "title": "CVE-2026-123158"}
      ]
    }"#;

    #[test]
    fn a_bsi_document_is_read() {
        let a = parse(BSI_DOC.as_bytes()).unwrap();
        assert_eq!(a.tracking_id, "WID-SEC-W-2026-4365");
        assert_eq!(a.display_id, "WID-SEC-2026-4365");
        assert_eq!(
            a.web_url,
            "https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4365"
        );
        assert_eq!(a.title, "OpenSSH: Schwachstelle ermöglicht Codeausführung");
        assert!(a.summary.starts_with("Ein entfernter, anonymer Angreifer"));
        assert_eq!((a.severity, a.severity_text.as_str()), ("high", "hoch"));
        assert_eq!(a.cvss_score, None);
        assert_eq!(a.tlp, "WHITE");
        assert_eq!(a.lang, "de-DE");
        assert_eq!(a.published_ms, Some(1_793_919_600_000));
        assert_eq!(a.updated_ms, a.published_ms);
        assert_eq!(a.cves, ["CVE-2026-123158"]);
        assert_eq!(a.notes.len(), 3, "without the legal disclaimer");
        assert_eq!(a.refs.len(), 3, "without the javascript: link");

        let ids: Vec<_> = a
            .products
            .iter()
            .map(|p| (p.id.as_str(), p.status))
            .collect();
        assert_eq!(
            ids,
            [
                ("T062555", "affected"),
                ("T062554", "affected"),
                ("T062554-fixed", "")
            ]
        );
        let ssh = &a.products[1];
        assert_eq!(
            (
                ssh.vendor_name.as_str(),
                ssh.product_name.as_str(),
                ssh.version.as_str()
            ),
            ("Open Source", "OpenSSH", "<10.6p2")
        );
        assert!(ssh.version_range);
        let fixed = &a.products[2];
        assert_eq!(
            (fixed.version.as_str(), fixed.version_range),
            ("10.6p2", false)
        );
        assert_eq!(fixed.cpe, "cpe:/a:openbsd:openssh:10.6p2");
        assert_eq!(
            a.products_text(),
            "Open Source Alpine Linux, Open Source OpenSSH"
        );
    }

    #[test]
    fn documents_that_are_not_public_or_not_csaf_are_refused() {
        let green = BSI_DOC.replace(r#""label": "WHITE""#, r#""label": "GREEN""#);
        assert_eq!(
            parse(green.as_bytes()).unwrap_err(),
            "the document is TLP:GREEN"
        );
        let clear = BSI_DOC.replace(r#""label": "WHITE""#, r#""label": "CLEAR""#);
        assert!(parse(clear.as_bytes()).is_ok());
        let none = BSI_DOC.replace(r#""label": "WHITE""#, r#""label": null"#);
        assert!(parse(none.as_bytes()).unwrap_err().contains("no TLP"));
        let old = BSI_DOC.replace(r#""csaf_version": "2.0""#, r#""csaf_version": "1.2""#);
        assert!(parse(old.as_bytes()).is_err());
        let no_id = BSI_DOC.replace(r#""id": "WID-SEC-W-2026-4365""#, r#""id": """#);
        assert!(parse(no_id.as_bytes()).is_err());
        assert!(parse(b"not json").is_err());
    }

    #[test]
    fn vendor_documents_with_relationships_scores_and_statuses() {
        let doc = r#"{
          "document": {"csaf_version": "2.0", "title": "Important: openssh security update", "lang": "en",
            "publisher": {"name": "Red Hat Product Security"},
            "aggregate_severity": {"text": "Important"},
            "distribution": {"tlp": {"label": "WHITE"}},
            "notes": [{"category": "summary", "text": "An update for openssh is now available."}],
            "references": [
              {"category": "self", "summary": "https://access.redhat.com/errata/RHSA-2026:1", "url": "https://access.redhat.com/errata/RHSA-2026:1"},
              {"category": "self", "summary": "Canonical URL", "url": "https://security.access.redhat.com/data/csaf/v2/advisories/2026/rhsa-2026_1.json"}
            ],
            "tracking": {"id": "RHSA-2026:1", "status": "final", "version": 3,
                         "initial_release_date": "2026-01-02T00:00:00Z", "current_release_date": "2026-02-03T00:00:00Z"}},
          "product_tree": {
            "branches": [{"category": "vendor", "name": "Red Hat", "branches": [
              {"category": "product_family", "name": "Red Hat Enterprise Linux", "branches": [
                {"category": "product_name", "name": "Red Hat Enterprise Linux 9",
                 "product": {"name": "Red Hat Enterprise Linux 9", "product_id": "BaseOS-9",
                             "product_identification_helper": {"cpe": "cpe:/o:redhat:enterprise_linux:9::baseos"}}}]},
              {"category": "product_version", "name": "openssh-0:8.7p1-38.el9.x86_64",
               "product": {"name": "openssh-0:8.7p1-38.el9.x86_64", "product_id": "openssh-0:8.7p1-38.el9.x86_64",
                           "product_identification_helper": {"purl": "pkg:rpm/redhat/openssh@8.7p1-38.el9?arch=x86_64"}}}
            ]}],
            "full_product_names": [{"name": "Lonely Product", "product_id": "LP-1",
                                    "product_identification_helper": {"cpe": "cpe:2.3:a:acme:lonely:1.0:*:*:*:*:*:*:*"}}],
            "relationships": [{"category": "default_component_of",
              "full_product_name": {"name": "openssh-0:8.7p1-38.el9.x86_64 as a component of Red Hat Enterprise Linux 9",
                                    "product_id": "BaseOS-9:openssh-0:8.7p1-38.el9.x86_64"},
              "product_reference": "openssh-0:8.7p1-38.el9.x86_64", "relates_to_product_reference": "BaseOS-9"},
              {"category": "default_component_of", "full_product_name": {"name": "x", "product_id": "dangling"},
               "product_reference": "missing"}]
          },
          "vulnerabilities": [
            {"cve": "CVE-2026-1111", "scores": [{"cvss_v3": {"baseScore": 8.1}, "products": []}],
             "product_status": {"fixed": ["BaseOS-9:openssh-0:8.7p1-38.el9.x86_64"], "known_not_affected": ["LP-1"]}},
            {"cve": "CVE-2026-2222", "scores": [{"cvss_v3": {"baseScore": 99}}, {"cvss_v2": {"baseScore": 5.0}}],
             "product_status": {"known_affected": ["LP-1", 7], "under_investigation": null}},
            {"cve": "not-a-cve"}
          ]
        }"#;
        let a = parse(doc.as_bytes()).unwrap();
        assert_eq!(a.display_id, "RHSA-2026:1");
        assert_eq!(a.web_url, "https://access.redhat.com/errata/RHSA-2026:1");
        assert_eq!(a.version, "3", "a number is read as text");
        assert_eq!((a.severity, a.cvss_score), ("high", Some(8.1)));
        assert_eq!(a.cves, ["CVE-2026-1111", "CVE-2026-2222"]);
        assert_eq!(a.updated_ms, parse_time_ms("2026-02-03T00:00:00Z"));
        let by_id = |id: &str| a.products.iter().find(|p| p.id == id).unwrap();
        let rel = by_id("BaseOS-9:openssh-0:8.7p1-38.el9.x86_64");
        assert_eq!(rel.status, "fixed");
        assert_eq!(rel.vendor_name, "Red Hat");
        assert_eq!(rel.version, "openssh-0:8.7p1-38.el9.x86_64");
        assert!(rel.purl.starts_with("pkg:rpm/redhat/openssh@"));
        let rhel = by_id("BaseOS-9");
        assert_eq!(rhel.product_name, "Red Hat Enterprise Linux 9");
        let lonely = by_id("LP-1");
        assert_eq!(
            (lonely.vendor_name.as_str(), lonely.product_name.as_str()),
            ("acme", "lonely")
        );
        assert_eq!(lonely.status, "affected", "affected beats not affected");
        assert!(a.products.iter().all(|p| p.id != "dangling"));
    }

    #[test]
    fn severity_bands() {
        assert_eq!(band_of_text("Kritisch"), Some("critical"));
        assert_eq!(band_of_text("moderate"), Some("medium"));
        assert_eq!(band_of_text("niedrig"), Some("low"));
        assert_eq!(band_of_text("unbekannt"), None);
        assert_eq!(band_of_score(9.8), "critical");
        assert_eq!(band_of_score(7.0), "high");
        assert_eq!(band_of_score(4.3), "medium");
        assert_eq!(band_of_score(0.1), "low");
        assert_eq!(band_of_score(0.0), "");
        assert_eq!(
            cpe_names("cpe:2.3:o:avm:fritz\\!os:8.20:*:*:*:*:*:*:*"),
            Some(("avm".into(), "fritz!os".into()))
        );
        assert_eq!(cpe_names("cpe:/a:*:x"), None);
        assert_eq!(cpe_names("nonsense"), None);
    }

    #[test]
    fn too_many_products_keep_those_with_a_status() {
        let mut branches = Vec::new();
        for i in 0..MAX_PRODUCTS + 10 {
            branches.push(format!(
                r#"{{"category": "product_name", "name": "P{i}", "product": {{"name": "P{i}", "product_id": "P{i}"}}}}"#
            ));
        }
        let last = MAX_PRODUCTS + 9;
        let doc = format!(
            r#"{{"document": {{"csaf_version": "2.0", "distribution": {{"tlp": {{"label": "WHITE"}}}},
                "tracking": {{"id": "X-1"}}}},
               "product_tree": {{"branches": [{}]}},
               "vulnerabilities": [{{"product_status": {{"known_affected": ["P{last}"]}}}}]}}"#,
            branches.join(",")
        );
        let a = parse(doc.as_bytes()).unwrap();
        assert_eq!(a.products.len(), MAX_PRODUCTS);
        assert_eq!(a.products_cut, 10);
        assert_eq!(a.products[0].id, format!("P{last}"));
    }
}
