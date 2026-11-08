//! A reader for CSAF 2.0 providers: the provider metadata, ROLIE feeds, `changes.csv` of directory
//! distributions, the checksum files and (in [`document`]) the documents themselves.
//!
//! Everything here parses data from foreign servers: strictly, with limits, and without following anything it
//! says beyond the documented links. Only distributions labelled TLP:WHITE or TLP:CLEAR are kept.

pub mod document;

use serde::{Deserialize, Deserializer, Serialize};
use sha2::Digest;

/// Most distributions kept from one provider metadata file.
const MAX_DISTRIBUTIONS: usize = 50;
/// Most documents read from one feed or `changes.csv` (BSI's largest feed has about 15,000).
pub const MAX_ENTRIES: usize = 500_000;
/// Longest URL accepted from a provider.
const MAX_URL: usize = 1_000;

/// Accepts a string, a number, `null` or a missing value (CSAF producers are not all strict about types).
pub(crate) fn lenient<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Ok(match Option::<serde_json::Value>::deserialize(d)? {
        Some(serde_json::Value::String(s)) => s,
        Some(serde_json::Value::Number(n)) => n.to_string(),
        _ => String::new(),
    })
}

/// Accepts `null` for a structure or list and uses its default.
pub(crate) fn nullable<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

thread_local! {
    /// How many more list elements the running parse may build (see [`with_budget`]).
    static BUDGET: std::cell::Cell<usize> = const { std::cell::Cell::new(usize::MAX) };
}

/// Runs a parse that may build at most `elements` list elements in all ([`list`] counts them): JSON of a
/// few bytes per element (`{}`) must not grow into gigabytes of structures before any limit is checked.
pub(crate) fn with_budget<T>(elements: usize, parse: impl FnOnce() -> T) -> T {
    BUDGET.set(elements);
    let out = parse();
    BUDGET.set(usize::MAX);
    out
}

/// A list (`null` = empty) whose elements count against the budget of [`with_budget`].
pub(crate) fn list<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Elements<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Elements<T> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a list or null")
        }
        fn visit_unit<E>(self) -> Result<Vec<T>, E> {
            Ok(Vec::new())
        }
        fn visit_none<E>(self) -> Result<Vec<T>, E> {
            Ok(Vec::new())
        }
        fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Vec<T>, D::Error> {
            d.deserialize_seq(self)
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
            let mut out = Vec::new();
            loop {
                let left = BUDGET.get();
                if left == 0 {
                    return Err(serde::de::Error::custom("too many list elements"));
                }
                match seq.next_element()? {
                    Some(e) => {
                        BUDGET.set(left - 1);
                        out.push(e);
                    }
                    None => return Ok(out),
                }
            }
        }
    }
    d.deserialize_option(Elements(std::marker::PhantomData))
}

/// Whether a TLP label may be loaded: only the public ones.
pub fn public_tlp(label: &str) -> bool {
    matches!(
        label.trim().to_ascii_uppercase().as_str(),
        "WHITE" | "CLEAR"
    )
}

/// An HTTPS URL of sane length without spaces or control characters. (The tests also accept their local
/// server, `http://127.0.0.1:…`.)
pub fn https_url(url: &str) -> Option<String> {
    let url = url.trim();
    let scheme_ok = url
        .get(..8)
        .is_some_and(|s| s.eq_ignore_ascii_case("https://"))
        || (cfg!(test) && url.starts_with("http://127.0.0.1:"));
    (url.len() <= MAX_URL
        && url.len() > "https://".len()
        && scheme_ok
        && !url.chars().any(|c| c.is_whitespace() || c.is_control()))
    .then(|| url.to_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DistKind {
    Rolie,
    Directory,
}

/// One place where a provider publishes documents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Distribution {
    pub kind: DistKind,
    pub url: String,
    /// TLP label of a ROLIE feed (directories carry none; their documents are checked one by one).
    #[serde(default)]
    pub tlp: String,
    /// What the provider calls it (ROLIE: the feed summary).
    #[serde(default)]
    pub summary: String,
}

/// What a provider-metadata.json says about the provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    pub name: String,
    pub namespace: String,
    pub role: String,
    pub distributions: Vec<Distribution>,
    /// Feeds left out because they are not TLP:WHITE/CLEAR (only counted).
    pub restricted: usize,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawMetadata {
    #[serde(deserialize_with = "lenient")]
    role: String,
    #[serde(deserialize_with = "nullable")]
    publisher: RawPublisher,
    #[serde(deserialize_with = "list")]
    distributions: Vec<RawDistribution>,
    #[serde(deserialize_with = "lenient")]
    canonical_url: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub(crate) struct RawPublisher {
    #[serde(deserialize_with = "lenient")]
    pub name: String,
    #[serde(deserialize_with = "lenient")]
    pub namespace: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawDistribution {
    #[serde(deserialize_with = "lenient")]
    directory_url: String,
    #[serde(deserialize_with = "nullable")]
    rolie: RawRolie,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawRolie {
    #[serde(deserialize_with = "list")]
    feeds: Vec<RawFeedRef>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawFeedRef {
    #[serde(deserialize_with = "lenient")]
    summary: String,
    #[serde(deserialize_with = "lenient")]
    tlp_label: String,
    #[serde(deserialize_with = "lenient")]
    url: String,
}

/// Reads a provider-metadata.json.
/// A directory distribution whose path names a restricted TLP level (`…/green/`, `…/tlp-amber/`).
fn restricted_dir(url: &str) -> bool {
    url.trim_end_matches('/')
        .rsplit('/')
        .take(2)
        .any(|segment| {
            let s = segment.to_ascii_lowercase();
            let s = s
                .strip_prefix("tlp")
                .map_or(s.as_str(), |r| r.trim_start_matches(['-', '_', ':']));
            matches!(s, "green" | "amber" | "amber+strict" | "red")
        })
}

pub fn parse_metadata(bytes: &[u8]) -> Result<Metadata, String> {
    let raw: RawMetadata = serde_json::from_slice(bytes)
        .map_err(|e| format!("the provider metadata is not valid JSON: {e}"))?;
    if raw.canonical_url.trim().is_empty() && raw.publisher.name.trim().is_empty() {
        return Err("this is not a CSAF provider metadata file".to_owned());
    }
    let mut distributions = Vec::new();
    let mut restricted = 0;
    for d in raw.distributions {
        // A directory carries no TLP label; one named like a restricted level is not loaded at all.
        if let Some(url) = https_url(&d.directory_url) {
            if restricted_dir(&url) {
                restricted += 1;
            } else {
                distributions.push(Distribution {
                    kind: DistKind::Directory,
                    url: url.trim_end_matches('/').to_owned(),
                    tlp: String::new(),
                    summary: String::new(),
                });
            }
        }
        for feed in d.rolie.feeds {
            let Some(url) = https_url(&feed.url) else {
                continue;
            };
            if !public_tlp(&feed.tlp_label) {
                restricted += 1;
                continue;
            }
            distributions.push(Distribution {
                kind: DistKind::Rolie,
                url,
                tlp: feed.tlp_label.trim().to_ascii_uppercase(),
                summary: crate::sources::cve5::clip(feed.summary.trim(), 200),
            });
        }
    }
    let mut seen = std::collections::HashSet::new();
    distributions.retain(|d| seen.insert(d.url.clone()));
    distributions.truncate(MAX_DISTRIBUTIONS);
    if distributions.is_empty() {
        return Err(if restricted > 0 {
            "the provider publishes no TLP:WHITE documents".to_owned()
        } else {
            "the provider metadata names no distribution".to_owned()
        });
    }
    Ok(Metadata {
        name: crate::sources::cve5::clip(raw.publisher.name.trim(), 200),
        namespace: crate::sources::cve5::clip(raw.publisher.namespace.trim(), 200),
        role: crate::sources::cve5::clip(raw.role.trim(), 60),
        distributions,
        restricted,
    })
}

/// One document a feed or `changes.csv` names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocRef {
    pub url: String,
    /// The time the feed gives for the current version (compared as text with the stored one).
    pub updated: String,
    /// Checksum file named by the feed (ROLIE `rel="hash"`); directories use `<url>.sha512`/`.sha256`.
    pub hash_url: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawFeedFile {
    #[serde(deserialize_with = "nullable")]
    feed: RawFeed,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawFeed {
    #[serde(deserialize_with = "list")]
    entry: Vec<RawEntry>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawEntry {
    #[serde(deserialize_with = "lenient")]
    updated: String,
    #[serde(deserialize_with = "list")]
    link: Vec<RawLink>,
    #[serde(deserialize_with = "nullable")]
    content: RawContent,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawLink {
    #[serde(deserialize_with = "lenient")]
    rel: String,
    #[serde(deserialize_with = "lenient")]
    href: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawContent {
    #[serde(deserialize_with = "lenient")]
    src: String,
}

/// Reads a ROLIE feed: the documents with their `updated` time and checksum link.
pub fn parse_rolie(bytes: &[u8]) -> Result<Vec<DocRef>, String> {
    // An entry has a few links: room for MAX_ENTRIES entries.
    let raw: RawFeedFile = with_budget(4 * MAX_ENTRIES, || serde_json::from_slice(bytes))
        .map_err(|e| format!("the ROLIE feed is not valid JSON: {e}"))?;
    if raw.feed.entry.len() > MAX_ENTRIES {
        return Err(format!("the feed has more than {MAX_ENTRIES} entries"));
    }
    let mut docs = Vec::with_capacity(raw.feed.entry.len());
    for e in raw.feed.entry {
        let self_link = e
            .link
            .iter()
            .find(|l| l.rel == "self")
            .map(|l| l.href.as_str());
        let Some(url) = https_url(&e.content.src).or_else(|| self_link.and_then(https_url)) else {
            continue;
        };
        let hashes: Vec<String> = e
            .link
            .iter()
            .filter(|l| l.rel == "hash")
            .filter_map(|l| https_url(&l.href))
            .collect();
        let hash_url = hashes
            .iter()
            .find(|h| h.ends_with(".sha512"))
            .or_else(|| hashes.iter().find(|h| h.ends_with(".sha256")))
            .cloned();
        docs.push(DocRef {
            url,
            updated: crate::sources::cve5::clip(e.updated.trim(), 40),
            hash_url,
        });
    }
    Ok(docs)
}

/// Reads the `changes.csv` of a directory distribution (`"2026/x.json","2026-11-06T10:45:47+00:00"`); the
/// paths are relative to `base`. Lines that do not look right (absolute paths, `..`, no `.json`) are skipped.
pub fn parse_changes(text: &str, base: &str) -> Result<Vec<DocRef>, String> {
    let base = base.trim_end_matches('/');
    let mut docs = Vec::new();
    for line in text.lines() {
        let mut fields = line.split(',').map(|f| f.trim().trim_matches('"'));
        let (Some(path), Some(time)) = (fields.next(), fields.next()) else {
            continue;
        };
        let safe = !path.is_empty()
            && path.ends_with(".json")
            && !path.starts_with('/')
            && !path.contains("..")
            && !path.contains("://")
            && path
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "/-_.+".contains(c));
        if !safe || crate::sources::parse_time_ms(time).is_none() {
            continue;
        }
        let Some(url) = https_url(&format!("{base}/{path}")) else {
            continue;
        };
        if docs.len() >= MAX_ENTRIES {
            return Err(format!("changes.csv has more than {MAX_ENTRIES} entries"));
        }
        docs.push(DocRef {
            url,
            updated: crate::sources::cve5::clip(time, 40),
            hash_url: None,
        });
    }
    Ok(docs)
}

/// A checksum read from a `.sha256` or `.sha512` file (`<hex>  <file name>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Checksum {
    Sha256(Vec<u8>),
    Sha512(Vec<u8>),
}

impl Checksum {
    pub fn parse(text: &str) -> Option<Self> {
        let hex = text.split_whitespace().next()?;
        let bytes = decode_hex(hex)?;
        match bytes.len() {
            32 => Some(Self::Sha256(bytes)),
            64 => Some(Self::Sha512(bytes)),
            _ => None,
        }
    }

    /// Whether `data` has this checksum.
    pub fn matches(&self, data: &[u8]) -> bool {
        match self {
            Self::Sha256(want) => sha2::Sha256::digest(data).as_slice() == want.as_slice(),
            Self::Sha512(want) => sha2::Sha512::digest(data).as_slice() == want.as_slice(),
        }
    }
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) || hex.len() > 128 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect()
}

/// One provider of the BSI's list (aggregator.json).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub url: String,
    pub name: String,
    pub role: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawAggregator {
    #[serde(deserialize_with = "list")]
    csaf_providers: Vec<RawListed>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawListed {
    #[serde(deserialize_with = "nullable")]
    metadata: RawListedMetadata,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawListedMetadata {
    #[serde(deserialize_with = "nullable")]
    publisher: RawPublisher,
    #[serde(deserialize_with = "lenient")]
    role: String,
    #[serde(deserialize_with = "lenient")]
    url: String,
}

/// Reads a CSAF lister or aggregator file: the providers with the URL of their metadata.
pub fn parse_aggregator(bytes: &[u8]) -> Result<Vec<Listed>, String> {
    let raw: RawAggregator = serde_json::from_slice(bytes)
        .map_err(|e| format!("the provider list is not valid JSON: {e}"))?;
    let mut out: Vec<Listed> = raw
        .csaf_providers
        .into_iter()
        .filter_map(|p| {
            Some(Listed {
                url: https_url(&p.metadata.url)?,
                name: crate::sources::cve5::clip(p.metadata.publisher.name.trim(), 200),
                role: crate::sources::cve5::clip(p.metadata.role.trim(), 60),
            })
        })
        .take(1000)
        .collect();
    out.sort_by_key(|l| l.name.to_lowercase());
    out.dedup_by(|a, b| a.url == b.url);
    if out.is_empty() {
        return Err("the provider list names no provider".to_owned());
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const METADATA: &str = r#"{
      "canonical_url": "https://example.org/.well-known/csaf/provider-metadata.json",
      "publisher": {"name": "Example CERT", "namespace": "https://example.org", "category": "coordinator"},
      "role": "csaf_trusted_provider",
      "distributions": [
        {"rolie": {"feeds": [
          {"summary": "WHITE advisories", "tlp_label": "WHITE", "url": "https://example.org/white/feed.json"},
          {"summary": "GREEN advisories", "tlp_label": "GREEN", "url": "https://example.org/green/feed.json"},
          {"summary": "no https", "tlp_label": "CLEAR", "url": "http://example.org/clear/feed.json"}
        ]}},
        {"directory_url": "https://example.org/csaf/v2/advisories/"},
        {"directory_url": "https://example.org/csaf/v2/green/"},
        {"directory_url": "https://example.org/csaf/v2/tlp-amber/2026"},
        {"directory_url": null, "rolie": null}
      ]
    }"#;

    #[test]
    fn only_public_distributions_of_the_metadata_are_kept() {
        let m = parse_metadata(METADATA.as_bytes()).unwrap();
        assert_eq!(m.name, "Example CERT");
        assert_eq!(m.role, "csaf_trusted_provider");
        assert_eq!(m.restricted, 3, "a GREEN feed and two directories");
        assert_eq!(
            m.distributions,
            [
                Distribution {
                    kind: DistKind::Rolie,
                    url: "https://example.org/white/feed.json".into(),
                    tlp: "WHITE".into(),
                    summary: "WHITE advisories".into()
                },
                Distribution {
                    kind: DistKind::Directory,
                    url: "https://example.org/csaf/v2/advisories".into(),
                    tlp: String::new(),
                    summary: String::new()
                }
            ]
        );
        let only_green = r#"{"publisher": {"name": "X"}, "distributions": [{"rolie": {"feeds": [
            {"tlp_label": "GREEN", "url": "https://x.example/g.json"}]}}]}"#;
        assert!(
            parse_metadata(only_green.as_bytes())
                .unwrap_err()
                .contains("no TLP:WHITE")
        );
        assert!(parse_metadata(b"<html>blocked</html>").is_err());
        assert!(parse_metadata(b"{}").is_err());
    }

    #[test]
    fn rolie_entries_give_document_time_and_checksum() {
        let feed = r#"{"feed": {"id": "x", "entry": [
          {"id": "A-1", "updated": "2026-11-05T23:00:00.000+00:00",
           "link": [{"rel": "self", "href": "https://example.org/white/2026/a-1.json"},
                    {"rel": "hash", "href": "https://example.org/white/2026/a-1.json.sha256"},
                    {"rel": "hash", "href": "https://example.org/white/2026/a-1.json.sha512"},
                    {"rel": "signature", "href": "https://example.org/white/2026/a-1.json.asc"}],
           "content": {"type": "application/json", "src": "https://example.org/white/2026/a-1.json"}},
          {"id": "A-2", "updated": "2026-11-04T10:00:00Z",
           "link": [{"rel": "self", "href": "https://example.org/white/2026/a-2.json"}]},
          {"id": "A-3", "updated": "2026-11-04T10:00:00Z", "link": [{"rel": "self", "href": "ftp://x/a.json"}]}
        ]}}"#;
        let docs = parse_rolie(feed.as_bytes()).unwrap();
        assert_eq!(docs.len(), 2);
        assert_eq!(docs[0].url, "https://example.org/white/2026/a-1.json");
        assert_eq!(
            docs[0].hash_url.as_deref(),
            Some("https://example.org/white/2026/a-1.json.sha512")
        );
        assert_eq!(docs[1].hash_url, None);
        assert_eq!(docs[1].updated, "2026-11-04T10:00:00Z");
        assert!(parse_rolie(b"[1, 2]").is_err());
    }

    #[test]
    fn changes_csv_lines_become_documents_below_the_directory() {
        let text = "\"2026/rhsa-2026_37387.json\",\"2026-11-06T10:45:47+00:00\"\n\
                    \"../../etc/passwd.json\",\"2026-11-06T10:45:47+00:00\"\n\
                    \"https://evil.example/x.json\",\"2026-11-06T10:45:47+00:00\"\n\
                    \"2026/broken.json\",\"yesterday\"\n\
                    \n\
                    2025/rhsa-2025_1.json,2025-01-02T03:04:05Z\n";
        let docs = parse_changes(text, "https://example.org/csaf/v2/advisories/").unwrap();
        let urls: Vec<_> = docs.iter().map(|d| d.url.as_str()).collect();
        assert_eq!(
            urls,
            [
                "https://example.org/csaf/v2/advisories/2026/rhsa-2026_37387.json",
                "https://example.org/csaf/v2/advisories/2025/rhsa-2025_1.json"
            ]
        );
        assert_eq!(docs[1].updated, "2025-01-02T03:04:05Z");
    }

    #[test]
    fn checksums_are_read_and_compared() {
        let data = b"{}";
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let sha256 = format!("{}  a.json\n", hex(sha2::Sha256::digest(data).as_slice()));
        let sha512 = format!("{}  a.json\n", hex(sha2::Sha512::digest(data).as_slice()));
        assert!(Checksum::parse(&sha256).unwrap().matches(data));
        assert!(Checksum::parse(&sha512).unwrap().matches(data));
        assert!(!Checksum::parse(&sha512).unwrap().matches(b"{ }"));
        assert_eq!(Checksum::parse("abc  a.json"), None);
        assert_eq!(Checksum::parse(""), None);
        assert_eq!(Checksum::parse(&"zz".repeat(32)), None);
    }

    #[test]
    fn the_lister_names_providers_by_metadata_url() {
        let agg = r#"{"aggregator": {"name": "BSI"}, "csaf_providers": [
          {"metadata": {"publisher": {"name": "Siemens"}, "role": "csaf_trusted_provider",
                        "url": "https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json"}},
          {"metadata": {"publisher": {"name": "ABB"}, "role": "csaf_provider",
                        "url": "https://www.abb.com/.well-known/csaf/provider-metadata.json"}},
          {"metadata": {"publisher": {"name": "Broken"}, "url": "javascript:alert(1)"}}
        ]}"#;
        let listed = parse_aggregator(agg.as_bytes()).unwrap();
        let names: Vec<_> = listed.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, ["ABB", "Siemens"]);
        assert!(parse_aggregator(b"{}").is_err());
    }

    #[test]
    fn urls_must_be_https() {
        assert_eq!(
            https_url(" https://a.example/x.json "),
            Some("https://a.example/x.json".into())
        );
        assert_eq!(
            https_url("HTTPS://a.example/"),
            Some("HTTPS://a.example/".into())
        );
        assert_eq!(https_url("http://a.example/"), None);
        assert_eq!(https_url("https://a.example/x y"), None);
        assert_eq!(https_url("https://"), None);
        assert!(
            public_tlp("white") && public_tlp("CLEAR") && !public_tlp("GREEN") && !public_tlp("")
        );
    }
}
