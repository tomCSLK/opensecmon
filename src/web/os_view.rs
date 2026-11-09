//! Windows, Apple and Android in the section "Operating systems" of the CVE detail, beside Debian and Ubuntu.
//!
//! Microsoft, Apple and Google (Android) are CNAs and write into their CVE records which versions of their
//! systems are affected (`cves.affected`): Windows per version with the build that fixes it, Apple per system with
//! the version that fixes it, Android per version, fixed by the security patch level of the bulletin the record
//! links to. These entries are grouped here like the distributions and left out of the raw list "affected
//! according to the record". Own assets of such a system are marked at their row with what the matching says
//! (the same [`cna_verdict`]).

use std::collections::BTreeMap;

use serde_json::Value;

use crate::i18n::Lang;
use crate::matching::{Verdict, cna_verdict};
use crate::sources::name_key;
use crate::web::distro_view::{AdvisoryRef, DistroRow, DistroView, OwnMark};

/// Texts that only templates use, for the catalog check: "os-notes".
///
/// Rows shown per system (a patch day of Microsoft names 20 to 30 Windows versions).
const MAX_ROWS: usize = 40;

/// The systems this module shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum System {
    Windows,
    Apple,
    Android,
}

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
}

/// Which system an entry of `affected` describes, if any: Windows itself (not "Windows Admin Center" or
/// "Windows Defender"), Apple's operating systems (not Safari or Xcode), Android (not apps for Android).
fn system_of(entry: &Value) -> Option<System> {
    let vendor = name_key(text(entry, "vendor"));
    let product = text(entry, "product");
    match vendor.as_str() {
        "microsoft" => {
            let rest = product.strip_prefix("Windows")?;
            let rest = rest.trim_start();
            let os = rest.is_empty()
                || rest.starts_with(|c: char| c.is_ascii_digit())
                || ["Server", "RT", "Vista", "XP"]
                    .iter()
                    .any(|p| rest.starts_with(p));
            os.then_some(System::Windows)
        }
        "apple" => {
            let key = name_key(product);
            let os = matches!(
                key.as_str(),
                "iosandipados" | "ios" | "ipados" | "watchos" | "tvos" | "visionos"
            ) || key.starts_with("macos");
            os.then_some(System::Apple)
        }
        "google" | "googleinc" | "googlellc" | "na" | "android" => {
            let lower = product.to_ascii_lowercase();
            (lower == "android" || lower.starts_with("android ")).then_some(System::Android)
        }
        _ => None,
    }
}

/// Whether an entry of `affected` is shown in "Operating systems" instead of the raw list.
pub fn is_os_entry(entry: &Value) -> bool {
    system_of(entry).is_some()
}

/// An own asset that may be one of these systems (vendor and product as keys, see `sources::name_key`).
pub struct OwnSystem {
    pub id: i64,
    pub vendor: String,
    pub product: String,
    pub version: String,
    /// The computer or host, else the name of the product.
    pub name: String,
}

/// The (vendor, product) keys of the system entries, to look up own assets of them.
pub fn product_keys(affected: &Value) -> Vec<(String, String)> {
    let mut keys: Vec<(String, String)> = affected
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| system_of(e).is_some())
        .map(|e| (name_key(text(e, "vendor")), name_key(text(e, "product"))))
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

/// One row while it is built: the entries of the same system version (Windows lists "Server Core" and each
/// processor architecture apart).
#[derive(Default)]
struct Acc {
    sort: Vec<u64>,
    keys: Vec<(String, String)>,
    fixed: Vec<String>,
    last_affected: Vec<String>,
    publication: bool,
    platforms: Vec<&'static str>,
    server_core: bool,
}

impl Acc {
    fn add_version(&mut self, v: &Value) {
        let lt = text(v, "less_than");
        let lte = text(v, "less_than_or_equal");
        if lt == "publication" {
            self.publication = true;
        } else if !lt.is_empty() && lt != "*" {
            push_unique(&mut self.fixed, lt);
        } else if !lte.is_empty() && lte != "*" {
            push_unique(&mut self.last_affected, lte);
        }
    }
}

fn push_unique(list: &mut Vec<String>, value: &str) {
    if !list.iter().any(|v| v == value) {
        list.push(value.to_owned());
    }
}

/// The numbers of a version or build, for sorting ("10.0.26100.9711" → [10, 0, 26100, 9711]).
fn numbers(version: &str) -> Vec<u64> {
    version
        .split(|c: char| !c.is_ascii_digit())
        .filter(|p| !p.is_empty())
        .filter_map(|p| p.parse().ok())
        .collect()
}

/// The architecture in a Windows product name or platform ("for x64-based Systems" → "x64").
fn platform(text: &str) -> Option<&'static str> {
    let lower = text.to_ascii_lowercase();
    if lower.contains("arm64") {
        Some("ARM64")
    } else if lower.contains("x64") {
        Some("x64")
    } else if lower.contains("32-bit") || lower.contains("x86") {
        Some("32-Bit")
    } else if lower.contains("itanium") {
        Some("Itanium")
    } else {
        None
    }
}

/// A Windows version as one row: "Windows 11 version 26H1" and "… Version 26H1" meet, "(Server Core
/// installation)" and the architecture ("for x64-based Systems", in older records also in the middle: "Windows 7
/// for 32-bit Systems Service Pack 1", or without "for": "Windows 8.1 x64-based systems") become notes.
/// Returns (name, server core, architecture).
fn windows_name(name: &str) -> (String, bool, Option<&'static str>) {
    let mut name = name.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut core = false;
    for marker in ["(Server Core installation)", "(Core installation)"] {
        if let Some(i) = name.to_ascii_lowercase().find(&marker.to_ascii_lowercase()) {
            name.replace_range(i..i + marker.len(), "");
            core = true;
        }
    }
    let tokens: Vec<&str> = name.split_whitespace().collect();
    let mut kept: Vec<&str> = Vec::with_capacity(tokens.len());
    let mut arch = None;
    let mut i = 0;
    while i < tokens.len() {
        let word = tokens[i].to_ascii_lowercase();
        let systems = tokens
            .get(i + 1)
            .is_some_and(|n| n.trim_end_matches(',').eq_ignore_ascii_case("systems"));
        if systems && (word.ends_with("-based") || word == "32-bit") {
            arch = arch.or(platform(&word));
            if kept.last().is_some_and(|w| w.eq_ignore_ascii_case("for")) {
                kept.pop();
            }
            i += 2;
            continue;
        }
        kept.push(tokens[i]);
        i += 1;
    }
    let name = kept
        .join(" ")
        .trim_end_matches(',')
        .replace(" version ", " Version ");
    (name, core, arch)
}

/// The rows of Windows: one per version, newest first, clients before servers.
fn windows_rows(entries: &[&Value]) -> Vec<(String, Acc)> {
    let mut rows: BTreeMap<String, Acc> = BTreeMap::new();
    for e in entries {
        let product = text(e, "product");
        let key = (name_key(text(e, "vendor")), name_key(product));
        for v in e
            .get("versions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if text(v, "status") != "affected" {
                continue;
            }
            let version = text(v, "version");
            // Older records name the version in the version field: "Windows" + "10 Version 1803 for x64-based Systems".
            let textual = !version.chars().all(|c| c.is_ascii_digit() || c == '.')
                && !matches!(version, "unspecified" | "n/a" | "*");
            let full = if !textual {
                product.to_owned()
            } else if version.to_ascii_lowercase().starts_with("windows") {
                version.to_owned()
            } else {
                format!("{product} {version}")
            };
            let (name, core, arch) = windows_name(&full);
            let acc = rows.entry(name).or_default();
            if !acc.keys.contains(&key) {
                acc.keys.push(key.clone());
            }
            acc.server_core |= core;
            for p in arch.into_iter().chain(
                e.get("platforms")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .filter_map(platform),
            ) {
                if !acc.platforms.contains(&p) {
                    acc.platforms.push(p);
                }
            }
            acc.add_version(v);
            if acc.sort.is_empty() {
                acc.sort = numbers(if version.contains('.') {
                    version
                } else {
                    text(v, "less_than")
                });
            }
        }
    }
    let mut rows: Vec<(String, Acc)> = rows.into_iter().collect();
    rows.sort_by(|(a_name, a), (b_name, b)| {
        windows_order(b_name)
            .cmp(&windows_order(a_name))
            .then_with(|| b.sort.cmp(&a.sort))
    });
    rows
}

/// The order of Windows versions, newest last: servers below clients, then the number ("11", "8.1", "2025"),
/// then the rest as text, which also orders the releases of a version ("1809" < "1909" < "2004" < "20H2" <
/// "22H2", "2022" < "2022, 23H2 Edition", "2012" < "2012 R2").
fn windows_order(name: &str) -> (bool, Vec<u64>, String) {
    // "Windows 10 Servers Version 1803" in older records is a server too.
    let server = name.contains("Server");
    let rest = name.strip_prefix("Windows").unwrap_or(name).trim_start();
    let rest = rest.strip_prefix("Server").map_or(rest, str::trim_start);
    let end = rest
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(rest.len());
    (!server, numbers(&rest[..end]), rest[end..].to_owned())
}

/// The rows of Apple: one per system in a fixed order.
fn apple_rows(entries: &[&Value]) -> Vec<(String, Acc)> {
    const ORDER: [&str; 7] = [
        "iosandipados",
        "ios",
        "ipados",
        "macos",
        "watchos",
        "tvos",
        "visionos",
    ];
    let mut rows: Vec<(String, Acc)> = Vec::new();
    for e in entries {
        let product = text(e, "product");
        let key = (name_key(text(e, "vendor")), name_key(product));
        let i = match rows.iter().position(|(n, _)| n == product) {
            Some(i) => i,
            None => {
                rows.push((product.to_owned(), Acc::default()));
                rows.len() - 1
            }
        };
        let acc = &mut rows[i].1;
        if !acc.keys.contains(&key) {
            acc.keys.push(key.clone());
        }
        let rank = ORDER
            .iter()
            .position(|k| key.1.starts_with(k))
            .unwrap_or(ORDER.len());
        acc.sort = vec![rank as u64];
        for v in e
            .get("versions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|v| text(v, "status") == "affected")
        {
            acc.add_version(v);
        }
    }
    for (name, acc) in &mut rows {
        // "iOS 12.1.4" in older records: the name of the system is already in the row.
        for f in acc.fixed.iter_mut().chain(acc.last_affected.iter_mut()) {
            if let Some(rest) = f.strip_prefix(name.as_str()) {
                *f = rest.trim().to_owned();
            }
        }
        acc.fixed.sort_by_key(|f| std::cmp::Reverse(numbers(f)));
    }
    rows.sort_by(|a, b| a.1.sort.cmp(&b.1.sort).then_with(|| a.0.cmp(&b.0)));
    rows
}

/// The rows of Android: one per version ("Android 14", "Android kernel"), newest first.
fn android_rows(entries: &[&Value]) -> Vec<(String, Acc)> {
    let mut rows: BTreeMap<String, Acc> = BTreeMap::new();
    for e in entries {
        let product = text(e, "product");
        let key = (name_key(text(e, "vendor")), name_key(product));
        for v in e
            .get("versions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|v| text(v, "status") == "affected")
        {
            // "14", "Android kernel", or several in one: "Android-7.0 Android-7.1.1 Android-8.0".
            let version = text(v, "version");
            let tokens: Vec<String> = if version
                .split_whitespace()
                .all(|w| w.to_ascii_lowercase().starts_with("android-"))
            {
                version
                    .split_whitespace()
                    .map(|w| w["android-".len()..].to_owned())
                    .collect()
            } else {
                vec![version.to_owned()]
            };
            for token in tokens {
                let token = token.trim();
                if token.is_empty() || matches!(token, "n/a" | "unspecified" | "0") {
                    continue;
                }
                let name = if token
                    .to_ascii_lowercase()
                    .starts_with(&product.to_ascii_lowercase())
                {
                    token.to_owned()
                } else {
                    format!("{product} {token}")
                };
                let acc = rows.entry(name).or_default();
                if !acc.keys.contains(&key) {
                    acc.keys.push(key.clone());
                }
                acc.sort = numbers(token);
                acc.add_version(v);
            }
        }
    }
    let mut rows: Vec<(String, Acc)> = rows.into_iter().collect();
    rows.sort_by(|a, b| b.1.sort.cmp(&a.1.sort).then_with(|| b.0.cmp(&a.0)));
    rows
}

/// What the bulletin links of an Android record say: the patch level (date of the bulletin), or the Android
/// release that fixed it ("android-13"), and which bulletin it is (Pixel, Wear OS).
struct Bulletin {
    url: String,
    level: Option<String>,
    release: Option<String>,
    kind: Option<&'static str>,
}

fn bulletin(url: &str) -> Option<Bulletin> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let (host, path) = rest.split_once('/')?;
    if host != "source.android.com" || !path.contains("bulletin") {
        return None;
    }
    let last = path
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .trim_end_matches(".html");
    let is_date = last.len() == 10
        && last.char_indices().all(|(i, c)| {
            if i == 4 || i == 7 {
                c == '-'
            } else {
                c.is_ascii_digit()
            }
        });
    let release = last
        .strip_prefix("android-")
        .filter(|r| !r.is_empty() && r.len() <= 4)
        .map(|r| format!("Android {}", r.to_ascii_uppercase()));
    let kind = if path.contains("/pixel/") {
        Some("os-pixel")
    } else if path.contains("/wear/") {
        Some("os-wear")
    } else {
        None
    };
    Some(Bulletin {
        url: url.to_owned(),
        level: is_date.then(|| last.to_owned()),
        release,
        kind,
    })
}

/// The groups Windows, Apple and Android for a CVE, from the CNA's `affected` entries and the references.
pub fn build(
    t: Lang,
    cve_id: &str,
    affected: &Value,
    refs: &Value,
    own: &[OwnSystem],
) -> Vec<DistroView> {
    let entries: Vec<&Value> = affected.as_array().into_iter().flatten().collect();
    let of = |s: System| -> Vec<&Value> {
        entries
            .iter()
            .copied()
            .filter(|e| system_of(e) == Some(s))
            .collect()
    };
    let urls: Vec<&str> = refs
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| r.get("url").and_then(Value::as_str))
        .collect();
    let mut out = Vec::new();

    let windows = windows_rows(&of(System::Windows));
    if !windows.is_empty() {
        out.push(group(
            t,
            "Windows",
            format!("https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}"),
            "os-link-windows",
            Vec::new(),
            windows
                .into_iter()
                .map(|(name, acc)| {
                    let mut notes: Vec<String> = Vec::new();
                    if !acc.platforms.is_empty() {
                        let mut platforms = acc.platforms.clone();
                        platforms.sort_by_key(|p| {
                            ["x64", "ARM64", "32-Bit", "Itanium"]
                                .iter()
                                .position(|o| o == p)
                        });
                        notes.push(platforms.join(", "));
                    }
                    if acc.server_core {
                        notes.push(t.get("os-server-core"));
                    }
                    row(t, name, &acc, notes, None, affected, own)
                })
                .collect(),
        ));
    }

    let apple = apple_rows(&of(System::Apple));
    if !apple.is_empty() {
        let notes: Vec<AdvisoryRef> = urls
            .iter()
            .filter(|u| {
                u.starts_with("https://support.apple.com/")
                    || u.starts_with("http://support.apple.com/")
            })
            .take(10)
            .map(|u| AdvisoryRef {
                id: u
                    .trim_end_matches('/')
                    .rsplit('/')
                    .next()
                    .unwrap_or_default()
                    .to_owned(),
                url: (*u).to_owned(),
            })
            .collect();
        out.push(group(
            t,
            "Apple",
            "https://support.apple.com/100100".to_owned(),
            "os-link-apple",
            notes,
            apple
                .into_iter()
                .map(|(name, acc)| row(t, name, &acc, Vec::new(), None, affected, own))
                .collect(),
        ));
    }

    let android = android_rows(&of(System::Android));
    if !android.is_empty() {
        let bulletins: Vec<Bulletin> = urls.iter().filter_map(|u| bulletin(u)).collect();
        // The main bulletin first; Pixel and Wear OS bulletins only when there is no other.
        let main = bulletins
            .iter()
            .find(|b| b.kind.is_none() && (b.level.is_some() || b.release.is_some()))
            .or_else(|| {
                bulletins
                    .iter()
                    .find(|b| b.level.is_some() || b.release.is_some())
            });
        let link = main.map_or_else(
            || "https://source.android.com/docs/security/bulletin".to_owned(),
            |b| b.url.clone(),
        );
        out.push(group(
            t,
            "Android",
            link,
            "os-link-android",
            Vec::new(),
            android
                .into_iter()
                .map(|(name, acc)| {
                    let notes = main
                        .and_then(|b| b.kind)
                        .map(|k| vec![t.get(k)])
                        .unwrap_or_default();
                    row(t, name, &acc, notes, main, affected, own)
                })
                .collect(),
        ));
    }
    out
}

fn group(
    t: Lang,
    name: &'static str,
    link: String,
    label: &str,
    refs: Vec<AdvisoryRef>,
    mut rows: Vec<DistroRow>,
) -> DistroView {
    let hidden = rows.len().saturating_sub(MAX_ROWS);
    rows.truncate(MAX_ROWS);
    DistroView {
        name,
        priority: String::new(),
        link,
        link_label: t.get(label),
        refs,
        rows,
        more: if hidden > 0 {
            t.get1("os-more", "count", t.number(hidden as i64))
        } else {
            String::new()
        },
    }
}

/// One row: the state from the versions (fixed in a build or version, by the update at publication, by a patch
/// level, or only "affected"), the notes and the own assets of these products.
fn row(
    t: Lang,
    name: String,
    acc: &Acc,
    notes: Vec<String>,
    bulletin: Option<&Bulletin>,
    affected: &Value,
    own: &[OwnSystem],
) -> DistroRow {
    let (class, state, version) = if !acc.fixed.is_empty() {
        ("ok", t.get("distro-fixed"), acc.fixed.join(", "))
    } else if acc.publication {
        ("ok", t.get("os-fixed-publication"), String::new())
    } else if let Some(level) = bulletin.and_then(|b| b.level.clone()) {
        ("ok", t.get("os-patch-level"), level)
    } else if let Some(release) = bulletin.and_then(|b| b.release.clone()) {
        ("ok", t.get("distro-fixed"), release)
    } else if !acc.last_affected.is_empty() {
        (
            "warn",
            t.get("distro-last-affected"),
            acc.last_affected.join(", "),
        )
    } else {
        ("warn", t.get("os-affected"), String::new())
    };
    let own = own
        .iter()
        .filter(|a| {
            acc.keys
                .iter()
                .any(|(v, p)| *v == a.vendor && *p == a.product)
        })
        .take(10)
        .map(|a| {
            let (class, state) = match cna_verdict(affected, &a.vendor, &a.product, &a.version) {
                Verdict::Affected { checked: true, .. } => ("err", t.get("os-own-affected")),
                Verdict::Affected { checked: false, .. } => ("warn", t.get("os-own-unchecked")),
                Verdict::NotAffected => ("ok", t.get("os-own-ok")),
            };
            OwnMark {
                name: a.name.clone(),
                href: format!("/assets/{}", a.id),
                version: a.version.clone(),
                class,
                state,
            }
        })
        .collect();
    DistroRow {
        release: name,
        package: String::new(),
        class,
        state,
        version,
        note: notes.join(" · "),
        advisories: Vec::new(),
        own,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn win(product: &str, from: &str, lt: &str, platforms: &[&str]) -> Value {
        json!({"vendor": "Microsoft", "product": product, "platforms": platforms,
               "versions": [{"version": from, "less_than": lt, "status": "affected", "type": "custom"}]})
    }

    #[test]
    fn only_the_systems_themselves_are_taken() {
        let os = |vendor: &str, product: &str| {
            is_os_entry(&json!({"vendor": vendor, "product": product}))
        };
        assert!(os("Microsoft", "Windows 11 Version 24H2"));
        assert!(os(
            "Microsoft",
            "Windows Server 2019 (Server Core installation)"
        ));
        assert!(os("Microsoft", "Windows"));
        assert!(os("Microsoft", "Windows RT 8.1"));
        assert!(!os("Microsoft", "Windows Admin Center"));
        assert!(!os("Microsoft", "Windows Defender on Windows Server 2019"));
        assert!(!os("Microsoft", "Windows Subsystem for Linux (WSL2)"));
        assert!(!os("Other", "Windows 11"));
        assert!(os("Apple", "iOS and iPadOS"));
        assert!(os("Apple", "macOS"));
        assert!(os("Apple", "visionOS"));
        assert!(!os("Apple", "Safari"));
        assert!(!os("Apple", "iCloud for Windows"));
        assert!(os("Google", "Android"));
        assert!(os("n/a", "Android"));
        assert!(os("Google Inc.", "Android"));
        assert!(os("Google", "Android XR"));
        assert!(!os("Microsoft", "Microsoft Office for Android"));
        assert!(!os("Google", "Chrome"));
    }

    #[test]
    fn windows_versions_become_one_row_each_with_the_fixing_build() {
        let affected = json!([
            win(
                "Windows 11 Version 24H2",
                "10.0.26100.0",
                "10.0.26100.9711",
                &["ARM64-based Systems", "x64-based Systems"]
            ),
            win(
                "Windows 11 version 26H1",
                "10.0.28000.0",
                "10.0.28000.3231",
                &["x64-based Systems"]
            ),
            win(
                "Windows Server 2025",
                "10.0.26100.0",
                "10.0.26100.9711",
                &[]
            ),
            win(
                "Windows Server 2025 (Server Core installation)",
                "10.0.26100.0",
                "10.0.26100.9711",
                &[]
            ),
            win("Windows 10 Version 1809", "10.0.0", "publication", &[]),
            json!({"vendor": "Microsoft", "product": "Windows 10 Version 1903 for 32-bit Systems",
                   "versions": [{"version": "unspecified", "status": "affected"}]}),
            json!({"vendor": "Microsoft", "product": "Windows 10 Version 1903 for x64-based Systems",
                   "versions": [{"version": "unspecified", "status": "affected"}]}),
            json!({"vendor": "Microsoft", "product": "Windows Admin Center",
                   "versions": [{"version": "1.0", "less_than": "2.0", "status": "affected"}]}),
        ]);
        let groups = build(Lang::De, "CVE-2026-1", &affected, &json!([]), &[]);
        assert_eq!(groups.len(), 1);
        let g = &groups[0];
        assert_eq!(g.name, "Windows");
        assert!(g.link.ends_with("/update-guide/vulnerability/CVE-2026-1"));
        let names: Vec<&str> = g.rows.iter().map(|r| r.release.as_str()).collect();
        assert_eq!(
            names,
            [
                "Windows 11 Version 26H1",
                "Windows 11 Version 24H2",
                "Windows 10 Version 1903",
                "Windows 10 Version 1809",
                "Windows Server 2025",
            ]
        );
        let r = &g.rows[1];
        assert_eq!((r.class, r.state.as_str()), ("ok", "behoben in"));
        assert_eq!(r.version, "10.0.26100.9711");
        assert_eq!(r.note, "x64, ARM64");
        assert_eq!(g.rows[4].note, "auch Server Core");
        assert_eq!(g.rows[2].state, "betroffen");
        assert_eq!(g.rows[2].note, "x64, 32-Bit");
        assert_eq!(
            g.rows[3].state,
            "behoben mit dem Update zur Veröffentlichung"
        );
    }

    #[test]
    fn older_windows_records_name_the_version_in_the_version_field() {
        let affected = json!([
            {"vendor": "Microsoft", "product": "Windows", "versions": [
                {"version": "10 Version 1803 for x64-based Systems", "status": "affected"},
                {"version": "10 Version 1803 for ARM64-based Systems", "status": "affected"}]},
            {"vendor": "Microsoft", "product": "Windows Server", "versions": [
                {"version": "2019  (Core installation)", "status": "affected"}]},
            {"vendor": "Microsoft", "product": "Windows 7", "versions": [
                {"version": "for x64-based Systems Service Pack 1", "status": "affected"},
                {"version": "for 32-bit Systems Service Pack 1", "status": "affected"}]},
            {"vendor": "Microsoft", "product": "Windows", "versions": [
                {"version": "8.1 x64-based systems", "status": "affected"},
                {"version": "Windows RT 8.1", "status": "affected"}]},
            {"vendor": "Microsoft", "product": "Windows 10 Servers", "versions": [
                {"version": "Version 1803 (Server Core installation)", "status": "affected"}]},
        ]);
        let groups = build(Lang::De, "CVE-2020-1", &affected, &json!([]), &[]);
        let rows: Vec<(&str, &str)> = groups[0]
            .rows
            .iter()
            .map(|r| (r.release.as_str(), r.note.as_str()))
            .collect();
        assert_eq!(
            rows,
            [
                ("Windows 10 Version 1803", "x64, ARM64"),
                ("Windows 8.1", "x64"),
                ("Windows 7 Service Pack 1", "x64, 32-Bit"),
                ("Windows RT 8.1", ""),
                ("Windows Server 2019", "auch Server Core"),
                ("Windows 10 Servers Version 1803", "auch Server Core"),
            ]
        );
    }

    #[test]
    fn apple_systems_show_the_versions_that_fix_them_and_the_notes() {
        let affected = json!([
            {"vendor": "Apple", "product": "macOS", "versions": [
                {"version": "0", "less_than": "13.7.1", "status": "affected"},
                {"version": "0", "less_than": "15.1", "status": "affected"},
                {"version": "0", "less_than": "14.7.1", "status": "affected"}]},
            {"vendor": "Apple", "product": "iOS and iPadOS", "versions": [
                {"version": "0", "less_than": "27.2", "status": "affected"}]},
            {"vendor": "Apple", "product": "iOS", "versions": [
                {"version": "unspecified", "less_than": "iOS 12.1.4", "status": "affected"}]},
            {"vendor": "Apple", "product": "Safari", "versions": [
                {"version": "0", "less_than": "18.1", "status": "affected"}]},
        ]);
        let refs = json!([{"url": "https://support.apple.com/en-us/149230"}, {"url": "https://example.com/x"}]);
        let groups = build(Lang::De, "CVE-2026-2", &affected, &refs, &[]);
        let g = &groups[0];
        assert_eq!(g.name, "Apple");
        let rows: Vec<(&str, &str)> = g
            .rows
            .iter()
            .map(|r| (r.release.as_str(), r.version.as_str()))
            .collect();
        assert_eq!(
            rows,
            [
                ("iOS and iPadOS", "27.2"),
                ("iOS", "12.1.4"),
                ("macOS", "15.1, 14.7.1, 13.7.1"),
            ]
        );
        assert_eq!(g.refs.len(), 1);
        assert_eq!(g.refs[0].id, "149230");
    }

    #[test]
    fn android_versions_are_fixed_by_the_patch_level_of_the_bulletin() {
        let affected = json!([
            {"vendor": "Google", "product": "Android", "default": "unaffected", "versions": [
                {"version": "14", "status": "affected"}, {"version": "16", "status": "affected"},
                {"version": "15", "status": "affected"}]},
        ]);
        let refs = json!([
            {"url": "https://source.android.com/docs/security/bulletin/pixel/2026-11-01"},
            {"url": "https://source.android.com/docs/security/bulletin/2026/2026-11-01"},
        ]);
        let groups = build(Lang::De, "CVE-2026-3", &affected, &refs, &[]);
        let g = &groups[0];
        assert_eq!(g.name, "Android");
        assert_eq!(
            g.link,
            "https://source.android.com/docs/security/bulletin/2026/2026-11-01"
        );
        let rows: Vec<(&str, &str, &str)> = g
            .rows
            .iter()
            .map(|r| (r.release.as_str(), r.state.as_str(), r.version.as_str()))
            .collect();
        assert_eq!(
            rows,
            [
                ("Android 16", "behoben mit Patch-Ebene", "2026-11-01"),
                ("Android 15", "behoben mit Patch-Ebene", "2026-11-01"),
                ("Android 14", "behoben mit Patch-Ebene", "2026-11-01"),
            ]
        );

        // Older records: several versions in one field, a release bulletin, a Pixel bulletin alone.
        let old = json!([{"vendor": "Android", "product": "Android", "versions": [
            {"version": "Android-8.0 Android-9", "status": "affected"}]}]);
        let release = build(
            Lang::De,
            "CVE-2019-1",
            &old,
            &json!([{"url": "https://source.android.com/security/bulletin/android-10"}]),
            &[],
        );
        let r: Vec<(&str, &str)> = release[0]
            .rows
            .iter()
            .map(|r| (r.release.as_str(), r.version.as_str()))
            .collect();
        assert_eq!(
            r,
            [("Android 9", "Android 10"), ("Android 8.0", "Android 10")]
        );
        let pixel = build(
            Lang::De,
            "CVE-2019-2",
            &old,
            &json!([{"url": "https://source.android.com/security/bulletin/pixel/2019-06-01.html"}]),
            &[],
        );
        assert_eq!(pixel[0].rows[0].version, "2019-06-01");
        assert_eq!(pixel[0].rows[0].note, "Pixel-Update");
        let none = build(Lang::De, "CVE-2019-3", &old, &json!([]), &[]);
        assert_eq!(none[0].rows[0].state, "betroffen");
        assert_eq!(
            none[0].link,
            "https://source.android.com/docs/security/bulletin"
        );
    }

    #[test]
    fn own_computers_are_marked_at_their_windows_version() {
        let affected = json!([
            win(
                "Windows 11 Version 24H2",
                "10.0.26100.0",
                "10.0.26100.9711",
                &[]
            ),
            win(
                "Windows 11 Version 25H2",
                "10.0.26200.0",
                "10.0.26200.9711",
                &[]
            ),
        ]);
        let own = [
            OwnSystem {
                id: 7,
                vendor: "microsoft".into(),
                product: "windows11version24h2".into(),
                version: "10.0.26100.9000".into(),
                name: "Laptop".into(),
            },
            OwnSystem {
                id: 8,
                vendor: "microsoft".into(),
                product: "windows11version24h2".into(),
                version: "10.0.26100.9800".into(),
                name: "Desktop".into(),
            },
        ];
        assert_eq!(
            product_keys(&affected),
            [
                ("microsoft".to_owned(), "windows11version24h2".to_owned()),
                ("microsoft".to_owned(), "windows11version25h2".to_owned()),
            ]
        );
        let groups = build(Lang::De, "CVE-2026-4", &affected, &json!([]), &own);
        let rows = &groups[0].rows;
        assert!(rows[0].own.is_empty(), "25H2 has none");
        let marks: Vec<(&str, &str, &str)> = rows[1]
            .own
            .iter()
            .map(|m| (m.name.as_str(), m.class, m.href.as_str()))
            .collect();
        assert_eq!(
            marks,
            [
                ("Laptop", "err", "/assets/7"),
                ("Desktop", "ok", "/assets/8")
            ]
        );
    }

    #[test]
    fn every_text_exists_in_every_language() {
        for lang in Lang::ALL {
            for id in [
                "os-link-windows",
                "os-link-apple",
                "os-link-android",
                "os-pixel",
                "os-wear",
                "os-notes",
            ] {
                assert_ne!(lang.get(id), id, "{id} missing in {lang:?}");
            }
        }
    }

    #[test]
    fn a_patch_day_is_cut_at_the_limit() {
        let affected: Vec<Value> = (0..45)
            .map(|i| {
                win(
                    &format!("Windows Server 20{i:02}"),
                    "10.0.0.0",
                    "10.0.1.0",
                    &[],
                )
            })
            .collect();
        let groups = build(
            Lang::En,
            "CVE-2026-5",
            &Value::Array(affected),
            &json!([]),
            &[],
        );
        assert_eq!(groups[0].rows.len(), MAX_ROWS);
        assert_eq!(groups[0].more, "5 more rows, all of them at the vendor.");
    }
}
