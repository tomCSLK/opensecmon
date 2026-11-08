//! Random tests of the parts that read data from outside: the readers of the sources (CVE records, NVD
//! feeds, CSAF documents and provider files, OSV, the Debian tracker, KEV, EPSS), the output of the
//! inventory command, the CSV import, the version comparison and the range checks of the matching.
//! Samples from the unit tests are garbled (bytes flipped, cut, repeated, JSON tokens and deep nesting
//! inserted); nothing may panic or take long. `FUZZ_ITERATIONS` sets the rounds per reader (a quick run by
//! default; a long one: `FUZZ_ITERATIONS=20000 cargo test --release fuzz`), `FUZZ_SEED` the start.

use std::cmp::Ordering;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::version::{Scheme, compare, is_version};

fn iterations(default: usize) -> usize {
    std::env::var("FUZZ_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// A small xorshift generator (no dependency needed for tests).
struct Rng(u64);

impl Rng {
    fn new(salt: u64) -> Self {
        let seed = std::env::var("FUZZ_SEED")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0x5eed_0f5e_c0de);
        Self((seed ^ salt.wrapping_mul(0x9e37_79b9_7f4a_7c15)) | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }

    fn pick<'a, T>(&mut self, list: &'a [T]) -> &'a T {
        &list[self.below(list.len())]
    }
}

const TOKENS: [&str; 24] = [
    "{",
    "}",
    "[",
    "]",
    "\"",
    ",",
    ":",
    "null",
    "true",
    "-1",
    "1e999",
    "0.0000001",
    "\\u0000",
    "\\ud800",
    "\n",
    "\t",
    "---",
    ";",
    "ä€😀",
    "18446744073709551616",
    "\"\"",
    "{}",
    "[]",
    "%",
];

/// A garbled copy of `sample`.
fn mutate(rng: &mut Rng, sample: &[u8]) -> Vec<u8> {
    let mut out = sample.to_vec();
    for _ in 0..=rng.below(6) {
        let at = rng.below(out.len() + 1);
        match rng.below(8) {
            0 if !out.is_empty() => {
                let i = rng.below(out.len());
                out[i] ^= 1 << rng.below(8);
            }
            1 if !out.is_empty() => {
                let i = rng.below(out.len());
                out[i] = rng.next() as u8;
            }
            2 => {
                let end = (at + rng.below(64)).min(out.len());
                out.drain(at..end);
            }
            3 => {
                let end = (at + rng.below(200)).min(out.len());
                let piece = out[at..end].to_vec();
                for _ in 0..=rng.below(4) {
                    out.splice(at..at, piece.iter().copied());
                }
            }
            4 => {
                let token = rng.pick(&TOKENS).as_bytes().to_vec();
                out.splice(at..at, token);
            }
            5 => out.truncate(at),
            6 => {
                // Deep nesting.
                let depth = 1 + rng.below(400);
                let open = if rng.below(2) == 0 { b'[' } else { b'{' };
                out.splice(at..at, std::iter::repeat_n(open, depth));
            }
            _ => {
                // Swap a quoted value for another of the same sample.
                let quotes: Vec<usize> = out
                    .iter()
                    .enumerate()
                    .filter(|(_, b)| **b == b'"')
                    .map(|(i, _)| i)
                    .collect();
                if quotes.len() >= 4 {
                    let a = *rng.pick(&quotes);
                    let b = *rng.pick(&quotes);
                    if a < b {
                        let piece = out[a..b].to_vec();
                        let at = *rng.pick(&quotes);
                        out.splice(at..at, piece);
                    }
                }
            }
        }
    }
    out
}

/// Runs `f` on `input`; a panic shows the input (cut) before it is passed on. Returns how long it took.
fn run(name: &str, round: usize, input: &[u8], f: &mut dyn FnMut(&[u8])) -> Duration {
    let started = Instant::now();
    if let Err(e) = catch_unwind(AssertUnwindSafe(|| f(input))) {
        let text = String::from_utf8_lossy(&input[..input.len().min(2000)]);
        eprintln!("{name}: panic in round {round} with input {text:?}");
        resume_unwind(e);
    }
    started.elapsed()
}

/// Garbles each sample `rounds` times and feeds it to `f`; none of the calls may take longer than `limit`.
fn fuzz(name: &str, salt: u64, samples: &[&[u8]], rounds: usize, f: &mut dyn FnMut(&[u8])) {
    let limit = Duration::from_secs(if cfg!(debug_assertions) { 5 } else { 1 });
    let mut rng = Rng::new(salt);
    let mut slowest = Duration::ZERO;
    for sample in samples {
        slowest = slowest.max(run(name, 0, sample, f));
    }
    for round in 1..=rounds {
        let sample = *rng.pick(samples);
        let input = mutate(&mut rng, sample);
        let took = run(name, round, &input, f);
        assert!(took < limit, "{name}: round {round} took {took:?}");
        slowest = slowest.max(took);
    }
    eprintln!("{name}: {rounds} rounds, slowest {slowest:?}");
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn fuzz_cve_records_and_nvd_feeds() {
    use crate::sources::{cve5, cvelist, nvd};
    let n = iterations(1500);
    fuzz("cve5", 1, &[cve5::tests::RECORD.as_bytes()], n, &mut |b| {
        let _ = cve5::parse(b);
    });
    fuzz("nvd feed", 2, &[nvd::tests::FEED.as_bytes()], n, &mut |b| {
        let _ = nvd::read_feed(b, &mut |_| Ok(()));
    });
    let meta = b"lastModifiedDate:2026-11-05T03:00:01-05:00\r\nsize:123\r\nzipSize:12\r\ngzSize:12\r\nsha256:ABCDEF0123\r\n";
    fuzz("nvd meta", 3, &[meta], n, &mut |b| {
        let _ = nvd::parse_meta(&text(b));
    });
    let releases = br#"[{"tag_name": "cve_2026-11-05_0100Z", "body": "x", "assets": [
        {"name": "2026-11-05_delta_CVEs_at_0100Z.zip",
         "browser_download_url": "https://github.com/CVEProject/cvelistV5/releases/download/x/a.zip"}]}]"#;
    fuzz("cvelist releases", 4, &[releases], n, &mut |b| {
        let _ = cvelist::parse_releases(
            b,
            "https://api.github.com/repos/CVEProject/cvelistV5/releases",
        );
    });
    fuzz(
        "cpe",
        5,
        &[
            b"cpe:2.3:o:tp-link:er605_firmware:2.2.3:*:*:*:*:*:*:*",
            b"cpe:2.3:a:open\\:ssh:openssh:9.6p1",
        ],
        n,
        &mut |b| {
            let t = text(b);
            let _ = nvd::cpe_vendor_product(&t);
            let _ = crate::csaf::document::cpe_names(&t);
            let _ = crate::storage::assets::cpe_keys(&t);
            let _ = crate::storage::assets::cpe_version(&t);
        },
    );
}

#[test]
fn fuzz_csaf_documents_and_provider_files() {
    use crate::csaf;
    let n = iterations(1500);
    fuzz(
        "csaf document",
        11,
        &[csaf::document::tests::BSI_DOC.as_bytes()],
        n,
        &mut |b| {
            let _ = csaf::document::parse(b);
        },
    );
    fuzz(
        "csaf metadata",
        12,
        &[csaf::tests::METADATA.as_bytes()],
        n,
        &mut |b| {
            let _ = csaf::parse_metadata(b);
        },
    );
    let rolie = br#"{"feed": {"id": "x", "entry": [
        {"id": "WID-SEC-2026-0001", "updated": "2026-11-05T10:00:00Z",
         "link": [{"rel": "self", "href": "https://example.org/csaf/2026/wid-sec-2026-0001.json"},
                  {"rel": "hash", "href": "https://example.org/csaf/2026/wid-sec-2026-0001.json.sha512"}]}]}}"#;
    fuzz("rolie", 13, &[rolie], n, &mut |b| {
        let _ = csaf::parse_rolie(b);
    });
    let changes =
        b"\"2026/a-1.json\",\"2026-11-05T10:00:00Z\"\n2026/b-2.json,2026-11-04T09:00:00Z\n";
    fuzz("changes.csv", 14, &[changes], n, &mut |b| {
        let _ = csaf::parse_changes(&text(b), "https://example.org/csaf/v2/advisories/");
    });
    let aggregator = br#"{"csaf_providers": [{"metadata": {"publisher": {"name": "Example", "category": "vendor"},
        "url": "https://example.org/.well-known/csaf/provider-metadata.json", "role": "csaf_trusted_provider"}}]}"#;
    fuzz("aggregator", 15, &[aggregator], n, &mut |b| {
        let _ = csaf::parse_aggregator(b);
    });
}

#[test]
fn fuzz_distribution_sources() {
    use crate::sources::osv::{self, Distro};
    use crate::sources::{debian_tracker, epss, kev};
    let n = iterations(1500);
    let records = [
        osv::tests::DSA.as_bytes(),
        osv::tests::DEBIAN_CVE.as_bytes(),
        osv::tests::UBUNTU_CVE.as_bytes(),
    ];
    fuzz("osv", 21, &records, n, &mut |b| {
        let _ = osv::parse(b, Distro::Debian);
        let _ = osv::parse(b, Distro::Ubuntu);
    });
    let modified =
        b"2026-11-06T01:11:58.823517344Z,DSA-6189-1\n2026-11-05T00:00:00Z,DEBIAN-CVE-2026-1\n";
    fuzz("osv modified", 22, &[modified], n, &mut |b| {
        let _ = osv::parse_modified(b, None);
    });
    fuzz(
        "debian tracker",
        23,
        &[debian_tracker::tests::TRACKER.as_bytes()],
        n,
        &mut |b| {
            let _ = debian_tracker::parse(b);
        },
    );
    let catalog = br#"{"title": "CISA Catalog", "catalogVersion": "2026.11.04", "count": 1,
        "vulnerabilities": [{"cveID": "CVE-2026-0001", "vendorProject": "Example", "product": "Widget",
        "vulnerabilityName": "x", "dateAdded": "2026-11-04", "shortDescription": "y", "requiredAction": "z",
        "dueDate": "2026-11-25", "knownRansomwareCampaignUse": "Unknown"}]}"#;
    fuzz("kev", 24, &[catalog], n, &mut |b| {
        let _ = kev::parse(b);
    });
    fuzz("epss", 25, &[epss::tests::CSV.as_bytes()], n, &mut |b| {
        let _ = epss::parse(&text(b));
    });
}

#[test]
fn fuzz_inventory_listing_csv_and_suggestions() {
    use crate::inventory::{csv, listing, opennetmon};
    let n = iterations(1500);
    fuzz(
        "listing",
        31,
        &[
            listing::tests::UBUNTU_OUT.as_bytes(),
            format!(
                "{}--- snap\nName Version Rev Tracking Publisher Notes\n\
                 lxd 5.21.3-c5ae129 33110 5.21/stable canonical** -\n\
                 --- flatpak\norg.gimp.GIMP\tGIMP\t3.0.4\tuser\n",
                listing::tests::UBUNTU_OUT
            )
            .as_bytes(),
        ],
        n,
        &mut |b| {
            let _ = listing::parse(&text(b));
        },
    );
    fuzz("csv import", 32, &[csv::EXAMPLE.as_bytes()], n, &mut |b| {
        let _ = csv::parse(&text(b), &[]);
    });
    let descr: [&[u8]; 4] = [
        b"FRITZ!Box 7590 (UI) 154.08.20",
        b"Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, RELEASE",
        b"Linux EAP653 4.4.60 #1 SMP PREEMPT armv7l",
        b"1.3.6.1.4.1.11863.5.154",
    ];
    fuzz("onm suggest", 33, &descr, n, &mut |b| {
        let t = text(b);
        let _ = opennetmon::suggest(&t, &t);
        let _ = opennetmon::suggest(&t, "1.3.6.1.4.1.11863.5.134");
    });
    fuzz("packed", 34, &[b"\x8b\x8e\x05\x00"], n, &mut |b| {
        let _ = crate::storage::packed::text(String::new(), Some(b.to_vec()));
    });
}

#[test]
fn fuzz_agent_reports() {
    use crate::web::agent_api::fuzz_report;
    let n = iterations(1500);
    let json = br#"{"schema":1,"agent":{"name":"a","version":"1"},"hostname":"pc","os":{"family":"linux","os_release":"ID=debian\nVERSION_ID=13\n"},"dpkg":"ii \tbash\t5.2\tbash\t5.2\n","items":[{"type":"snap","id":"x"}]}"#;
    let short = br#"{"schema":1,"unchanged":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}"#;
    let windows = br#"{"schema":1,"os":{"family":"windows","product_name":"Windows 10 Pro","display_version":"24H2","build":26100,"ubr":4652,"installation_type":"Client"},"items":[{"type":"win","id":"{1F1C}","name":"7-Zip 24.08 (x64)","version":"24.08","publisher":"Igor Pavlov","scope":"machine"},{"type":"appx","id":"Microsoft.WindowsTerminal_8wekyb3d8bbwe","name":"Microsoft.WindowsTerminal","version":"1.23.12811.0","publisher":"Microsoft Corporation","scope":"user"},{"type":"flatpak","id":"org.gimp.GIMP","name":"GIMP (Java 8 Update 431) [x64]","version":"v3.0.4-1"}]}"#;
    fuzz("agent json", 35, &[json, short, windows], n, &mut |b| {
        fuzz_report(true, false, b);
    });
    let plain = crate::inventory::listing::tests::UBUNTU_OUT.as_bytes();
    fuzz("agent text", 36, &[plain], n, &mut |b| {
        fuzz_report(false, false, b);
    });
    let mut z = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    std::io::Write::write_all(&mut z, json).unwrap();
    let packed = z.finish().unwrap();
    fuzz("agent gzip", 37, &[&packed], n, &mut |b| {
        fuzz_report(true, true, b);
    });
}

/// A random version-like text.
fn version_text(rng: &mut Rng) -> String {
    const PARTS: [&str; 16] = [
        "0",
        "1",
        "9",
        "10",
        "007",
        ".",
        ".",
        "-",
        ":",
        "~",
        "+",
        "p",
        "rc",
        "a",
        "ä",
        "18446744073709551617",
    ];
    (0..rng.below(12)).map(|_| *rng.pick(&PARTS)).collect()
}

#[test]
fn fuzz_versions_compare_consistently() {
    let mut rng = Rng::new(41);
    for _ in 0..iterations(20_000) {
        let a = version_text(&mut rng);
        let b = version_text(&mut rng);
        for scheme in [Scheme::Deb, Scheme::Generic] {
            let ab = compare(scheme, &a, &b);
            assert_eq!(
                ab,
                compare(scheme, &b, &a).reverse(),
                "{scheme:?} {a:?} {b:?}"
            );
            assert_eq!(compare(scheme, &a, &a), Ordering::Equal, "{scheme:?} {a:?}");
            let _ = is_version(scheme, &a);
        }
    }
    // Long inputs stay fast.
    let long = "1.".repeat(50_000);
    let started = Instant::now();
    let _ = compare(Scheme::Deb, &long, &format!("{long}1"));
    let _ = compare(Scheme::Generic, &long, &format!("{long}1"));
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn fuzz_range_checks_of_the_matching() {
    use crate::matching::{cna_verdict, nvd_verdict};
    let nvd = br#"[{"nodes": [{"operator": "OR", "cpeMatch": [
        {"vulnerable": true, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
         "versionStartIncluding": "9.0", "versionEndExcluding": "9.8p1"},
        {"vulnerable": true, "criteria": "cpe:2.3:a:openbsd:openssh:9.9:p1:*:*:*:*:*:*"}]}]}]"#;
    let cna = br#"[{"vendor": "OpenBSD", "product": "OpenSSH", "versions": [
        {"version": "9.0", "lessThan": "9.8p1", "status": "affected", "versionType": "custom"},
        {"version": "0", "lessThanOrEqual": "8.9", "status": "unaffected"},
        {"version": "9.9p1", "status": "affected", "changes": [{"at": "9.9p2", "status": "unaffected"}]}]}]"#;
    let n = iterations(1500);
    let mut rng = Rng::new(51);
    let versions: Vec<String> = (0..64).map(|_| version_text(&mut rng)).collect();
    let mut i = 0;
    fuzz("nvd verdict", 52, &[nvd], n, &mut |b| {
        if let Ok(v) = serde_json::from_slice::<Value>(b) {
            i += 1;
            for version in ["9.6p1", "", &versions[i % versions.len()]] {
                let _ = nvd_verdict(&v, "openbsd", "openssh", version);
            }
        }
    });
    fuzz("cna verdict", 53, &[cna], n, &mut |b| {
        if let Ok(v) = serde_json::from_slice::<Value>(b) {
            i += 1;
            for version in ["9.6p1", "", &versions[i % versions.len()]] {
                let _ = cna_verdict(&v, "openbsd", "openssh", version);
            }
        }
    });
}

/// A ZIP archive with one stored entry `{}` that `copies` entries of the central directory point to.
fn shared_data_zip(copies: usize) -> Vec<u8> {
    let data = b"{}";
    let mut crc = flate2::Crc::new();
    crc.update(data);
    let crc = crc.sum();
    let name = b"CVE-2026-00000.json";
    let u16le = |v: usize| (v as u16).to_le_bytes();
    let u32le = |v: u32| v.to_le_bytes();
    let mut out = Vec::new();
    out.extend_from_slice(&u32le(0x0403_4b50));
    out.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    out.extend_from_slice(&u32le(crc));
    out.extend_from_slice(&u32le(2));
    out.extend_from_slice(&u32le(2));
    out.extend_from_slice(&u16le(name.len()));
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(name);
    out.extend_from_slice(data);
    let cd_start = out.len();
    for i in 0..copies {
        let name = format!("CVE-2026-{i:05}.json");
        let name = name.as_bytes();
        out.extend_from_slice(&u32le(0x0201_4b50));
        out.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&u32le(crc));
        out.extend_from_slice(&u32le(2));
        out.extend_from_slice(&u32le(2));
        out.extend_from_slice(&u16le(name.len()));
        out.extend_from_slice(&[0; 12]);
        out.extend_from_slice(&u32le(0));
        out.extend_from_slice(name);
    }
    let cd_size = out.len() - cd_start;
    out.extend_from_slice(&u32le(0x0605_4b50));
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&u16le(copies));
    out.extend_from_slice(&u16le(copies));
    out.extend_from_slice(&u32le(cd_size as u32));
    out.extend_from_slice(&u32le(cd_start as u32));
    out.extend_from_slice(&u16le(0));
    out
}

#[test]
fn archives_whose_entries_share_data_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.zip");
    std::fs::write(&path, shared_data_zip(1)).unwrap();
    assert_eq!(crate::sources::open_archive(&path, 10).unwrap().len(), 1);
    std::fs::write(&path, shared_data_zip(3)).unwrap();
    let error = crate::sources::open_archive(&path, 10)
        .unwrap_err()
        .to_string();
    assert!(error.contains("share"), "{error}");
    assert!(
        crate::sources::open_archive(&path, 2).is_err(),
        "too many entries"
    );
}

/// Lists of empty objects (a few bytes each) stop at the budget instead of filling the memory.
#[test]
fn lists_of_empty_objects_stop_early() {
    let many = |n: usize| vec!["{}"; n].join(",");
    let doc = crate::csaf::document::tests::BSI_DOC.replacen(
        "\"product_tree\": {",
        &format!(
            "\"product_tree\": {{\"full_product_names\": [{}],",
            many(300_000)
        ),
        1,
    );
    assert_ne!(doc, crate::csaf::document::tests::BSI_DOC);
    let error = crate::csaf::document::parse(doc.as_bytes()).unwrap_err();
    assert!(error.contains("too many"), "{error}");
    let feed = format!(r#"{{"feed": {{"entry": [{}]}}}}"#, many(2_100_000));
    assert!(
        crate::csaf::parse_rolie(feed.as_bytes())
            .unwrap_err()
            .contains("too many")
    );
    let catalog = format!(r#"{{"vulnerabilities": [{}]}}"#, many(100_002));
    let error = crate::sources::kev::parse(catalog.as_bytes()).unwrap_err();
    assert!(format!("{error:#}").contains("too many"), "{error:#}");
}
