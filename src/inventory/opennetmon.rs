//! The devices of opennetmon: read from its inventory endpoint and turned into product suggestions by rules
//! over `sysDescr` and `sysObjectID`. The user takes a suggestion over (it becomes an asset that follows
//! the device), changes it, or skips the device.
//!
//! The endpoint (to be built in opennetmon; the contract is noted in its CLAUDE.md):
//!
//! ```text
//! GET <base>/api/v1/inventory
//! Authorization: Bearer <token>
//!
//! {"devices": [{"id": 17, "name": "Router", "address": "192.0.2.1",
//!               "sys_descr": "…", "sys_object_id": "1.3.6.1.4.1.…"}]}
//! ```
//!
//! Unknown fields are ignored; texts are limited and cleaned, never interpreted.

use std::time::Duration;

use serde::Deserialize;
use sqlx::SqlitePool;

use crate::crypto::SecretBox;
use crate::error::Result;
use crate::http_client::{self, Get, Outcome};
use crate::inventory::runner::error_text;
use crate::sources::now_ms;
use crate::storage::assets::{self, Input};
use crate::storage::inventory::{self, OnmDevice};

/// How often opennetmon is read.
pub const INTERVAL_MS: i64 = 6 * 3600 * 1000;
/// Most bytes of an answer.
const MAX_BYTES: u64 = 4 * 1024 * 1024;
/// Most devices taken.
const MAX_DEVICES: usize = 5_000;
const TIMEOUT: Duration = Duration::from_secs(30);
/// The path of the endpoint below the address of opennetmon.
pub const PATH: &str = "/api/v1/inventory";

/// The rules of [`suggest`] ('' = none matched).
pub const RULES: [&str; 9] = [
    "",
    "linux",
    "avm",
    "avm-model",
    "cisco-ios",
    "mikrotik",
    "tp-link",
    "huawei",
    "enterprise",
];

/// The id of the text that names a rule.
pub fn rule_label_id(rule: &str) -> &'static str {
    match rule {
        "avm" | "avm-model" => "onm-rule-avm",
        "cisco-ios" => "onm-rule-cisco",
        "mikrotik" => "onm-rule-mikrotik",
        "tp-link" => "onm-rule-tp-link",
        "huawei" => "onm-rule-huawei",
        "enterprise" => "onm-rule-enterprise",
        "linux" => "onm-rule-linux",
        _ => "onm-rule-none",
    }
}

/// Checks the address of opennetmon: HTTPS, or plain HTTP only on this machine (the token must not
/// cross the network in clear). Returns it without a trailing slash.
pub fn check_url(url: &str) -> std::result::Result<String, &'static str> {
    let url = url.trim().trim_end_matches('/');
    let target = http_client::parse_url(url).map_err(|_| "onm-error-url")?;
    if !target.tls {
        let host = target.host.to_ascii_lowercase();
        let loopback = host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback());
        if !loopback {
            return Err("onm-error-http");
        }
    }
    if url.contains('?') || url.contains('#') {
        return Err("onm-error-url");
    }
    Ok(url.to_owned())
}

/// Checks the fingerprint of opennetmon's certificate for the address `url` (already checked): empty, or
/// SHA-256 in hex, then returned as `AB:CD:…`. Only for HTTPS.
pub fn check_pin(url: &str, pin: &str) -> std::result::Result<String, &'static str> {
    let pin = pin.trim();
    if pin.is_empty() {
        return Ok(String::new());
    }
    let sha = http_client::parse_fingerprint(pin).ok_or("onm-error-pin")?;
    if !url.starts_with("https://") {
        return Err("onm-error-pin-http");
    }
    Ok(http_client::format_fingerprint(&sha))
}

#[derive(Debug, Deserialize)]
struct Answer {
    devices: Vec<RawDevice>,
}

#[derive(Debug, Deserialize)]
struct RawDevice {
    id: i64,
    #[serde(default)]
    name: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    sys_descr: String,
    #[serde(default)]
    sys_object_id: String,
}

fn clean(text: &str, max: usize) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(max)
        .collect()
}

/// What the rules make of a device.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Suggestion {
    pub kind: &'static str,
    pub vendor: String,
    pub product: String,
    pub version: String,
    /// The rule that matched ('' = none).
    pub rule: &'static str,
    /// Product and version are certain (the version comes from the device).
    pub sure: bool,
}

/// The first run of characters in `text` that look like a version (`8.20`, `15.0(2)SE11`, `1.2.3`).
fn version_after<'a>(text: &'a str, marker: &str) -> Option<&'a str> {
    let at = text.find(marker)? + marker.len();
    let rest = text[at..].trim_start();
    let end = rest
        .find(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .unwrap_or(rest.len());
    let v = &rest[..end];
    v.starts_with(|c: char| c.is_ascii_digit()).then_some(v)
}

/// The vendor of an SNMP enterprise number (`1.3.6.1.4.1.<n>…`).
fn enterprise_vendor(oid: &str) -> Option<&'static str> {
    let rest = oid.trim_start_matches('.').strip_prefix("1.3.6.1.4.1.")?;
    let number = rest.split('.').next()?;
    Some(match number {
        "9" => "Cisco",
        "11" => "HP",
        "311" => "Microsoft",
        "872" => "AVM",
        "2011" => "Huawei",
        "2636" => "Juniper",
        "4413" => "Broadcom",
        "6574" => "Synology",
        "11863" => "TP-Link",
        "12356" => "Fortinet",
        "14988" => "MikroTik",
        "25461" => "Palo Alto Networks",
        "41112" => "Ubiquiti",
        _ => return None,
    })
}

/// The product suggestion for a device.
pub fn suggest(sys_descr: &str, sys_object_id: &str) -> Suggestion {
    let d = sys_descr;
    let lower = d.to_ascii_lowercase();
    // AVM FRITZ!Box: "FRITZ!Box 7590 (UI) 154.08.20": the firmware is FRITZ!OS 8.20 (the first part
    // names the hardware).
    if let Some(at) = d.find("FRITZ!Box") {
        let model = d[at..].split_whitespace().nth(1).unwrap_or_default();
        let version = d
            .split_whitespace()
            .rev()
            .find(|w| w.matches('.').count() == 2 && w.starts_with(|c: char| c.is_ascii_digit()))
            .and_then(|w| w.split_once('.'))
            .map(|(_, v)| v.trim_start_matches('0').to_owned())
            .unwrap_or_default();
        return Suggestion {
            kind: "hardware",
            vendor: "AVM".into(),
            product: "FRITZ!OS".into(),
            sure: !version.is_empty(),
            version,
            rule: if model.is_empty() { "avm" } else { "avm-model" },
        };
    }
    // Cisco IOS / IOS XE: "Cisco IOS Software, C2960 Software (…), Version 15.0(2)SE11, RELEASE …".
    if d.contains("Cisco IOS") {
        let product = if d.contains("IOS XE") || d.contains("IOS-XE") {
            "IOS XE"
        } else {
            "IOS"
        };
        let version = version_after(d, "Version").unwrap_or_default().to_owned();
        return Suggestion {
            kind: "software",
            vendor: "Cisco".into(),
            product: product.into(),
            sure: !version.is_empty(),
            version,
            rule: "cisco-ios",
        };
    }
    // MikroTik: "RouterOS CCR1009-7G-1C-1S+" (version not in sysDescr).
    if d.starts_with("RouterOS") {
        return Suggestion {
            kind: "software",
            vendor: "MikroTik".into(),
            product: "RouterOS".into(),
            version: String::new(),
            rule: "mikrotik",
            sure: false,
        };
    }
    // TP-Link Omada / JetStream: the model ("ER605 v2.0", "Linux EAP653 4.4.60 …" on the access points and
    // routers), else the model of the sysObjectID (the switches only name the series: "Omada 8-Port Gigabit
    // Smart Switch"); the firmware is not in sysDescr.
    let vendor = enterprise_vendor(sys_object_id);
    let words: Vec<&str> = d.split_whitespace().collect();
    let linux_model =
        words.first() == Some(&"Linux") && words.get(1).is_some_and(|w| tp_link_model(w));
    if vendor == Some("TP-Link")
        || lower.contains("jetstream")
        || lower.contains("omada")
        || linux_model
        || lower.starts_with("er605")
        || lower.starts_with("eap")
        || lower.starts_with("tl-")
    {
        let model = words
            .iter()
            .take(2)
            .find(|w| tp_link_model(w))
            .map(|w| (*w).to_owned())
            .or_else(|| tp_link_model_of(sys_object_id).map(str::to_owned))
            .unwrap_or_default();
        return Suggestion {
            kind: "hardware",
            vendor: "TP-Link".into(),
            product: model,
            version: String::new(),
            rule: "tp-link",
            sure: false,
        };
    }
    if vendor == Some("Huawei") || lower.contains("huawei") {
        return Suggestion {
            kind: "hardware",
            vendor: "Huawei".into(),
            product: clean(d.trim_start_matches("Huawei").trim(), 60),
            version: String::new(),
            rule: "huawei",
            sure: false,
        };
    }
    // Other enterprise numbers: at least the vendor.
    if let Some(v) = vendor {
        return Suggestion {
            kind: "hardware",
            vendor: v.into(),
            product: String::new(),
            version: String::new(),
            rule: "enterprise",
            sure: false,
        };
    }
    // A Linux host with Net-SNMP (a server, a Raspberry Pi, a NAS): its packages are read over SSH, the
    // kernel of sysDescr alone would bring every kernel CVE.
    if words.first() == Some(&"Linux")
        || sys_object_id
            .trim_start_matches('.')
            .starts_with("1.3.6.1.4.1.8072.")
    {
        return Suggestion {
            kind: "hardware",
            rule: "linux",
            ..Default::default()
        };
    }
    Suggestion {
        kind: "hardware",
        ..Default::default()
    }
}

/// A TP-Link model name: "ER605", "EAP653", "SG2008P", "TL-SG108E" (letters, then a digit).
fn tp_link_model(word: &str) -> bool {
    let w = word.strip_prefix("TL-").unwrap_or(word);
    let letters = w.chars().take_while(|c| c.is_ascii_uppercase()).count();
    (1..=4).contains(&letters)
        && w[letters..].starts_with(|c: char| c.is_ascii_digit())
        && w.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
}

/// The model of a TP-Link sysObjectID, for switches whose sysDescr names only the series (seen on
/// Omada switches; more as they turn up).
fn tp_link_model_of(oid: &str) -> Option<&'static str> {
    Some(match oid.trim_start_matches('.') {
        "1.3.6.1.4.1.11863.5.134" => "SG2008",
        "1.3.6.1.4.1.11863.5.154" => "SG2008P",
        _ => return None,
    })
}

/// Reads the devices from opennetmon and stores them with their suggestions; taken devices whose
/// version the rules know get the new version (and are matched again).
pub async fn read(
    pool: &SqlitePool,
    secrets: &SecretBox,
) -> Result<std::result::Result<usize, String>> {
    let settings = inventory::onm_settings(pool).await?;
    let Some(token) = inventory::onm_token(pool, secrets).await? else {
        return Ok(Err("onm-error-no-token".into()));
    };
    let url = format!("{}{PATH}", settings.url);
    let bearer = format!("Bearer {}", token.expose());
    let mut get = Get::new(&url, MAX_BYTES, TIMEOUT)
        .accept("application/json")
        .authorization(&bearer)
        .local_network();
    if let Some(sha) = http_client::parse_fingerprint(&settings.cert_sha256) {
        get = get.pinned_cert(sha);
    }
    let now = now_ms();
    let body = match http_client::get_bytes(&get).await {
        Ok(Outcome::Fresh(f)) => f.body,
        Ok(Outcome::NotModified) => {
            inventory::record_onm(pool, "", now).await?;
            return Ok(Ok(0));
        }
        Err(e) => {
            let text = match e {
                http_client::HttpError::Status(401 | 403) => "onm-error-token".to_owned(),
                http_client::HttpError::Status(404) => "onm-error-missing".to_owned(),
                http_client::HttpError::RedirectRefused(to) => {
                    error_text("onm-error-redirect", &clean(&to, 200))
                }
                http_client::HttpError::Untrusted {
                    fingerprint,
                    pinned,
                    ..
                } => error_text(
                    if pinned {
                        "onm-error-pin-mismatch"
                    } else {
                        "onm-error-cert"
                    },
                    &fingerprint,
                ),
                e => error_text("onm-error-fetch", &clean(&e.to_string(), 300)),
            };
            inventory::record_onm(pool, &text, now).await?;
            return Ok(Err(text));
        }
    };
    let answer: Answer = match serde_json::from_slice(&body) {
        Ok(a) => a,
        Err(e) => {
            let text = error_text("onm-error-format", &clean(&e.to_string(), 200));
            inventory::record_onm(pool, &text, now).await?;
            return Ok(Err(text));
        }
    };
    let devices: Vec<OnmDevice> = answer
        .devices
        .into_iter()
        .filter(|d| d.id > 0)
        .take(MAX_DEVICES)
        .map(|d| {
            let sys_descr = clean(&d.sys_descr, 500);
            let sys_object_id = clean(&d.sys_object_id, 100);
            let s = suggest(&sys_descr, &sys_object_id);
            OnmDevice {
                id: d.id,
                name: clean(&d.name, 100),
                address: clean(&d.address, 100),
                sys_descr,
                sys_object_id,
                vendor_name: s.vendor,
                product_name: s.product,
                version: s.version,
                kind: s.kind.to_owned(),
                rule: s.rule.to_owned(),
                sure: s.sure,
                state: "new".into(),
                asset_id: None,
                seen_ms: now,
            }
        })
        .collect();
    inventory::store_onm_devices(pool, &devices, now).await?;
    inventory::record_onm(pool, "", now).await?;
    // Taken devices follow their firmware.
    let mut changed = Vec::new();
    for d in inventory::onm_devices(pool).await? {
        let (Some(asset_id), true, false) = (d.asset_id, d.sure, d.version.is_empty()) else {
            continue;
        };
        if let Some(a) = assets::get(pool, asset_id).await?
            && a.origin_ref == format!("onm:{}", d.id)
            && a.version != d.version
        {
            let input = Input {
                kind: a.kind.clone(),
                vendor_name: a.vendor_name.clone(),
                product_name: a.product_name.clone(),
                version: d.version.clone(),
                host: a.host.clone(),
                cpe: a.cpe.clone(),
                distro: a.distro.clone(),
                release: a.release.clone(),
                pro: a.pro,
                note: a.note.clone(),
            };
            if let Ok(checked) = input.check() {
                assets::update(pool, a.id, &checked, now).await?;
                changed.push(a.id);
            }
        }
    }
    crate::matching::match_assets(pool, &changed, now).await?;
    tracing::info!(
        devices = devices.len(),
        updated = changed.len(),
        "opennetmon read"
    );
    Ok(Ok(devices.len()))
}

/// Reads opennetmon if it is set up and due.
pub async fn run_due(pool: &SqlitePool, secrets: &SecretBox) -> Result<()> {
    let s = inventory::onm_settings(pool).await?;
    if s.url.is_empty() || !s.has_token {
        return Ok(());
    }
    if s.last_ms.is_some_and(|last| now_ms() < last + INTERVAL_MS) {
        return Ok(());
    }
    // A failed reading is stored with the settings and shown on the page.
    let _ = read(pool, secrets).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_https_or_local_http() {
        assert_eq!(
            check_url(" https://onm.example.org/ "),
            Ok("https://onm.example.org".to_owned())
        );
        assert_eq!(
            check_url("http://127.0.0.1:8080"),
            Ok("http://127.0.0.1:8080".into())
        );
        assert_eq!(
            check_url("http://localhost:8080/onm"),
            Ok("http://localhost:8080/onm".into())
        );
        assert_eq!(
            check_url("http://[::1]:8080"),
            Ok("http://[::1]:8080".into())
        );
        assert_eq!(check_url("http://192.168.1.2:8080"), Err("onm-error-http"));
        assert_eq!(check_url("ftp://x"), Err("onm-error-url"));
        assert_eq!(check_url("https://user:pw@x"), Err("onm-error-url"));
        assert_eq!(check_url("https://x/?a=1"), Err("onm-error-url"));
    }

    #[test]
    fn pins_are_checked_and_written_alike() {
        let hex = "97b14560".repeat(8);
        let colons =
            http_client::format_fingerprint(&http_client::parse_fingerprint(&hex).unwrap());
        let https = "https://127.0.0.1:8443";
        assert_eq!(check_pin(https, ""), Ok(String::new()));
        assert_eq!(check_pin(https, &hex), Ok(colons.clone()));
        assert_eq!(
            check_pin(https, &format!(" {} ", colons.to_lowercase())),
            Ok(colons)
        );
        assert_eq!(check_pin(https, "97:B1"), Err("onm-error-pin"));
        assert_eq!(
            check_pin("http://127.0.0.1:8080", &hex),
            Err("onm-error-pin-http")
        );
    }

    #[test]
    fn rules_suggest_products() {
        let s = suggest("FRITZ!Box 7590 (UI) 154.08.20", "");
        assert_eq!(
            (
                s.vendor.as_str(),
                s.product.as_str(),
                s.version.as_str(),
                s.sure
            ),
            ("AVM", "FRITZ!OS", "8.20", true)
        );
        let s = suggest(
            "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)",
            "1.3.6.1.4.1.9.1.1208",
        );
        assert_eq!(
            (
                s.vendor.as_str(),
                s.product.as_str(),
                s.version.as_str(),
                s.sure
            ),
            ("Cisco", "IOS", "15.0(2)SE11", true)
        );
        let s = suggest(
            "JetStream 8-Port Gigabit L2+ Managed Switch with 8-Port PoE+",
            "",
        );
        assert_eq!((s.vendor.as_str(), s.sure), ("TP-Link", false));
        let s = suggest("ER605 v2.0", "1.3.6.1.4.1.11863.5.1");
        assert_eq!(
            (s.vendor.as_str(), s.product.as_str()),
            ("TP-Link", "ER605")
        );
        let s = suggest("Linux gw 4.4.198 #1 SMP armv7l", "1.3.6.1.4.1.8072.3.2.10");
        assert_eq!(
            (s.rule, s.vendor.as_str(), s.product.as_str()),
            ("linux", "", "")
        );
        // Omada: the model after "Linux" (access points, routers with Net-SNMP), else from the sysObjectID.
        let tp = |d: &str, oid: &str| {
            let s = suggest(d, oid);
            (s.rule, s.vendor, s.product)
        };
        let tp_link = |p: &str| ("tp-link", "TP-Link".to_owned(), p.to_owned());
        assert_eq!(
            tp(
                "Linux ER605 3.10.108 #1 SMP Thu Oct 30 04:37:01 CST 2025 mips",
                "1.3.6.1.4.1.8072.3.2.10"
            ),
            tp_link("ER605")
        );
        assert_eq!(
            tp(
                "Linux EAP653 4.4.60 #1 SMP PREEMPT armv7l",
                "1.3.6.1.4.1.11863.10.1"
            ),
            tp_link("EAP653")
        );
        assert_eq!(
            tp(
                "Omada 8-Port Gigabit Smart Switch with 4-Port PoE+",
                "1.3.6.1.4.1.11863.5.154"
            ),
            tp_link("SG2008P")
        );
        assert_eq!(
            tp(
                "Omada 8-Port Gigabit Smart Switch",
                "1.3.6.1.4.1.11863.5.99"
            ),
            tp_link("")
        );
        assert_eq!(tp("TL-SG108E 6.0", ""), tp_link("TL-SG108E"));
        assert_eq!(
            tp(
                "Linux pi 6.18.39+rpt-rpi-v8 #1 SMP PREEMPT Debian aarch64",
                "1.3.6.1.4.1.8072.3.2.10"
            )
            .0,
            "linux"
        );
        let s = suggest("something", ".1.3.6.1.4.1.14988.1");
        assert_eq!((s.rule, s.vendor.as_str()), ("enterprise", "MikroTik"));
    }

    #[test]
    fn answers_are_read_leniently() {
        let a: Answer = serde_json::from_str(
            r#"{"version": 1, "devices": [{"id": 3, "name": "fw", "extra": true},
                {"id": 4, "name": "sw", "sys_descr": "x\u001b[2Jy", "address": "192.0.2.4"}]}"#,
        )
        .unwrap();
        assert_eq!(a.devices.len(), 2);
        assert_eq!(clean(&a.devices[1].sys_descr, 50), "x [2Jy");
    }
    /// A small opennetmon on this machine that answers with `body` for the right token.
    async fn fake_onm(body: &'static str) -> String {
        use axum::http::{HeaderMap, StatusCode};
        let app = axum::Router::new().route(
            PATH,
            axum::routing::get(move |headers: HeaderMap| async move {
                let ok = headers
                    .get("authorization")
                    .is_some_and(|v| v.as_bytes() == b"Bearer t0ken");
                if ok {
                    (StatusCode::OK, body)
                } else {
                    (StatusCode::UNAUTHORIZED, "")
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn devices_are_read_suggested_and_followed() {
        use crate::crypto::Secret;
        let dir = tempfile::tempdir().unwrap();
        let pool = crate::storage::connect(&dir.path().join("o.db"))
            .await
            .unwrap();
        crate::storage::migrate(&pool).await.unwrap();
        let secrets = SecretBox::from_key([5; 32]);
        assert_eq!(
            read(&pool, &secrets).await.unwrap(),
            Err("onm-error-no-token".into())
        );
        let url = fake_onm(
            r#"{"devices": [
                {"id": 1, "name": "fritz", "address": "192.0.2.1",
                 "sys_descr": "FRITZ!Box 7590 AX (UI) 287.08.20", "sys_object_id": ""},
                {"id": 2, "name": "linux", "sys_descr": "Linux pi 6.12", "sys_object_id": "1.3.6.1.4.1.8072.3.2.10"},
                {"id": 0, "name": "invalid"}]}"#,
        )
        .await;
        inventory::save_onm(&pool, &secrets, &url, "", Some(&Secret::new("wrong")))
            .await
            .unwrap();
        assert_eq!(
            read(&pool, &secrets).await.unwrap(),
            Err("onm-error-token".into())
        );
        assert_eq!(
            inventory::onm_settings(&pool).await.unwrap().error,
            "onm-error-token"
        );
        inventory::save_onm(&pool, &secrets, &url, "", Some(&Secret::new("t0ken")))
            .await
            .unwrap();
        assert_eq!(read(&pool, &secrets).await.unwrap(), Ok(2));
        let devices = inventory::onm_devices(&pool).await.unwrap();
        assert_eq!(devices.len(), 2);
        let fritz = devices.iter().find(|d| d.id == 1).unwrap();
        assert!(fritz.sure, "{fritz:?}");
        assert_eq!(fritz.state, "new");
        // Taken with an older version: the next reading brings the asset to the device's version.
        let checked = Input {
            kind: fritz.kind.clone(),
            vendor_name: fritz.vendor_name.clone(),
            product_name: fritz.product_name.clone(),
            version: "7.00".into(),
            host: fritz.name.clone(),
            ..Default::default()
        }
        .check()
        .unwrap();
        let asset_id = assets::add_from(&pool, &checked, "opennetmon", "onm:1", 1)
            .await
            .unwrap();
        inventory::set_onm_state(&pool, 1, "taken", Some(asset_id))
            .await
            .unwrap();
        assert_eq!(read(&pool, &secrets).await.unwrap(), Ok(2));
        let a = assets::get(&pool, asset_id).await.unwrap().unwrap();
        assert_eq!(a.version, fritz.version);
        // A wrong address is an error for the page, not for the loop.
        inventory::save_onm(&pool, &secrets, "http://127.0.0.1:1", "", None)
            .await
            .unwrap();
        let Err(text) = read(&pool, &secrets).await.unwrap() else {
            panic!("read from a closed port");
        };
        assert!(text.starts_with("onm-error-fetch\t"), "{text}");
        assert_eq!(inventory::onm_devices(&pool).await.unwrap().len(), 2);
    }
}
