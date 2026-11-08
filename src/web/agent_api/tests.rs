//! The agent API with the pages of the computers: enrollment, status, the allowed networks, malformed
//! requests, the throttle, revoking and removing.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};

use crate::storage::agents;
use crate::web::testutil::*;

const LAN: &str = "192.168.1.20:50000";

fn api(method: &str, path: &str, from: Option<&str>) -> axum::http::request::Builder {
    let mut b = Request::builder().method(method).uri(path);
    if let Some(addr) = from {
        b = b.extension(ConnectInfo(addr.parse::<SocketAddr>().unwrap()));
    }
    b
}

fn enroll_request(from: Option<&str>, body: &str) -> Request<Body> {
    api("POST", "/api/v1/agent/enroll", from)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

fn enroll_body(code: &str) -> String {
    format!(
        r#"{{"schema":1,"code":"{code}","hostname":"zorin-laptop","agent":{{"name":"curl-script","version":"1"}}}}"#
    )
}

fn status_request(from: Option<&str>, token: Option<&str>) -> Request<Body> {
    let mut b = api("GET", "/api/v1/agent/status", from);
    if let Some(token) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    b.body(Body::empty()).unwrap()
}

fn json(reply: &Reply) -> serde_json::Value {
    assert_eq!(
        reply.headers[header::CONTENT_TYPE],
        "application/json",
        "{}",
        reply.body
    );
    serde_json::from_str(&reply.body).unwrap()
}

fn error_code(reply: &Reply) -> String {
    json(reply)["error"].as_str().unwrap().to_owned()
}

/// Adds a computer on the page and returns its id and the code the page shows.
async fn add_computer(h: &Harness, session: &str, csrf: &str, name: &str) -> (i64, String) {
    let form = format!("csrf_token={csrf}&name={name}");
    let reply = send(&h.app, post("/assets/computers/new", Some(session), &form)).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    let id: i64 = reply
        .location()
        .rsplit('/')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let page = send(
        &h.app,
        get(&format!("/assets/computers/{id}"), Some(session)),
    )
    .await;
    assert_eq!(page.status, StatusCode::OK);
    let code = page
        .body
        .split("<b class=\"mono\">")
        .nth(1)
        .unwrap()
        .split('<')
        .next()
        .unwrap()
        .to_owned();
    assert_eq!(code.len(), 9, "{code}");
    (id, code)
}

fn with_state(h: &Harness, change: impl FnOnce(&mut crate::web::AppState)) -> Router {
    let mut state = h.state.clone();
    change(&mut state);
    crate::web::router(state)
}

#[tokio::test]
async fn a_computer_is_enrolled_with_its_code_and_then_known_by_its_token() {
    let h = harness(true).await;
    let (session, csrf) = login(&h, "anna").await;
    let list = send(&h.app, get("/assets/computers", Some(&session))).await;
    assert!(list.body.contains("Noch keine Rechner"));
    let (id, code) = add_computer(&h, &session, &csrf, "laptop").await;
    let page = send(
        &h.app,
        get(&format!("/assets/computers/{id}"), Some(&session)),
    )
    .await;
    assert!(page.body.contains("wartet auf Anmeldung"));
    assert!(page.body.contains("/api/v1/agent/enroll"));
    assert!(!page.body.contains("--cacert"), "no built-in HTTPS here");

    // Lower case and without the dash works too.
    let typed = code.replace('-', "").to_lowercase();
    let reply = send(&h.app, enroll_request(Some(LAN), &enroll_body(&typed))).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    let answer = json(&reply);
    assert_eq!(answer["device"], "laptop");
    assert_eq!(answer["report_interval_s"], 21600);
    let token = answer["token"].as_str().unwrap().to_owned();
    assert!(token.starts_with("osm1_"));
    let stored = agents::device(&h.state.pool, id).await.unwrap().unwrap();
    assert!(!stored.token_hash.contains(&token) && stored.token_hash.len() == 64);

    let reply = send(&h.app, status_request(Some(LAN), Some(&token))).await;
    assert_eq!(reply.status, StatusCode::OK);
    let answer = json(&reply);
    assert_eq!(answer["device"], "laptop");
    assert!(answer["last_report"].is_null());
    assert_eq!(answer["next_report_s"], 21600);

    // The page shows what the computer said, and no longer the code.
    let page = send(
        &h.app,
        get(&format!("/assets/computers/{id}"), Some(&session)),
    )
    .await;
    assert!(page.body.contains("angemeldet") && page.body.contains("zorin-laptop"));
    assert!(page.body.contains("curl-script 1"));
    assert!(!page.body.contains(&code));
    let audit = send(&h.app, get("/settings/audit", Some(&session))).await;
    assert!(
        audit.body.contains("agent:laptop"),
        "the enrollment is in the audit log"
    );
    assert!(!audit.body.contains(&token) && !audit.body.contains(&code));

    // The code works once.
    let reply = send(&h.app, enroll_request(Some(LAN), &enroll_body(&code))).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(error_code(&reply), "invalid_code");

    // Revoked: the token stops working at once.
    let form = format!("csrf_token={csrf}");
    let reply = send(
        &h.app,
        post(
            &format!("/assets/computers/{id}/revoke"),
            Some(&session),
            &form,
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    let reply = send(&h.app, status_request(Some(LAN), Some(&token))).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(error_code(&reply), "invalid_token");

    // A new code enrolls it again with a new token.
    let reply = send(
        &h.app,
        post(
            &format!("/assets/computers/{id}/code"),
            Some(&session),
            &form,
        ),
    )
    .await;
    assert_eq!(
        reply.location(),
        format!("/assets/computers/{id}?msg=computer_code")
    );
    let d = agents::device(&h.state.pool, id).await.unwrap().unwrap();
    let code = agents::shown_code(&h.state.secrets, &d, crate::web::audit::now_ms()).unwrap();
    let reply = send(&h.app, enroll_request(Some(LAN), &enroll_body(&code))).await;
    assert_eq!(reply.status, StatusCode::CREATED);
    let token2 = json(&reply)["token"].as_str().unwrap().to_owned();
    assert_ne!(token, token2);
    let reply = send(&h.app, status_request(Some(LAN), Some(&token2))).await;
    assert_eq!(reply.status, StatusCode::OK);

    // Removed: gone from the list, the token is dead.
    let reply = send(
        &h.app,
        post(
            &format!("/assets/computers/{id}/delete"),
            Some(&session),
            &form,
        ),
    )
    .await;
    assert_eq!(reply.location(), "/assets/computers?msg=computer_deleted");
    let reply = send(&h.app, status_request(Some(LAN), Some(&token2))).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn only_the_allowed_networks_reach_the_api() {
    let h = harness(true).await;
    for from in [Some("203.0.113.5:4000"), None] {
        let reply = send(&h.app, enroll_request(from, &enroll_body("K7FQ-29XM"))).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{from:?}");
        assert_eq!(error_code(&reply), "network_not_allowed");
        let reply = send(&h.app, status_request(from, Some("osm1_x"))).await;
        assert_eq!(error_code(&reply), "network_not_allowed");
    }
    // IPv4 as the dual-stack listener sees it.
    let reply = send(
        &h.app,
        enroll_request(
            Some("[::ffff:192.168.1.20]:4000"),
            &enroll_body("K7FQ-29XM"),
        ),
    )
    .await;
    assert_eq!(error_code(&reply), "invalid_code");

    let off = with_state(&h, |s| s.agent_networks = Arc::from([]));
    let reply = send(&off, enroll_request(Some(LAN), &enroll_body("K7FQ-29XM"))).await;
    assert_eq!(error_code(&reply), "network_not_allowed");
    let lan_only = with_state(&h, |s| {
        s.agent_networks = Arc::from([crate::agent::Network::parse("10.1.0.0/16").unwrap()]);
    });
    let reply = send(
        &lan_only,
        enroll_request(Some(LAN), &enroll_body("K7FQ-29XM")),
    )
    .await;
    assert_eq!(error_code(&reply), "network_not_allowed");
    let reply = send(
        &lan_only,
        enroll_request(Some("10.1.2.3:1"), &enroll_body("K7FQ-29XM")),
    )
    .await;
    assert_eq!(error_code(&reply), "invalid_code");
}

#[tokio::test]
async fn malformed_requests_get_a_json_error() {
    let h = harness(true).await;
    let cases: [(&str, &str, StatusCode, &str); 7] = [
        (
            "application/json",
            "{",
            StatusCode::BAD_REQUEST,
            "bad_request",
        ),
        (
            "application/json",
            r#"{"code":"K7FQ-29XM"}"#,
            StatusCode::BAD_REQUEST,
            "bad_request",
        ),
        (
            "application/json",
            r#"{"schema":2,"code":"K7FQ-29XM"}"#,
            StatusCode::BAD_REQUEST,
            "unsupported_schema",
        ),
        (
            "application/json",
            r#"{"schema":1}"#,
            StatusCode::BAD_REQUEST,
            "bad_request",
        ),
        (
            "application/json",
            r#"{"schema":1,"code":"K7FQ-29XM","hostname":"a\u0007b"}"#,
            StatusCode::BAD_REQUEST,
            "bad_request",
        ),
        (
            "text/plain",
            r#"{"schema":1,"code":"K7FQ-29XM"}"#,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
        ),
        (
            "application/x-www-form-urlencoded",
            "code=K7FQ-29XM",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
        ),
    ];
    for (content_type, body, status, code) in cases {
        let request = api("POST", "/api/v1/agent/enroll", Some(LAN))
            .header(header::CONTENT_TYPE, content_type)
            // A browser asking for a page still gets the JSON error, not an error page.
            .header(header::ACCEPT, "text/html")
            .body(Body::from(body.to_owned()))
            .unwrap();
        let reply = send(&h.app, request).await;
        assert_eq!(reply.status, status, "{body}");
        assert_eq!(error_code(&reply), code, "{body}");
    }
    let big = format!(
        r#"{{"schema":1,"code":"K7FQ-29XM","hostname":"{}"}}"#,
        "a".repeat(20_000)
    );
    let reply = send(&h.app, enroll_request(Some(LAN), &big)).await;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(error_code(&reply), "too_large");
    let long = format!(
        r#"{{"schema":1,"code":"K7FQ-29XM","hostname":"{}"}}"#,
        "a".repeat(254)
    );
    let reply = send(&h.app, enroll_request(Some(LAN), &long)).await;
    assert_eq!(error_code(&reply), "bad_request");

    // Status: no token, a malformed one, and the session cookie of a signed-in user do not count.
    let (session, _) = login(&h, "anna").await;
    for token in [None, Some("osm1_short"), Some("not-a-token")] {
        let reply = send(&h.app, status_request(Some(LAN), token)).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{token:?}");
        assert_eq!(error_code(&reply), "invalid_token");
    }
    let mut request = status_request(Some(LAN), None);
    request
        .headers_mut()
        .insert(header::COOKIE, session.parse().unwrap());
    let reply = send(&h.app, request).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_codes_are_throttled() {
    let h = harness(true).await;
    let mut statuses = Vec::new();
    for _ in 0..6 {
        let reply = send(&h.app, enroll_request(Some(LAN), &enroll_body("AAAA-AAAA"))).await;
        statuses.push(reply.status);
        if reply.status == StatusCode::TOO_MANY_REQUESTS {
            assert_eq!(error_code(&reply), "too_many_requests");
            let wait: i64 = reply.headers[header::RETRY_AFTER]
                .to_str()
                .unwrap()
                .parse()
                .unwrap();
            assert!(wait >= 1);
        }
    }
    assert_eq!(statuses[..5], [StatusCode::UNAUTHORIZED; 5]);
    assert_eq!(statuses[5], StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn the_pages_check_names_and_offer_the_certificate() {
    let h = harness(true).await;
    let (session, csrf) = login(&h, "anna").await;
    let (id, _) = add_computer(&h, &session, &csrf, "laptop").await;
    let (other, _) = add_computer(&h, &session, &csrf, "desktop").await;

    // Names: the rule of the hosts, unique among hosts and computers.
    let reply = send(
        &h.app,
        post(
            "/assets/computers/new",
            Some(&session),
            &format!("csrf_token={csrf}&name=a%20b"),
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.contains("Der Name darf nur"));
    let reply = send(
        &h.app,
        post(
            "/assets/computers/new",
            Some(&session),
            &format!("csrf_token={csrf}&name=laptop"),
        ),
    )
    .await;
    assert!(
        reply
            .body
            .contains("Ein Host oder Rechner mit diesem Namen")
    );
    let reply = send(
        &h.app,
        post(
            &format!("/assets/computers/{other}"),
            Some(&session),
            &format!("csrf_token={csrf}&name=laptop"),
        ),
    )
    .await;
    assert!(
        reply
            .body
            .contains("Ein Host oder Rechner mit diesem Namen")
    );
    let reply = send(
        &h.app,
        post(
            &format!("/assets/computers/{other}"),
            Some(&session),
            &format!("csrf_token={csrf}&name=pc-wohnzimmer"),
        ),
    )
    .await;
    assert_eq!(
        reply.location(),
        format!("/assets/computers/{other}?msg=computer_saved")
    );
    let list = send(&h.app, get("/assets/computers", Some(&session))).await;
    assert!(list.body.contains("pc-wohnzimmer") && list.body.contains("laptop"));
    // Without the CSRF token nothing happens.
    let reply = send(
        &h.app,
        post(
            &format!("/assets/computers/{id}/delete"),
            Some(&session),
            "csrf_token=x",
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);

    // Without built-in HTTPS there is no certificate to download.
    let reply = send(
        &h.app,
        get("/assets/computers/opensecmon.pem", Some(&session)),
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    let cert = crate::tls::PublicCertificate {
        pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".to_owned(),
        fingerprint: "AB:CD:EF".to_owned(),
    };
    let app = with_state(&h, |s| s.tls_certificate = Some(Arc::new(cert)));
    let reply = send(
        &app,
        get("/assets/computers/opensecmon.pem", Some(&session)),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(
        reply.headers[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap()
            .contains("opensecmon.pem")
    );
    let reply = send(
        &app,
        get(&format!("/assets/computers/{id}"), Some(&session)),
    )
    .await;
    assert!(reply.body.contains("AB:CD:EF") && reply.body.contains("--cacert opensecmon.pem"));
    // Not signed in: no pages.
    let reply = send(&app, get("/assets/computers/opensecmon.pem", None)).await;
    assert_ne!(reply.status, StatusCode::OK);
}

// ---- Reports (step 3) ----

/// Adds a computer and enrolls it; returns its id and token.
async fn enrolled(h: &Harness, session: &str, csrf: &str, name: &str) -> (i64, String) {
    let (id, code) = add_computer(h, session, csrf, name).await;
    let reply = send(&h.app, enroll_request(Some(LAN), &enroll_body(&code))).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    (id, json(&reply)["token"].as_str().unwrap().to_owned())
}

fn report_request(token: Option<&str>, content_type: &str, body: impl Into<Body>) -> Request<Body> {
    let mut b =
        api("POST", "/api/v1/agent/report", Some(LAN)).header(header::CONTENT_TYPE, content_type);
    if let Some(token) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    b.body(body.into()).unwrap()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn gzip_request(token: &str, content_type: &str, body: &[u8]) -> Request<Body> {
    api("POST", "/api/v1/agent/report", Some(LAN))
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_ENCODING, "gzip")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(gzip(body)))
        .unwrap()
}

/// A fresh pace, as after the waiting time.
fn later(h: &Harness) -> Router {
    with_state(h, |s| s.agent_pace = Arc::default())
}

const DEBIAN_REPORT: &str = "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"
ID=debian
VERSION_ID=13
---
ii \topenssh-server\t1:10.0p1-7\topenssh\t1:10.0p1-7
ii \tzlib1g\t1:1.3.dfsg+really1.3.1-1+b1\tzlib\t1:1.3.dfsg+really1.3.1-1
rc \told-package\t1.0\told-package\t1.0
ii \tbroken line
";

#[tokio::test]
async fn a_windows_computer_reports_its_system_and_it_is_matched() {
    let h = harness(true).await;
    let (session, csrf) = login(&h, "anna").await;
    sqlx::raw_sql(
        r#"INSERT INTO cves (id, state, title, published_ms, affected) VALUES ('CVE-2026-20001', 'published',
             'Windows Kernel', 1790000000000, '[{"vendor":"Microsoft","product":"Windows 11 Version 24H2",
             "versions":[{"version":"10.0.26100.0","less_than":"10.0.26100.5000","status":"affected","type":"custom"}]}]');
           INSERT INTO cve_products VALUES ('CVE-2026-20001', 'cna', 'microsoft', 'windows11version24h2',
             'Microsoft', 'Windows 11 Version 24H2');"#,
    )
    .execute(&h.state.pool)
    .await
    .unwrap();
    let (id, token) = enrolled(&h, &session, &csrf, "pc").await;
    let report = |ubr: u32| {
        serde_json::json!({
            "schema": 1,
            "agent": { "name": "opensecmon-agent", "version": "0.1.0" },
            "hostname": "PC-WOHNZIMMER",
            "os": {
                "family": "windows",
                "product_name": "Windows 10 Pro",
                "display_version": "24H2",
                "build": 26100,
                "ubr": ubr,
                "installation_type": "Client",
                "arch": "x64"
            },
            "items": [
                { "type": "win", "id": "{1F1C2DFC}", "name": "Mozilla Firefox (x64 de)", "version": "144.0.2" },
                { "type": "win", "id": "{PY}", "name": "Python 3.12.10 (64-bit)", "version": "3.12.10150.0" },
                { "type": "win", "id": "abc", "name": "GitHub", "version": "1.0", "publisher": "Google\\Chrome" },
                { "type": "appx", "id": "Microsoft.WindowsTerminal_8wekyb3d8bbwe", "name": "Windows Terminal" }
            ]
        })
        .to_string()
    };
    let reply = send(
        &h.app,
        report_request(Some(&token), "application/json", report(4652)),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let answer = json(&reply);
    assert_eq!(answer["status"], "stored");
    assert_eq!(answer["warnings"], serde_json::json!([]));
    // Windows, Firefox and Python by the built-in rules (Python with the version of its name, its installer
    // encodes it as 3.12.10150), the web app of Chrome ignored; the store app without a rule stays unassigned.
    let assets = || async {
        sqlx::query_as::<_, (i64, String, String, String, String, String)>(
            "SELECT id, kind, product_name, version, host, origin_ref FROM assets ORDER BY product_name DESC",
        )
        .fetch_all(&h.state.pool)
        .await
        .unwrap()
    };
    let first = assets().await;
    assert_eq!(first.len(), 3);
    assert_eq!(
        (first[1].2.as_str(), first[1].3.as_str()),
        ("Python", "3.12.10")
    );
    assert_eq!(
        (first[2].2.as_str(), first[2].3.as_str()),
        ("Firefox", "144.0.2")
    );
    let unassigned = crate::storage::items::unassigned(&h.state.pool)
        .await
        .unwrap();
    assert_eq!(unassigned.len(), 1);
    assert_eq!(unassigned[0].name, "Windows Terminal");
    let (asset_id, kind, product, version, host, origin_ref) = first[0].clone();
    assert_eq!(
        (
            kind.as_str(),
            product.as_str(),
            version.as_str(),
            host.as_str()
        ),
        (
            "software",
            "Windows 11 Version 24H2",
            "10.0.26100.4652",
            "pc"
        )
    );
    assert_eq!(origin_ref, format!("agent:{id}"));
    let d = agents::device(&h.state.pool, id).await.unwrap().unwrap();
    assert_eq!(
        (
            d.os_name.as_str(),
            d.release.as_str(),
            d.packages,
            d.hostname.as_str()
        ),
        ("Windows 11 Pro 24H2", "24H2", 3, "PC-WOHNZIMMER")
    );
    let mut found = Vec::new();
    for _ in 0..100 {
        found = open_matches(&h).await;
        if !found.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(found, [("CVE-2026-20001".to_owned(), "new".to_owned())]);

    // After the patch day: the same asset with the new version, the match resolves itself.
    let reply = send(
        &later(&h),
        report_request(Some(&token), "application/json", report(5100)),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let second = assets().await;
    assert_eq!(second.len(), 3);
    assert_eq!(
        (second[0].0, second[0].3.as_str()),
        (asset_id, "10.0.26100.5100")
    );
    let mut state = String::new();
    for _ in 0..100 {
        state = open_matches(&h).await[0].1.clone();
        if state != "new" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_ne!(state, "new", "the patched version resolves the match");

    // Assets written before the rules changed (here set back by hand) are set right when the rules are applied
    // again, as at start-up; the others stay untouched.
    sqlx::query("UPDATE assets SET version = '3.12.10150.0' WHERE product_name = 'Python'")
        .execute(&h.state.pool)
        .await
        .unwrap();
    let changed = crate::storage::items::resync_all(&h.state.pool, 1_800_000_000_000)
        .await
        .unwrap();
    assert_eq!(changed, [second[1].0]);
    assert_eq!(assets().await[1].3, "3.12.10");
    assert!(
        crate::storage::items::resync_all(&h.state.pool, 1_800_000_000_000)
            .await
            .unwrap()
            .is_empty()
    );

    // Windows before 10 is refused and noted on the page.
    let old = r#"{"schema":1,"os":{"family":"windows","product_name":"Windows 8.1 Pro","build":9600,"ubr":0}}"#;
    let reply = send(
        &later(&h),
        report_request(Some(&token), "application/json", old),
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error_code(&reply), "unsupported_system");
    let d = agents::device(&h.state.pool, id).await.unwrap().unwrap();
    assert!(
        d.last_error.starts_with("computers-error-windows"),
        "{}",
        d.last_error
    );
    assert_eq!(assets().await.len(), 3, "a refused report keeps the assets");
}

async fn open_matches(h: &Harness) -> Vec<(String, String)> {
    sqlx::query_as("SELECT vuln, state FROM matches ORDER BY vuln")
        .fetch_all(&h.state.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_debian_computer_reports_its_packages_and_they_are_matched() {
    let h = harness(true).await;
    let (session, csrf) = login(&h, "anna").await;
    sqlx::raw_sql(
        "INSERT INTO osv_records (seq, source, id, kind, summary, modified, modified_ms, fetched_ms)
           VALUES (1, 'debian', 'DSA-6000-1', 'advisory', 'openssh security update', '2026-01-01', 0, 0);
         INSERT INTO osv_affected (record_seq, ecosystem, release, package, introduced, fixed)
           VALUES (1, 'Debian:13', '13', 'openssh', '0', '1:10.0p1-8');
         INSERT INTO osv_cves (record_seq, cve_id) VALUES (1, 'CVE-2026-10001');",
    )
    .execute(&h.state.pool)
    .await
    .unwrap();
    let (id, token) = enrolled(&h, &session, &csrf, "laptop").await;

    // The output of the inventory script as plain text.
    let reply = send(
        &h.app,
        report_request(Some(&token), "text/plain; charset=utf-8", DEBIAN_REPORT),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let answer = json(&reply);
    assert_eq!(answer["status"], "stored");
    assert_eq!(answer["next_report_s"], 21600);
    assert_eq!(
        answer["warnings"],
        serde_json::json!([{ "code": "lines_skipped", "count": 1 }])
    );
    let assets: Vec<(String, String, String, String, String)> = sqlx::query_as(
        "SELECT product, version, host, origin, origin_ref FROM assets ORDER BY product",
    )
    .fetch_all(&h.state.pool)
    .await
    .unwrap();
    assert_eq!(assets.len(), 2);
    assert_eq!(
        assets[0],
        (
            "openssh".into(),
            "1:10.0p1-7".into(),
            "laptop".into(),
            "agent".into(),
            format!("agent:{id}")
        )
    );
    // Matched in the background, after the response.
    let mut found = Vec::new();
    for _ in 0..100 {
        found = open_matches(&h).await;
        if !found.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(found, vec![("CVE-2026-10001".to_owned(), "new".to_owned())]);

    let d = agents::device(&h.state.pool, id).await.unwrap().unwrap();
    assert_eq!(
        (
            d.os_name.as_str(),
            d.distro.as_str(),
            d.release.as_str(),
            d.packages
        ),
        ("Debian GNU/Linux 13 (trixie)", "debian", "13", 2)
    );
    assert!(d.last_report_ms.is_some() && d.last_error.is_empty());
    let reply = send(&h.app, status_request(Some(LAN), Some(&token))).await;
    assert!(json(&reply)["last_report"].as_str().unwrap().ends_with('Z'));
    let page = send(
        &h.app,
        get(&format!("/assets/computers/{id}"), Some(&session)),
    )
    .await;
    assert!(page.body.contains("meldet") && page.body.contains("Debian GNU/Linux 13 (trixie)"));
    assert!(page.body.contains("/assets?host=laptop"));
    let assets_page = send(&h.app, get("/assets", Some(&session))).await;
    assert!(
        assets_page
            .body
            .contains("Debian GNU/Linux 13 (trixie) · Agent"),
        "the computer's packages are grouped like a host's"
    );

    // At once again: too soon.
    let reply = send(
        &h.app,
        report_request(Some(&token), "text/plain", DEBIAN_REPORT),
    )
    .await;
    assert_eq!(reply.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(error_code(&reply), "too_many_requests");
    let wait: i64 = reply.headers[header::RETRY_AFTER]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((295..=300).contains(&wait), "{wait}");

    // Later, the same body: only noted.
    let app = later(&h);
    let reply = send(
        &app,
        report_request(Some(&token), "text/plain", DEBIAN_REPORT),
    )
    .await;
    assert_eq!(json(&reply)["status"], "unchanged");

    // The short form: a wrong hash asks for the full report, the right one is enough.
    let short = |hash: &str| format!(r#"{{"schema":1,"unchanged":"{hash}"}}"#);
    let app = later(&h);
    let reply = send(
        &app,
        report_request(Some(&token), "application/json", short(&"0".repeat(64))),
    )
    .await;
    assert_eq!(reply.status, StatusCode::CONFLICT);
    assert_eq!(error_code(&reply), "full_report_required");
    let hash = crate::auth::hex(&<sha2::Sha256 as sha2::Digest>::digest(
        DEBIAN_REPORT.as_bytes(),
    ));
    let reply = send(
        &app,
        report_request(
            Some(&token),
            "application/json",
            short(&hash.to_uppercase()),
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(json(&reply)["status"], "unchanged");

    // JSON, compressed: openssh fixed, zlib gone, another package new; the snap and the Flatpak become software
    // assets by the built-in rules, an entry of an unknown type is skipped. The sections of the script after the
    // packages count as well (the text form sends them so), beside `items`.
    let report = serde_json::json!({
        "schema": 1,
        "agent": { "name": "opensecmon-agent", "version": "0.1.0" },
        "hostname": "zorin-laptop-2",
        "os": {
            "family": "linux",
            "os_release": "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID=debian\nVERSION_ID=13\n",
            "arch": "x86_64",
            "kernel": "6.12.57+deb13-amd64",
            "reboot_required": true,
            "unknown_field": true
        },
        "dpkg": "ii \topenssh-server\t1:10.0p1-8\topenssh\t1:10.0p1-8\nii \tbash\t5.2.37-2\tbash\t5.2.37-2\n\
                 --- snap\nName Version Rev Tracking Publisher Notes\ncore24 20250929 1196 latest/stable canonical** base\n\
                 --- flatpak\norg.inkscape.Inkscape\tInkscape\t1.4.2\tsystem\n",
        "items": [
            { "type": "snap", "id": "firefox", "name": "firefox", "version": "144.0.2-1" },
            { "type": "flatpak", "id": "org.gimp.GIMP", "name": "GIMP", "version": "3.0.4" },
            { "type": "rpm", "id": "x" }
        ]
    });
    let app = later(&h);
    let reply = send(
        &app,
        gzip_request(&token, "application/json", report.to_string().as_bytes()),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let answer = json(&reply);
    assert_eq!(answer["status"], "stored");
    assert_eq!(
        answer["warnings"],
        serde_json::json!([{ "code": "items_skipped", "count": 1 }])
    );
    let products: Vec<(String, String)> =
        sqlx::query_as("SELECT product, version FROM assets ORDER BY product")
            .fetch_all(&h.state.pool)
            .await
            .unwrap();
    assert_eq!(
        products,
        vec![
            ("bash".to_owned(), "5.2.37-2".to_owned()),
            ("firefox".to_owned(), "144.0.2".to_owned()),
            ("gimp".to_owned(), "3.0.4".to_owned()),
            ("inkscape".to_owned(), "1.4.2".to_owned()),
            ("openssh".to_owned(), "1:10.0p1-8".to_owned())
        ]
    );
    let d = agents::device(&h.state.pool, id).await.unwrap().unwrap();
    assert_eq!(
        (
            d.hostname.as_str(),
            d.agent_name.as_str(),
            d.agent_version.as_str()
        ),
        ("zorin-laptop-2", "opensecmon-agent", "0.1.0")
    );
    assert_eq!(
        (d.kernel.as_str(), d.reboot_required),
        ("6.12.57+deb13-amd64", true)
    );
    let mut state = String::new();
    for _ in 0..100 {
        state = open_matches(&h).await[0].1.clone();
        if state != "new" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_ne!(state, "new", "the fixed version resolves the match");

    // Revoked: no more reports, the assets stay.
    let form = format!("csrf_token={csrf}");
    send(
        &h.app,
        post(
            &format!("/assets/computers/{id}/revoke"),
            Some(&session),
            &form,
        ),
    )
    .await;
    let reply = send(
        &later(&h),
        report_request(Some(&token), "text/plain", DEBIAN_REPORT),
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(error_code(&reply), "invalid_token");
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM assets")
        .fetch_one(&h.state.pool)
        .await
        .unwrap();
    assert_eq!(n, 5);
}

#[tokio::test]
async fn reports_that_cannot_be_used_are_refused_and_noted() {
    let h = harness(true).await;
    let (session, csrf) = login(&h, "anna").await;
    let (id, token) = enrolled(&h, &session, &csrf, "laptop").await;
    let t = Some(token.as_str());
    let check = |reply: Reply, status: StatusCode, code: &str| {
        assert_eq!(reply.status, status, "{}", reply.body);
        assert_eq!(error_code(&reply), code, "{}", reply.body);
    };
    let last_error = || async {
        agents::device(&h.state.pool, id)
            .await
            .unwrap()
            .unwrap()
            .last_error
    };

    check(
        send(&h.app, report_request(None, "text/plain", DEBIAN_REPORT)).await,
        StatusCode::UNAUTHORIZED,
        "invalid_token",
    );
    let mut foreign = report_request(t, "text/plain", DEBIAN_REPORT);
    foreign.extensions_mut().insert(ConnectInfo(
        "203.0.113.5:4000".parse::<SocketAddr>().unwrap(),
    ));
    check(
        send(&h.app, foreign).await,
        StatusCode::FORBIDDEN,
        "network_not_allowed",
    );
    for content_type in [
        "text/html",
        "application/xml",
        "text/plain; charset=latin1",
        "",
    ] {
        check(
            send(&h.app, report_request(t, content_type, DEBIAN_REPORT)).await,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
        );
    }
    let mut br = report_request(t, "text/plain", DEBIAN_REPORT);
    br.headers_mut()
        .insert(header::CONTENT_ENCODING, "br".parse().unwrap());
    check(
        send(&h.app, br).await,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported_media_type",
    );
    let mut not_gzip = report_request(t, "text/plain", DEBIAN_REPORT);
    not_gzip
        .headers_mut()
        .insert(header::CONTENT_ENCODING, "gzip".parse().unwrap());
    check(
        send(&h.app, not_gzip).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    );
    check(
        send(
            &h.app,
            report_request(t, "text/plain", vec![0xff, 0xfe, b'-']),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    );
    // Too large, plain and as a small gzip bomb.
    let big = vec![b'a'; crate::agent::REPORT_MAX_BYTES + 1];
    check(
        send(&h.app, report_request(t, "text/plain", big.clone())).await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "too_large",
    );
    check(
        send(&h.app, gzip_request(&token, "text/plain", &big)).await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "too_large",
    );
    assert_eq!(last_error().await, "", "nothing noted yet");

    // Not the script's output, another system, no packages: refused and noted on the page.
    check(
        send(&h.app, report_request(t, "text/plain", "hello\n")).await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    );
    assert_eq!(last_error().await, "computers-error-output");
    let page = send(
        &h.app,
        get(&format!("/assets/computers/{id}"), Some(&session)),
    )
    .await;
    assert!(
        page.body.contains("Meldung abgelehnt")
            && page.body.contains("Format des Inventar-Skripts")
    );
    check(
        send(
            &h.app,
            report_request(
                t,
                "text/plain",
                "ID=fedora\nVERSION_ID=43\n---\nii \tbash\t5.3\tbash\t5.3\n",
            ),
        )
        .await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "unsupported_system",
    );
    assert_eq!(last_error().await, "computers-error-system");
    check(
        send(
            &h.app,
            report_request(t, "text/plain", "ID=debian\nVERSION_ID=13\n---\n"),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "bad_request",
    );
    assert_eq!(last_error().await, "computers-error-no-packages");
    let windows = r#"{"schema":1,"os":{"family":"windows","product_name":"Windows 7 Professional","build":7601,"ubr":0},"items":[]}"#;
    check(
        send(&h.app, report_request(t, "application/json", windows)).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "unsupported_system",
    );
    assert_eq!(last_error().await, "computers-error-windows");

    // Malformed JSON reports.
    let long_release = format!(
        r#"{{"schema":1,"os":{{"family":"linux","os_release":"{}"}}}}"#,
        "A".repeat(crate::agent::OS_RELEASE_MAX_BYTES + 1)
    );
    for (body, code) in [
        ("{", "bad_request"),
        (
            r#"{"schema":2,"os":{"family":"linux"}}"#,
            "unsupported_schema",
        ),
        (r#"{"os":{"family":"linux"}}"#, "bad_request"),
        (r#"{"schema":1}"#, "bad_request"),
        (r#"{"schema":1,"os":{"family":"bsd"}}"#, "bad_request"),
        (
            r#"{"schema":1,"os":{"family":"linux","os_release":"ID=debian\n---\nii \tx\t1\tx\t1"}}"#,
            "bad_request",
        ),
        (
            r#"{"schema":1,"hostname":"a\u0007b","os":{"family":"linux"}}"#,
            "bad_request",
        ),
        (long_release.as_str(), "bad_request"),
        (
            r#"{"schema":1,"os":{"family":"linux","os_release":"ID=debian","kernel":"6.12\n---\nii \tx\t1\tx\t1"}}"#,
            "bad_request",
        ),
    ] {
        check(
            send(
                &h.app,
                report_request(t, "application/json", body.to_owned()),
            )
            .await,
            StatusCode::BAD_REQUEST,
            code,
        );
    }

    // A good report clears the error.
    let reply = send(&h.app, report_request(t, "text/plain", DEBIAN_REPORT)).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(last_error().await, "");
}

const UBUNTU_REPORT: &str = "PRETTY_NAME=\"Ubuntu 26.04 LTS\"
ID=ubuntu
VERSION_ID=\"26.04\"
---
ii \topenssh-server\t1:10.2p1-1ubuntu1\topenssh\t1:10.2p1-1ubuntu1
ii \tzlib1g\t1:1.3.dfsg-3.1ubuntu2\tzlib\t1:1.3.dfsg-3.1ubuntu2
";

async fn pro_of_assets(h: &Harness) -> Vec<bool> {
    sqlx::query_scalar("SELECT pro FROM assets ORDER BY product")
        .fetch_all(&h.state.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn ubuntu_pro_is_set_per_computer_and_kept_by_the_reports() {
    let h = harness(true).await;
    let (session, csrf) = login(&h, "anna").await;
    let (id, token) = enrolled(&h, &session, &csrf, "laptop").await;
    let page = format!("/assets/computers/{id}");
    // Before the first report the system is unknown: no setting.
    let reply = send(&h.app, get(&page, Some(&session))).await;
    assert!(!reply.body.contains("name=\"pro_mode\""));
    let reply = send(
        &h.app,
        report_request(Some(&token), "text/plain", UBUNTU_REPORT),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(
        pro_of_assets(&h).await,
        [false, false],
        "no esm package: not detected"
    );
    let reply = send(&h.app, get(&page, Some(&session))).await;
    assert!(reply.body.contains("<option value=\"auto\" selected>"));
    assert!(reply.body.contains("nicht erkannt"));

    // Set by hand: the packages follow at once …
    let form = format!("csrf_token={csrf}&pro_mode=yes");
    let reply = send(&h.app, post(&format!("{page}/pro"), Some(&session), &form)).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(pro_of_assets(&h).await, [true, true]);
    let reply = send(&h.app, get(&page, Some(&session))).await;
    assert!(reply.body.contains("<option value=\"yes\" selected>"));
    let logged: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE detail LIKE '%audit-field-pro%'")
            .fetch_one(&h.state.pool)
            .await
            .unwrap();
    assert_eq!(logged, 1, "the change is in the log");
    // … and a later report (other versions) keeps it.
    let changed = UBUNTU_REPORT.replace("ubuntu1\n", "ubuntu1.1\n");
    let reply = send(
        &later(&h),
        report_request(Some(&token), "text/plain", changed),
    )
    .await;
    assert_eq!(json(&reply)["status"], "stored", "{}", reply.body);
    assert_eq!(pro_of_assets(&h).await, [true, true]);
    // The form of a package says where it is set.
    let asset: i64 = sqlx::query_scalar("SELECT id FROM assets ORDER BY id LIMIT 1")
        .fetch_one(&h.state.pool)
        .await
        .unwrap();
    let reply = send(&h.app, get(&format!("/assets/{asset}"), Some(&session))).await;
    assert!(reply.body.contains(&format!(
        "href=\"/assets/computers/{id}\">Einstellung ändern"
    )));
    assert!(!reply.body.contains("type=\"checkbox\" name=\"pro\""));

    // Back to automatic: an esm version is detected.
    let form = format!("csrf_token={csrf}&pro_mode=auto");
    send(&h.app, post(&format!("{page}/pro"), Some(&session), &form)).await;
    assert_eq!(pro_of_assets(&h).await, [false, false]);
    let esm = UBUNTU_REPORT.replace("1:1.3.dfsg-3.1ubuntu2", "1:1.3.dfsg-3.1ubuntu2+esm1");
    let reply = send(&later(&h), report_request(Some(&token), "text/plain", esm)).await;
    assert_eq!(json(&reply)["status"], "stored", "{}", reply.body);
    assert_eq!(pro_of_assets(&h).await, [true, true]);
    let reply = send(&h.app, get(&page, Some(&session))).await;
    assert!(reply.body.contains("Automatisch: erkannt"));
    // "No" wins over the detection, also for the next report.
    let form = format!("csrf_token={csrf}&pro_mode=no");
    send(&h.app, post(&format!("{page}/pro"), Some(&session), &form)).await;
    assert_eq!(pro_of_assets(&h).await, [false, false]);
    let esm2 = UBUNTU_REPORT.replace("1:1.3.dfsg-3.1ubuntu2", "1:1.3.dfsg-3.1ubuntu2+esm2");
    send(&later(&h), report_request(Some(&token), "text/plain", esm2)).await;
    assert_eq!(pro_of_assets(&h).await, [false, false]);

    // Unknown values and a missing CSRF token are refused.
    let form = format!("csrf_token={csrf}&pro_mode=maybe");
    let reply = send(&h.app, post(&format!("{page}/pro"), Some(&session), &form)).await;
    assert_ne!(reply.status, StatusCode::SEE_OTHER);
    let reply = send(
        &h.app,
        post(&format!("{page}/pro"), Some(&session), "pro_mode=yes"),
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(pro_of_assets(&h).await, [false, false]);
}

#[tokio::test]
async fn debian_computers_have_no_pro_setting() {
    let h = harness(true).await;
    let (session, csrf) = login(&h, "anna").await;
    let (id, token) = enrolled(&h, &session, &csrf, "pi").await;
    send(
        &h.app,
        report_request(Some(&token), "text/plain", DEBIAN_REPORT),
    )
    .await;
    let reply = send(
        &h.app,
        get(&format!("/assets/computers/{id}"), Some(&session)),
    )
    .await;
    assert!(!reply.body.contains("name=\"pro_mode\""));
    // Set anyway (an old form): Debian packages never count as Pro.
    let form = format!("csrf_token={csrf}&pro_mode=yes");
    send(
        &h.app,
        post(
            &format!("/assets/computers/{id}/pro"),
            Some(&session),
            &form,
        ),
    )
    .await;
    assert_eq!(pro_of_assets(&h).await, [false, false]);
}

#[tokio::test]
async fn the_page_offers_the_script_for_debian_and_ubuntu() {
    let h = harness(true).await;
    let (session, csrf) = login(&h, "anna").await;
    let (id, code) = add_computer(&h, &session, &csrf, "laptop").await;
    let page = send(
        &h.app,
        get(&format!("/assets/computers/{id}"), Some(&session)),
    )
    .await;
    // No Host header in the test: the address is a placeholder (escaped in the page).
    assert!(
        page.body.contains(&format!(
            "sudo sh opensecmon-agent.sh enroll https://&#60;server&#62; {code}"
        )),
        "{}",
        page.body
    );
    let script = send(
        &h.app,
        get("/assets/computers/opensecmon-agent.sh", Some(&session)),
    )
    .await;
    assert_eq!(script.status, StatusCode::OK);
    assert!(script.body.starts_with("#!/bin/sh"));
    assert!(
        script.headers[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap()
            .contains("opensecmon-agent.sh")
    );
    let anonymous = send(&h.app, get("/assets/computers/opensecmon-agent.sh", None)).await;
    assert_ne!(anonymous.status, StatusCode::OK, "only for signed-in users");
    assert!(
        !page.body.contains("Skript aktualisieren"),
        "the enrollment offers it"
    );

    // An enrolled computer keeps the link to the script, with the command to update it.
    let (id, _) = enrolled(&h, &session, &csrf, "server").await;
    let page = send(
        &h.app,
        get(&format!("/assets/computers/{id}"), Some(&session)),
    )
    .await;
    assert!(page.body.contains("Skript aktualisieren"), "{}", page.body);
    assert!(
        page.body
            .contains("href=\"/assets/computers/opensecmon-agent.sh\" download")
    );
    assert!(
        page.body
            .contains("sudo install -m 755 opensecmon-agent.sh /usr/local/sbin/opensecmon-agent")
    );
}

#[tokio::test]
async fn the_page_offers_the_script_for_windows() {
    let h = harness(true).await;
    let (session, csrf) = login(&h, "anna").await;
    let (id, code) = add_computer(&h, &session, &csrf, "pc").await;
    let page = send(
        &h.app,
        get(&format!("/assets/computers/{id}"), Some(&session)),
    )
    .await;
    assert!(
        page.body.contains(&format!(
            "powershell -ExecutionPolicy Bypass -File .\\opensecmon-agent.ps1 enroll https://&#60;server&#62; {code}"
        )),
        "{}",
        page.body
    );
    assert!(
        page.body
            .contains("href=\"/assets/computers/opensecmon-agent.ps1\" download")
    );
    let script = send(
        &h.app,
        get("/assets/computers/opensecmon-agent.ps1", Some(&session)),
    )
    .await;
    assert_eq!(script.status, StatusCode::OK);
    assert!(script.body.starts_with("<#"));
    assert!(
        script.headers[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap()
            .contains("opensecmon-agent.ps1")
    );
    let anonymous = send(&h.app, get("/assets/computers/opensecmon-agent.ps1", None)).await;
    assert_ne!(anonymous.status, StatusCode::OK, "only for signed-in users");

    // Once Windows has reported, the page offers the update of the PowerShell script, not of the shell script.
    let (id, token) = enrolled(&h, &session, &csrf, "server").await;
    let body = serde_json::json!({
        "schema": 1,
        "agent": { "name": "opensecmon-agent.ps1", "version": "1" },
        "hostname": "PC",
        "os": { "family": "windows", "product_name": "Windows 10 Pro", "display_version": "24H2",
                "build": 26100, "ubr": 4652, "installation_type": "Client", "arch": "x64" },
        "items": []
    })
    .to_string();
    let reply = send(
        &h.app,
        report_request(Some(&token), "application/json", body),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let page = send(
        &h.app,
        get(&format!("/assets/computers/{id}"), Some(&session)),
    )
    .await;
    assert!(page.body.contains("Skript aktualisieren"), "{}", page.body);
    assert!(page.body.contains("opensecmon-agent.ps1 update"));
    assert!(!page.body.contains("sudo install -m 755"));
}

#[test]
fn the_report_errors_have_texts() {
    for lang in [crate::i18n::Lang::De, crate::i18n::Lang::En] {
        for id in [
            "computers-error-system",
            "computers-error-windows",
            "computers-error-output",
            "computers-error-no-packages",
        ] {
            assert_ne!(lang.get(id), id, "{id}");
        }
    }
}

// ---- opensecagent: enrollment code, interval, updates (step 7) ----

const SIGNATURE: &str =
    "-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQ==\n-----END SSH SIGNATURE-----\n";

/// A folder with two opensecagent packages for Debian (0.1.0 and 0.2.0) and one for Windows, all signed.
fn package_folder() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for (name, content) in [
        ("opensecagent_0.1.0-1_amd64.deb", "old deb"),
        ("opensecagent_0.2.0-1_amd64.deb", "new deb"),
        ("opensecagent-0.2.0-x64-setup.exe", "setup"),
    ] {
        std::fs::write(dir.path().join(name), content).unwrap();
        std::fs::write(dir.path().join(format!("{name}.sig")), SIGNATURE).unwrap();
    }
    dir
}

fn agent_report(version: &str, updates: bool, update_error: Option<&str>) -> String {
    let mut agent =
        serde_json::json!({ "name": "opensecagent", "version": version, "updates": updates });
    if let Some(e) = update_error {
        agent["update_error"] = e.into();
    }
    serde_json::json!({
        "schema": 1,
        "agent": agent,
        "hostname": "zorin-laptop",
        "os": {
            "family": "linux",
            "os_release": "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID=debian\nVERSION_ID=13",
            "arch": "x86_64"
        },
        "dpkg": "ii \tzlib1g\t1:1.3.dfsg+really1.3.1-1+b1\tzlib\t1:1.3.dfsg+really1.3.1-1\n"
    })
    .to_string()
}

fn page_request(path: &str, session: &str) -> Request<Body> {
    let mut r = get(path, Some(session));
    r.headers_mut()
        .insert(header::HOST, "192.0.2.10:8444".parse().unwrap());
    r
}

fn download_request(file: &str, token: Option<&str>, from: &str) -> Request<Body> {
    let mut b = api("GET", &format!("/api/v1/agent/packages/{file}"), Some(from));
    if let Some(token) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    b.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn opensecagent_gets_one_code_reports_every_15_minutes_and_is_updated_on_request() {
    let h = harness(true).await;
    let (session, csrf) = login(&h, "anna").await;
    let folder = package_folder();
    let fingerprint = (0..32)
        .map(|i| format!("{i:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    let app = with_state(&h, |s| {
        s.agent_packages = Arc::new(crate::agent_packages::Catalog::load(folder.path()));
        s.tls_certificate = Some(Arc::new(crate::tls::PublicCertificate {
            pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".to_owned(),
            fingerprint: fingerprint.clone(),
        }));
    });
    let (id, code) = add_computer(&h, &session, &csrf, "laptop").await;

    // Without packages the page shows no enrollment code; with them it does, with the downloads.
    let page = send(
        &h.app,
        page_request(&format!("/assets/computers/{id}"), &session),
    )
    .await;
    assert!(!page.body.contains("osa1_"));
    let page = send(
        &app,
        page_request(&format!("/assets/computers/{id}"), &session),
    )
    .await;
    assert!(
        page.body.contains("Mit opensecagent (empfohlen)"),
        "{}",
        page.body
    );
    assert!(
        page.body
            .contains("/assets/computers/agent/opensecagent_0.2.0-1_amd64.deb")
    );
    assert!(
        page.body
            .contains("/assets/computers/agent/opensecagent-0.2.0-x64-setup.exe")
    );
    assert!(
        !page.body.contains("opensecagent_0.1.0-1_amd64.deb"),
        "only the newest"
    );
    assert!(
        page.body.contains("Ohne opensecagent"),
        "the scripts stay, folded"
    );
    let shown = page
        .body
        .split("data-copy-box>osa1_")
        .nth(1)
        .unwrap()
        .split('<')
        .next()
        .unwrap();
    let decoded = crate::agent_code::decode(&format!("osa1_{shown}")).unwrap();
    assert_eq!(decoded.address, "192.0.2.10:8444");
    assert_eq!(decoded.code, code);
    assert_eq!(
        decoded.fingerprint,
        crate::agent_code::parse_fingerprint(&fingerprint)
    );
    // The browser can download the packages.
    let reply = send(
        &app,
        get(
            "/assets/computers/agent/opensecagent_0.2.0-1_amd64.deb",
            Some(&session),
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body, "new deb");
    let reply = send(
        &app,
        get("/assets/computers/agent/..%2Fsecret.key", Some(&session)),
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);

    // The enrollment of opensecagent asks for a report every 15 minutes.
    let body = format!(
        r#"{{"schema":1,"code":"{code}","hostname":"zorin-laptop","agent":{{"name":"opensecagent","version":"0.1.0"}}}}"#
    );
    let reply = send(&app, enroll_request(Some(LAN), &body)).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    assert_eq!(json(&reply)["report_interval_s"], 900);
    let token = json(&reply)["token"].as_str().unwrap().to_owned();
    let reply = send(&app, status_request(Some(LAN), Some(&token))).await;
    assert_eq!(json(&reply)["next_report_s"], 900);

    // First report: an update is available, but nobody asked for it.
    let reply = send(
        &fresh(&h, folder.path()),
        report_request(
            Some(&token),
            "application/json",
            agent_report("0.1.0", true, None),
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let answer = json(&reply);
    assert_eq!(answer["next_report_s"], 900);
    assert!(answer.get("update").is_none());
    let d = agents::device(&h.state.pool, id).await.unwrap().unwrap();
    assert_eq!((d.arch.as_str(), d.can_update), ("x86_64", true));
    let list = send(&app, get("/assets/computers", Some(&session))).await;
    assert!(list.body.contains("Update verfügbar: 0.2.0"));
    assert!(list.body.contains("Alle aktualisieren (1)"));
    let page = send(
        &app,
        get(&format!("/assets/computers/{id}"), Some(&session)),
    )
    .await;
    assert!(page.body.contains("Auf 0.2.0 aktualisieren"));

    // The user asks; the next answer (here to the short form) carries the update.
    let reply = send(
        &app,
        post(
            &format!("/assets/computers/{id}/update"),
            Some(&session),
            &format!("csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(
        reply.location(),
        format!("/assets/computers/{id}?msg=computer_update")
    );
    let page = send(
        &app,
        get(&format!("/assets/computers/{id}"), Some(&session)),
    )
    .await;
    assert!(page.body.contains("wartet auf die nächste Meldung"));
    let hash = crate::auth::hex(&<sha2::Sha256 as sha2::Digest>::digest(
        agent_report("0.1.0", true, None).as_bytes(),
    ));
    let short = format!(r#"{{"schema":1,"unchanged":"{hash}"}}"#);
    let reply = send(
        &later(&h),
        report_request(Some(&token), "application/json", short.clone()),
    )
    .await;
    // `later` has no packages: the request stays, nothing is offered.
    assert!(json(&reply).get("update").is_none());
    let app = with_state(&h, |s| {
        s.agent_packages = Arc::new(crate::agent_packages::Catalog::load(folder.path()));
    });
    let reply = send(
        &fresh(&h, folder.path()),
        report_request(Some(&token), "application/json", short.clone()),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let update = json(&reply)["update"].clone();
    assert_eq!(update["version"], "0.2.0");
    assert_eq!(update["file"], "opensecagent_0.2.0-1_amd64.deb");
    assert_eq!(update["size"], 7);
    assert_eq!(
        update["sha256"],
        crate::auth::hex(&<sha2::Sha256 as sha2::Digest>::digest(b"new deb"))
    );
    assert_eq!(update["signature"], SIGNATURE);
    let d = agents::device(&h.state.pool, id).await.unwrap().unwrap();
    assert!(d.update_sent_ms.is_some());
    let reply = send(&app, status_request(Some(LAN), Some(&token))).await;
    assert_eq!(
        json(&reply)["update"]["version"],
        "0.2.0",
        "status offers it too"
    );
    let page = send(
        &app,
        get(&format!("/assets/computers/{id}"), Some(&session)),
    )
    .await;
    assert!(page.body.contains("an den Rechner übergeben"));

    // The download needs the token and the network, and only offers files of the catalogue.
    let file = "opensecagent_0.2.0-1_amd64.deb";
    let reply = send(&app, download_request(file, Some(&token), LAN)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body, "new deb");
    let reply = send(&app, download_request(file, None, LAN)).await;
    assert_eq!(error_code(&reply), "invalid_token");
    let reply = send(
        &app,
        download_request(file, Some(&token), "203.0.113.5:4000"),
    )
    .await;
    assert_eq!(error_code(&reply), "network_not_allowed");
    let reply = send(
        &app,
        download_request("opensecagent_9.9.9-1_amd64.deb", Some(&token), LAN),
    )
    .await;
    assert_eq!(error_code(&reply), "not_found");

    // The agent reports the new version: the request is done.
    let reply = send(
        &fresh(&h, folder.path()),
        report_request(
            Some(&token),
            "application/json",
            agent_report("0.2.0", true, None),
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert!(json(&reply).get("update").is_none());
    let d = agents::device(&h.state.pool, id).await.unwrap().unwrap();
    assert_eq!((d.update_version.as_str(), d.update_sent_ms), ("", None));
    let page = send(
        &app,
        get(&format!("/assets/computers/{id}"), Some(&session)),
    )
    .await;
    assert!(page.body.contains("opensecagent 0.2.0 ist aktuell."));
    let list = send(&app, get("/assets/computers", Some(&session))).await;
    assert!(!list.body.contains("Update verfügbar") && !list.body.contains("Alle aktualisieren"));
}

#[tokio::test]
async fn a_failed_update_is_shown_and_no_longer_offered() {
    let h = harness(true).await;
    let (session, csrf) = login(&h, "anna").await;
    let folder = package_folder();
    let app = with_state(&h, |s| {
        s.agent_packages = Arc::new(crate::agent_packages::Catalog::load(folder.path()));
    });
    let (id, token) = enrolled(&h, &session, &csrf, "laptop").await;
    let report = |body: String| {
        let app = fresh(&h, folder.path());
        let token = token.clone();
        async move { send(&app, report_request(Some(&token), "application/json", body)).await }
    };
    let reply = report(agent_report("0.1.0", true, None)).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);

    // "Update all" asks for every computer that can be updated.
    let reply = send(
        &app,
        post(
            "/assets/computers/update-all",
            Some(&session),
            &format!("csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(reply.location(), "/assets/computers?msg=computer_update");
    let d = agents::device(&h.state.pool, id).await.unwrap().unwrap();
    assert_eq!(d.update_version, "0.2.0");

    let reply = report(agent_report(
        "0.1.0",
        true,
        Some("signature does not match"),
    ))
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert!(json(&reply).get("update").is_none());
    let d = agents::device(&h.state.pool, id).await.unwrap().unwrap();
    assert_eq!(d.update_version, "");
    assert_eq!(d.update_error, "signature does not match");
    let page = send(
        &app,
        get(&format!("/assets/computers/{id}"), Some(&session)),
    )
    .await;
    assert!(
        page.body
            .contains("Das letzte Update ist fehlgeschlagen: signature does not match")
    );
    assert!(
        page.body.contains("Auf 0.2.0 aktualisieren"),
        "the user can try again"
    );

    // Asked again and taken back: nothing is offered.
    send(
        &app,
        post(
            &format!("/assets/computers/{id}/update"),
            Some(&session),
            &format!("csrf_token={csrf}"),
        ),
    )
    .await;
    let d = agents::device(&h.state.pool, id).await.unwrap().unwrap();
    assert_eq!(
        (d.update_version.as_str(), d.update_error.as_str()),
        ("0.2.0", "")
    );
    let reply = send(
        &app,
        post(
            &format!("/assets/computers/{id}/update/cancel"),
            Some(&session),
            &format!("csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(
        reply.location(),
        format!("/assets/computers/{id}?msg=computer_update_cancelled")
    );
    let reply = send(&app, status_request(Some(LAN), Some(&token))).await;
    assert!(json(&reply).get("update").is_none());
    // Without the CSRF token nothing happens.
    let reply = send(
        &app,
        post(
            &format!("/assets/computers/{id}/update"),
            Some(&session),
            "csrf_token=x",
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
}

/// The router with the packages and a fresh pace (reports right after each other).
fn fresh(h: &Harness, folder: &std::path::Path) -> Router {
    with_state(h, |s| {
        s.agent_packages = Arc::new(crate::agent_packages::Catalog::load(folder));
        s.agent_pace = Arc::default();
    })
}

#[tokio::test]
async fn agents_that_cannot_update_and_scripts_are_never_offered_one() {
    let h = harness(true).await;
    let (session, csrf) = login(&h, "anna").await;
    let folder = package_folder();
    let app = with_state(&h, |s| {
        s.agent_packages = Arc::new(crate::agent_packages::Catalog::load(folder.path()));
    });
    let (id, token) = enrolled(&h, &session, &csrf, "laptop").await;
    // An opensecagent without the publisher's key.
    let reply = send(
        &fresh(&h, folder.path()),
        report_request(
            Some(&token),
            "application/json",
            agent_report("0.1.0", false, None),
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let page = send(
        &app,
        get(&format!("/assets/computers/{id}"), Some(&session)),
    )
    .await;
    assert!(page.body.contains("installiert keine Updates"));
    assert!(!page.body.contains("aktualisieren</button>"));
    let reply = send(
        &app,
        post(
            &format!("/assets/computers/{id}/update"),
            Some(&session),
            &format!("csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(
        reply.location(),
        format!("/assets/computers/{id}"),
        "nothing to ask for"
    );
    let d = agents::device(&h.state.pool, id).await.unwrap().unwrap();
    assert_eq!(d.update_version, "");

    // A script keeps its 6 hours and gets no update section of opensecagent.
    let (other, token) = enrolled(&h, &session, &csrf, "desktop").await;
    let reply = send(
        &fresh(&h, folder.path()),
        report_request(Some(&token), "text/plain; charset=utf-8", DEBIAN_REPORT),
    )
    .await;
    assert_eq!(json(&reply)["next_report_s"], 21600);
    let page = send(
        &app,
        get(&format!("/assets/computers/{other}"), Some(&session)),
    )
    .await;
    assert!(!page.body.contains("opensecagent aktualisieren"));
    assert!(page.body.contains("Skript aktualisieren"));
}
