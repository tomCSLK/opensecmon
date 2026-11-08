//! Tests of the import pages: hosts over SSH (the whole wizard against the test server of
//! `inventory::ssh`), opennetmon (against a small server on this machine) and CSV.

use axum::http::StatusCode;

use crate::inventory::ssh::{self, testserver};
use crate::storage::{assets, inventory};
use crate::web::testutil::*;

async fn post_form(h: &Harness, session: &str, path: &str, fields: &[(&str, &str)]) -> Reply {
    let form: Vec<String> = fields
        .iter()
        .map(|(k, v)| format!("{k}={}", crate::web::cves::encode(v)))
        .collect();
    send(&h.app, post(path, Some(session), &form.join("&"))).await
}

async fn page(h: &Harness, session: &str, path: &str) -> String {
    let reply = send(&h.app, get(path, Some(session))).await;
    assert_eq!(reply.status, StatusCode::OK, "{path}");
    reply.body
}

#[tokio::test]
async fn a_host_goes_through_the_wizard_and_its_packages_are_listed() {
    let h = harness(true).await;
    let (session, csrf) = login(&h, "anna").await;
    assert!(
        page(&h, &session, "/assets/hosts")
            .await
            .contains("Noch keine Hosts")
    );

    // An OSV record that hits openssh (glibc stays without matches).
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
    let key = inventory::ssh_key(&h.state.pool, &h.state.secrets)
        .await
        .unwrap();
    let server = testserver::start(
        &ssh::public_line(&key),
        testserver::Reply::Output(
            "ID=debian\nVERSION_ID=13\nPRETTY_NAME=\"Debian <b>13</b>\"\n---\n\
             ii \topenssh-server\t1:10.0p1-7\topenssh\t1:10.0p1-7\n\
             ii \tlibc6\t2.41-12\tglibc\t2.41-12\n",
        ),
    )
    .await;
    let port = server.port.to_string();

    // Step 1: checked, then stored.
    let reply = post_form(
        &h,
        &session,
        "/assets/hosts/new",
        &[
            ("csrf_token", &csrf),
            ("name", "pi 01"),
            ("address", "127.0.0.1"),
            ("port", &port),
            ("username", "opensecmon"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.contains("Der Name darf nur"));
    let reply = post_form(
        &h,
        &session,
        "/assets/hosts/new",
        &[
            ("csrf_token", &csrf),
            ("name", "pi01"),
            ("address", "127.0.0.1"),
            ("port", &port),
            ("username", "opensecmon"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    let setup = reply.location().to_owned();
    assert_eq!(setup, "/assets/hosts/1/setup");

    // Step 2: script and key line.
    let body = page(&h, &session, &setup).await;
    assert!(
        body.contains(
            "restrict,command=&#34;/usr/local/bin/opensecmon-inventory&#34; ssh-ed25519 "
        )
    );
    assert!(body.contains("dpkg-query"));

    // Connecting learns the host key: step 3 shows its fingerprint.
    let reply = post_form(
        &h,
        &session,
        "/assets/hosts/1/connect",
        &[("csrf_token", &csrf)],
    )
    .await;
    assert_eq!(reply.location(), setup);
    let body = page(&h, &session, &setup).await;
    let fingerprint = ssh::fingerprint(&server.host_key);
    assert!(body.contains(&fingerprint), "{body}");
    let seen = inventory::host(&h.state.pool, 1)
        .await
        .unwrap()
        .unwrap()
        .seen_key;

    // Without the check box nothing is confirmed; with it the host is read.
    let reply = post_form(
        &h,
        &session,
        "/assets/hosts/1/confirm",
        &[("csrf_token", &csrf), ("key", &seen)],
    )
    .await;
    assert_eq!(reply.location(), setup);
    assert!(
        inventory::host(&h.state.pool, 1)
            .await
            .unwrap()
            .unwrap()
            .host_key
            .is_empty()
    );
    let reply = post_form(
        &h,
        &session,
        "/assets/hosts/1/confirm",
        &[("csrf_token", &csrf), ("key", &seen), ("ok", "1")],
    )
    .await;
    assert_eq!(reply.location(), setup);
    let body = page(&h, &session, &setup).await;
    assert!(
        body.contains("Verbindung ok. Debian &#60;b&#62;13&#60;/b&#62;, 2 Pakete gelesen."),
        "{body}"
    );
    assert!(body.contains("1 Paket hat offene Meldungen"), "{body}");

    // The list folds packages without open matches; ?host= shows them.
    let body = page(&h, &session, "/assets").await;
    assert!(
        body.contains("1 weiteres Paket ohne offene Meldungen"),
        "{body}"
    );
    assert!(body.contains("openssh") && !body.contains("glibc"));
    let body = page(&h, &session, "/assets?host=pi01").await;
    assert!(body.contains("glibc"));
    assert!(body.contains("Paket (Debian/Ubuntu) · Debian 13 · SSH"));
    // The form of such a package says that the next reading overwrites it.
    let id: i64 = sqlx::query_scalar("SELECT id FROM assets WHERE product = 'openssh'")
        .fetch_one(&h.state.pool)
        .await
        .unwrap();
    let body = page(&h, &session, &format!("/assets/{id}")).await;
    assert!(body.contains("Abfrage des Hosts per SSH"));

    let body = page(&h, &session, "/assets/hosts").await;
    assert!(body.contains("Debian &#60;b&#62;13&#60;/b&#62;"));
    let reply = post_form(
        &h,
        &session,
        "/assets/hosts/1/run",
        &[("csrf_token", &csrf)],
    )
    .await;
    assert_eq!(reply.location(), "/assets/hosts?msg=host_read");

    // Switched off, then removed with its packages.
    let reply = post_form(
        &h,
        &session,
        "/assets/hosts/1/enabled",
        &[("csrf_token", &csrf), ("enabled", "0")],
    )
    .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert!(page(&h, &session, "/assets/hosts").await.contains(">aus<"));
    let reply = post_form(
        &h,
        &session,
        "/assets/hosts/1/delete",
        &[("csrf_token", &csrf)],
    )
    .await;
    assert_eq!(reply.location(), "/assets/hosts?msg=host_deleted");
    assert!(assets::all(&h.state.pool).await.unwrap().is_empty());
    let audit = page(&h, &session, "/settings/audit").await;
    assert!(audit.contains("Host-Schlüssel"), "{audit}");
}

#[tokio::test]
async fn host_pages_need_the_csrf_token() {
    let h = harness(true).await;
    let (session, _) = login(&h, "anna").await;
    let reply = post_form(
        &h,
        &session,
        "/assets/hosts/new",
        &[
            ("csrf_token", "wrong"),
            ("name", "x"),
            ("address", "127.0.0.1"),
            ("username", "x"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert!(inventory::hosts(&h.state.pool).await.unwrap().is_empty());
}

#[tokio::test]
async fn an_ubuntu_host_has_the_pro_setting_on_its_page() {
    let h = harness(true).await;
    let (session, csrf) = login(&h, "anna").await;
    sqlx::raw_sql(
        "INSERT INTO ssh_hosts (id, name, address, username, distro, release, created_ms)
           VALUES (1, 'server01', '127.0.0.1', 'opensecmon', 'ubuntu', '26.04', 0),
                  (2, 'pi01', '127.0.0.2', 'opensecmon', 'debian', '13', 0);
         INSERT INTO assets (kind, vendor, product, vendor_name, product_name, version, host, distro, release,
                             origin, origin_ref, created_ms, updated_ms)
           VALUES ('package', 'ubuntu', 'zlib', 'Ubuntu', 'zlib', '1:1.3-1', 'server01', 'ubuntu', '26.04',
                   'ssh', 'ssh:1', 0, 0);",
    )
    .execute(&h.state.pool)
    .await
    .unwrap();
    let body = page(&h, &session, "/assets/hosts/1/edit").await;
    assert!(body.contains("action=\"/assets/hosts/1/pro\""));
    assert!(
        !page(&h, &session, "/assets/hosts/2/edit")
            .await
            .contains("name=\"pro_mode\"")
    );
    let reply = post_form(
        &h,
        &session,
        "/assets/hosts/1/pro",
        &[("csrf_token", &csrf), ("pro_mode", "yes")],
    )
    .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(reply.location(), "/assets/hosts/1/edit?msg=host_saved");
    let pro: bool = sqlx::query_scalar("SELECT pro FROM assets")
        .fetch_one(&h.state.pool)
        .await
        .unwrap();
    assert!(pro);
    assert!(
        page(&h, &session, "/assets/hosts/1/edit")
            .await
            .contains("<option value=\"yes\" selected>")
    );
    let body = page(&h, &session, "/assets/1").await;
    assert!(body.contains("href=\"/assets/hosts/1/edit\">Einstellung ändern"));
}

/// A small opennetmon on this machine.
async fn fake_onm() -> String {
    use axum::http::HeaderMap;
    let app = axum::Router::new().route(
        crate::inventory::opennetmon::PATH,
        axum::routing::get(|headers: HeaderMap| async move {
            if headers
                .get("authorization")
                .is_none_or(|v| v.as_bytes() != b"Bearer s3cret")
            {
                return (StatusCode::UNAUTHORIZED, String::new());
            }
            (
                StatusCode::OK,
                r#"{"devices": [
                    {"id": 1, "name": "fritz", "address": "192.0.2.1",
                     "sys_descr": "FRITZ!Box 7590 (UI) 154.08.20", "sys_object_id": ""},
                    {"id": 2, "name": "gw<script>", "address": "192.0.2.2",
                     "sys_descr": "Linux gw 4.4.198", "sys_object_id": "1.3.6.1.4.1.8072.3.2.10"}]}"#
                    .to_owned(),
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

#[tokio::test]
async fn a_self_signed_opennetmon_is_reached_by_its_fingerprint() {
    let h = harness(true).await;
    let (session, csrf) = login(&h, "anna").await;
    let save = |url: &'static str, cert: &'static str, token: &'static str| {
        let (h, session, csrf) = (&h, &session, &csrf);
        async move {
            post_form(
                h,
                session,
                "/assets/opennetmon/settings",
                &[
                    ("csrf_token", csrf),
                    ("url", url),
                    ("cert", cert),
                    ("token", token),
                ],
            )
            .await
        }
    };
    let pin = "97b145602 1f6e419 22d475718 8bbddd85c4f785a5d01e28be2ed1afd221b9f96";
    let shown = "97:B1:45:60:21:F6:E4:19:22:D4:75:71:88:BB:DD:D8:5C:4F:78:5A:5D:01:E2:8B:E2:ED:1A:FD:22:1B:9F:96";
    let reply = save("https://127.0.0.1:8443", "97:B1", "s3cret").await;
    assert!(reply.body.contains("kein SHA-256-Wert"), "{}", reply.body);
    assert!(
        reply.body.contains("value=\"97:B1\""),
        "the entry stays in the form"
    );
    let reply = save("http://127.0.0.1:8080", pin, "s3cret").await;
    assert!(reply.body.contains("nur für eine HTTPS-Adresse"));
    let reply = save("https://127.0.0.1:8443", pin, "s3cret").await;
    assert_eq!(reply.location(), "/assets/opennetmon?msg=onm_saved");
    let settings = inventory::onm_settings(&h.state.pool).await.unwrap();
    assert_eq!(settings.cert_sha256, shown);
    assert!(
        page(&h, &session, "/assets/opennetmon")
            .await
            .contains(shown)
    );
    // The stored token only goes to the certificate it was entered for.
    let reply = save("https://127.0.0.1:8443", "", "").await;
    assert!(reply.body.contains("Bitte das Token erneut eingeben"));
    let reply = save("https://127.0.0.1:8443", shown, "").await;
    assert_eq!(reply.location(), "/assets/opennetmon?msg=onm_saved");
    // An untrusted certificate is reported with the fingerprint to compare.
    inventory::record_onm(&h.state.pool, &format!("onm-error-cert\t{shown}"), 1)
        .await
        .unwrap();
    let body = page(&h, &session, "/assets/opennetmon").await;
    assert!(
        body.contains("vertraut dem Zertifikat von opennetmon nicht"),
        "{body}"
    );
    // Removing the connection forgets the fingerprint as well.
    let reply = post_form(
        &h,
        &session,
        "/assets/opennetmon/settings",
        &[("csrf_token", &csrf), ("action", "remove")],
    )
    .await;
    assert_eq!(reply.location(), "/assets/opennetmon?msg=onm_saved");
    let settings = inventory::onm_settings(&h.state.pool).await.unwrap();
    assert_eq!(
        (settings.url.as_str(), settings.cert_sha256.as_str()),
        ("", "")
    );
}

#[tokio::test]
async fn devices_from_opennetmon_are_taken_changed_or_skipped() {
    let h = harness(true).await;
    let (session, csrf) = login(&h, "anna").await;
    assert!(
        page(&h, &session, "/assets/opennetmon")
            .await
            .contains("Noch keine Geräte")
    );

    // Plain HTTP only on this machine; a token is needed.
    let reply = post_form(
        &h,
        &session,
        "/assets/opennetmon/settings",
        &[
            ("csrf_token", &csrf),
            ("url", "http://192.0.2.9"),
            ("token", "x"),
        ],
    )
    .await;
    assert!(
        reply
            .body
            .contains("HTTP ist nur auf diesem Rechner erlaubt")
    );
    let url = fake_onm().await;
    let reply = post_form(
        &h,
        &session,
        "/assets/opennetmon/settings",
        &[("csrf_token", &csrf), ("url", &url)],
    )
    .await;
    assert!(reply.body.contains("Bitte ein Token angeben"));
    let reply = post_form(
        &h,
        &session,
        "/assets/opennetmon/settings",
        &[("csrf_token", &csrf), ("url", &url), ("token", "s3cret")],
    )
    .await;
    assert_eq!(reply.location(), "/assets/opennetmon?msg=onm_saved");
    // The stored token does not go to another address without being typed again.
    let elsewhere = format!("{url}/other");
    let reply = post_form(
        &h,
        &session,
        "/assets/opennetmon/settings",
        &[("csrf_token", &csrf), ("url", &elsewhere)],
    )
    .await;
    assert!(reply.body.contains("Bitte das Token erneut eingeben"));
    let reply = post_form(
        &h,
        &session,
        "/assets/opennetmon/settings",
        &[("csrf_token", &csrf), ("url", &url)],
    )
    .await;
    assert_eq!(
        reply.location(),
        "/assets/opennetmon?msg=onm_saved",
        "same address"
    );
    let reply = post_form(
        &h,
        &session,
        "/assets/opennetmon/run",
        &[("csrf_token", &csrf)],
    )
    .await;
    assert_eq!(reply.location(), "/assets/opennetmon?msg=onm_read");
    let body = page(&h, &session, "/assets/opennetmon").await;
    assert!(body.contains("AVM · FRITZ!OS · 8.20"), "{body}");
    assert!(body.contains("gw&#60;script&#62;"));
    assert!(!body.contains("s3cret"));

    // Taken over: an asset that follows the device.
    let reply = post_form(
        &h,
        &session,
        "/assets/opennetmon/1/take",
        &[("csrf_token", &csrf)],
    )
    .await;
    assert_eq!(reply.location(), "/assets/opennetmon?msg=device_taken");
    let all = assets::all(&h.state.pool).await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(
        (
            all[0].origin.as_str(),
            all[0].origin_ref.as_str(),
            all[0].version.as_str()
        ),
        ("opennetmon", "onm:1", "8.20")
    );

    // Changed in the form: filled with the device, linked on saving.
    let body = page(&h, &session, "/assets/new?onm=2").await;
    assert!(
        body.contains("mit dem Gerät „gw&#60;script&#62;“"),
        "{body}"
    );
    let reply = post_form(
        &h,
        &session,
        "/assets/new",
        &[
            ("csrf_token", &csrf),
            ("kind", "hardware"),
            ("vendor_name", "Zigbee"),
            ("product_name", "Gateway"),
            ("version", "1.0"),
            ("host", "gw"),
            ("onm", "2"),
        ],
    )
    .await;
    assert_eq!(reply.location(), "/assets/opennetmon?msg=device_taken");
    let d = inventory::onm_device(&h.state.pool, 2)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(d.state, "taken");

    // Removing the asset puts the device back; it can then be skipped.
    let id = d.asset_id.unwrap();
    let reply = post_form(
        &h,
        &session,
        &format!("/assets/{id}/delete"),
        &[("csrf_token", &csrf)],
    )
    .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    let reply = post_form(
        &h,
        &session,
        "/assets/opennetmon/2/state",
        &[("csrf_token", &csrf), ("state", "skipped")],
    )
    .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert!(
        page(&h, &session, "/assets/opennetmon")
            .await
            .contains("übersprungen")
    );
}

#[tokio::test]
async fn a_csv_file_is_previewed_and_taken_over() {
    let h = harness(true).await;
    let (session, csrf) = login(&h, "anna").await;
    assert!(
        page(&h, &session, "/assets/csv")
            .await
            .contains("typ;hersteller;produkt")
    );
    let text = "typ;hersteller;produkt;version;host\n\
                software;Traefik Labs;Traefik;3.7.1;server01\n\
                hardware;AVM;FRITZ!OS;8.20;<b>router</b>\n\
                rakete;;x;1;\n";
    let reply = post_form(
        &h,
        &session,
        "/assets/csv",
        &[("csrf_token", &csrf), ("text", text), ("action", "preview")],
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(
        reply
            .body
            .contains("2 neu, 0 geändert, 0 unverändert, 1 mit Fehler"),
        "{}",
        reply.body
    );
    assert!(reply.body.contains("&#60;b&#62;router&#60;/b&#62;"));
    assert!(reply.body.contains("2 Zeilen übernehmen"));
    assert!(assets::all(&h.state.pool).await.unwrap().is_empty());

    let reply = post_form(
        &h,
        &session,
        "/assets/csv",
        &[("csrf_token", &csrf), ("text", text), ("action", "import")],
    )
    .await;
    assert_eq!(reply.location(), "/assets?msg=csv_imported");
    let all = assets::all(&h.state.pool).await.unwrap();
    assert_eq!(all.len(), 2);
    assert!(all.iter().all(|a| a.origin == "csv"));

    // The same file again changes nothing; a new version changes the asset.
    let reply = post_form(
        &h,
        &session,
        "/assets/csv",
        &[
            ("csrf_token", &csrf),
            ("text", &text.replace("3.7.1", "3.7.2")),
            ("action", "preview"),
        ],
    )
    .await;
    assert!(
        reply
            .body
            .contains("0 neu, 1 geändert, 1 unverändert, 1 mit Fehler"),
        "{}",
        reply.body
    );

    let reply = post_form(
        &h,
        &session,
        "/assets/csv",
        &[
            ("csrf_token", &csrf),
            ("text", "a;b\n1;2"),
            ("action", "preview"),
        ],
    )
    .await;
    assert!(reply.body.contains("mindestens „produkt“"));
}

#[tokio::test]
async fn the_kernel_of_a_pi_stays_visible_without_a_data_source() {
    let h = harness(true).await;
    let (session, _) = login(&h, "anna").await;
    sqlx::raw_sql(
        "INSERT INTO ssh_hosts (id, name, address, username, distro, release, created_ms)
           VALUES (1, 'pi01', '127.0.0.2', 'opensecmon', 'debian', '13', 0);
         INSERT INTO assets (id, kind, vendor, product, vendor_name, product_name, version, host, distro, release,
                             origin, origin_ref, created_ms, updated_ms)
           VALUES (1, 'package', 'debian', 'linux', 'Debian', 'linux', '1:6.18.60-1+rpt1', 'pi01', 'debian', '13',
                   'ssh', 'ssh:1', 0, 0),
                  (2, 'package', 'debian', 'glibc', 'Debian', 'glibc', '2.41-12+rpt1', 'pi01', 'debian', '13',
                   'ssh', 'ssh:1', 0, 0);",
    )
    .execute(&h.state.pool)
    .await
    .unwrap();
    // Packages of a host without matches are folded, the kernel without a data source is not.
    let body = page(&h, &session, "/assets").await;
    assert!(body.contains("ohne Datenquelle (Raspberry-Pi-Kernel)"));
    assert!(body.contains("href=\"/assets/1\""));
    assert!(!body.contains("href=\"/assets/2\""));
    let body = page(&h, &session, "/assets/1").await;
    assert!(body.contains("Die Daten von Debian passen nicht dazu"));
    assert!(
        !page(&h, &session, "/assets/2")
            .await
            .contains("Die Daten von Debian passen nicht dazu")
    );
}

#[tokio::test]
async fn a_vulnerability_of_two_packages_counts_once_per_host() {
    let h = harness(true).await;
    let (session, _) = login(&h, "anna").await;
    sqlx::raw_sql(
        "INSERT INTO ssh_hosts (id, name, address, username, distro, release, packages, created_ms)
           VALUES (1, 'server01', '127.0.0.1', 'opensecmon', 'ubuntu', '26.04', 2, 0);
         INSERT INTO agent_devices (id, name, packages, created_ms) VALUES (1, 'laptop01', 1, 0);
         INSERT INTO cves (id, state, title, prio) VALUES ('CVE-2026-1', 'published', 'one', 50),
                                                         ('CVE-2026-2', 'published', 'two', 50);
         INSERT INTO assets (id, kind, vendor, product, vendor_name, product_name, version, host, distro, release,
                             origin, origin_ref, created_ms, updated_ms)
           VALUES (1, 'package', 'ubuntu', 'qemu', 'Ubuntu', 'qemu', '1:10.1-1', 'server01', 'ubuntu', '26.04',
                   'ssh', 'ssh:1', 0, 0),
                  (2, 'package', 'ubuntu', 'qemu-hwe', 'Ubuntu', 'qemu-hwe', '1:10.1-1', 'server01', 'ubuntu',
                   '26.04', 'ssh', 'ssh:1', 0, 0),
                  (3, 'package', 'ubuntu', 'zlib', 'Ubuntu', 'zlib', '1:1.3-1', 'laptop01', 'ubuntu', '24.04',
                   'agent', 'agent:1', 0, 0);
         INSERT INTO matches (subject, asset_id, vuln, confidence, method, first_seen_ms, updated_ms, state_ms)
           VALUES ('asset:1', 1, 'CVE-2026-1', 'high', 'distro', 0, 0, 0),
                  ('asset:2', 2, 'CVE-2026-1', 'high', 'distro', 0, 0, 0),
                  ('asset:2', 2, 'CVE-2026-2', 'high', 'distro', 0, 0, 0),
                  ('asset:3', 3, 'CVE-2026-1', 'high', 'distro', 0, 0, 0);",
    )
    .execute(&h.state.pool)
    .await
    .unwrap();
    // The asset list counts per asset in its rows and per host in the head of the group.
    let body = page(&h, &session, "/assets").await;
    assert!(body.contains("2 Schwachstellen offen"), "{body}");
    assert!(!body.contains("3 Schwachstellen offen"));
    assert!(body.contains("1 Schwachstelle offen"));
    let body = page(&h, &session, "/assets/hosts").await;
    assert!(body.contains("2 Schwachstellen in 2 Paketen"), "{body}");
    let body = page(&h, &session, "/assets/computers").await;
    assert!(body.contains("1 Schwachstelle in 1 Paket"), "{body}");
}

#[tokio::test]
async fn a_pending_reboot_shows_the_running_and_the_installed_kernel() {
    let h = harness(true).await;
    let (session, _) = login(&h, "anna").await;
    sqlx::raw_sql(
        "INSERT INTO ssh_hosts (id, name, address, username, distro, release, packages, kernel, kernel_installed,
                                reboot_required, created_ms)
           VALUES (1, 'server01', '127.0.0.1', 'opensecmon', 'ubuntu', '26.04', 1, '7.0.0-38-generic',
                   '7.0.0-42.42', 1, 0),
                  (2, 'pi01', '127.0.0.2', 'opensecmon', 'debian', '13', 1, '6.18.60+rpt-rpi-v8',
                   '1:6.18.60-1+rpt1', 0, 0),
                  (3, 'nas01', '127.0.0.3', 'opensecmon', 'debian', '13', 1, '', '', 0, 0);
         INSERT INTO agent_devices (id, name, packages, kernel, kernel_installed, reboot_required, created_ms)
           VALUES (1, 'laptop01', 1, '6.17.0-6-generic', '6.17.0-7.7', 1, 0);",
    )
    .execute(&h.state.pool)
    .await
    .unwrap();
    let body = page(&h, &session, "/assets/hosts").await;
    assert!(
        body.contains("Neustart nötig, läuft Kernel 7.0.0-38-generic, installiert 7.0.0-42.42")
    );
    assert!(body.contains("Kernel 6.18.60+rpt-rpi-v8"));
    assert_eq!(
        body.matches("Kernel ").count(),
        2,
        "nas01 has an older script"
    );
    assert!(
        page(&h, &session, "/assets/hosts/1/edit")
            .await
            .contains("Neustart nötig, läuft Kernel 7.0.0-38-generic")
    );
    let body = page(&h, &session, "/assets/computers").await;
    assert!(body.contains("Neustart nötig, läuft Kernel 6.17.0-6-generic, installiert 6.17.0-7.7"));
    assert!(
        page(&h, &session, "/assets/computers/1")
            .await
            .contains("Neustart nötig, läuft Kernel 6.17.0-6-generic")
    );
}
