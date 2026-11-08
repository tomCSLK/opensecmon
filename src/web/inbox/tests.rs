use axum::http::StatusCode;

use crate::sources::now_ms;
use crate::storage::matches::{self, Confidence, Found, Method, Subject};
use crate::web::cves::encode;
use crate::web::testutil::*;

async fn post_form(h: &Harness, session: &str, fields: &[(&str, &str)]) -> Reply {
    let form: Vec<String> = fields
        .iter()
        .map(|(k, v)| format!("{k}={}", encode(v)))
        .collect();
    send(&h.app, post("/inbox", Some(session), &form.join("&"))).await
}

/// Two assets on two hosts; a critical KEV CVE on both, a medium one and a USN on the first.
async fn fixture(h: &Harness) -> (i64, i64) {
    let pool = &h.state.pool;
    sqlx::raw_sql(
        "INSERT INTO cves (id, state, title, published_ms, prio, kev_added) VALUES
           ('CVE-2026-10001', 'published', 'regreSSHion again', 1, 80, 1),
           ('CVE-2026-20002', 'published', 'a <b>medium</b> one', 1, 50, NULL);
         INSERT INTO assets (kind, vendor, product, vendor_name, product_name, version, host, distro, release,
                             created_ms, updated_ms)
           VALUES ('package', 'ubuntu', 'openssh', '', 'openssh', '1:9.6p1-3ubuntu13.4', 'server01', 'ubuntu',
                   '24.04', 0, 0),
                  ('software', 'openbsd', 'openssh', 'OpenBSD', 'OpenSSH', '9.6p1', 'pi01', '', '', 0, 0);",
    )
    .execute(pool)
    .await
    .unwrap();
    let found = |vuln: &str, conf: Confidence, method: Method, base: i64| Found {
        vuln: vuln.to_owned(),
        title: format!("title of {vuln}"),
        confidence: conf,
        method,
        fixed: "1:9.6p1-3ubuntu13.5".to_owned(),
        evidence: vec!["USN-7000-1".to_owned()],
        base_prio: base,
        rating: crate::storage::matches::Rating::None,
    };
    let now = now_ms();
    matches::sync(
        pool,
        Subject::Asset(1),
        &[
            found("CVE-2026-10001", Confidence::High, Method::Distro, 0),
            found("CVE-2026-20002", Confidence::High, Method::Distro, 0),
            found("osv:USN-7000-1", Confidence::High, Method::Distro, 70),
        ],
        now,
    )
    .await
    .unwrap();
    matches::sync(
        pool,
        Subject::Asset(2),
        &[found("CVE-2026-10001", Confidence::Medium, Method::Nvd, 0)],
        now,
    )
    .await
    .unwrap();
    (1, 2)
}

async fn state_of(h: &Harness, vuln: &str) -> Vec<String> {
    sqlx::query_scalar("SELECT state FROM matches WHERE vuln = ? ORDER BY id")
        .bind(vuln)
        .fetch_all(&h.state.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn without_assets_the_inbox_shows_how_to_start() {
    let h = harness(true).await;
    let (session, _) = login(&h, "anna").await;
    let reply = send(&h.app, get("/", Some(&session))).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.body.contains("Noch keine Assets"));
    assert!(reply.body.contains("href=\"/assets/new\""));
}

#[tokio::test]
async fn the_inbox_lists_vulnerabilities_by_priority_with_their_assets() {
    let h = harness(true).await;
    fixture(&h).await;
    let (session, _) = login(&h, "anna").await;
    let reply = send(&h.app, get("/", Some(&session))).await;
    assert_eq!(reply.status, StatusCode::OK);
    let body = &reply.body;
    let first = body.find("data-href=\"/?sel=CVE-2026-10001\"").unwrap();
    let second = body.find("data-href=\"/?sel=osv%3AUSN-7000-1\"").unwrap();
    let third = body.find("data-href=\"/?sel=CVE-2026-20002\"").unwrap();
    assert!(first < second && second < third, "ordered by priority");
    assert!(body.contains("3 Meldungen"));
    assert!(body.contains("pi01, server01"), "both hosts of the first");
    assert!(
        body.contains("a &#60;b&#62;medium&#60;/b&#62; one") || body.contains("a &lt;b&gt;medium")
    );
    // Without a choice the first is shown beside the list, but stays unread.
    assert!(body.contains("name=\"action\" value=\"done\""));
    assert!(!body.contains("Im Eingang bearbeiten"));
    assert_eq!(state_of(&h, "CVE-2026-10001").await, ["new", "new"]);
    // Choosing it marks it as seen.
    let reply = send(&h.app, get("/?sel=CVE-2026-10001", Some(&session))).await;
    assert!(reply.body.contains("data-sheet-open"));
    assert!(
        reply.body.contains("Gilt für"),
        "two open matches: ignore can pick"
    );
    assert_eq!(state_of(&h, "CVE-2026-10001").await, ["seen", "seen"]);
    // The USN without a record of its own.
    let reply = send(&h.app, get("/?sel=osv%3AUSN-7000-1", Some(&session))).await;
    assert!(
        reply
            .body
            .contains("https://osv.dev/vulnerability/USN-7000-1")
    );
}

#[tokio::test]
async fn filters_narrow_the_list_and_count_the_rest() {
    let h = harness(true).await;
    fixture(&h).await;
    let (session, _) = login(&h, "anna").await;
    let reply = send(&h.app, get("/?host=pi01", Some(&session))).await;
    assert!(reply.body.contains("1 Meldung"));
    assert!(reply.body.contains("Host / Gerät: pi01"), "chip");
    // The host group still counts the other host (its own filter is left out).
    assert!(reply.body.contains("href=\"/?host=server01\""));
    let reply = send(&h.app, get("/?view=critical", Some(&session))).await;
    assert!(reply.body.contains("1 Meldung"));
    let reply = send(&h.app, get("/?kev=1&conf=medium", Some(&session))).await;
    assert!(reply.body.contains("1 Meldung"));
    let reply = send(&h.app, get("/?sev=low", Some(&session))).await;
    assert!(reply.body.contains("Nichts gefunden"));
    let reply = send(&h.app, get("/?asset=2&sort=host", Some(&session))).await;
    assert!(reply.body.contains("1 Meldung"));
}

#[tokio::test]
async fn the_fix_filter_keeps_matches_with_an_announced_fix() {
    let h = harness(true).await;
    fixture(&h).await;
    // The NVD match on pi01 and the medium CVE have no fixed version.
    sqlx::query("UPDATE matches SET fixed = '' WHERE asset_id = 2 OR vuln = 'CVE-2026-20002'")
        .execute(&h.state.pool)
        .await
        .unwrap();
    let (session, _) = login(&h, "anna").await;
    let reply = send(&h.app, get("/", Some(&session))).await;
    assert!(reply.body.contains("href=\"/?fix=1\""));
    assert!(reply.body.contains("Korrektur angekündigt"));
    let reply = send(&h.app, get("/?fix=1", Some(&session))).await;
    assert!(reply.body.contains("2 Meldungen"));
    assert!(
        !reply
            .body
            .contains("data-href=\"/?fix=1&sel=CVE-2026-20002\"")
    );
    assert!(
        reply.body.contains("name=\"fix\" value=\"1\""),
        "kept when sorting"
    );
    assert!(reply.body.contains("href=\"/inbox.csv?fix=1\""));
    // A match counts by itself: pi01 has no fix, so the CVE leaves its host.
    let reply = send(&h.app, get("/?fix=1&host=pi01", Some(&session))).await;
    assert!(reply.body.contains("Nichts gefunden"));
    let reply = send(&h.app, get("/?fix=1&host=server01", Some(&session))).await;
    assert!(reply.body.contains("2 Meldungen"));
    let reply = send(&h.app, get("/inbox.csv?fix=1", Some(&session))).await;
    assert!(!reply.body.contains("CVE-2026-20002"));
    assert!(!reply.body.contains("pi01"));
}

#[tokio::test]
async fn triage_moves_matches_between_the_views() {
    let h = harness(true).await;
    fixture(&h).await;
    let (session, csrf) = login(&h, "anna").await;

    // Done, then on to the next one of the list.
    let reply = post_form(
        &h,
        &session,
        &[
            ("csrf_token", &csrf),
            ("action", "done"),
            ("vuln", "CVE-2026-10001"),
            ("back", "sort=new&host=<x>"),
            ("next", "CVE-2026-20002"),
        ],
    )
    .await;
    assert_eq!(
        reply.location(),
        "/?host=%3Cx%3E&sort=new&sel=CVE-2026-20002&msg=triage_done"
    );
    assert_eq!(state_of(&h, "CVE-2026-10001").await, ["done", "done"]);
    let reply = send(&h.app, get("/?view=done", Some(&session))).await;
    assert!(reply.body.contains("1 Meldung"));

    // Reopen.
    post_form(
        &h,
        &session,
        &[
            ("csrf_token", &csrf),
            ("action", "reopen"),
            ("vuln", "CVE-2026-10001"),
        ],
    )
    .await;
    assert_eq!(state_of(&h, "CVE-2026-10001").await, ["seen", "seen"]);

    // Ignore only the match on pi01, with a reason.
    let id: i64 =
        sqlx::query_scalar("SELECT id FROM matches WHERE vuln = 'CVE-2026-10001' AND asset_id = 2")
            .fetch_one(&h.state.pool)
            .await
            .unwrap();
    post_form(
        &h,
        &session,
        &[
            ("csrf_token", &csrf),
            ("action", "ignore"),
            ("vuln", "CVE-2026-10001"),
            ("id", &id.to_string()),
            ("reason", "lan"),
            ("note", "only behind the VPN"),
        ],
    )
    .await;
    assert_eq!(state_of(&h, "CVE-2026-10001").await, ["seen", "ignored"]);
    let reply = send(&h.app, get("/?sel=CVE-2026-10001", Some(&session))).await;
    assert!(reply.body.contains("Nur im LAN erreichbar"));
    assert!(reply.body.contains("only behind the VPN"));

    // Bulk: later for two.
    post_form(
        &h,
        &session,
        &[
            ("csrf_token", &csrf),
            ("action", "later:30"),
            ("vuln", "CVE-2026-20002"),
            ("vuln", "osv:USN-7000-1"),
        ],
    )
    .await;
    assert_eq!(state_of(&h, "CVE-2026-20002").await, ["later"]);
    let until: i64 =
        sqlx::query_scalar("SELECT until_ms FROM matches WHERE vuln = 'CVE-2026-20002'")
            .fetch_one(&h.state.pool)
            .await
            .unwrap();
    assert!(until > now_ms() + 29 * 86_400_000);
    // Waking up: the date has come.
    sqlx::query("UPDATE matches SET until_ms = 1 WHERE vuln = 'CVE-2026-20002'")
        .execute(&h.state.pool)
        .await
        .unwrap();
    send(&h.app, get("/", Some(&session))).await;
    assert_eq!(state_of(&h, "CVE-2026-20002").await, ["seen"]);
}

#[tokio::test]
async fn triage_needs_the_csrf_token_and_a_known_action() {
    let h = harness(true).await;
    fixture(&h).await;
    let (session, csrf) = login(&h, "anna").await;
    let reply = post_form(
        &h,
        &session,
        &[
            ("csrf_token", "wrong"),
            ("action", "done"),
            ("vuln", "CVE-2026-10001"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    let reply = post_form(
        &h,
        &session,
        &[
            ("csrf_token", &csrf),
            ("action", "explode"),
            ("vuln", "CVE-2026-10001"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(state_of(&h, "CVE-2026-10001").await, ["new", "new"]);
}

#[tokio::test]
async fn cve_pages_show_the_own_assets() {
    let h = harness(true).await;
    fixture(&h).await;
    let (session, _) = login(&h, "anna").await;
    let reply = send(&h.app, get("/cves/CVE-2026-10001", Some(&session))).await;
    assert!(reply.body.contains("Im Eingang bearbeiten"));
    assert!(reply.body.contains("1:9.6p1-3ubuntu13.4"));
    assert!(reply.body.contains("href=\"/assets/2\""));
    let reply = send(&h.app, get("/cves/CVE-2026-20002", Some(&session))).await;
    assert!(reply.body.contains("href=\"/?sel=CVE-2026-20002\""));
    assert!(reply.body.contains("gefunden <time class=\"ts\""));
    assert!(!reply.body.contains("Sofort-Mail <time"));
    // The instant mail shows with its time once it went out.
    let id: i64 = sqlx::query_scalar("SELECT id FROM matches WHERE vuln = 'CVE-2026-20002'")
        .fetch_one(&h.state.pool)
        .await
        .unwrap();
    matches::set_alert(&h.state.pool, &[id], true, 1_792_915_200_000)
        .await
        .unwrap();
    let reply = send(&h.app, get("/cves/CVE-2026-20002", Some(&session))).await;
    assert!(
        reply
            .body
            .contains("Sofort-Mail <time class=\"ts\" datetime=\"2026-10-25T08:00:00Z\">")
    );
}

#[tokio::test]
async fn the_lists_download_as_csv_with_their_filters() {
    let h = harness(true).await;
    fixture(&h).await;
    sqlx::query("UPDATE cves SET title = '=cmd|calc' WHERE id = 'CVE-2026-20002'")
        .execute(&h.state.pool)
        .await
        .unwrap();
    let (session, _) = login(&h, "anna").await;
    let reply = send(&h.app, get("/", Some(&session))).await;
    assert!(reply.body.contains("href=\"/inbox.csv\""));
    let reply = send(&h.app, get("/?kev=1", Some(&session))).await;
    assert!(reply.body.contains("href=\"/inbox.csv?kev=1\""));

    let reply = send(&h.app, get("/inbox.csv", Some(&session))).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.headers.get("content-type").unwrap(),
        "text/csv; charset=utf-8"
    );
    assert!(
        reply
            .headers
            .get("content-disposition")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("attachment; filename=\"opensecmon-inbox-")
    );
    let lines: Vec<&str> = reply.body.lines().collect();
    assert!(lines[0].starts_with("\u{feff}Kennung;Titel;Priorität;"));
    // One line per match: the KEV CVE on two assets, the medium CVE, the USN.
    assert_eq!(lines.len(), 1 + 4, "{}", reply.body);
    assert!(
        lines[1].starts_with(
            "CVE-2026-10001;regreSSHion again;90;Kritisch;ja;neu;openssh;server01;Ubuntu 24.04;"
        ),
        "{}",
        lines[1]
    );
    assert!(reply.body.contains(";'=cmd|calc;"), "formula defused");

    let reply = send(&h.app, get("/inbox.csv?kev=1", Some(&session))).await;
    assert_eq!(reply.body.lines().count(), 1 + 2);

    let reply = send(&h.app, get("/cves.csv?period=all&mine=1", Some(&session))).await;
    assert_eq!(reply.status, StatusCode::OK);
    let lines: Vec<&str> = reply.body.lines().collect();
    assert!(lines[0].starts_with("\u{feff}CVE;Status;Veröffentlicht;Titel;"));
    assert_eq!(lines.len(), 1 + 2, "{}", reply.body);
    assert!(
        lines
            .iter()
            .all(|l| l.ends_with(";ja") || l.starts_with('\u{feff}'))
    );
    let reply = send(
        &h.app,
        accepting(get("/cves.csv?period=all", Some(&session)), "en"),
    )
    .await;
    assert!(reply.body.starts_with("\u{feff}CVE,State,Published,"));
    let reply = send(&h.app, get("/cves?period=all", Some(&session))).await;
    assert!(reply.body.contains("href=\"/cves.csv?period=all\""));
    let reply = send(&h.app, get("/cves.csv", None)).await;
    assert_eq!(reply.location(), "/login");
}

/// Labels that functions return, which the catalog check in i18n.rs cannot follow.
#[test]
fn every_label_of_assets_and_matches_exists_in_every_language() {
    use crate::storage::assets::Kind;
    let mut ids: Vec<&str> = super::View::ALL.iter().map(|v| v.label_id()).collect();
    ids.extend(Kind::ALL.iter().map(|k| k.label_id()));
    ids.extend(
        [Confidence::High, Confidence::Medium, Confidence::Low]
            .iter()
            .map(|c| c.label_id()),
    );
    ids.extend(
        [
            Method::Distro,
            Method::Nvd,
            Method::Cna,
            Method::Csaf,
            Method::Watch,
        ]
        .iter()
        .map(|m| m.label_id()),
    );
    ids.extend([
        "asset-error-kind",
        "asset-error-too-long",
        "asset-error-control",
        "asset-error-distro",
        "asset-error-release",
        "asset-error-package",
        "asset-error-package-version",
        "asset-error-cpe",
        "asset-error-product",
        "watch-error-short",
    ]);
    for id in ids {
        for t in crate::i18n::Lang::ALL {
            assert_ne!(t.get(id), id, "{id} is missing");
        }
    }
    for key in super::REASONS {
        for t in crate::i18n::Lang::ALL {
            assert_ne!(super::reason_text(t, key), key, "reason {key}");
        }
    }
}

#[tokio::test]
async fn muted_matches_leave_the_inbox_unless_it_is_filtered_by_their_asset() {
    let h = harness(true).await;
    fixture(&h).await;
    let (admin, _) = login(&h, "anna").await;
    // From 75 on, server01 hides the medium CVE (50) and the USN (70); the KEV CVE (80) stays.
    sqlx::query("UPDATE assets SET min_prio = 75 WHERE id = 1")
        .execute(&h.state.pool)
        .await
        .unwrap();
    let page = send(&h.app, get("/", Some(&admin))).await;
    assert!(page.body.contains("CVE-2026-10001"));
    assert!(!page.body.contains("CVE-2026-20002"), "muted");
    assert_eq!(
        page.body.matches("<li class=\"row").count(),
        1,
        "only the KEV CVE"
    );
    assert!(
        page.body
            .contains("2 Schwachstellen unter der Mindestpriorität ihres Assets ausgeblendet"),
        "{}",
        page.body
    );
    assert!(page.body.contains("href=\"/?view=open&#38;asset=1\""));
    let filtered = send(&h.app, get("/?asset=1", Some(&admin))).await;
    assert!(filtered.body.contains("CVE-2026-20002"));
    assert!(filtered.body.contains("Mindestpriorität 75"));
    let csv = send(&h.app, get("/inbox.csv", Some(&admin))).await;
    assert!(!csv.body.contains("CVE-2026-20002"));
    assert_eq!(matches::open_count(&h.state.pool).await.unwrap(), 1);
}

#[tokio::test]
async fn the_rating_of_the_distribution_takes_off_and_shows() {
    let h = harness(true).await;
    fixture(&h).await;
    let (admin, _) = login(&h, "anna").await;
    // Ubuntu rates the medium CVE (50) as negligible: 50 − 30 = 20; the KEV CVE (80) as low: it stays at the floor.
    sqlx::raw_sql(
        "UPDATE matches SET rating = 'negligible' WHERE vuln = 'CVE-2026-20002';
         UPDATE matches SET rating = 'low' WHERE vuln = 'CVE-2026-10001' AND asset_id = 1;",
    )
    .execute(&h.state.pool)
    .await
    .unwrap();
    let rows = matches::rows(&h.state.pool, &[matches::State::New])
        .await
        .unwrap();
    let prio = |vuln: &str, asset: i64| {
        rows.iter()
            .find(|r| r.vuln == vuln && r.asset_id == Some(asset))
            .unwrap()
            .prio()
    };
    assert_eq!(prio("CVE-2026-20002", 1), 20);
    assert_eq!(prio("CVE-2026-10001", 1), 90, "KEV floor");
    let page = send(&h.app, get("/?sev=low", Some(&admin))).await;
    assert!(page.body.contains("CVE-2026-20002"), "now in the low band");
    let page = send(&h.app, get("/?sel=CVE-2026-20002", Some(&admin))).await;
    assert!(
        page.body
            .contains("Ubuntu stuft ein: unbedeutend („negligible“) (−30 Punkte)"),
        "{}",
        page.body
    );
    // The SQL of the counts takes off the same: from 25 on, the rated CVE is muted.
    sqlx::query("UPDATE assets SET min_prio = 25 WHERE id = 1")
        .execute(&h.state.pool)
        .await
        .unwrap();
    let rows = matches::rows(&h.state.pool, &[matches::State::New, matches::State::Seen])
        .await
        .unwrap();
    let mut shown: Vec<&str> = rows
        .iter()
        .filter(|r| !r.muted())
        .map(|r| r.vuln.as_str())
        .collect();
    shown.sort_unstable();
    shown.dedup();
    assert_eq!(
        shown,
        ["CVE-2026-10001", "osv:USN-7000-1"],
        "all but the rated CVE"
    );
    assert_eq!(matches::open_count(&h.state.pool).await.unwrap(), 2);
}
