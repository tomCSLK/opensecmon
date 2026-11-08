use super::*;
use crate::mail::testsmtp::{Behavior, TestSmtp};
use crate::web::testutil::*;

const ALERTS: &str = "instant=on&on_kev=on&prio_on=on&prio_min=80&cvss_on=on&cvss_min=8%2C5&epss_min=10\
    &min_confidence=high&bundle=on&public_url=https%3A%2F%2Fsec.example.org%2F";

#[test]
fn the_interface_address_is_checked_and_normalised() {
    assert_eq!(check_public_url("").unwrap(), "");
    assert_eq!(
        check_public_url(" HTTPS://Sec.Example.org/ ").unwrap(),
        "https://sec.example.org"
    );
    assert_eq!(
        check_public_url("http://192.168.1.2:8090/secmon/").unwrap(),
        "http://192.168.1.2:8090/secmon"
    );
    for bad in [
        "sec.example.org",
        "ftp://x.org",
        "https://",
        "https://x.org:0",
        "https://x.org:99999",
        "https://user@x.org",
        "https://x.org/?a=b",
        "https://x.org/#top",
        "https://x.org/a b",
        "https://x.org/\"><script>",
        "javascript:alert(1)",
    ] {
        assert!(check_public_url(bad).is_err(), "{bad}");
    }
}

#[test]
fn report_times_are_hours_and_minutes() {
    assert_eq!(parse_time("07:00"), Some(420));
    assert_eq!(parse_time("23:59"), Some(1439));
    for bad in ["24:00", "7", "07:60", "-1:00", "07:00:00", ""] {
        assert_eq!(parse_time(bad), None, "{bad}");
    }
}

#[tokio::test]
async fn the_pages_need_a_session_and_a_valid_token() {
    let h = harness(true).await;
    for path in ["/settings/alerts", "/settings/report"] {
        assert_eq!(send(&h.app, get(path, None)).await.location(), "/login");
    }
    let (admin, _) = login(&h, "anna").await;
    for (path, body) in [
        ("/settings/alerts", format!("csrf_token=wrong&{ALERTS}")),
        ("/settings/report", "csrf_token=wrong&time=07:00".to_owned()),
        ("/settings/report/send", "csrf_token=wrong".to_owned()),
    ] {
        assert_eq!(
            send(&h.app, post(path, Some(&admin), &body)).await.status,
            StatusCode::FORBIDDEN,
            "{path}"
        );
    }
    assert_eq!(
        send(&h.app, get("/settings", Some(&admin)))
            .await
            .location(),
        "/settings/alerts"
    );
    let page = send(&h.app, get("/settings/alerts", Some(&admin))).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(
        page.body
            .contains("<a href=\"/settings/alerts\" aria-current=\"page\"")
    );
    assert!(
        page.body
            .contains("E-Mail-Benachrichtigung ist ausgeschaltet"),
        "mail is off by default"
    );
}

#[tokio::test]
async fn the_instant_mail_settings_are_saved_and_logged() {
    let h = harness(true).await;
    let (admin, csrf) = login(&h, "anna").await;
    let reply = send(
        &h.app,
        post(
            "/settings/alerts",
            Some(&admin),
            &format!("csrf_token={csrf}&{ALERTS}"),
        ),
    )
    .await;
    assert_eq!(reply.location(), "/settings/alerts?msg=alerts_saved");
    let s = store::settings(&h.state.pool).await.unwrap();
    assert_eq!(
        (
            s.prio_min,
            s.cvss_on,
            s.cvss_min,
            s.epss_on,
            s.min_confidence,
            s.once_per_vuln
        ),
        (80, true, 8.5, false, Confidence::High, false)
    );
    assert_eq!(s.public_url, "https://sec.example.org");
    assert!(s.report, "the report part stays");
    let page = send(
        &h.app,
        get("/settings/alerts?msg=alerts_saved", Some(&admin)),
    )
    .await;
    assert!(
        page.body
            .contains("Einstellungen der Sofort-Mail gespeichert")
    );
    assert!(page.body.contains("value=\"8,5\""), "German decimal comma");
    let audit = send(&h.app, get("/settings/audit", Some(&admin))).await;
    assert!(audit.body.contains("Sofort-Mail"), "{}", audit.body);

    for (field, message) in [
        ("prio_min=101", "ganze Zahl von 0 bis 100"),
        ("cvss_min=11", "zwischen 0 und 10"),
        ("epss_min=abc", "zwischen 0 und 100"),
        ("public_url=sec.example.org", "http:// oder https://"),
    ] {
        let body = format!("csrf_token={csrf}&{ALERTS}&{field}").replacen(
            &format!("{}=", field.split('=').next().unwrap()),
            "x=",
            1,
        );
        let reply = send(&h.app, post("/settings/alerts", Some(&admin), &body)).await;
        assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY, "{field}");
        assert!(reply.body.contains(message), "{field}");
    }
    assert_eq!(store::settings(&h.state.pool).await.unwrap().prio_min, 80);
}

#[tokio::test]
async fn the_report_settings_show_a_preview_and_send_now_works() {
    let h = harness(true).await;
    let (admin, csrf) = login(&h, "anna").await;
    let reply = send(
        &h.app,
        post(
            "/settings/report",
            Some(&admin),
            &format!("csrf_token={csrf}&report=on&time=06%3A45&report_new=on&report_due=on"),
        ),
    )
    .await;
    assert_eq!(reply.location(), "/settings/report?msg=report_saved");
    let s = store::settings(&h.state.pool).await.unwrap();
    assert_eq!(
        (
            s.report_minute,
            s.report_new,
            s.report_open,
            s.report_due,
            s.report_skip_empty
        ),
        (405, true, false, true, false)
    );
    let page = send(&h.app, get("/settings/report", Some(&admin))).await;
    assert!(page.body.contains("value=\"06:45\""));
    assert!(
        page.body.contains("[opensecmon] Tagesbericht"),
        "{}",
        page.body
    );
    assert!(page.body.contains("Nichts zu melden"));

    let bad = send(
        &h.app,
        post(
            "/settings/report",
            Some(&admin),
            &format!("csrf_token={csrf}&time=25%3A00"),
        ),
    )
    .await;
    assert_eq!(bad.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(bad.body.contains("HH:MM"));

    // "Send now" with a mail server: the report goes out and is logged.
    let smtp = TestSmtp::spawn(Behavior::default()).await;
    let input = crate::mail::MailInput {
        enabled: false,
        host: "127.0.0.1".to_owned(),
        port: smtp.port,
        security: crate::mail::Security::None,
        username: String::new(),
        password: None,
        from_address: "opensecmon@example.org".to_owned(),
        recipients: "admin@example.org".to_owned(),
        language: Lang::En,
    };
    mail_store::save(&h.state.pool, &h.state.secrets, &input.check().unwrap())
        .await
        .unwrap();
    let reply = send(
        &h.app,
        post(
            "/settings/report/send",
            Some(&admin),
            &format!("csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(
        reply
            .body
            .contains("Tagesbericht an admin@example.org gesendet"),
        "{}",
        reply.body
    );
    assert_eq!(smtp.received().len(), 1);
    assert!(
        smtp.received()[0].data.contains("Daily report"),
        "mail language"
    );
    let log = mail_store::recent_notifications(&h.state.pool, 1)
        .await
        .unwrap();
    assert_eq!(log[0].kind, mail_store::Kind::Report);
}
