use super::*;
use crate::web::testutil::*;

#[test]
fn sizes_and_periods_read_well() {
    assert_eq!(size_text(Lang::De, 2_329_088_000), "2,3 GB");
    assert_eq!(size_text(Lang::De, 520_400_000), "520 MB");
    assert_eq!(size_text(Lang::En, 1_500_000), "1.5 MB");
    assert_eq!(size_text(Lang::De, 64_000), "64 KB");
    assert_eq!(period_text(Lang::De, 730), "2 Jahre");
    assert_eq!(period_text(Lang::De, 90), "90 Tage");
    assert_eq!(period_text(Lang::De, 0), "immer behalten");
}

#[tokio::test]
async fn the_retention_is_saved_and_logged() {
    let h = harness(true).await;
    assert_eq!(
        send(&h.app, get("/settings/retention", None))
            .await
            .location(),
        "/login"
    );
    let (admin, csrf) = login(&h, "anna").await;
    let page = send(&h.app, get("/settings/retention", Some(&admin))).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(
        page.body
            .contains("<a href=\"/settings/retention\" aria-current=\"page\"")
    );
    assert!(
        page.body
            .contains("<option value=\"\" selected>wie Konfiguration (2 Jahre)</option>"),
        "{}",
        page.body
    );
    assert!(
        page.body
            .contains("<option value=\"365\" selected>1 Jahr</option>")
    );
    assert!(page.body.contains("noch keine Messung"));

    let reply = send(
        &h.app,
        post(
            "/settings/retention",
            Some(&admin),
            "csrf_token=wrong&audit_days=90&closed_days=0",
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    let reply = send(
        &h.app,
        post(
            "/settings/retention",
            Some(&admin),
            &format!("csrf_token={csrf}&audit_days=90&closed_days=0"),
        ),
    )
    .await;
    assert_eq!(reply.location(), "/settings/retention?msg=retention_saved");
    assert_eq!(
        store::settings(&h.state.pool).await.unwrap(),
        Settings {
            audit_days: Some(90),
            closed_days: 0
        }
    );
    let audit = send(&h.app, get("/settings/audit", Some(&admin))).await;
    assert!(audit.body.contains("Protokoll behalten"), "{}", audit.body);

    for bad in [
        "audit_days=0&closed_days=0",
        "audit_days=1&closed_days=0",
        "audit_days=&closed_days=x",
    ] {
        let reply = send(
            &h.app,
            post(
                "/settings/retention",
                Some(&admin),
                &format!("csrf_token={csrf}&{bad}"),
            ),
        )
        .await;
        assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
        assert!(reply.body.contains("angebotenen Fristen"), "{bad}");
    }
}

#[tokio::test]
async fn compacting_runs_in_the_background() {
    let h = harness(true).await;
    let (admin, csrf) = login(&h, "anna").await;
    let reply = send(
        &h.app,
        post(
            "/settings/retention/vacuum",
            Some(&admin),
            &format!("csrf_token={csrf}"),
        ),
    )
    .await;
    assert_eq!(reply.location(), "/settings/retention?msg=vacuum_started");
    for _ in 0..500 {
        if !store::vacuum_state(&h.state.pool).await.unwrap().running() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(!store::vacuum_state(&h.state.pool).await.unwrap().running());
    let page = send(&h.app, get("/settings/retention", Some(&admin))).await;
    assert!(page.body.contains("Zuletzt verkleinert"), "{}", page.body);
    assert!(
        page.body.contains("Eigene Daten"),
        "measured after compacting"
    );
    let audit = send(&h.app, get("/settings/audit", Some(&admin))).await;
    assert!(audit.body.contains("Datenbank verkleinern"));
}
