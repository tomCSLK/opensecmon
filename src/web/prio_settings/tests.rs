use super::*;
use crate::web::testutil::*;

const FORM: &str = "cvss_weight=8&epss_weight=12%2C5&kev_floor=95&penalty_medium=5&penalty_low=30&penalty_unimportant=40&penalty_minor=15";

#[test]
fn whole_weights_show_without_decimals() {
    assert_eq!(weight_text(Lang::De, 7.0), "7");
    assert_eq!(weight_text(Lang::De, 12.5), "12,5");
    assert_eq!(weight_text(Lang::En, 12.5), "12.5");
}

#[tokio::test]
async fn the_page_needs_a_session_and_a_valid_token() {
    let h = harness(true).await;
    assert_eq!(
        send(&h.app, get("/settings/priority", None))
            .await
            .location(),
        "/login"
    );
    let (admin, _) = login(&h, "anna").await;
    let reply = send(
        &h.app,
        post(
            "/settings/priority",
            Some(&admin),
            &format!("csrf_token=wrong&{FORM}"),
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    let page = send(&h.app, get("/settings/priority", Some(&admin))).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(
        page.body
            .contains("<a href=\"/settings/priority\" aria-current=\"page\"")
    );
    assert!(page.body.contains("value=\"7\""), "{}", page.body);
    // CVSS 9.8 and EPSS 97 % with the defaults: 68.6 + 19.4 = 88.
    assert!(page.body.contains("<span>88</span>"));
    assert!(
        !page.body.contains("neu berechnet. Listen"),
        "nothing pending"
    );
}

#[tokio::test]
async fn the_weights_are_saved_logged_and_followed() {
    let h = harness(true).await;
    sqlx::raw_sql(
        "INSERT INTO cves (id, state, cvss_score, epss_percentile, kev_added, prio)
           VALUES ('CVE-1', 'published', 9.8, 0.97, NULL, 88)",
    )
    .execute(&h.state.pool)
    .await
    .unwrap();
    let (admin, csrf) = login(&h, "anna").await;
    let reply = send(
        &h.app,
        post(
            "/settings/priority",
            Some(&admin),
            &format!("csrf_token={csrf}&{FORM}"),
        ),
    )
    .await;
    assert_eq!(reply.location(), "/settings/priority?msg=prio_saved");
    let w = prio::load(&h.state.pool).await.unwrap();
    assert_eq!(
        w,
        Weights {
            cvss_weight: 8.0,
            epss_weight: 12.5,
            kev_floor: 95,
            penalty_medium: 5,
            penalty_low: 30,
            penalty_unimportant: 40,
            penalty_minor: 15,
        }
    );
    // The recompute runs in the background; wait for it.
    for _ in 0..100 {
        if !prio::pending(&h.state.pool).await.unwrap() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(!prio::pending(&h.state.pool).await.unwrap());
    let p: i64 = sqlx::query_scalar("SELECT prio FROM cves WHERE id = 'CVE-1'")
        .fetch_one(&h.state.pool)
        .await
        .unwrap();
    assert_eq!(p, 91, "9.8 × 8 + 0.97 × 12.5 = 90.5 → 91");

    let page = send(
        &h.app,
        get("/settings/priority?msg=prio_saved", Some(&admin)),
    )
    .await;
    assert!(page.body.contains("Gewichte der Priorität gespeichert"));
    assert!(page.body.contains("value=\"12,5\""), "German decimal comma");
    let audit = send(&h.app, get("/settings/audit", Some(&admin))).await;
    assert!(audit.body.contains("KEV-Untergrenze"), "{}", audit.body);

    for (field, message) in [
        ("cvss_weight=11", "zwischen 0 und 10"),
        ("epss_weight=abc", "zwischen 0 und 100"),
        ("kev_floor=9.5", "KEV-Untergrenze muss"),
        ("penalty_low=101", "Abzüge müssen"),
        ("penalty_low=1", "nicht weniger abziehen"),
        ("penalty_minor=-1", "Abzüge müssen"),
        ("penalty_minor=50", "„Unwichtig“ darf nicht weniger"),
    ] {
        let name = field.split('=').next().unwrap();
        let body = format!("csrf_token={csrf}&{FORM}").replacen(&format!("{name}="), "x=", 1)
            + "&"
            + field;
        let reply = send(&h.app, post("/settings/priority", Some(&admin), &body)).await;
        assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY, "{field}");
        assert!(reply.body.contains(message), "{field}");
    }
    assert_eq!(prio::load(&h.state.pool).await.unwrap().kev_floor, 95);

    let reply = send(
        &h.app,
        post(
            "/settings/priority",
            Some(&admin),
            &format!("csrf_token={csrf}&{FORM}&reset=1"),
        ),
    )
    .await;
    assert_eq!(reply.location(), "/settings/priority?msg=prio_saved");
    assert_eq!(prio::load(&h.state.pool).await.unwrap(), Weights::default());
}
