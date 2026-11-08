//! Tests of the page "Unassigned": rules apply to all computers at once, removing one takes its assets away.

use axum::http::StatusCode;

use crate::web::testutil::*;

/// Stores a computer with entries as a report would (without the API).
async fn computer_with(h: &Harness, name: &str, entries: &[(&str, &str, &str, &str)]) -> i64 {
    let id = crate::storage::agents::add(&h.state.pool, name, 1)
        .await
        .unwrap()
        .unwrap();
    let list: Vec<crate::inventory::items::Item> = entries
        .iter()
        .map(|(t, item_id, n, v)| {
            crate::inventory::items::Item::new(
                crate::inventory::items::ItemType::parse_sent(t).unwrap(),
                item_id,
                n,
                v,
                "Some Vendor Ltd.",
                "",
                false,
            )
            .unwrap()
        })
        .collect();
    let mut tx = h.state.pool.begin().await.unwrap();
    let origin = format!("agent:{id}");
    crate::storage::items::replace(&mut tx, &origin, &list)
        .await
        .unwrap();
    crate::storage::items::sync_origin(&mut tx, &origin, name, 1)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    id
}

async fn software(h: &Harness) -> Vec<(String, String, String)> {
    sqlx::query_as(
        "SELECT host, product_name, version FROM assets WHERE kind = 'software' ORDER BY host, product_name, version",
    )
    .fetch_all(&h.state.pool)
    .await
    .unwrap()
}

async fn post_form(h: &Harness, session: &str, path: &str, fields: &[(&str, &str)]) -> Reply {
    let form: Vec<String> = fields
        .iter()
        .map(|(k, v)| format!("{k}={}", crate::web::cves::encode(v)))
        .collect();
    send(&h.app, post(path, Some(session), &form.join("&"))).await
}

#[tokio::test]
async fn an_assignment_applies_to_all_computers_and_goes_with_its_rule() {
    let h = harness(true).await;
    let (session, csrf) = login(&h, "anna").await;
    computer_with(
        &h,
        "pc1",
        &[
            ("win", "{A1}", "Frobnicator 2.1 (x64)", "2.1.0"),
            ("win", "{F}", "Mozilla Firefox (x64 de)", "144.0.2"),
        ],
    )
    .await;
    computer_with(
        &h,
        "pc2",
        &[
            ("win", "{A2}", "Frobnicator 2.4", "2.4.1"),
            ("win", "{A3}", "Frobnicator 1.0", "1.0"),
            (
                "appx",
                "Microsoft.WindowsCalculator_8wekyb3d8bbwe",
                "Microsoft.WindowsCalculator",
                "11.2",
            ),
        ],
    )
    .await;
    // Firefox by the built-in rule; the calculator has no rule here (its publisher is not Microsoft's).
    assert_eq!(
        software(&h).await,
        [("pc1".to_owned(), "Firefox".to_owned(), "144.0.2".to_owned())]
    );
    let page = send(&h.app, get("/assets/unassigned", Some(&session))).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("Frobnicator"), "{}", page.body);
    assert!(page.body.contains("Microsoft.WindowsCalculator"));
    assert!(page.body.contains("key=frobnicator"));
    // The tab counts the entries: Frobnicator once for both computers, and the calculator.
    assert!(
        page.body
            .contains("Nicht zugeordnet<span class=\"n\">2</span>"),
        "{}",
        page.body
    );

    // The form proposes the publisher and the name without the version.
    let form = send(
        &h.app,
        get(
            "/assets/unassigned/assign?type=win&key=frobnicator",
            Some(&session),
        ),
    )
    .await;
    assert_eq!(form.status, StatusCode::OK);
    assert!(
        form.body.contains("value=\"Some Vendor Ltd.\""),
        "{}",
        form.body
    );
    assert!(form.body.contains("value=\"Frobnicator\""));
    assert!(
        form.body.contains("value=\"2.4.1\""),
        "the newest version for the preview"
    );
    let preview = post_form(
        &h,
        &session,
        "/assets/unassigned/assign",
        &[
            ("csrf_token", &csrf),
            ("type", "win"),
            ("key", "frobnicator"),
            ("vendor_name", "Frob Inc."),
            ("product_name", "Frobnicator"),
            ("version", "2.4.1"),
            ("action", "preview"),
        ],
    )
    .await;
    assert_eq!(preview.status, StatusCode::OK);
    assert_eq!(software(&h).await.len(), 1, "a preview stores nothing");

    let reply = post_form(
        &h,
        &session,
        "/assets/unassigned/assign",
        &[
            ("csrf_token", &csrf),
            ("type", "win"),
            ("key", "frobnicator"),
            ("vendor_name", "Frob Inc."),
            ("product_name", "Frobnicator"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    // Both computers, each version of its own.
    assert_eq!(
        software(&h).await,
        [
            ("pc1".to_owned(), "Firefox".to_owned(), "144.0.2".to_owned()),
            (
                "pc1".to_owned(),
                "Frobnicator".to_owned(),
                "2.1.0".to_owned()
            ),
            ("pc2".to_owned(), "Frobnicator".to_owned(), "1.0".to_owned()),
            (
                "pc2".to_owned(),
                "Frobnicator".to_owned(),
                "2.4.1".to_owned()
            ),
        ]
    );
    let page = send(&h.app, get("/assets/unassigned", Some(&session))).await;
    assert!(!page.body.contains("key=frobnicator"));
    assert!(
        page.body.contains("Frob Inc. Frobnicator"),
        "listed as a rule"
    );

    // Ignore the calculator: no longer listed.
    let reply = post_form(
        &h,
        &session,
        "/assets/unassigned/ignore",
        &[
            ("csrf_token", &csrf),
            ("type", "appx"),
            ("key", "microsoft.windowscalculator"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert!(
        crate::storage::items::unassigned(&h.state.pool)
            .await
            .unwrap()
            .is_empty()
    );

    // Removing the rule takes the assets away again.
    let rules = crate::storage::items::list_rules(&h.state.pool)
        .await
        .unwrap();
    let rule = rules.iter().find(|r| r.key == "frobnicator").unwrap();
    let reply = post_form(
        &h,
        &session,
        &format!("/assets/unassigned/rules/{}/delete", rule.id),
        &[("csrf_token", &csrf)],
    )
    .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(software(&h).await.len(), 1);
    // Recorded in the audit log.
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE kind = 'item_rule'")
        .fetch_one(&h.state.pool)
        .await
        .unwrap();
    assert_eq!(n, 3);
}

#[tokio::test]
async fn bad_assignments_are_refused() {
    let h = harness(true).await;
    let (session, csrf) = login(&h, "anna").await;
    computer_with(&h, "pc1", &[("win", "{A1}", "Frobnicator 2.1", "2.1")]).await;
    let reply = post_form(
        &h,
        &session,
        "/assets/unassigned/assign",
        &[
            ("csrf_token", &csrf),
            ("type", "win"),
            ("key", "frobnicator"),
            ("vendor_name", "Frob"),
            ("product_name", " "),
        ],
    )
    .await;
    assert_eq!(
        reply.status,
        StatusCode::OK,
        "the form again, with the error"
    );
    assert!(reply.body.contains("notice bad"));
    // Unknown entries and types.
    let reply = send(
        &h.app,
        get(
            "/assets/unassigned/assign?type=win&key=nothing",
            Some(&session),
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    let reply = send(
        &h.app,
        get(
            "/assets/unassigned/assign?type=os&key=windows",
            Some(&session),
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    // Without a valid CSRF token nothing changes.
    let reply = post_form(
        &h,
        &session,
        "/assets/unassigned/ignore",
        &[
            ("csrf_token", "wrong"),
            ("type", "win"),
            ("key", "frobnicator"),
        ],
    )
    .await;
    assert_ne!(reply.status, StatusCode::SEE_OTHER);
    assert!(
        crate::storage::items::list_rules(&h.state.pool)
            .await
            .unwrap()
            .is_empty()
    );
}
