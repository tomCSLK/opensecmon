//! What is left of the pages of the main navigation: the settings start page. The inbox, "Situation",
//! "Assets", "All CVEs" and "Sources" have modules of their own.

use axum::response::Redirect;

use crate::web::auth::CurrentUser;

/// The settings start with the instant mail.
pub async fn settings(_user: CurrentUser) -> Redirect {
    Redirect::to("/settings/alerts")
}

#[cfg(test)]
mod tests {
    use crate::web::testutil::*;
    use axum::http::StatusCode;

    #[tokio::test]
    async fn every_page_of_the_navigation_opens_and_marks_itself() {
        let h = harness(true).await;
        let (session, _) = login(&h, "anna").await;
        for (path, heading) in [
            ("/", "Eingang"),
            ("/situation", "Lage"),
            ("/assets", "Assets"),
            ("/cves", "Alle CVEs"),
            ("/sources", "Quellen"),
        ] {
            let reply = send(&h.app, get(path, Some(&session))).await;
            assert_eq!(reply.status, StatusCode::OK, "{path}");
            assert!(
                reply
                    .body
                    .contains(&format!("<a href=\"{path}\" aria-current=\"page\"")),
                "{path} is not marked in the navigation"
            );
            assert!(reply.body.contains(heading), "{path}");
        }
        let reply = send(&h.app, get("/settings", Some(&session))).await;
        assert_eq!(reply.location(), "/settings/alerts");
    }

    #[tokio::test]
    async fn pages_need_a_session() {
        let h = harness(true).await;
        for path in [
            "/",
            "/situation",
            "/assets",
            "/cves",
            "/sources",
            "/settings",
        ] {
            let reply = send(&h.app, get(path, None)).await;
            assert_eq!(reply.location(), "/login", "{path}");
        }
    }

    #[tokio::test]
    async fn pages_follow_the_language_of_the_user() {
        let h = harness(true).await;
        let (session, _) = login(&h, "anna").await;
        let reply = send(&h.app, accepting(get("/cves", Some(&session)), "en")).await;
        assert!(reply.body.contains("<html lang=\"en\">"));
        assert!(reply.body.contains("All CVEs"));
    }
}
