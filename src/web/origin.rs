//! Host and origin checks in front of every handler (opennetmon has only the CSRF tokens):
//!
//! - With `allowed_hosts` in the config, requests for any other `Host` are refused (DNS rebinding: a foreign
//!   page whose name suddenly points at this server must not be able to read it).
//! - Requests that change something (every method but GET/HEAD/OPTIONS) must come from this site: an `Origin`
//!   header has to name the host of the request, and browsers that send `Sec-Fetch-Site` must not report a
//!   cross-site request. This backs up the CSRF tokens and the `SameSite=Strict` cookies.
//!
//! `/healthz` stays reachable under any host name for monitoring.

use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::web::AppState;

pub async fn check(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let headers = request.headers();
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_ascii_lowercase);
    if request.uri().path() != "/healthz"
        && !state.allowed_hosts.is_empty()
        && !host
            .as_deref()
            .is_some_and(|h| state.allowed_hosts.iter().any(|a| a == h))
    {
        tracing::warn!(host = ?host, "request for a host name that is not allowed");
        return (StatusCode::MISDIRECTED_REQUEST, "unknown host").into_response();
    }
    let changes = !matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    );
    if changes && !same_site(headers, host.as_deref()) {
        tracing::warn!(method = %request.method(), path = request.uri().path(), "cross-site request refused");
        return (StatusCode::FORBIDDEN, "cross-site request").into_response();
    }
    next.run(request).await
}

/// Whether a request that changes something comes from this site.
fn same_site(headers: &HeaderMap, host: Option<&str>) -> bool {
    if let Some(site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok())
        && site.eq_ignore_ascii_case("cross-site")
    {
        return false;
    }
    match headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        // No Origin: an older browser or a tool; the CSRF token still has to match.
        None => true,
        Some(origin) => {
            let authority = origin
                .strip_prefix("https://")
                .or_else(|| origin.strip_prefix("http://"));
            match (authority, host) {
                (Some(authority), Some(host)) => {
                    authority.eq_ignore_ascii_case(host)
                        // Behind a proxy on the default port the Host header may lack the port.
                        || authority
                            .strip_suffix(":443")
                            .or_else(|| authority.strip_suffix(":80"))
                            .is_some_and(|a| a.eq_ignore_ascii_case(host))
                }
                // `Origin: null` (sandboxed frames, some redirects) or no Host: refuse.
                _ => false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::crypto::SecretBox;
    use crate::storage;
    use crate::web::testutil::*;
    use axum::body::Body;
    use std::sync::Arc;

    fn with(mut request: Request<Body>, name: &'static str, value: &str) -> Request<Body> {
        request
            .headers_mut()
            .insert(name, header::HeaderValue::from_str(value).unwrap());
        request
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, value.parse().unwrap());
        }
        map
    }

    #[test]
    fn only_requests_of_this_site_change_something() {
        let host = Some("secmon.example.org");
        assert!(same_site(&headers(&[]), host));
        assert!(same_site(
            &headers(&[("origin", "https://secmon.example.org")]),
            host
        ));
        assert!(same_site(
            &headers(&[("origin", "https://SECMON.example.org:443")]),
            host
        ));
        assert!(same_site(
            &headers(&[("sec-fetch-site", "same-origin")]),
            host
        ));
        for bad in [
            headers(&[("origin", "https://evil.example")]),
            headers(&[("origin", "https://secmon.example.org.evil.example")]),
            headers(&[("origin", "null")]),
            headers(&[("sec-fetch-site", "cross-site")]),
        ] {
            assert!(!same_site(&bad, host), "{bad:?}");
        }
        assert!(!same_site(
            &headers(&[("origin", "https://secmon.example.org")]),
            None
        ));
    }

    #[tokio::test]
    async fn cross_site_posts_are_refused_before_the_handler() {
        let h = harness(true).await;
        let (cookie, csrf) = open_login(&h).await;
        let form = format!("username=anna&password={PASSWORD}&csrf_token={csrf}");
        let foreign = with(
            post("/login", Some(&cookie), &form),
            "origin",
            "https://evil.example",
        );
        let reply = send(&h.app, with(foreign, "host", "secmon.example.org")).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        assert!(
            reply
                .cookie_pair(crate::web::auth::SESSION_COOKIE)
                .is_none()
        );

        let own = with(
            post("/login", Some(&cookie), &form),
            "origin",
            "https://secmon.example.org",
        );
        let reply = send(&h.app, with(own, "host", "secmon.example.org")).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn other_host_names_are_refused_when_names_are_configured() {
        let dir = tempfile::tempdir().unwrap();
        let pool = storage::connect(&dir.path().join("o.db")).await.unwrap();
        storage::migrate(&pool).await.unwrap();
        let config = Config {
            allowed_hosts: vec!["Secmon.example.org".to_owned()],
            ..Config::default()
        };
        let state = AppState::new(pool, &config, Arc::new(SecretBox::from_key([2u8; 32])));
        let app = crate::web::router(state);
        let reply = send(&app, with(get("/login", None), "host", "rebound.example")).await;
        assert_eq!(reply.status, StatusCode::MISDIRECTED_REQUEST);
        assert_eq!(
            send(&app, get("/login", None)).await.status,
            StatusCode::MISDIRECTED_REQUEST,
            "a missing Host header is refused as well"
        );
        let reply = send(
            &app,
            with(get("/login", None), "host", "secmon.example.org"),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        let reply = send(&app, with(get("/healthz", None), "host", "10.0.0.5:8090")).await;
        assert_eq!(reply.status, StatusCode::OK);
    }
}
