//! `opensecmon healthcheck`: asks the running server for `/healthz` on its own address, for the health
//! check of the container image (it has no shell and no curl). An address that listens on every interface
//! is reached over loopback. With built-in HTTPS the server must present the certificate of
//! `tls_cert_file` (its fingerprint is pinned, so name and validity dates do not matter).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use crate::config::Config;
use crate::http_client::{self, Get};

/// Time the server gets to answer.
const TIMEOUT: Duration = Duration::from_secs(5);

/// The address of `/healthz` for a server listening on `listen`.
pub fn url(listen: SocketAddr, tls: bool) -> String {
    let ip = match listen.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    let scheme = if tls { "https" } else { "http" };
    format!("{scheme}://{}/healthz", SocketAddr::new(ip, listen.port()))
}

/// `Ok` when the server answers `/healthz` with 200, else what went wrong.
pub async fn check(config: &Config) -> Result<(), String> {
    let pinned = match config.tls_files() {
        Some((cert, _)) => {
            let public = crate::tls::public_certificate(cert)
                .ok_or_else(|| format!("cannot read the certificate {}", cert.display()))?;
            Some(
                http_client::parse_fingerprint(&public.fingerprint)
                    .ok_or("the fingerprint of the certificate cannot be read")?,
            )
        }
        None => None,
    };
    check_url(&url(config.listen, pinned.is_some()), pinned).await
}

async fn check_url(url: &str, pinned: Option<[u8; 32]>) -> Result<(), String> {
    let mut get = Get::new(url, 64, TIMEOUT).local_network();
    if let Some(sha) = pinned {
        get = get.pinned_cert(sha);
    }
    http_client::get_bytes(&get)
        .await
        .map(|_| ())
        .map_err(|e| format!("{url}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_client::testserver;

    #[test]
    fn any_address_is_reached_over_loopback() {
        let cases = [
            ("0.0.0.0:8444", true, "https://127.0.0.1:8444/healthz"),
            ("[::]:8444", true, "https://[::1]:8444/healthz"),
            ("127.0.0.1:8090", false, "http://127.0.0.1:8090/healthz"),
            ("192.0.2.5:9000", false, "http://192.0.2.5:9000/healthz"),
        ];
        for (listen, tls, expected) in cases {
            assert_eq!(url(listen.parse().unwrap(), tls), expected);
        }
    }

    #[tokio::test]
    async fn a_server_that_answers_200_is_healthy() {
        let addr = testserver::serve(vec![testserver::ok(b"ok")]).await;
        assert_eq!(check_url(&url(addr, false), None).await, Ok(()));
    }

    #[tokio::test]
    async fn an_error_status_or_no_server_is_unhealthy() {
        let addr = testserver::serve(vec![testserver::status(503, "")]).await;
        let err = check_url(&url(addr, false), None).await.unwrap_err();
        assert!(err.contains("503"), "{err}");

        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        assert!(check_url(&url(closed, false), None).await.is_err());
    }

    #[tokio::test]
    async fn the_own_https_server_is_healthy_and_the_certificate_is_pinned() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
        crate::tls::generate(&cert, &key, &[]).unwrap();
        let loaded = crate::tls::load(&cert, &key).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = listener.local_addr().unwrap();
        let app = axum::Router::new().route("/healthz", axum::routing::get(|| async { "ok" }));
        tokio::spawn(crate::tls::serve(
            listener,
            app,
            loaded.config,
            std::future::pending(),
        ));
        let config = Config {
            listen,
            tls_cert_file: Some(cert),
            tls_key_file: Some(key.clone()),
            ..Config::default()
        };
        assert_eq!(check(&config).await, Ok(()));

        // Another certificate in the file than the server presents: not healthy.
        let other = tempfile::tempdir().unwrap();
        let other_cert = other.path().join("cert.pem");
        crate::tls::generate(&other_cert, &other.path().join("key.pem"), &[]).unwrap();
        let config = Config {
            tls_cert_file: Some(other_cert),
            ..config
        };
        assert!(check(&config).await.is_err());
    }
}
