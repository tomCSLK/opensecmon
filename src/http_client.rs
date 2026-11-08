//! A small HTTPS client for the sources, adapted from opennetmon: one GET per connection, HTTP/1.1,
//! rustls with the Mozilla roots of `webpki-roots` (certificates are always checked; opennetmon with a
//! self-signed certificate is checked against the SHA-256 fingerprint the user entered), conditional
//! requests (`If-None-Match`, `If-Modified-Since`), redirects, a cap on the bytes that are accepted,
//! a deadline for the whole request and one for every chunk of the body.
//!
//! Small answers are kept in memory (and unpacked when the server sent them gzipped); large files
//! go straight to disk.

use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::{Request, StatusCode, Uri, header};
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::{
    WebPkiSupportedAlgorithms, ring, verify_tls12_signature, verify_tls13_signature,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};

/// Longest accepted URL.
pub const MAX_URL_CHARS: usize = 2_000;
/// Redirects followed at most.
pub const MAX_REDIRECTS: usize = 5;
/// Longest wait for the next piece of the response (head or body chunk).
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// What the client calls itself.
pub const USER_AGENT: &str = concat!(
    "opensecmon/",
    env!("CARGO_PKG_VERSION"),
    " (+",
    env!("CARGO_PKG_REPOSITORY"),
    ")"
);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HttpError {
    #[error("invalid URL")]
    InvalidUrl,
    #[error("redirect from HTTPS to plain HTTP refused")]
    InsecureRedirect,
    #[error("timed out")]
    Timeout,
    #[error("cannot connect: {0}")]
    Connect(String),
    #[error("TLS: {0}")]
    Tls(String),
    #[error("HTTP: {0}")]
    Protocol(String),
    #[error("connection closed by the server")]
    Closed,
    #[error("more than {MAX_REDIRECTS} redirects")]
    TooManyRedirects,
    /// A request with a token was redirected (to the given host); it follows no redirect.
    #[error("redirect to {0} refused (a request with a token follows no redirect)")]
    RedirectRefused(String),
    /// The certificate is not trusted (no known authority, or not the pinned one).
    #[error("certificate not trusted ({reason}); its SHA-256 fingerprint is {fingerprint}")]
    Untrusted {
        /// Of the certificate the server presented, as `AB:CD:…`.
        fingerprint: String,
        reason: String,
        /// A pinned fingerprint was set and differs.
        pinned: bool,
    },
    #[error("HTTP status {0}")]
    Status(u16),
    #[error("response larger than {0} bytes")]
    TooLarge(u64),
    #[error("cannot unpack the response: {0}")]
    Decode(String),
    #[error("cannot write the download: {0}")]
    Io(String),
}

/// One GET request.
#[derive(Clone)]
pub struct Get<'a> {
    pub url: &'a str,
    /// `ETag` of the copy we have; sent as `If-None-Match`.
    pub etag: Option<&'a str>,
    /// `Last-Modified` of the copy we have; sent as `If-Modified-Since`.
    pub last_modified: Option<&'a str>,
    /// Value of the `Accept` header.
    pub accept: &'static str,
    /// Bytes accepted at most (after unpacking gzip); more fails the request.
    pub max_bytes: u64,
    /// Deadline for the whole request, redirects and body included.
    pub timeout: Duration,
    /// Longest wait for each step (name, connection, TLS, head, every body chunk).
    pub idle: Duration,
    /// `Authorization` header (opennetmon's token). Such a request follows no redirect, so the token
    /// never goes to another address.
    pub authorization: Option<&'a str>,
    /// May connect to addresses of the local network (opennetmon); otherwise only public addresses, so
    /// a feed or a redirect cannot make the service probe hosts of the own network.
    pub local_network: bool,
    /// SHA-256 of the server certificate that is accepted instead of a certificate from a known authority
    /// (opennetmon with its self-signed certificate). Name and validity dates are then not checked.
    pub pinned_cert: Option<[u8; 32]>,
}

impl std::fmt::Debug for Get<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Get")
            .field("url", &self.url)
            .field("max_bytes", &self.max_bytes)
            .field("timeout", &self.timeout)
            .field("authorization", &self.authorization.map(|_| "…"))
            .field("local_network", &self.local_network)
            .field("pinned_cert", &self.pinned_cert.is_some())
            .finish_non_exhaustive()
    }
}

impl<'a> Get<'a> {
    /// A GET of `url` without conditions.
    pub fn new(url: &'a str, max_bytes: u64, timeout: Duration) -> Self {
        Self {
            url,
            etag: None,
            last_modified: None,
            accept: "*/*",
            max_bytes,
            timeout,
            idle: IDLE_TIMEOUT,
            authorization: None,
            local_network: false,
            pinned_cert: None,
        }
    }

    /// Sends `Authorization: <value>` and follows no redirect.
    pub fn authorization(mut self, value: &'a str) -> Self {
        self.authorization = Some(value);
        self
    }

    /// Allows addresses of the local network (loopback, private, link-local).
    pub fn local_network(mut self) -> Self {
        self.local_network = true;
        self
    }

    /// Accepts the server certificate with this SHA-256 fingerprint (and only it).
    pub fn pinned_cert(mut self, sha256: [u8; 32]) -> Self {
        self.pinned_cert = Some(sha256);
        self
    }

    /// A shorter wait per step than [`IDLE_TIMEOUT`], for many small files where a stalled
    /// connection is better given up and tried again.
    pub fn idle(mut self, idle: Duration) -> Self {
        self.idle = idle.min(IDLE_TIMEOUT);
        self
    }

    pub fn accept(mut self, accept: &'static str) -> Self {
        self.accept = accept;
        self
    }

    /// Asks only for a copy that differs from the one described by `etag` and `last_modified`.
    pub fn conditional(mut self, etag: Option<&'a str>, last_modified: Option<&'a str>) -> Self {
        self.etag = etag;
        self.last_modified = last_modified;
        self
    }
}

/// A fresh copy (status 200).
#[derive(Debug)]
pub struct Fetched<T> {
    pub body: T,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

/// The answer to a [`Get`]: a fresh copy, or `NotModified` (304) for a conditional request.
#[derive(Debug)]
pub enum Outcome<T> {
    Fresh(Fetched<T>),
    NotModified,
}

impl<T> Outcome<T> {
    /// The fresh copy; `None` for 304.
    pub fn fresh(self) -> Option<Fetched<T>> {
        match self {
            Self::Fresh(f) => Some(f),
            Self::NotModified => None,
        }
    }
}

/// Fetches into memory. A gzipped answer (`Content-Encoding: gzip`) is unpacked.
pub async fn get_bytes(get: &Get<'_>) -> Result<Outcome<Vec<u8>>, HttpError> {
    bytes_via(get, None).await
}

/// Several requests over one kept-alive connection (HTTP/1.1 keep-alive), for many small files
/// from one server such as CSAF documents: the server sees one connection instead of one per
/// file. Requests through a session run one after another. A connection is only kept after a
/// complete `200` answer; a redirect, an error or a timeout closes it, and a kept connection that
/// the server has closed in the meantime is replaced by a new one.
#[derive(Default)]
pub struct Session {
    conn: Option<Conn>,
}

impl Session {
    pub fn new() -> Self {
        Self::default()
    }

    /// Like [`get_bytes`], over the kept connection when it goes to the same host.
    pub async fn get_bytes(&mut self, get: &Get<'_>) -> Result<Outcome<Vec<u8>>, HttpError> {
        bytes_via(get, Some(self)).await
    }

    /// Whether a connection is kept open (for tests).
    pub fn is_connected(&self) -> bool {
        self.conn.as_ref().is_some_and(|c| !c.sender.is_closed())
    }
}

async fn bytes_via(
    get: &Get<'_>,
    session: Option<&mut Session>,
) -> Result<Outcome<Vec<u8>>, HttpError> {
    let mut sink = Sink::Memory(Vec::new());
    let outcome = within(get.timeout, fetch(get, &mut sink, true, session)).await?;
    let Sink::Memory(raw) = sink else {
        unreachable!("memory sink")
    };
    Ok(match outcome {
        Head::NotModified => Outcome::NotModified,
        Head::Fresh {
            etag,
            last_modified,
            gzip,
        } => {
            let body = if gzip {
                gunzip(&raw, get.max_bytes)?
            } else {
                raw
            };
            Outcome::Fresh(Fetched {
                body,
                etag,
                last_modified,
            })
        }
    })
}

/// Fetches into the file `path` (created or truncated, mode 0600); the body is the number of bytes
/// written. The bytes are stored as sent (no `Accept-Encoding`). On an error the file may be partial.
pub async fn get_file(get: &Get<'_>, path: &Path) -> Result<Outcome<u64>, HttpError> {
    let io = |e: std::io::Error| HttpError::Io(e.to_string());
    let file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .await
        .map_err(io)?;
    let mut sink = Sink::File {
        file: tokio::io::BufWriter::with_capacity(1 << 20, file),
        written: 0,
    };
    let outcome = within(get.timeout, fetch(get, &mut sink, false, None)).await?;
    let Sink::File { mut file, written } = sink else {
        unreachable!("file sink")
    };
    file.flush().await.map_err(io)?;
    file.get_ref().sync_all().await.map_err(io)?;
    Ok(match outcome {
        Head::NotModified => Outcome::NotModified,
        Head::Fresh {
            etag,
            last_modified,
            ..
        } => Outcome::Fresh(Fetched {
            body: written,
            etag,
            last_modified,
        }),
    })
}

async fn within<T>(
    timeout: Duration,
    work: impl Future<Output = Result<T, HttpError>>,
) -> Result<T, HttpError> {
    tokio::time::timeout(timeout, work)
        .await
        .unwrap_or(Err(HttpError::Timeout))
}

/// Unpacks gzip data, refusing more than `max` bytes.
pub fn gunzip(data: &[u8], max: u64) -> Result<Vec<u8>, HttpError> {
    let mut out = Vec::new();
    flate2::read::MultiGzDecoder::new(data)
        .take(max.saturating_add(1))
        .read_to_end(&mut out)
        .map_err(|e| HttpError::Decode(e.to_string()))?;
    if out.len() as u64 > max {
        return Err(HttpError::TooLarge(max));
    }
    Ok(out)
}

enum Sink {
    Memory(Vec<u8>),
    File {
        file: tokio::io::BufWriter<tokio::fs::File>,
        written: u64,
    },
}

impl Sink {
    fn len(&self) -> u64 {
        match self {
            Self::Memory(v) => v.len() as u64,
            Self::File { written, .. } => *written,
        }
    }

    async fn write(&mut self, data: &[u8]) -> Result<(), HttpError> {
        match self {
            Self::Memory(v) => v.extend_from_slice(data),
            Self::File { file, written } => {
                file.write_all(data)
                    .await
                    .map_err(|e| HttpError::Io(e.to_string()))?;
                *written += data.len() as u64;
            }
        }
        Ok(())
    }
}

enum Head {
    Fresh {
        etag: Option<String>,
        last_modified: Option<String>,
        gzip: bool,
    },
    NotModified,
}

/// Where a URL points to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub tls: bool,
    /// Host name or IP address, without brackets.
    pub host: String,
    pub port: u16,
    /// Path and query, at least `/`.
    pub path: String,
    /// What the `Host` header says (`host` or `host:port`).
    pub authority: String,
}

/// Parses an absolute `http://` or `https://` URL; user names and passwords in the URL are refused.
pub fn parse_url(url: &str) -> Result<Target, HttpError> {
    if url.chars().count() > MAX_URL_CHARS || url.chars().any(|c| c.is_control() || c == ' ') {
        return Err(HttpError::InvalidUrl);
    }
    let uri: Uri = url.parse().map_err(|_| HttpError::InvalidUrl)?;
    let tls = match uri.scheme_str() {
        Some("https") => true,
        Some("http") => false,
        _ => return Err(HttpError::InvalidUrl),
    };
    let authority = uri.authority().ok_or(HttpError::InvalidUrl)?;
    if authority.as_str().contains('@') {
        return Err(HttpError::InvalidUrl);
    }
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    if host.is_empty() {
        return Err(HttpError::InvalidUrl);
    }
    let port = authority.port_u16().unwrap_or(if tls { 443 } else { 80 });
    let path = uri
        .path_and_query()
        .map(|p| p.as_str())
        .filter(|p| !p.is_empty())
        .unwrap_or("/");
    Ok(Target {
        tls,
        host: host.to_owned(),
        port,
        path: path.to_owned(),
        authority: authority.as_str().to_owned(),
    })
}

/// The target a `Location` header of a response to `from` points to. A step down from HTTPS to
/// plain HTTP is refused.
fn redirect_target(from: &Target, location: &str) -> Result<Target, HttpError> {
    let location = location.trim();
    let scheme = if from.tls { "https" } else { "http" };
    let next = if location.starts_with("http://") || location.starts_with("https://") {
        parse_url(location)?
    } else if let Some(rest) = location.strip_prefix("//") {
        parse_url(&format!("{scheme}://{rest}"))?
    } else {
        let path = if location.starts_with('/') {
            location.to_owned()
        } else {
            // Relative to the directory of the current path.
            let current = from.path.split('?').next().unwrap_or("/");
            let dir = &current[..current.rfind('/').map_or(0, |i| i + 1)];
            format!("{}{location}", if dir.is_empty() { "/" } else { dir })
        };
        parse_url(&format!("{scheme}://{}{path}", from.authority))?
    };
    if from.tls && !next.tls {
        return Err(HttpError::InsecureRedirect);
    }
    Ok(next)
}

/// One request, following redirects. With a session the connection is taken out of it and only put
/// back after a clean answer, so a request that fails or times out never leaves a half-used
/// connection behind.
async fn fetch(
    get: &Get<'_>,
    sink: &mut Sink,
    allow_gzip: bool,
    mut session: Option<&mut Session>,
) -> Result<Head, HttpError> {
    let keep_alive = session.is_some();
    let mut target = parse_url(get.url)?;
    for _ in 0..=MAX_REDIRECTS {
        let kept = session
            .as_deref_mut()
            .and_then(|s| s.conn.take())
            .filter(|c| c.serves(&target, get.pinned_cert));
        let (outcome, reusable, conn) = match kept {
            Some(mut conn) => {
                match exchange(&mut conn, &target, get, sink, allow_gzip, keep_alive).await {
                    Ok((outcome, reusable)) => (outcome, reusable, conn),
                    // The server closed the kept connection before answering: a GET can be
                    // repeated on a new one.
                    Err(HttpError::Protocol(_) | HttpError::Closed) if sink.len() == 0 => {
                        let mut conn = open(&target, get).await?;
                        let (outcome, reusable) =
                            exchange(&mut conn, &target, get, sink, allow_gzip, keep_alive).await?;
                        (outcome, reusable, conn)
                    }
                    Err(e) => return Err(e),
                }
            }
            None => {
                let mut conn = open(&target, get).await?;
                let (outcome, reusable) =
                    exchange(&mut conn, &target, get, sink, allow_gzip, keep_alive).await?;
                (outcome, reusable, conn)
            }
        };
        if reusable && let Some(s) = session.as_deref_mut() {
            s.conn = Some(conn);
        }
        match outcome {
            Exchanged::Redirect(location) if get.authorization.is_some() => {
                let to = redirect_target(&target, &location)
                    .map(|t| t.host)
                    .unwrap_or_else(|_| location.chars().take(100).collect());
                return Err(HttpError::RedirectRefused(to));
            }
            Exchanged::Redirect(location) => target = redirect_target(&target, &location)?,
            Exchanged::Done(head) => return Ok(head),
        }
    }
    Err(HttpError::TooManyRedirects)
}

/// How long a resolved address is reused. A CSAF import makes thousands of requests to one host,
/// one connection each; resolving the name every time took seconds per request when the local
/// resolver throttled the lookups.
const DNS_CACHE_TTL: Duration = Duration::from_secs(60);

type DnsCache = HashMap<(String, u16), (Instant, Vec<SocketAddr>)>;

fn dns_cache() -> &'static Mutex<DnsCache> {
    static CACHE: OnceLock<Mutex<DnsCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The addresses of `host`, from the cache while they are fresh.
async fn resolve(host: &str, port: u16, idle: Duration) -> Result<Vec<SocketAddr>, HttpError> {
    let key = (host.to_owned(), port);
    if let Some((at, addrs)) = dns_cache().lock().expect("dns cache").get(&key)
        && at.elapsed() < DNS_CACHE_TTL
    {
        return Ok(addrs.clone());
    }
    let addrs: Vec<SocketAddr> =
        match tokio::time::timeout(idle, tokio::net::lookup_host((host, port))).await {
            Ok(Ok(found)) => found.collect(),
            Ok(Err(e)) => return Err(HttpError::Connect(e.to_string())),
            Err(_) => return Err(HttpError::Timeout),
        };
    if addrs.is_empty() {
        return Err(HttpError::Connect(format!("no address for {host}")));
    }
    let mut cache = dns_cache().lock().expect("dns cache");
    cache.retain(|_, (at, _)| at.elapsed() < DNS_CACHE_TTL);
    cache.insert(key, (Instant::now(), addrs.clone()));
    Ok(addrs)
}

/// An address of the own network: loopback, private, link-local, shared (CGNAT), unspecified.
pub fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || (a == 100 && (64..128).contains(&b))
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_local(IpAddr::V4(v4)),
            None => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_unique_local()
                    || v6.is_unicast_link_local()
            }
        },
    }
}

async fn connect_tcp(
    host: &str,
    port: u16,
    idle: Duration,
    local_network: bool,
) -> Result<TcpStream, HttpError> {
    let mut addrs = resolve(host, port, idle).await?;
    if !local_network {
        // The tests' servers listen on loopback.
        addrs.retain(|a| !is_local(a.ip()) || (cfg!(test) && a.ip().is_loopback()));
        if addrs.is_empty() {
            return Err(HttpError::Connect(format!(
                "{host} is an address of the local network"
            )));
        }
    }
    match tokio::time::timeout(idle, TcpStream::connect(&addrs[..])).await {
        Ok(Ok(tcp)) => Ok(tcp),
        Ok(Err(e)) => {
            // The host may have moved: resolve again next time.
            dns_cache()
                .lock()
                .expect("dns cache")
                .remove(&(host.to_owned(), port));
            Err(HttpError::Connect(e.to_string()))
        }
        Err(_) => Err(HttpError::Timeout),
    }
}

/// The TLS settings: Mozilla's roots, built once.
fn tls_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let mut config =
                ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
                    .with_safe_default_protocol_versions()
                    .expect("the ring provider supports the default protocol versions")
                    .with_root_certificates(roots)
                    .with_no_client_auth();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Arc::new(config)
        })
        .clone()
}

/// `AB:CD:…`, as browsers and `openssl x509 -fingerprint` show a fingerprint.
pub fn format_fingerprint(sha256: &[u8]) -> String {
    sha256
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Reads a SHA-256 fingerprint as hex digits, with or without colons or spaces, in either case; a
/// leading label up to `=` (`sha256 Fingerprint=AB:…` from openssl) is ignored.
pub fn parse_fingerprint(text: &str) -> Option<[u8; 32]> {
    let text = text.rsplit('=').next().unwrap_or(text);
    let hex: Vec<u8> = text
        .bytes()
        .filter(|b| !matches!(b, b':' | b' ' | b'-' | b'\t'))
        .collect();
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in hex.chunks(2).enumerate() {
        let digit = |b: u8| (b as char).to_digit(16);
        out[i] = u8::try_from(digit(pair[0])? * 16 + digit(pair[1])?).ok()?;
    }
    Some(out)
}

/// Checks the certificate of opennetmon: against the pinned fingerprint if there is one, otherwise like
/// every other request against the Mozilla roots. Either way it remembers why it refused the
/// certificate and which one it was, so the page can show the fingerprint to compare. The signatures
/// of the handshake are always checked, so only the holder of the key passes.
#[derive(Debug)]
struct OwnVerifier {
    webpki: Arc<WebPkiServerVerifier>,
    pin: Option<[u8; 32]>,
    algorithms: WebPkiSupportedAlgorithms,
    /// Fingerprint of the refused certificate and the reason.
    refused: Mutex<Option<([u8; 32], String)>>,
}

impl OwnVerifier {
    fn new(pin: Option<[u8; 32]>) -> Arc<Self> {
        let provider = Arc::new(ring::default_provider());
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let webpki = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .expect("the Mozilla roots are valid");
        Arc::new(Self {
            webpki,
            pin,
            algorithms: provider.signature_verification_algorithms,
            refused: Mutex::new(None),
        })
    }

    fn refused(&self) -> Option<([u8; 32], String)> {
        self.refused.lock().expect("verifier").clone()
    }
}

impl ServerCertVerifier for OwnVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        let mut seen = [0u8; 32];
        seen.copy_from_slice(&Sha256::digest(end_entity.as_ref()));
        let result = match self.pin {
            Some(pin) if pin == seen => Ok(ServerCertVerified::assertion()),
            Some(_) => Err(tokio_rustls::rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            )),
            None => self.webpki.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            ),
        };
        if let Err(e) = &result {
            let reason = if self.pin.is_some() {
                "not the certificate with the stored fingerprint".to_owned()
            } else {
                e.to_string()
            };
            *self.refused.lock().expect("verifier") = Some((seen, reason));
        }
        result
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// TLS for a request to the own network (opennetmon): built per connection around an [`OwnVerifier`].
fn own_tls_config(verifier: Arc<OwnVerifier>) -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

async fn connect_tls(
    tcp: TcpStream,
    host: &str,
    get: &Get<'_>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, HttpError> {
    let name = ServerName::try_from(host.to_owned()).map_err(|_| HttpError::InvalidUrl)?;
    // The feeds use the shared configuration; only opennetmon (own network, maybe pinned) gets its own.
    let own =
        (get.local_network || get.pinned_cert.is_some()).then(|| OwnVerifier::new(get.pinned_cert));
    let config = own.clone().map_or_else(tls_config, own_tls_config);
    let handshake = TlsConnector::from(config).connect(name, tcp);
    match tokio::time::timeout(get.idle, handshake).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => match own.and_then(|v| v.refused()) {
            Some((seen, reason)) => Err(HttpError::Untrusted {
                fingerprint: format_fingerprint(&seen),
                reason,
                pinned: get.pinned_cert.is_some(),
            }),
            None => Err(HttpError::Tls(e.to_string())),
        },
        Err(_) => Err(HttpError::Timeout),
    }
}

/// An open HTTP/1.1 connection.
struct Conn {
    tls: bool,
    host: String,
    port: u16,
    /// The pinned certificate the connection was checked against.
    pin: Option<[u8; 32]>,
    sender: hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
    _task: AbortOnDrop,
}

impl Conn {
    fn serves(&self, target: &Target, pin: Option<[u8; 32]>) -> bool {
        self.tls == target.tls
            && self.pin == pin
            && self.host == target.host
            && self.port == target.port
            && !self.sender.is_closed()
    }
}

async fn open(target: &Target, get: &Get<'_>) -> Result<Conn, HttpError> {
    let tcp = connect_tcp(&target.host, target.port, get.idle, get.local_network).await?;
    let (sender, task) = if target.tls {
        handshake(connect_tls(tcp, &target.host, get).await?).await?
    } else {
        handshake(tcp).await?
    };
    Ok(Conn {
        tls: target.tls,
        host: target.host.clone(),
        port: target.port,
        pin: if target.tls { get.pinned_cert } else { None },
        sender,
        _task: task,
    })
}

async fn handshake<S>(
    stream: S,
) -> Result<
    (
        hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
        AbortOnDrop,
    ),
    HttpError,
>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| HttpError::Protocol(e.to_string()))?;
    let task = AbortOnDrop(tokio::spawn(async move {
        let _ = connection.await;
    }));
    Ok((sender, task))
}

/// Aborts the connection task when the request is done or given up.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

enum Exchanged {
    Redirect(String),
    Done(Head),
}

/// A response header as text, cut to `max` characters (validators are short; a `Location` can be long,
/// GitHub's signed download links have about 1,000 characters).
fn header_text(
    headers: &header::HeaderMap,
    name: header::HeaderName,
    max: usize,
) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().chars().take(max).collect())
}

/// Sends the request over `conn` and reads the answer. The flag says whether the connection can
/// carry another request (only with `keep_alive`, after a complete `200` answer the server did not
/// mark with `Connection: close`).
async fn exchange(
    conn: &mut Conn,
    target: &Target,
    get: &Get<'_>,
    sink: &mut Sink,
    allow_gzip: bool,
    keep_alive: bool,
) -> Result<(Exchanged, bool), HttpError> {
    let protocol = |e: hyper::Error| HttpError::Protocol(e.to_string());
    match tokio::time::timeout(get.idle, conn.sender.ready()).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => return Err(HttpError::Closed),
        Err(_) => return Err(HttpError::Timeout),
    }
    let sender = &mut conn.sender;
    let mut request = Request::builder()
        .uri(target.path.as_str())
        .header(header::HOST, target.authority.as_str())
        .header(header::USER_AGENT, USER_AGENT)
        .header(header::ACCEPT, get.accept)
        .header(
            header::ACCEPT_ENCODING,
            if allow_gzip { "gzip" } else { "identity" },
        )
        .header(
            header::CONNECTION,
            if keep_alive { "keep-alive" } else { "close" },
        );
    if let Some(value) = get.authorization {
        request = request.header(header::AUTHORIZATION, value);
    }
    if let Some(etag) = get.etag {
        request = request.header(header::IF_NONE_MATCH, etag);
    }
    if let Some(since) = get.last_modified {
        request = request.header(header::IF_MODIFIED_SINCE, since);
    }
    let request = request
        .body(Empty::<Bytes>::new())
        .map_err(|_| HttpError::InvalidUrl)?;
    let response = match tokio::time::timeout(get.idle, sender.send_request(request)).await {
        Ok(response) => response.map_err(protocol)?,
        Err(_) => return Err(HttpError::Timeout),
    };
    let (head, mut body) = response.into_parts();
    let status = head.status;
    if status.is_redirection() && status != StatusCode::NOT_MODIFIED {
        let location = header_text(&head.headers, header::LOCATION, MAX_URL_CHARS + 1)
            .ok_or_else(|| HttpError::Protocol("redirect without Location".to_owned()))?;
        return Ok((Exchanged::Redirect(location), false));
    }
    if status == StatusCode::NOT_MODIFIED {
        return Ok((Exchanged::Done(Head::NotModified), false));
    }
    if status != StatusCode::OK {
        return Err(HttpError::Status(status.as_u16()));
    }
    let gzip = allow_gzip
        && header_text(&head.headers, header::CONTENT_ENCODING, 200)
            .is_some_and(|e| e.eq_ignore_ascii_case("gzip"));
    loop {
        let frame = match tokio::time::timeout(get.idle, body.frame()).await {
            Ok(Some(frame)) => frame.map_err(protocol)?,
            Ok(None) => break,
            Err(_) => return Err(HttpError::Timeout),
        };
        if let Ok(data) = frame.into_data() {
            if sink.len() + data.len() as u64 > get.max_bytes {
                return Err(HttpError::TooLarge(get.max_bytes));
            }
            sink.write(&data).await?;
        }
    }
    let reusable = keep_alive
        && !header_text(&head.headers, header::CONNECTION, 100)
            .is_some_and(|c| c.eq_ignore_ascii_case("close"));
    Ok((
        Exchanged::Done(Head::Fresh {
            etag: header_text(&head.headers, header::ETAG, 200),
            last_modified: header_text(&head.headers, header::LAST_MODIFIED, 200),
            gzip,
        }),
        reusable,
    ))
}

#[cfg(test)]
pub(crate) mod testserver {
    //! A local HTTP server for tests: each connection gets the next canned response.

    use std::net::SocketAddr;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    /// Serves `responses` (raw HTTP responses), one per connection, then stops accepting.
    pub async fn serve(responses: Vec<Vec<u8>>) -> SocketAddr {
        serve_and_record(responses).await.0
    }

    /// Like [`serve`]; the head of every request arrives on the receiver.
    pub async fn serve_and_record(
        responses: Vec<Vec<u8>>,
    ) -> (SocketAddr, mpsc::UnboundedReceiver<String>) {
        let (listener, addr) = listen().await;
        (addr, serve_on(listener, responses))
    }

    /// A listener on a free local port, for responses that must know the address.
    pub async fn listen() -> (TcpListener, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        (listener, addr)
    }

    /// Serves `responses` on `listener`, one per connection; the head of every request arrives on the receiver.
    pub fn serve_on(
        listener: TcpListener,
        responses: Vec<Vec<u8>>,
    ) -> mpsc::UnboundedReceiver<String> {
        let (requests, received) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            for response in responses {
                let Ok((mut tcp, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = vec![0u8; 4096];
                let mut seen = Vec::new();
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tcp.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => seen.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = requests.send(String::from_utf8_lossy(&seen).into_owned());
                let _ = tcp.write_all(&response).await;
                let _ = tcp.shutdown().await;
            }
        });
        received
    }

    /// `200 OK` with `body` and extra header lines (each ending in `\r\n`).
    pub fn ok_with(headers: &str, body: &[u8]) -> Vec<u8> {
        let mut r = format!(
            "HTTP/1.1 200 OK\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        r.extend_from_slice(body);
        r
    }

    pub fn ok(body: &[u8]) -> Vec<u8> {
        ok_with("", body)
    }

    pub fn status(code: u16, extra_headers: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {code} X\r\n{extra_headers}Content-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .into_bytes()
    }

    /// `data` packed with gzip.
    pub fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::testserver::{gzip, ok, ok_with, serve, serve_and_record, status};
    use super::*;

    fn get(url: &str) -> Get<'_> {
        Get::new(url, 64, Duration::from_secs(5))
    }

    #[test]
    fn addresses_of_the_own_network_are_recognised() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.2",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:192.168.1.1",
        ] {
            assert!(is_local(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "93.184.216.34",
            "172.32.0.1",
            "100.128.0.1",
            "2a00:1450::1",
            "::ffff:8.8.8.8",
        ] {
            assert!(!is_local(ip.parse().unwrap()), "{ip}");
        }
    }

    #[tokio::test]
    async fn feeds_cannot_reach_the_own_network() {
        // Refused before any packet is sent.
        let error = get_bytes(&get("https://192.168.0.1/x")).await.unwrap_err();
        assert!(
            matches!(&error, HttpError::Connect(t) if t.contains("local network")),
            "{error:?}"
        );
        let error = get_bytes(&get("https://[fd00::1]/x")).await.unwrap_err();
        assert!(
            matches!(&error, HttpError::Connect(t) if t.contains("local network")),
            "{error:?}"
        );
        // The token stays out of debug output.
        let g = get("https://x/").authorization("Bearer onm_secret");
        assert!(!format!("{g:?}").contains("onm_secret"));
    }

    /// A server that answers every request on a connection with a numbered body and counts the
    /// connections; the second connection is closed after its first answer.
    async fn keep_alive_server() -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncBufReadExt, BufReader};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&connections);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let n = count.fetch_add(1, Ordering::SeqCst) + 1;
                tokio::spawn(async move {
                    let mut stream = BufReader::new(stream);
                    let mut answered = 0;
                    loop {
                        // Read one request head.
                        let mut line = String::new();
                        loop {
                            line.clear();
                            if stream.read_line(&mut line).await.unwrap_or(0) == 0 {
                                return;
                            }
                            if line == "\r\n" {
                                break;
                            }
                        }
                        answered += 1;
                        let body = format!("c{n}r{answered}");
                        let close = n == 2;
                        let reply = format!(
                            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n{}\r\n{body}",
                            body.len(),
                            if close { "connection: close\r\n" } else { "" }
                        );
                        stream.get_mut().write_all(reply.as_bytes()).await.unwrap();
                        if close {
                            return;
                        }
                    }
                });
            }
        });
        (addr, connections)
    }

    #[tokio::test]
    async fn a_session_keeps_the_connection_until_the_server_closes_it() {
        use std::sync::atomic::Ordering;
        let (addr, connections) = keep_alive_server().await;
        let url = format!("http://{addr}/doc");
        let mut session = Session::new();
        let body = |o: Outcome<Vec<u8>>| String::from_utf8(o.fresh().unwrap().body).unwrap();
        assert_eq!(body(session.get_bytes(&get(&url)).await.unwrap()), "c1r1");
        assert!(session.is_connected());
        assert_eq!(body(session.get_bytes(&get(&url)).await.unwrap()), "c1r2");
        assert_eq!(connections.load(Ordering::SeqCst), 1);

        // Without a session every request opens its own connection (and asks to close it).
        assert_eq!(body(get_bytes(&get(&url)).await.unwrap()), "c2r1");
        // The session still holds connection 1.
        assert_eq!(body(session.get_bytes(&get(&url)).await.unwrap()), "c1r3");
        assert_eq!(connections.load(Ordering::SeqCst), 2);

        // An error drops the kept connection; the next request opens a new one.
        let too_small = Get::new(&url, 2, Duration::from_secs(5));
        assert!(matches!(
            session.get_bytes(&too_small).await,
            Err(HttpError::TooLarge(2))
        ));
        assert!(!session.is_connected());
        assert_eq!(body(session.get_bytes(&get(&url)).await.unwrap()), "c3r1");
        assert_eq!(connections.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn urls_are_parsed_and_checked() {
        let t = parse_url("https://example.org").unwrap();
        assert_eq!(
            (t.tls, t.host.as_str(), t.port, t.path.as_str()),
            (true, "example.org", 443, "/")
        );
        let t = parse_url("http://[::1]:8080/a?b=1").unwrap();
        assert_eq!(
            (t.host.as_str(), t.port, t.authority.as_str()),
            ("::1", 8080, "[::1]:8080")
        );
        for bad in [
            "",
            "example.org",
            "ftp://example.org/",
            "https://user:pass@example.org/",
            "https:///path",
            "https://exa mple.org/",
            "https://example.org/\n",
        ] {
            assert_eq!(parse_url(bad), Err(HttpError::InvalidUrl), "{bad:?}");
        }
    }

    #[test]
    fn redirects_resolve_and_never_step_down_to_plain_http() {
        let from = parse_url("https://example.org/dir/page?x=1").unwrap();
        let to = |l: &str| redirect_target(&from, l).map(|t| format!("{}{}", t.host, t.path));
        assert_eq!(to("/login").unwrap(), "example.org/login");
        assert_eq!(to("other.csv.gz").unwrap(), "example.org/dir/other.csv.gz");
        assert_eq!(to("//cdn.example.org/x").unwrap(), "cdn.example.org/x");
        assert_eq!(to("http://example.org/"), Err(HttpError::InsecureRedirect));
    }

    #[tokio::test]
    async fn a_conditional_request_sends_the_validators_and_understands_304() {
        let (addr, mut requests) = serve_and_record(vec![status(304, "")]).await;
        let url = format!("http://{addr}/feed.json");
        let request = get(&url)
            .accept("application/json")
            .conditional(Some("\"abc\""), Some("Wed, 04 Nov 2026 20:00:05 GMT"));
        let outcome = get_bytes(&request).await.unwrap();
        assert!(matches!(outcome, Outcome::NotModified));
        let head = requests.recv().await.unwrap().to_ascii_lowercase();
        assert!(head.starts_with("get /feed.json http/1.1\r\n"), "{head}");
        assert!(head.contains("if-none-match: \"abc\"\r\n"), "{head}");
        assert!(
            head.contains("if-modified-since: wed, 04 nov 2026 20:00:05 gmt\r\n"),
            "{head}"
        );
        assert!(head.contains("accept: application/json\r\n"), "{head}");
        assert!(head.contains("user-agent: opensecmon/"), "{head}");
    }

    #[tokio::test]
    async fn fresh_copies_carry_their_validators_and_are_unpacked() {
        let body = gzip(b"{\"hello\": 1}");
        let addr = serve(vec![ok_with(
            "Content-Encoding: gzip\r\nETag: \"v2\"\r\nLast-Modified: Thu, 05 Nov 2026 13:30:39 GMT\r\n",
            &body,
        )])
        .await;
        let url = format!("http://{addr}/");
        let fetched = get_bytes(&get(&url)).await.unwrap().fresh().unwrap();
        assert_eq!(fetched.body, b"{\"hello\": 1}");
        assert_eq!(fetched.etag.as_deref(), Some("\"v2\""));
        assert_eq!(
            fetched.last_modified.as_deref(),
            Some("Thu, 05 Nov 2026 13:30:39 GMT")
        );
    }

    #[tokio::test]
    async fn too_large_answers_fail_also_after_unpacking() {
        let addr = serve(vec![ok(&[b'x'; 65])]).await;
        let url = format!("http://{addr}/");
        assert_eq!(
            get_bytes(&get(&url)).await.unwrap_err(),
            HttpError::TooLarge(64)
        );
        let bomb = gzip(&[0u8; 10_000]);
        assert!(bomb.len() < 200);
        let addr = serve(vec![ok_with("Content-Encoding: gzip\r\n", &bomb)]).await;
        let url = format!("http://{addr}/");
        let request = Get::new(&url, 200, Duration::from_secs(5));
        assert_eq!(
            get_bytes(&request).await.unwrap_err(),
            HttpError::TooLarge(200)
        );
    }

    #[tokio::test]
    async fn downloads_go_to_a_private_file_and_follow_redirects() {
        use std::os::unix::fs::PermissionsExt;
        // Signed download links (GitHub release assets) are about 1,000 characters long.
        let query = "x".repeat(1_200);
        let (addr, mut requests) = serve_and_record(vec![
            status(302, &format!("Location: /files/data.zip?sig={query}\r\n")),
            ok(b"PK-data"),
        ])
        .await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("download");
        let url = format!("http://{addr}/latest");
        let fetched = get_file(&get(&url), &path).await.unwrap().fresh().unwrap();
        assert_eq!(fetched.body, 7);
        assert_eq!(std::fs::read(&path).unwrap(), b"PK-data");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = requests.recv().await.unwrap();
        let second = requests.recv().await.unwrap().to_ascii_lowercase();
        assert!(
            second.starts_with(&format!("get /files/data.zip?sig={query} ")),
            "{second}"
        );
        assert!(second.contains("accept-encoding: identity\r\n"), "{second}");
    }

    #[tokio::test]
    async fn errors_are_reported() {
        let addr = serve(vec![status(503, "")]).await;
        let url = format!("http://{addr}/");
        assert_eq!(
            get_bytes(&get(&url)).await.unwrap_err(),
            HttpError::Status(503)
        );

        let addr = serve(vec![status(302, "Location: /again\r\n"); 7]).await;
        let url = format!("http://{addr}/");
        assert_eq!(
            get_bytes(&get(&url)).await.unwrap_err(),
            HttpError::TooManyRedirects
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let url = format!("http://127.0.0.1:{port}/");
        assert!(matches!(
            get_bytes(&get(&url)).await,
            Err(HttpError::Connect(_))
        ));
    }

    #[tokio::test]
    async fn a_silent_server_runs_into_the_deadline() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _keep = tokio::spawn(async move {
            let _conn = listener.accept().await;
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let url = format!("http://{addr}/");
        let quick = Get::new(&url, 64, Duration::from_millis(200));
        assert_eq!(get_bytes(&quick).await.unwrap_err(), HttpError::Timeout);
    }

    #[test]
    fn fingerprints_are_read_in_the_usual_spellings() {
        let colons = (0..32)
            .map(|i| format!("{i:02X}"))
            .collect::<Vec<_>>()
            .join(":");
        let expected: [u8; 32] = std::array::from_fn(|i| i as u8);
        assert_eq!(parse_fingerprint(&colons), Some(expected));
        assert_eq!(format_fingerprint(&expected), colons);
        let plain = colons.replace(':', "").to_lowercase();
        assert_eq!(parse_fingerprint(&plain), Some(expected));
        assert_eq!(
            parse_fingerprint(&format!("sha256 Fingerprint={colons}")),
            Some(expected)
        );
        assert_eq!(parse_fingerprint(&format!(" {plain} ")), Some(expected));
        for wrong in [
            "",
            "AB:CD",
            &plain[..62],
            &format!("{plain}00"),
            &plain.replace('0', "g"),
        ] {
            assert_eq!(parse_fingerprint(wrong), None, "{wrong}");
        }
    }

    /// An HTTPS server with a new self-signed certificate that answers every connection with `response`;
    /// returns its address and the fingerprint of the certificate.
    async fn tls_server(response: Vec<u8>) -> (SocketAddr, String, tempfile::TempDir) {
        use tokio::io::AsyncReadExt;
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = (dir.path().join("c.pem"), dir.path().join("k.pem"));
        let generated = crate::tls::generate(&cert, &key, &["localhost".into()]).unwrap();
        let loaded = crate::tls::load(&cert, &key).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(loaded.config);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    continue;
                };
                let mut buf = vec![0u8; 4096];
                let mut seen = Vec::new();
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => seen.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = tls.write_all(&response).await;
                let _ = tls.shutdown().await;
            }
        });
        (addr, generated.fingerprint, dir)
    }

    #[tokio::test]
    async fn a_self_signed_certificate_needs_its_fingerprint() {
        let (addr, fingerprint, _dir) = tls_server(ok(b"devices")).await;
        let url = format!("https://{addr}/api");
        let local = || get(&url).local_network().authorization("Bearer t0ken");
        // Without a pin it is refused, and the error names the certificate to compare.
        match get_bytes(&local()).await.unwrap_err() {
            HttpError::Untrusted {
                fingerprint: seen,
                pinned: false,
                reason,
            } => {
                assert_eq!(seen, fingerprint);
                assert!(!reason.is_empty());
            }
            e => panic!("{e:?}"),
        }
        // The pinned certificate is accepted, also for an address it was not made for.
        let pin = parse_fingerprint(&fingerprint).unwrap();
        let fetched = get_bytes(&local().pinned_cert(pin)).await.unwrap();
        assert_eq!(fetched.fresh().unwrap().body, b"devices");
        // Another fingerprint is refused before the token is sent.
        let mut other = pin;
        other[0] ^= 1;
        match get_bytes(&local().pinned_cert(other)).await.unwrap_err() {
            HttpError::Untrusted {
                fingerprint: seen,
                pinned: true,
                ..
            } => assert_eq!(seen, fingerprint),
            e => panic!("{e:?}"),
        }
        // The feeds never accept it, and do not learn about pins.
        let feed = get_bytes(&get(&url)).await.unwrap_err();
        assert!(matches!(feed, HttpError::Tls(_)), "{feed:?}");
    }

    #[tokio::test]
    async fn a_request_with_a_token_names_the_refused_redirect() {
        let (addr, mut requests) = serve_and_record(vec![status(
            302,
            "Location: https://team.cloudflareaccess.com/cdn-cgi/access/login/x?kid=1\r\n",
        )])
        .await;
        let url = format!("http://{addr}/api");
        let error = get_bytes(&get(&url).authorization("Bearer t0ken"))
            .await
            .unwrap_err();
        assert_eq!(
            error,
            HttpError::RedirectRefused("team.cloudflareaccess.com".into())
        );
        assert!(requests.recv().await.unwrap().contains("Bearer t0ken"));
        assert!(requests.try_recv().is_err(), "the redirect was followed");
    }
}
