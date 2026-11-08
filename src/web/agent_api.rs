//! The agent API (`docs/agent-api.md`): computers enroll with a one-time code and then use their own token.
//! Only requests from `agent_networks` are taken; answers and errors are JSON (`{"error", "message"}`).
//! The API never reads the session cookie and a token never opens a page.
//!
//! Reports: Debian and Ubuntu packages as plain text or JSON, Windows as JSON (its system becomes an asset), and
//! the `items` beside them (Windows programs, store apps, snaps, Flatpaks), stored per computer and turned into
//! assets by rules (`storage::items`); entries of an unknown type are skipped and counted.

use std::net::{IpAddr, SocketAddr};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use crate::agent;
use crate::audit::{Action, Changes, Kind as AuditKind};
use crate::auth::{throttle, token_hash};
use crate::inventory::items::{Item, ItemType};
use crate::inventory::listing::{self, ListingError};
use crate::storage::agents::{self, EnrollInfo};
use crate::web::audit::{Object, now_ms, write};
use crate::web::{AppState, iso_utc};

/// The version of the formats this server reads (`schema`).
pub const SCHEMA: i64 = 1;
/// Largest body of an enrollment.
const ENROLL_LIMIT: usize = 16 * 1024;
/// The name under which wrong codes are counted by the sign-in throttle (no user name can contain `#`).
const THROTTLE_NAME: &str = "#agent-enroll";

/// An error of the API.
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    retry_after_secs: Option<i64>,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            retry_after_secs: None,
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = json!({ "error": self.code, "message": self.message });
        let mut response = (self.status, axum::Json(body)).into_response();
        if let Some(secs) = self.retry_after_secs
            && let Ok(value) = header::HeaderValue::from_str(&secs.max(1).to_string())
        {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        response
    }
}

type ApiResult = Result<Response, ApiError>;

/// The client address (behind a proxy from `client_ip_header`) and whether it may use the API.
fn client(state: &AppState, request: &Request) -> Result<Option<IpAddr>, ApiError> {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(a)| a.ip());
    let ip = throttle::client_ip(peer, request.headers(), state.client_ip_header);
    if agent::allowed(&state.agent_networks, ip) {
        Ok(ip)
    } else {
        tracing::warn!(address = ?ip, path = request.uri().path(), "agent request from a network that is not allowed");
        Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "network_not_allowed",
            "this address may not use the agent API (agent_networks)",
        ))
    }
}

/// Requires `Content-Type: application/json` without a content encoding.
fn require_json(headers: &HeaderMap) -> Result<(), ApiError> {
    let json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"));
    let encoded = headers.get(header::CONTENT_ENCODING).is_some();
    if json && !encoded {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "send the enrollment as application/json",
        ))
    }
}

/// Reads the body up to `limit` bytes.
async fn body(request: Request, limit: usize) -> Result<Bytes, ApiError> {
    axum::body::to_bytes(request.into_body(), limit)
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "too_large",
                format!("the body is larger than {limit} bytes"),
            )
        })
}

/// Checks `schema`: missing or older than 1 is malformed, newer is not known yet.
fn check_schema(schema: Option<i64>) -> Result<(), ApiError> {
    match schema {
        Some(SCHEMA) => Ok(()),
        Some(n) if n > SCHEMA => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "unsupported_schema",
            format!("schema {n} is not supported; supported: {SCHEMA}"),
        )),
        _ => Err(ApiError::bad_request("\"schema\" must be 1")),
    }
}

/// A text field a computer sends about itself: at most `max` characters, no control characters.
fn text_field(value: Option<String>, name: &str, max: usize) -> Result<String, ApiError> {
    let value = value.unwrap_or_default();
    let value = value.trim();
    if value.chars().count() > max || value.chars().any(char::is_control) {
        return Err(ApiError::bad_request(format!(
            "\"{name}\" must be at most {max} characters without control characters"
        )));
    }
    Ok(value.to_owned())
}

/// `POST /api/v1/agent/report`: the complete inventory of a computer, or the short form `unchanged`.
pub async fn report(State(state): State<AppState>, request: Request) -> Response {
    report_inner(&state, request)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}

/// The two forms of a report body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form {
    Text,
    Json,
}

/// Requires `text/plain` (UTF-8) or `application/json`, with no encoding or gzip; returns the form and
/// whether the body is compressed.
fn report_form(headers: &HeaderMap) -> Result<(Form, bool), ApiError> {
    let unsupported = || {
        ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "send the report as text/plain; charset=utf-8 or application/json, optionally with Content-Encoding: gzip",
        )
    };
    let value = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let mut parts = value.split(';').map(str::trim);
    let form = match parts.next() {
        Some("text/plain") => Form::Text,
        Some("application/json") => Form::Json,
        _ => return Err(unsupported()),
    };
    for p in parts {
        if let Some(charset) = p.strip_prefix("charset=")
            && !matches!(charset.trim_matches('"'), "utf-8" | "utf8" | "us-ascii")
        {
            return Err(unsupported());
        }
    }
    let gzip = match headers
        .get(header::CONTENT_ENCODING)
        .map(|v| v.to_str().map(|v| v.trim().to_ascii_lowercase()))
    {
        None => false,
        Some(Ok(v)) if v == "gzip" => true,
        Some(Ok(v)) if v == "identity" => false,
        _ => return Err(unsupported()),
    };
    Ok((form, gzip))
}

fn too_large() -> ApiError {
    ApiError::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        "too_large",
        format!(
            "the report is larger than {} bytes",
            agent::REPORT_MAX_BYTES
        ),
    )
}

/// Unpacks a gzip body, stopping at the limit.
fn gunzip(bytes: &[u8]) -> Result<Vec<u8>, ApiError> {
    use std::io::Read;
    let mut out = Vec::new();
    flate2::read::MultiGzDecoder::new(bytes)
        .take(agent::REPORT_MAX_BYTES as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| ApiError::bad_request("the body is not valid gzip"))?;
    if out.len() > agent::REPORT_MAX_BYTES {
        return Err(too_large());
    }
    Ok(out)
}

#[derive(Deserialize)]
struct ReportBody {
    schema: Option<i64>,
    unchanged: Option<String>,
    hostname: Option<String>,
    agent: Option<AgentBody>,
    os: Option<OsBody>,
    dpkg: Option<String>,
    #[serde(default)]
    items: Vec<ItemBody>,
}

/// An entry of `items`. Fields of the wrong kind make the report invalid; unknown types are skipped.
#[derive(Deserialize)]
struct ItemBody {
    #[serde(rename = "type")]
    item_type: Option<String>,
    id: Option<String>,
    name: Option<String>,
    version: Option<String>,
    publisher: Option<String>,
    winget_id: Option<String>,
    scope: Option<String>,
}

/// The entries of a report, and how many were skipped (unknown type, no id).
fn read_items(list: Vec<ItemBody>) -> (Vec<Item>, usize) {
    let mut out = Vec::with_capacity(list.len());
    let mut skipped = 0;
    for b in list {
        let item = b
            .item_type
            .as_deref()
            .and_then(ItemType::parse_sent)
            .and_then(|t| {
                Item::new(
                    t,
                    b.id.as_deref().unwrap_or_default(),
                    b.name.as_deref().unwrap_or_default(),
                    b.version.as_deref().unwrap_or_default(),
                    b.publisher.as_deref().unwrap_or_default(),
                    b.winget_id.as_deref().unwrap_or_default(),
                    b.scope.as_deref() == Some("user"),
                )
            });
        match item {
            Some(i) => out.push(i),
            None => skipped += 1,
        }
    }
    (out, skipped)
}

#[derive(Deserialize)]
struct OsBody {
    family: Option<String>,
    os_release: Option<String>,
    /// Linux: `uname -r`.
    kernel: Option<String>,
    /// Linux: `/var/run/reboot-required` exists.
    #[serde(default)]
    reboot_required: bool,
    /// Ubuntu: the sources of esm-infra or esm-apps are set up.
    #[serde(default)]
    ubuntu_pro: bool,
    /// Windows: `ProductName`, `DisplayVersion`, `CurrentBuild`, `UBR` and `InstallationType`.
    product_name: Option<String>,
    display_version: Option<String>,
    build: Option<u32>,
    ubr: Option<u32>,
    installation_type: Option<String>,
    /// The machine architecture (`x86_64`, `x64`, …).
    arch: Option<String>,
}

/// What a full report says about the system.
enum System {
    /// The text the listing parser reads (Debian, Ubuntu and systems based on them).
    Listing(String),
    Windows(crate::inventory::windows::WindowsSystem),
}

/// What a full report brings: the text the listing parser reads, and what is stored beside it.
struct FullReport {
    system: System,
    hostname: Option<String>,
    agent_name: Option<String>,
    agent_version: Option<String>,
    /// `os.arch`, `agent.updates`, `agent.update_error` (JSON only).
    arch: Option<String>,
    can_update: Option<bool>,
    update_error: Option<String>,
    items: Vec<Item>,
    /// Entries that were skipped (unknown type, no id).
    items_skipped: usize,
}

/// A report after reading the body.
enum Parsed {
    Short(String),
    Full(Box<FullReport>),
}

fn parse_report(form: Form, body: Vec<u8>) -> Result<Parsed, ApiError> {
    let text = String::from_utf8(body)
        .map_err(|_| ApiError::bad_request("the report is not valid UTF-8"))?;
    if form == Form::Text {
        return Ok(Parsed::Full(Box::new(FullReport {
            system: System::Listing(text),
            hostname: None,
            agent_name: None,
            agent_version: None,
            arch: None,
            can_update: None,
            update_error: None,
            items: Vec::new(),
            items_skipped: 0,
        })));
    }
    let b: ReportBody = serde_json::from_str(&text)
        .map_err(|e| ApiError::bad_request(format!("not a valid report: {e}")))?;
    check_schema(b.schema)?;
    if let Some(hash) = b.unchanged {
        return Ok(Parsed::Short(hash.trim().to_ascii_lowercase()));
    }
    let os =
        b.os.ok_or_else(|| ApiError::bad_request("\"os\" is missing"))?;
    let agent = b.agent.unwrap_or_default();
    let optional =
        |v: Option<String>, name: &str, max: usize| -> Result<Option<String>, ApiError> {
            match v {
                None => Ok(None),
                v => text_field(v, name, max).map(Some),
            }
        };
    let hostname = optional(b.hostname, "hostname", 253)?;
    if b.items.len() > listing::MAX_PACKAGES {
        return Err(ApiError::bad_request(format!(
            "\"items\" has more than {} entries",
            listing::MAX_PACKAGES
        )));
    }
    let (items, items_skipped) = read_items(b.items);
    let agent_name = optional(agent.name, "agent.name", 64)?;
    let agent_version = optional(agent.version, "agent.version", 64)?;
    let arch = optional(os.arch, "os.arch", 20)?;
    let can_update = Some(agent.updates.unwrap_or(false));
    let update_error = optional(agent.update_error, "agent.update_error", 200)?;
    match os.family.as_deref() {
        Some("linux") => {}
        Some("windows") => {
            let product_name = text_field(os.product_name, "os.product_name", 200)?;
            let display_version = optional(os.display_version, "os.display_version", 20)?;
            let installation_type = optional(os.installation_type, "os.installation_type", 40)?;
            let build = os
                .build
                .ok_or_else(|| ApiError::bad_request("\"os.build\" is missing"))?;
            let ubr = os
                .ubr
                .ok_or_else(|| ApiError::bad_request("\"os.ubr\" is missing"))?;
            let system = crate::inventory::windows::system(
                &product_name,
                display_version.as_deref().unwrap_or_default(),
                build,
                ubr,
                installation_type.as_deref().unwrap_or_default(),
            )
            .ok_or_else(|| unsupported_system(true))?;
            return Ok(Parsed::Full(Box::new(FullReport {
                system: System::Windows(system),
                hostname,
                agent_name,
                agent_version,
                arch,
                can_update,
                update_error,
                items,
                items_skipped,
            })));
        }
        _ => {
            return Err(ApiError::bad_request(
                "\"os.family\" must be \"linux\" or \"windows\"",
            ));
        }
    }
    let os_release = os.os_release.unwrap_or_default();
    if os_release.len() > agent::OS_RELEASE_MAX_BYTES {
        return Err(ApiError::bad_request(format!(
            "\"os.os_release\" is longer than {} bytes",
            agent::OS_RELEASE_MAX_BYTES
        )));
    }
    if os_release.lines().any(|l| l.trim() == "---") {
        return Err(ApiError::bad_request(
            "\"os.os_release\" must not contain a line \"---\"",
        ));
    }
    // The optional fields become the lines the inventory script writes before "---".
    let mut own = String::new();
    if let Some(kernel) = os.kernel {
        if !listing::is_kernel_release(&kernel) {
            return Err(ApiError::bad_request(
                "\"os.kernel\" is not a kernel release as uname -r gives it",
            ));
        }
        own.push_str(&format!("OPENSECMON_KERNEL={kernel}\n"));
    }
    if os.reboot_required {
        own.push_str("OPENSECMON_REBOOT=1\n");
    }
    if os.ubuntu_pro {
        own.push_str("OPENSECMON_PRO=1\n");
    }
    Ok(Parsed::Full(Box::new(FullReport {
        system: System::Listing(format!(
            "{}\n{own}---\n{}",
            os_release.trim_end(),
            b.dpkg.unwrap_or_default()
        )),
        hostname,
        agent_name,
        agent_version,
        arch,
        can_update,
        update_error,
        items,
        items_skipped,
    })))
}

fn unsupported_system(windows: bool) -> ApiError {
    let message = if windows {
        "only Windows 10, Windows 11 and Windows Server 2016 and later are supported"
    } else {
        "only Debian, Ubuntu and systems based on them are supported"
    };
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "unsupported_system",
        message,
    )
}

/// Turns a report away that came too soon.
fn paced(state: &AppState, device: i64, kind: agent::ReportKind, now: i64) -> Result<(), ApiError> {
    match state.agent_pace.wait_ms(device, kind, now) {
        None => Ok(()),
        Some(wait_ms) => Err(ApiError {
            retry_after_secs: Some((wait_ms + 999) / 1000),
            ..ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "too_many_requests",
                "reported too often, try again later",
            )
        }),
    }
}

/// Notes on the computer's page why a report was not used, and passes the error on.
async fn rejected(
    state: &AppState,
    device: &agents::AgentDevice,
    text_id: &str,
    error: ApiError,
) -> ApiError {
    let text = crate::inventory::runner::error_text(text_id, "");
    tracing::warn!(device = %device.name, error = error.code, message = %error.message, "agent report rejected");
    if let Err(e) = agents::record_error(&state.pool, device.id, &text, now_ms()).await {
        return internal(e);
    }
    error
}

async fn report_inner(state: &AppState, request: Request) -> ApiResult {
    client(state, &request)?;
    let device = authorized(state, request.headers()).await?;
    let (form, gzip) = report_form(request.headers())?;
    let bytes = axum::body::to_bytes(request.into_body(), agent::REPORT_MAX_BYTES)
        .await
        .map_err(|_| too_large())?;
    let body = if gzip {
        gunzip(&bytes)?
    } else {
        bytes.to_vec()
    };
    let hash = crate::auth::hex(&<sha2::Sha256 as sha2::Digest>::digest(&body));
    let parsed = match parse_report(form, body) {
        Ok(p) => p,
        Err(e) if e.code == "unsupported_system" => {
            return Err(rejected(state, &device, "computers-error-windows", e).await);
        }
        Err(e) => return Err(e),
    };
    let now = now_ms();
    let respond = |status: &'static str, warnings: Vec<serde_json::Value>| {
        answer(state, device.id, status, warnings)
    };
    let full = match parsed {
        Parsed::Short(known) => {
            paced(state, device.id, agent::ReportKind::Short, now)?;
            if device.report_hash.is_empty() || known != device.report_hash {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "full_report_required",
                    "the hash is not that of the last report; send the full report",
                ));
            }
            agents::note_unchanged(&state.pool, device.id, now)
                .await
                .map_err(internal)?;
            state
                .agent_pace
                .record(device.id, agent::ReportKind::Short, now);
            return respond("unchanged", Vec::new()).await;
        }
        Parsed::Full(full) => *full,
    };
    paced(state, device.id, agent::ReportKind::Full, now)?;
    let mut warnings = Vec::new();
    if full.items_skipped > 0 {
        warnings.push(json!({ "code": "items_skipped", "count": full.items_skipped }));
    }
    if hash == device.report_hash {
        agents::note_unchanged(&state.pool, device.id, now)
            .await
            .map_err(internal)?;
        state
            .agent_pace
            .record(device.id, agent::ReportKind::Full, now);
        return respond("unchanged", warnings).await;
    }
    let info = agents::ReportInfo {
        hash,
        hostname: full.hostname,
        agent_name: full.agent_name,
        agent_version: full.agent_version,
        arch: full.arch,
        can_update: full.can_update,
        update_error: full.update_error,
    };
    let listing_text = match full.system {
        System::Listing(text) => text,
        System::Windows(system) => {
            let Some(sync) =
                agents::store_windows(&state.pool, &device, &system, &full.items, &info, now)
                    .await
                    .map_err(internal)?
            else {
                return Err(invalid_token());
            };
            state
                .agent_pace
                .record(device.id, agent::ReportKind::Full, now);
            tracing::info!(device = %device.name, system = %system.product, version = %system.version,
                "agent report stored");
            crate::inventory::runner::match_in_background(
                state.pool.clone(),
                sync.changed,
                device.name.clone(),
            );
            return respond("stored", warnings).await;
        }
    };
    let listing = match listing::parse(&listing_text) {
        Ok(l) => l,
        Err(e) => {
            let (id, error) = match e {
                ListingError::Unsupported => ("computers-error-system", unsupported_system(false)),
                ListingError::NoSeparator => (
                    "computers-error-output",
                    ApiError::bad_request(
                        "the report is not the output of the inventory script (no line \"---\")",
                    ),
                ),
                ListingError::NoPackages => (
                    "computers-error-no-packages",
                    ApiError::bad_request("the report lists no installed packages"),
                ),
            };
            return Err(rejected(state, &device, id, error).await);
        }
    };
    if listing.skipped > 0 {
        warnings.insert(
            0,
            json!({ "code": "lines_skipped", "count": listing.skipped }),
        );
    }
    let started = std::time::Instant::now();
    let Some(sync) = agents::store_report(&state.pool, &device, &listing, &full.items, &info, now)
        .await
        .map_err(internal)?
    else {
        return Err(invalid_token());
    };
    state
        .agent_pace
        .record(device.id, agent::ReportKind::Full, now);
    tracing::info!(
        device = %device.name,
        packages = listing.sources.len(),
        added = sync.added,
        updated = sync.updated,
        removed = sync.removed,
        ms = started.elapsed().as_millis(),
        "agent report stored"
    );
    crate::inventory::runner::match_in_background(
        state.pool.clone(),
        sync.changed,
        device.name.clone(),
    );
    respond("stored", warnings).await
}

/// The update to offer a computer: the user asked for one, its agent can install it, and there is a package with
/// a higher version than it runs. Notes when it was first offered.
async fn offer(
    state: &AppState,
    d: &agents::AgentDevice,
) -> Result<Option<serde_json::Value>, ApiError> {
    if d.update_version.is_empty() {
        return Ok(None);
    }
    let Some(p) = state.agent_packages.update_for(
        d.windows(),
        &d.arch,
        &d.agent_name,
        &d.agent_version,
        d.can_update,
    ) else {
        return Ok(None);
    };
    agents::update_offered(&state.pool, d.id, now_ms())
        .await
        .map_err(internal)?;
    Ok(Some(json!({
        "version": p.version,
        "file": p.file,
        "size": p.size,
        "sha256": p.sha256,
        "signature": p.signature,
    })))
}

/// The answer to a report: when to report next by the agent's name, and an update the user asked for.
async fn answer(
    state: &AppState,
    id: i64,
    status: &'static str,
    warnings: Vec<serde_json::Value>,
) -> ApiResult {
    let d = agents::device(&state.pool, id)
        .await
        .map_err(internal)?
        .ok_or_else(invalid_token)?;
    let mut body = json!({
        "status": status,
        "next_report_s": agent::report_interval_secs(&d.agent_name),
        "warnings": warnings,
    });
    if let Some(update) = offer(state, &d).await? {
        body["update"] = update;
    }
    Ok(axum::Json(body).into_response())
}

#[derive(Deserialize)]
struct EnrollBody {
    schema: Option<i64>,
    code: Option<String>,
    hostname: Option<String>,
    #[serde(default)]
    agent: AgentBody,
}

#[derive(Default, Deserialize)]
struct AgentBody {
    name: Option<String>,
    version: Option<String>,
    /// The agent can install updates offered by opensecmon (reports only).
    updates: Option<bool>,
    /// Why it could not install the update offered last (reports only).
    update_error: Option<String>,
}

/// `POST /api/v1/agent/enroll`: exchanges a one-time code for the computer's token.
pub async fn enroll(State(state): State<AppState>, request: Request) -> Response {
    enroll_inner(&state, request)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}

async fn enroll_inner(state: &AppState, request: Request) -> ApiResult {
    let ip = client(state, &request)?;
    require_json(request.headers())?;
    let bytes = body(request, ENROLL_LIMIT).await?;
    let b: EnrollBody = serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::bad_request(format!("not a valid enrollment: {e}")))?;
    check_schema(b.schema)?;
    let code = b
        .code
        .ok_or_else(|| ApiError::bad_request("\"code\" is missing"))?;
    let info = EnrollInfo {
        hostname: text_field(b.hostname, "hostname", 253)?,
        agent_name: text_field(b.agent.name, "agent.name", 64)?,
        agent_version: text_field(b.agent.version, "agent.version", 64)?,
    };

    // Wrong codes count like failed sign-ins (per address, and all of them together under one name).
    let now = now_ms();
    if let Err(wait_ms) = state.login_throttle.begin_attempt(now, THROTTLE_NAME, ip) {
        return Err(ApiError {
            retry_after_secs: Some((wait_ms + 999) / 1000),
            ..ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "too_many_requests",
                "too many wrong codes, try again later",
            )
        });
    }
    let token = agent::new_token();
    let device = match agent::normalize_code(&code) {
        Some(plain) => agents::enroll(&state.pool, &plain, &token_hash(&token), &info, now)
            .await
            .map_err(internal)?,
        None => None,
    };
    let Some(device) = device else {
        tracing::warn!(address = ?ip, "agent enrollment with a wrong or expired code");
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_code",
            "the code is unknown, used or expired",
        ));
    };
    state.login_throttle.record_success(THROTTLE_NAME, ip);
    let program = format!("{} {}", info.agent_name, info.agent_version);
    write(
        state,
        &format!("agent:{}", device.name),
        ip.map(|a| a.to_string()),
        Action::Changed,
        Object::new(AuditKind::AgentDevice, device.id, &device.name),
        &Changes::new()
            .value("audit-field-hostname", &info.hostname)
            .value("audit-field-agent", program.trim())
            .secret("audit-field-agent-token", true)
            .into_msg(),
    )
    .await;
    tracing::info!(device = %device.name, address = ?ip, "computer enrolled");
    Ok((
        StatusCode::CREATED,
        axum::Json(json!({
            "device": device.name,
            "token": token,
            "report_interval_s": agent::report_interval_secs(&info.agent_name),
        })),
    )
        .into_response())
}

/// `GET /api/v1/agent/status`: whether the token is valid, and when to report.
pub async fn status(State(state): State<AppState>, request: Request) -> Response {
    status_inner(&state, request)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}

async fn status_inner(state: &AppState, request: Request) -> ApiResult {
    client(state, &request)?;
    let (parts, _) = request.into_parts();
    let device = authorized(state, &parts.headers).await?;
    agents::touch(&state.pool, device.id, now_ms())
        .await
        .map_err(internal)?;
    let mut body = json!({
        "device": device.name,
        "last_report": device.last_report_ms.map(iso_utc),
        "next_report_s": agent::report_interval_secs(&device.agent_name),
    });
    if let Some(update) = offer(state, &device).await? {
        body["update"] = update;
    }
    Ok(axum::Json(body).into_response())
}

/// `GET /api/v1/agent/packages/{file}`: a package of opensecagent for a computer that holds a token. Only files of
/// the catalogue (read at start), so no path comes from the request.
pub async fn package(
    State(state): State<AppState>,
    axum::extract::Path(file): axum::extract::Path<String>,
    request: Request,
) -> Response {
    package_inner(&state, &file, request)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}

async fn package_inner(state: &AppState, file: &str, request: Request) -> ApiResult {
    client(state, &request)?;
    let device = authorized(state, request.headers()).await?;
    let Some(p) = state.agent_packages.file(file) else {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "no such package",
        ));
    };
    let bytes = tokio::fs::read(&p.path).await.map_err(|e| {
        tracing::error!(file = %p.file, error = %e, "agent package cannot be read");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "the package cannot be read",
        )
    })?;
    tracing::info!(device = %device.name, file = %p.file, "agent package downloaded");
    Ok(package_response(&p.file, bytes))
}

/// A package file as a download.
pub(crate) fn package_response(file: &str, bytes: Vec<u8>) -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{file}\""),
            ),
        ],
        bytes,
    )
        .into_response()
}

/// The computer of the `Authorization: Bearer` token.
async fn authorized(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<agents::AgentDevice, ApiError> {
    let invalid = invalid_token;
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(agent::bearer_token)
        .ok_or_else(invalid)?;
    agents::by_token(&state.pool, token)
        .await
        .map_err(internal)?
        .ok_or_else(invalid)
}

fn invalid_token() -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        "the token is unknown or revoked; enroll the computer again",
    )
}

fn internal(e: crate::error::Error) -> ApiError {
    tracing::error!(error = %e, "agent API");
    if matches!(&e, crate::error::Error::Database(_)) {
        return ApiError {
            retry_after_secs: Some(60),
            ..ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "busy",
                "the database is busy, try again later",
            )
        };
    }
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal",
        "internal error",
    )
}

/// Reads a report body as the endpoint does, for the fuzz tests.
#[cfg(test)]
pub(crate) fn fuzz_report(json: bool, gzip: bool, body: &[u8]) {
    let body = if gzip {
        match gunzip(body) {
            Ok(b) => b,
            Err(_) => return,
        }
    } else {
        body.to_vec()
    };
    let form = if json { Form::Json } else { Form::Text };
    if let Ok(Parsed::Full(full)) = parse_report(form, body)
        && let System::Listing(text) = full.system
    {
        let _ = listing::parse(&text);
    }
}

#[cfg(test)]
mod tests;
