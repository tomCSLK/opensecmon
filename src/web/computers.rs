//! The computers of the agent API (`/assets/computers`): the list, adding a computer (which shows its one-time
//! code), the page of a computer with what its agent needs (address, certificate, code, commands), renaming, a
//! new code, revoking and removing. What a computer reported about itself (host name, program) is shown escaped.

use askama::Template;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, header};
use axum::response::{Html, IntoResponse, Redirect, Response};

use crate::audit::{Action, Changes, Kind as AuditKind};
use crate::error::{Error, Result};
use crate::i18n::Lang;
use crate::storage::agents::{self, AgentDevice};
use crate::storage::inventory::valid_host_name;
use crate::web::FlashQuery as MsgParams;
use crate::web::asset_pages::{Tab, tabs};
use crate::web::audit::{Object, now_ms, record};
use crate::web::auth::CurrentUser;
use crate::web::{AppState, Layout, flash_message, time_html};

pub struct ComputerRow {
    pub id: i64,
    pub name: String,
    pub hostname: String,
    pub system: String,
    pub agent: String,
    pub packages: i64,
    /// "12 vulnerabilities in 5 packages", or empty without open matches.
    pub affected: String,
    /// "3 unassigned", or empty.
    pub unassigned: String,
    pub kernel: Option<crate::web::hosts::KernelView>,
    pub last: Option<String>,
    /// `ok`, `warn` or `off` (the classes of the drafts).
    pub state: &'static str,
    pub icon: &'static str,
    pub state_text: String,
    /// "Update available" or "Update requested" for opensecagent, else empty.
    pub update: String,
}

/// The newer opensecagent a computer could be updated to.
fn available<'a>(
    state: &'a AppState,
    d: &AgentDevice,
) -> Option<&'a crate::agent_packages::Package> {
    state.agent_packages.update_for(
        d.windows(),
        &d.arch,
        &d.agent_name,
        &d.agent_version,
        d.can_update,
    )
}

/// The hint on the update of a computer in the list.
fn update_hint(t: Lang, state: &AppState, d: &AgentDevice) -> String {
    if !d.update_version.is_empty() {
        t.get("computers-update-requested-short")
    } else if let Some(p) = available(state, d) {
        t.get1(
            "computers-update-available-short",
            "version",
            p.version.clone(),
        )
    } else {
        String::new()
    }
}

/// The state of a computer: class, icon, text.
fn state_of(t: Lang, d: &AgentDevice, now: i64) -> (&'static str, &'static str, String) {
    if d.revoked && !d.code_valid(now) {
        ("off", "pause-circle", t.get("computers-state-revoked"))
    } else if d.enrolled() && !d.last_error.is_empty() {
        ("warn", "alert", t.get("computers-state-error"))
    } else if d.enrolled() && d.last_report_ms.is_some() {
        ("ok", "check-circle", t.get("computers-state-reporting"))
    } else if d.enrolled() {
        ("ok", "check-circle", t.get("computers-state-enrolled"))
    } else if d.code_valid(now) {
        ("warn", "clock", t.get("computers-state-waiting"))
    } else {
        ("warn", "alert", t.get("computers-state-expired"))
    }
}

fn agent_text(d: &AgentDevice) -> String {
    format!("{} {}", d.agent_name, d.agent_version)
        .trim()
        .to_owned()
}

/// "3 unassigned" for a computer or host with entries no rule assigns, else "".
pub(crate) fn unassigned_text(t: Lang, count: usize) -> String {
    if count == 0 {
        String::new()
    } else {
        t.get1("computers-unassigned", "count", count)
    }
}

fn row(
    t: Lang,
    app: &AppState,
    d: &AgentDevice,
    now: i64,
    open: (i64, i64),
    unassigned: usize,
) -> ComputerRow {
    let (state, icon, state_text) = state_of(t, d, now);
    ComputerRow {
        update: update_hint(t, app, d),
        id: d.id,
        name: d.name.clone(),
        hostname: d.hostname.clone(),
        system: d.os_name.clone(),
        agent: agent_text(d),
        packages: d.packages,
        affected: crate::web::hosts::affected_text(t, open),
        unassigned: unassigned_text(t, unassigned),
        kernel: crate::web::hosts::kernel_view(
            t,
            &d.kernel,
            &d.kernel_installed,
            d.reboot_required,
        ),
        last: d.last_seen_ms.map(time_html),
        state,
        icon,
        state_text,
    }
}

#[derive(Template)]
#[template(path = "computers.html")]
struct ListTemplate {
    t: Lang,
    layout: Layout,
    tabs: Vec<Tab>,
    computers: Vec<ComputerRow>,
    /// Computers whose opensecagent can be updated and was not asked yet.
    updatable: usize,
    flash: Option<String>,
    error: Option<String>,
}

/// The list of computers.
pub async fn list(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(params): Query<MsgParams>,
) -> Result<Html<String>> {
    let t = user.lang;
    let now = now_ms();
    let open = crate::storage::matches::open_per_origin(&state.pool).await?;
    let (_, unassigned) = crate::storage::items::unassigned_counts(&state.pool).await?;
    let devices = agents::devices(&state.pool).await?;
    let updatable = devices
        .iter()
        .filter(|d| d.update_version.is_empty() && available(&state, d).is_some())
        .count();
    let computers = devices
        .iter()
        .map(|d| {
            let o = open.get(&d.origin_ref()).copied().unwrap_or((0, 0));
            row(
                t,
                &state,
                d,
                now,
                o,
                unassigned.get(&d.origin_ref()).copied().unwrap_or(0),
            )
        })
        .collect();
    let html = ListTemplate {
        t,
        layout: user.layout().at("assets"),
        tabs: tabs(&state, t, "computers").await?,
        computers,
        updatable,
        flash: flash_message(t, params.msg.as_deref()),
        error: None,
    }
    .render()?;
    Ok(Html(html))
}

/// Asks for an update of every computer whose opensecagent can be updated.
pub async fn update_all(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(form): Form<CsrfForm>,
) -> Result<Response> {
    user.verify_csrf(&form.csrf_token)?;
    let now = now_ms();
    for d in agents::devices(&state.pool).await? {
        if !d.update_version.is_empty() {
            continue;
        }
        if let Some(p) = available(&state, &d) {
            let version = p.version.clone();
            agents::request_update(&state.pool, d.id, &version, now).await?;
            record_update(&state, &user, &d, &version).await;
        }
    }
    Ok(Redirect::to("/assets/computers?msg=computer_update").into_response())
}

async fn record_update(state: &AppState, user: &CurrentUser, d: &AgentDevice, version: &str) {
    record(
        state,
        user,
        Action::Changed,
        Object::new(AuditKind::AgentDevice, d.id, &d.name),
        Changes::new().field("audit-field-agent-update", &d.agent_version, version),
    )
    .await;
}

/// Asks for an update of the computer's opensecagent to the newest version that came with opensecmon.
pub async fn update(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Response> {
    user.verify_csrf(&form.csrf_token)?;
    let d = load(&state, id).await?;
    let Some(p) = available(&state, &d) else {
        return Ok(Redirect::to(&format!("/assets/computers/{id}")).into_response());
    };
    let version = p.version.clone();
    agents::request_update(&state.pool, id, &version, now_ms()).await?;
    record_update(&state, &user, &d, &version).await;
    Ok(Redirect::to(&format!("/assets/computers/{id}?msg=computer_update")).into_response())
}

/// Takes the request for an update back.
pub async fn cancel_update(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Response> {
    user.verify_csrf(&form.csrf_token)?;
    let d = load(&state, id).await?;
    agents::cancel_update(&state.pool, id).await?;
    record(
        &state,
        &user,
        Action::Changed,
        Object::new(AuditKind::AgentDevice, id, &d.name),
        Changes::new().field("audit-field-agent-update", &d.update_version, ""),
    )
    .await;
    Ok(Redirect::to(&format!(
        "/assets/computers/{id}?msg=computer_update_cancelled"
    ))
    .into_response())
}

/// A package of opensecagent for download in the browser.
pub async fn agent_package(
    State(state): State<AppState>,
    _user: CurrentUser,
    Path(file): Path<String>,
) -> Result<Response> {
    let p = state.agent_packages.file(&file).ok_or(Error::NotFound)?;
    let bytes = tokio::fs::read(&p.path)
        .await
        .map_err(|e| Error::Internal(format!("agent package {}: {e}", p.file)))?;
    Ok(crate::web::agent_api::package_response(&p.file, bytes))
}

#[derive(Debug, Default, Clone, serde::Deserialize)]
pub struct NameForm {
    #[serde(default)]
    csrf_token: String,
    #[serde(default)]
    name: String,
}

#[derive(Template)]
#[template(path = "computer_form.html")]
struct FormTemplate {
    t: Lang,
    layout: Layout,
    tabs: Vec<Tab>,
    name: String,
    error: Option<String>,
    flash: Option<String>,
}

async fn render_form(
    state: &AppState,
    user: &CurrentUser,
    name: String,
    error: Option<String>,
) -> Result<Response> {
    let t = user.lang;
    let html = FormTemplate {
        t,
        layout: user.layout().at("assets"),
        tabs: tabs(state, t, "computers").await?,
        name,
        error,
        flash: None,
    }
    .render()?;
    Ok(Html(html).into_response())
}

/// The form for a new computer.
pub async fn new_form(State(state): State<AppState>, user: CurrentUser) -> Result<Response> {
    render_form(&state, &user, String::new(), None).await
}

/// Stores a new computer with a one-time code and shows its page.
pub async fn create(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(f): Form<NameForm>,
) -> Result<Response> {
    user.verify_csrf(&f.csrf_token)?;
    let t = user.lang;
    let name = f.name.trim().to_owned();
    if !valid_host_name(&name) {
        return render_form(&state, &user, f.name, Some(t.get("ssh-error-name"))).await;
    }
    let now = now_ms();
    let Some(id) = agents::add(&state.pool, &name, now).await? else {
        return render_form(&state, &user, f.name, Some(t.get("ssh-error-name-taken"))).await;
    };
    agents::new_code(&state.pool, &state.secrets, id, now).await?;
    record(
        &state,
        &user,
        Action::Created,
        Object::new(AuditKind::AgentDevice, id, &name),
        Changes::new()
            .value("audit-field-name", &name)
            .secret("audit-field-enroll-code", true),
    )
    .await;
    Ok(Redirect::to(&format!("/assets/computers/{id}")).into_response())
}

/// What the agent of a computer needs for the enrollment.
pub struct Enrollment {
    pub code: String,
    pub expires: String,
    pub base_url: String,
    /// The command for the script (Debian and Ubuntu).
    pub script_command: String,
    /// The command for the PowerShell script (Windows).
    pub windows_command: String,
    /// Commands to try it with curl.
    pub enroll_command: String,
    pub status_command: String,
    /// The enrollment code of opensecagent (only when its packages came with opensecmon).
    pub agent_code: Option<String>,
}

/// A package of opensecagent to download.
pub struct Download {
    pub label: String,
    pub href: String,
    pub size: String,
}

/// The update of opensecagent on a computer's page.
pub struct UpdateView {
    /// The version the agent runs.
    pub running: String,
    /// A newer version that came with opensecmon.
    pub available: Option<String>,
    /// Asked for: the version, when, and when the agent got the offer.
    pub requested: Option<String>,
    pub requested_at: Option<String>,
    pub sent_at: Option<String>,
    /// Why the agent could not install the last one.
    pub error: Option<String>,
    /// The agent can install updates (built and signed by its publisher).
    pub can_update: bool,
}

/// The script for Debian and Ubuntu computers (`contrib/opensecmon-agent.sh`), offered on the computer's page.
pub const AGENT_SCRIPT: &str = include_str!("../../contrib/opensecmon-agent.sh");

/// The script for Windows computers (`contrib/opensecmon-agent.ps1`), offered on the computer's page.
pub const WINDOWS_SCRIPT: &str = include_str!("../../contrib/opensecmon-agent.ps1");

#[derive(Template)]
#[template(path = "computer.html")]
struct PageTemplate {
    t: Lang,
    layout: Layout,
    tabs: Vec<Tab>,
    computer: AgentDevice,
    state: &'static str,
    icon: &'static str,
    state_text: String,
    agent: String,
    enrolled: Option<String>,
    last_seen: Option<String>,
    last_report: Option<String>,
    /// Why the last report was not used (text for the user).
    last_error: Option<String>,
    enrollment: Option<Enrollment>,
    fingerprint: Option<String>,
    /// Value of the name field (the stored name, or what was entered with an error).
    name: String,
    error: Option<String>,
    flash: Option<String>,
    pro: Option<crate::web::hosts::ProSetting>,
    kernel: Option<crate::web::hosts::KernelView>,
    /// "3 unassigned", or empty.
    unassigned: String,
    /// The packages of opensecagent (empty if none came with opensecmon).
    downloads: Vec<Download>,
    /// For computers with opensecagent.
    update: Option<UpdateView>,
}

/// The packages of opensecagent for download.
fn downloads(t: Lang, state: &AppState) -> Vec<Download> {
    use crate::agent_packages::System;
    state
        .agent_packages
        .downloads()
        .into_iter()
        .map(|p| {
            let system = match p.system {
                System::Windows => t.get("computers-agent-windows"),
                System::Debian => t.get("computers-agent-debian"),
            };
            Download {
                label: format!("{system} ({}) {}", p.arch, p.version),
                href: format!("/assets/computers/agent/{}", p.file),
                size: crate::web::retention::size_text(
                    t,
                    i64::try_from(p.size).unwrap_or(i64::MAX),
                ),
            }
        })
        .collect()
}

fn update_view(state: &AppState, d: &AgentDevice) -> Option<UpdateView> {
    if d.agent_name != crate::agent_packages::AGENT_NAME {
        return None;
    }
    Some(UpdateView {
        running: d.agent_version.clone(),
        available: available(state, d).map(|p| p.version.clone()),
        requested: (!d.update_version.is_empty()).then(|| d.update_version.clone()),
        requested_at: d.update_requested_ms.map(time_html),
        sent_at: d.update_sent_ms.map(time_html),
        error: (!d.update_error.is_empty()).then(|| d.update_error.clone()),
        can_update: d.can_update,
    })
}

/// The address of this server as the browser reached it: the agent uses the same one. Anything that is not a
/// plain host name with an optional port is replaced by a placeholder (the value ends up in a shell command).
fn base_url(headers: &HeaderMap) -> String {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .filter(|h| {
            !h.is_empty()
                && h.len() <= 260
                && h.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-.:[]".contains(&b))
        })
        .unwrap_or("<server>");
    format!("https://{host}")
}

fn script_command(base: &str, code: &str, with_cert: bool) -> String {
    let cert = if with_cert { " opensecmon.pem" } else { "" };
    format!("sudo sh opensecmon-agent.sh enroll {base} {code}{cert}")
}

/// Run in a PowerShell window as administrator, in the folder with the downloaded script.
fn windows_command(base: &str, code: &str, with_cert: bool) -> String {
    let cert = if with_cert { " opensecmon.pem" } else { "" };
    format!(
        "powershell -ExecutionPolicy Bypass -File .\\opensecmon-agent.ps1 enroll {base} {code}{cert}"
    )
}

fn commands(base: &str, code: &str, with_cert: bool) -> (String, String) {
    let cacert = if with_cert {
        " --cacert opensecmon.pem"
    } else {
        ""
    };
    let enroll = format!(
        "curl --fail-with-body{cacert} \\\n  -H 'Content-Type: application/json' \\\n  \
         -d \"{{\\\"schema\\\":1,\\\"code\\\":\\\"{code}\\\",\\\"hostname\\\":\\\"$(hostname)\\\"}}\" \\\n  \
         {base}/api/v1/agent/enroll"
    );
    let status = format!(
        "curl --fail-with-body{cacert} \\\n  -H 'Authorization: Bearer osm1_…' \\\n  {base}/api/v1/agent/status"
    );
    (enroll, status)
}

async fn render_page(
    state: &AppState,
    user: &CurrentUser,
    headers: &HeaderMap,
    d: AgentDevice,
    name: Option<String>,
    error: Option<String>,
    flash: Option<String>,
) -> Result<Response> {
    let t = user.lang;
    let now = now_ms();
    let (class, icon, state_text) = state_of(t, &d, now);
    let enrollment = agents::shown_code(&state.secrets, &d, now).map(|code| {
        let base = base_url(headers);
        let with_cert = state.tls_certificate.is_some();
        let (enroll_command, status_command) = commands(&base, &code, with_cert);
        let fingerprint = state
            .tls_certificate
            .as_ref()
            .and_then(|c| crate::agent_code::parse_fingerprint(&c.fingerprint));
        let agent_code = (!state.agent_packages.is_empty())
            .then(|| crate::agent_code::address_of(&base))
            .flatten()
            .and_then(|address| crate::agent_code::encode(address, fingerprint.as_ref(), &code));
        Enrollment {
            agent_code,
            script_command: script_command(&base, &code, with_cert),
            windows_command: windows_command(&base, &code, with_cert),
            code,
            expires: d.code_expires_ms.map(time_html).unwrap_or_default(),
            base_url: base,
            enroll_command,
            status_command,
        }
    });
    let (_, unassigned) = crate::storage::items::unassigned_counts(&state.pool).await?;
    let html = PageTemplate {
        t,
        downloads: downloads(t, state),
        update: update_view(state, &d),
        unassigned: unassigned_text(t, unassigned.get(&d.origin_ref()).copied().unwrap_or(0)),
        kernel: crate::web::hosts::kernel_view(
            t,
            &d.kernel,
            &d.kernel_installed,
            d.reboot_required,
        ),
        pro: crate::web::hosts::pro_setting(
            t,
            format!("/assets/computers/{}/pro", d.id),
            d.pro_mode(),
            d.pro_detected,
            &d.distro,
        ),
        layout: user.layout().at("assets"),
        tabs: tabs(state, t, "computers").await?,
        state: class,
        icon,
        state_text,
        agent: agent_text(&d),
        enrolled: d.enrolled_ms.map(time_html),
        last_seen: d.last_seen_ms.map(time_html),
        last_report: d.last_report_ms.map(time_html),
        last_error: (!d.last_error.is_empty()).then(|| {
            let (id, detail) = d.last_error.split_once('\t').unwrap_or((&d.last_error, ""));
            let text = t.get(id);
            if detail.is_empty() {
                text
            } else {
                format!("{text} ({detail})")
            }
        }),
        enrollment,
        fingerprint: state
            .tls_certificate
            .as_ref()
            .map(|c| c.fingerprint.clone()),
        name: name.unwrap_or_else(|| d.name.clone()),
        computer: d,
        error,
        flash,
    }
    .render()?;
    Ok(Html(html).into_response())
}

async fn load(state: &AppState, id: i64) -> Result<AgentDevice> {
    agents::device(&state.pool, id)
        .await?
        .ok_or(Error::NotFound)
}

/// The page of a computer.
pub async fn page(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Query(params): Query<MsgParams>,
) -> Result<Response> {
    let d = load(&state, id).await?;
    let flash = flash_message(user.lang, params.msg.as_deref());
    render_page(&state, &user, &headers, d, None, None, flash).await
}

/// Gives a computer another name (its assets follow).
/// Sets how the computer gets Ubuntu Pro.
pub async fn set_pro(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<crate::web::hosts::ProForm>,
) -> Result<Response> {
    let d = agents::device(&state.pool, id)
        .await?
        .ok_or(Error::NotFound)?;
    crate::web::hosts::save_pro(
        &state,
        &user,
        &form,
        crate::storage::inventory::ProOwner::Agent,
        id,
        &d.name,
        d.pro_mode(),
    )
    .await?;
    Ok(Redirect::to(&format!("/assets/computers/{id}?msg=computer_saved")).into_response())
}

pub async fn rename(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Form(f): Form<NameForm>,
) -> Result<Response> {
    user.verify_csrf(&f.csrf_token)?;
    let t = user.lang;
    let d = load(&state, id).await?;
    let name = f.name.trim().to_owned();
    let error = if !valid_host_name(&name) {
        Some("ssh-error-name")
    } else if !agents::rename(&state.pool, &d, &name).await? {
        Some("ssh-error-name-taken")
    } else {
        None
    };
    if let Some(error) = error {
        let error = Some(t.get(error));
        return render_page(&state, &user, &headers, d, Some(f.name), error, None).await;
    }
    record(
        &state,
        &user,
        Action::Changed,
        Object::new(AuditKind::AgentDevice, id, &name),
        Changes::new().field("audit-field-name", &d.name, &name),
    )
    .await;
    Ok(Redirect::to(&format!("/assets/computers/{id}?msg=computer_saved")).into_response())
}

#[derive(serde::Deserialize)]
pub struct CsrfForm {
    csrf_token: String,
}

/// Makes a new one-time code (the old one stops working).
pub async fn new_code(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Response> {
    user.verify_csrf(&form.csrf_token)?;
    let d = load(&state, id).await?;
    agents::new_code(&state.pool, &state.secrets, id, now_ms()).await?;
    record(
        &state,
        &user,
        Action::Changed,
        Object::new(AuditKind::AgentDevice, id, &d.name),
        Changes::new().secret("audit-field-enroll-code", true),
    )
    .await;
    Ok(Redirect::to(&format!("/assets/computers/{id}?msg=computer_code")).into_response())
}

/// Revokes the token and any open code.
pub async fn revoke(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Response> {
    user.verify_csrf(&form.csrf_token)?;
    let d = load(&state, id).await?;
    agents::revoke(&state.pool, id).await?;
    let label = |on: bool| if on { "audit-yes" } else { "audit-no" };
    record(
        &state,
        &user,
        Action::Changed,
        Object::new(AuditKind::AgentDevice, id, &d.name),
        Changes::new().label("audit-field-enabled", label(true), label(false)),
    )
    .await;
    Ok(Redirect::to(&format!("/assets/computers/{id}?msg=computer_revoked")).into_response())
}

/// Removes a computer with the assets it reported.
pub async fn delete(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Response> {
    user.verify_csrf(&form.csrf_token)?;
    let d = agents::delete(&state.pool, id)
        .await?
        .ok_or(Error::NotFound)?;
    record(
        &state,
        &user,
        Action::Deleted,
        Object::new(AuditKind::AgentDevice, id, &d.name),
        Changes::new()
            .value("audit-field-hostname", &d.hostname)
            .value("audit-field-packages", d.packages),
    )
    .await;
    Ok(Redirect::to("/assets/computers?msg=computer_deleted").into_response())
}

/// The script for Debian and Ubuntu computers.
pub async fn script(_user: CurrentUser) -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"opensecmon-agent.sh\"",
            ),
        ],
        AGENT_SCRIPT,
    )
        .into_response()
}

/// The script for Windows computers. Windows PowerShell reads a file without BOM in the ANSI code page: the
/// script is plain ASCII (a test makes sure).
pub async fn windows_script(_user: CurrentUser) -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"opensecmon-agent.ps1\"",
            ),
        ],
        WINDOWS_SCRIPT,
    )
        .into_response()
}

/// The certificate of the built-in HTTPS (public part only), for the agents.
pub async fn certificate(State(state): State<AppState>, _user: CurrentUser) -> Result<Response> {
    let cert = state.tls_certificate.as_ref().ok_or(Error::NotFound)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/x-pem-file"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"opensecmon.pem\"",
            ),
        ],
        cert.pem.clone(),
    )
        .into_response())
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn the_address_comes_from_the_host_header_and_never_breaks_the_command() {
        let mut h = HeaderMap::new();
        assert_eq!(base_url(&h), "https://<server>");
        h.insert(header::HOST, "192.0.2.10:8444".parse().unwrap());
        assert_eq!(base_url(&h), "https://192.0.2.10:8444");
        h.insert(header::HOST, "[fd00::2]:8444".parse().unwrap());
        assert_eq!(base_url(&h), "https://[fd00::2]:8444");
        h.insert(header::HOST, "x$(reboot)".parse().unwrap());
        assert_eq!(base_url(&h), "https://<server>");
    }

    #[test]
    fn the_commands_carry_the_code_and_the_certificate_only_when_there_is_one() {
        let (enroll, status) = commands("https://192.0.2.10:8444", "K7FQ-29XM", true);
        assert!(enroll.contains("--cacert opensecmon.pem"));
        assert!(enroll.contains(r#"\"code\":\"K7FQ-29XM\""#), "{enroll}");
        assert!(enroll.ends_with("https://192.0.2.10:8444/api/v1/agent/enroll"));
        assert!(status.contains("Authorization: Bearer"));
        assert!(status.ends_with("/api/v1/agent/status"));
        let (enroll, _) = commands("https://secmon.example.org", "K7FQ-29XM", false);
        assert!(!enroll.contains("cacert"));
        assert_eq!(
            script_command("https://192.0.2.10:8444", "K7FQ-29XM", true),
            "sudo sh opensecmon-agent.sh enroll https://192.0.2.10:8444 K7FQ-29XM opensecmon.pem"
        );
        assert!(!script_command("https://secmon.example.org", "K7FQ-29XM", false).contains(".pem"));
        assert_eq!(
            windows_command("https://192.0.2.10:8444", "K7FQ-29XM", true),
            "powershell -ExecutionPolicy Bypass -File .\\opensecmon-agent.ps1 enroll https://192.0.2.10:8444 \
             K7FQ-29XM opensecmon.pem"
        );
        assert!(
            !windows_command("https://secmon.example.org", "K7FQ-29XM", false).contains(".pem")
        );
    }

    #[test]
    fn the_script_reads_what_the_api_takes() {
        // The script sends exactly the output of the SSH import's inventory script.
        assert!(AGENT_SCRIPT.contains(
            "dpkg-query -W -f='${db:Status-Abbrev}\\t${Package}\\t${Version}\\t${source:Package}\\t${source:Version}\\n'"
        ));
        assert!(
            crate::inventory::listing::SCRIPT.contains(
                "dpkg-query -W -f='${db:Status-Abbrev}\\t${Package}\\t${Version}\\t${source:Package}\\t${source:Version}\\n'"
            )
        );
        // Both scripts write the same lines before "---" and the same sections after the packages.
        for line in [
            "echo \"--- snap\"",
            "LC_ALL=C snap list --unicode=never --color=never 2>/dev/null || true",
            "echo \"--- flatpak\"",
            "cache=$(mktemp -d 2>/dev/null) || cache=\"\"",
            "XDG_CACHE_HOME=${cache:-/tmp} LC_ALL=C flatpak list --app --columns=application,name,version,installation 2>/dev/null || true",
            "if [ -n \"$cache\" ]; then rm -rf \"$cache\"; fi",
            "echo \"OPENSECMON_KERNEL=$(uname -r)\"",
            "if [ -e /var/run/reboot-required ]; then echo \"OPENSECMON_REBOOT=1\"; fi",
            "for f in /etc/apt/sources.list.d/ubuntu-esm-infra.* /etc/apt/sources.list.d/ubuntu-esm-apps.*; do",
        ] {
            assert!(AGENT_SCRIPT.contains(line), "{line}");
            assert!(crate::inventory::listing::SCRIPT.contains(line), "{line}");
        }
        assert!(AGENT_SCRIPT.contains("/api/v1/agent/report"));
        assert!(AGENT_SCRIPT.contains("--proto =https"));
    }

    #[test]
    fn the_windows_script_sends_what_the_api_reads() {
        // Windows PowerShell 5.1 would read other characters in the ANSI code page.
        assert!(WINDOWS_SCRIPT.is_ascii());
        // The fields of `os` that `agent_api` reads for Windows, and the items.
        for key in [
            "family            = 'windows'",
            "product_name      =",
            "display_version   =",
            "build             =",
            "ubr               =",
            "installation_type =",
            "items    = $items",
            "type      = 'win'",
            "type      = 'appx'",
            "scope     =",
        ] {
            assert!(WINDOWS_SCRIPT.contains(key), "{key}");
        }
        assert!(WINDOWS_SCRIPT.contains("/api/v1/agent/report"));
        assert!(WINDOWS_SCRIPT.contains("/api/v1/agent/enroll"));
        assert!(WINDOWS_SCRIPT.contains("'--proto', '=https'"));
        // The token only in a header file, never on the command line.
        assert!(WINDOWS_SCRIPT.contains("'-H', \"@$header\""));
        // The same limit as the API.
        assert!(WINDOWS_SCRIPT.contains(&format!(
            "$MaxItems = {}",
            crate::inventory::listing::MAX_PACKAGES
        )));
    }
}
