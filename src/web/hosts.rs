//! The hosts whose packages are read over SSH (`/assets/hosts`): the list, the wizard for a new host
//! (connection → key and script on the host → confirm the host key → first reading), changing,
//! switching off and removing a host, and "read now".
//!
//! The host key is trusted only after the user compared its fingerprint; a host that later presents
//! another key is not read until the new key is confirmed. Everything a host sends (system name,
//! error texts) is shown escaped.

use askama::Template;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};

use crate::audit::{Action, Changes, Kind as AuditKind};
use crate::error::{Error, Result};
use crate::i18n::Lang;
use crate::inventory::listing::{SCRIPT, SCRIPT_PATH};
use crate::inventory::runner::{self, Outcome};
use crate::inventory::ssh;
use crate::sources::now_ms;
use crate::storage::inventory::{self, CheckedHost, HostInput, ProMode, ProOwner, SshHost};
use crate::storage::matches;
use crate::web::asset_pages::{Tab, tabs};
use crate::web::audit::{Object, record};
use crate::web::auth::CurrentUser;
use crate::web::{AppState, Layout, flash_message, time_html};

/// The setting "Ubuntu Pro" of a host or computer (only for Ubuntu).
pub struct ProSetting {
    pub action: String,
    /// Value, label, selected.
    pub options: Vec<(&'static str, String, bool)>,
    pub help: String,
}

pub(crate) fn pro_setting(
    t: Lang,
    action: String,
    mode: ProMode,
    detected: bool,
    distro: &str,
) -> Option<ProSetting> {
    (distro == "ubuntu").then(|| ProSetting {
        action,
        options: ProMode::ALL
            .iter()
            .map(|&m| (m.as_str(), t.get(m.label_id()), m == mode))
            .collect(),
        help: t.get(if detected {
            "pro-mode-help-detected"
        } else {
            "pro-mode-help-not-detected"
        }),
    })
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct ProForm {
    #[serde(default)]
    csrf_token: String,
    #[serde(default)]
    pro_mode: String,
}

/// Stores the setting "Ubuntu Pro" of a host or computer, makes its packages follow and matches the changed
/// ones again; the old and the new mode.
pub(crate) async fn save_pro(
    state: &AppState,
    user: &CurrentUser,
    form: &ProForm,
    owner: ProOwner,
    id: i64,
    host: &str,
    old: ProMode,
) -> Result<ProMode> {
    user.verify_csrf(&form.csrf_token)?;
    let mode = ProMode::parse(&form.pro_mode)
        .ok_or_else(|| Error::invalid(crate::i18n::Msg::new("pro-mode-invalid")))?;
    let changed = inventory::set_pro_mode(&state.pool, owner, id, mode, now_ms()).await?;
    if !changed.is_empty() {
        runner::match_in_background(state.pool.clone(), changed, host.to_owned());
    }
    let kind = match owner {
        ProOwner::Ssh => AuditKind::SshHost,
        ProOwner::Agent => AuditKind::AgentDevice,
    };
    record(
        state,
        user,
        Action::Changed,
        Object::new(kind, id, host),
        Changes::new().label("audit-field-pro", old.label_id(), mode.label_id()),
    )
    .await;
    Ok(mode)
}

/// Sets how the host gets Ubuntu Pro.
pub async fn set_pro(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<ProForm>,
) -> Result<Response> {
    let h = inventory::host(&state.pool, id)
        .await?
        .ok_or(Error::NotFound)?;
    save_pro(
        &state,
        &user,
        &form,
        ProOwner::Ssh,
        id,
        &h.name,
        h.pro_mode(),
    )
    .await?;
    Ok(Redirect::to(&format!("/assets/hosts/{id}/edit?msg=host_saved")).into_response())
}

/// The text of a stored error ("id\tdetail"): the catalog text, the detail of the host in brackets.
pub(crate) fn error_text(t: Lang, stored: &str) -> String {
    let (id, detail) = stored.split_once('\t').unwrap_or((stored, ""));
    let text = t.get(id);
    if detail.is_empty() {
        text
    } else {
        format!("{text} ({detail})")
    }
}

pub struct HostRow {
    pub id: i64,
    pub name: String,
    pub address: String,
    pub system: String,
    pub packages: i64,
    pub last: Option<String>,
    pub next: Option<String>,
    /// `ok`, `warn`, `err` or `off` (the classes of the drafts).
    pub state: &'static str,
    pub icon: &'static str,
    pub state_text: String,
    pub detail: String,
    /// The wizard is the next thing to do (setup open, key to confirm).
    pub setup: bool,
    /// "12 vulnerabilities in 5 packages", or empty without open matches.
    pub affected: String,
    pub kernel: Option<KernelView>,
    /// "3 unassigned" (snaps and Flatpaks no rule assigns), or empty.
    pub unassigned: String,
}

/// The kernel of a host or computer: the running one, and with a pending reboot a warning with the installed one.
pub struct KernelView {
    pub text: String,
    pub reboot: bool,
}

/// `None` while the inventory script does not say which kernel runs (an older script).
pub(crate) fn kernel_view(
    t: Lang,
    running: &str,
    installed: &str,
    reboot: bool,
) -> Option<KernelView> {
    if running.is_empty() {
        return None;
    }
    let text = if !reboot {
        t.get1("kernel-running", "running", running.to_owned())
    } else if installed.is_empty() {
        t.get1("kernel-reboot", "running", running.to_owned())
    } else {
        t.get2(
            "kernel-reboot-installed",
            "running",
            running.to_owned(),
            "installed",
            installed.to_owned(),
        )
    };
    Some(KernelView { text, reboot })
}

/// Packages with open matches and the different vulnerabilities among them, as a text (empty without any).
pub(crate) fn affected_text(t: Lang, (packages, vulns): (i64, i64)) -> String {
    if packages == 0 {
        String::new()
    } else {
        t.get2("hosts-affected", "vulns", vulns, "count", packages)
    }
}

fn row(t: Lang, h: &SshHost, open: (i64, i64), unassigned: usize) -> HostRow {
    let key_pending = !h.seen_key.is_empty() && h.seen_key != h.host_key;
    let (state, icon, state_text, detail, setup) = if !h.enabled {
        (
            "off",
            "pause-circle",
            t.get("hosts-state-off"),
            String::new(),
            false,
        )
    } else if h.host_key.is_empty() {
        let text = if key_pending {
            t.get("hosts-state-key")
        } else {
            t.get("hosts-state-setup")
        };
        ("warn", "alert", text, String::new(), true)
    } else if key_pending {
        (
            "err",
            "x-circle",
            t.get("hosts-state-key-changed"),
            String::new(),
            true,
        )
    } else if !h.last_error.is_empty() {
        (
            "err",
            "x-circle",
            t.get("hosts-state-error"),
            error_text(t, &h.last_error),
            false,
        )
    } else if h.last_ok_ms.is_some() {
        (
            "ok",
            "check-circle",
            t.get("hosts-state-ok"),
            String::new(),
            false,
        )
    } else {
        (
            "warn",
            "clock",
            t.get("hosts-state-waiting"),
            String::new(),
            false,
        )
    };
    HostRow {
        id: h.id,
        name: h.name.clone(),
        address: if h.port == 22 {
            h.address.clone()
        } else {
            format!("{}:{}", h.address, h.port)
        },
        system: h.os_name.clone(),
        packages: h.packages,
        last: h.last_ok_ms.map(time_html),
        next: h.next_ms().filter(|n| *n > 0).map(time_html),
        state,
        icon,
        state_text,
        detail,
        setup,
        affected: affected_text(t, open),
        kernel: kernel_view(t, &h.kernel, &h.kernel_installed, h.reboot_required),
        unassigned: crate::web::computers::unassigned_text(t, unassigned),
    }
}

#[derive(Template)]
#[template(path = "hosts.html")]
struct ListTemplate {
    t: Lang,
    layout: Layout,
    tabs: Vec<Tab>,
    hosts: Vec<HostRow>,
    public_line: String,
    flash: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct MsgParams {
    msg: Option<String>,
}

/// The list of hosts.
pub async fn list(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(params): Query<MsgParams>,
) -> Result<Html<String>> {
    let t = user.lang;
    let open = matches::open_per_origin(&state.pool).await?;
    let (_, unassigned) = crate::storage::items::unassigned_counts(&state.pool).await?;
    let hosts = inventory::hosts(&state.pool)
        .await?
        .iter()
        .map(|h| {
            let o = open.get(&h.origin_ref()).copied().unwrap_or((0, 0));
            row(
                t,
                h,
                o,
                unassigned.get(&h.origin_ref()).copied().unwrap_or(0),
            )
        })
        .collect();
    let key = inventory::ssh_key(&state.pool, &state.secrets).await?;
    let html = ListTemplate {
        t,
        layout: user.layout().at("assets"),
        tabs: tabs(&state, t, "hosts").await?,
        hosts,
        public_line: ssh::public_line(&key),
        flash: flash_message(t, params.msg.as_deref()),
        error: None,
    }
    .render()?;
    Ok(Html(html))
}

/// The fields of the connection form.
#[derive(Debug, Default, Clone, serde::Deserialize)]
pub struct HostForm {
    #[serde(default)]
    csrf_token: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    port: String,
    #[serde(default)]
    username: String,
}

impl HostForm {
    fn input(&self) -> HostInput {
        HostInput {
            name: self.name.clone(),
            address: self.address.clone(),
            port: self.port.clone(),
            username: self.username.clone(),
        }
    }
}

/// One step of the wizard in the step bar.
pub struct Step {
    pub label: String,
    pub done: bool,
    pub current: bool,
}

fn steps(t: Lang, current: usize) -> Vec<Step> {
    [
        "hosts-step-connection",
        "hosts-step-key",
        "hosts-step-confirm",
        "hosts-step-test",
    ]
    .iter()
    .enumerate()
    .map(|(i, id)| Step {
        label: t.get(id),
        done: i + 1 < current,
        current: i + 1 == current,
    })
    .collect()
}

#[derive(Template)]
#[template(path = "host_form.html")]
struct FormTemplate {
    t: Lang,
    layout: Layout,
    tabs: Vec<Tab>,
    title: String,
    action: String,
    /// The stored host (changing), `None` for a new one (step 1 of the wizard).
    host: Option<SshHost>,
    steps: Vec<Step>,
    f: HostForm,
    error: Option<String>,
    flash: Option<String>,
    pro: Option<ProSetting>,
    kernel: Option<KernelView>,
}

async fn render_form(
    state: &AppState,
    user: &CurrentUser,
    host: Option<SshHost>,
    f: HostForm,
    error: Option<String>,
    flash: Option<String>,
) -> Result<Response> {
    let t = user.lang;
    let html = FormTemplate {
        t,
        layout: user.layout().at("assets"),
        tabs: tabs(state, t, "hosts").await?,
        title: match &host {
            Some(h) => h.name.clone(),
            None => t.get("hosts-add"),
        },
        action: match &host {
            Some(h) => format!("/assets/hosts/{}", h.id),
            None => "/assets/hosts/new".to_owned(),
        },
        steps: steps(t, 1),
        kernel: host
            .as_ref()
            .and_then(|h| kernel_view(t, &h.kernel, &h.kernel_installed, h.reboot_required)),
        pro: host.as_ref().and_then(|h| {
            pro_setting(
                t,
                format!("/assets/hosts/{}/pro", h.id),
                h.pro_mode(),
                h.pro_detected,
                &h.distro,
            )
        }),
        host,
        f,
        error,
        flash,
    }
    .render()?;
    Ok(Html(html).into_response())
}

/// The suggested user on a host.
const DEFAULT_USER: &str = "opensecmon-inv";

/// What the wizard tells to run on a host, ready to copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupCommands {
    pub home: String,
    /// A system user with a real home directory: `adduser --system` alone gives `/nonexistent`, where sshd finds
    /// no `authorized_keys`.
    pub user: String,
    /// For SSH servers that let only some groups in (`AllowGroups`, e.g. `_ssh` on openmediavault).
    pub group: String,
    pub script_path: &'static str,
    pub script: String,
    pub key_path: String,
    pub key: String,
}

impl SetupCommands {
    /// `username` is checked already (lower-case letters, digits, `_` and `-`), so it needs no quoting.
    pub fn new(username: &str, key_line: &str) -> Self {
        let home = format!("/var/lib/{username}");
        let key_path = format!("{home}/.ssh/authorized_keys");
        Self {
            user: format!("sudo adduser --system --group --home {home} --shell /bin/sh {username}"),
            group: format!("sudo adduser {username} _ssh"),
            script_path: SCRIPT_PATH,
            script: format!(
                "sudo tee {SCRIPT_PATH} > /dev/null <<'EOF'\n{SCRIPT}EOF\n\
                 sudo chown root:root {SCRIPT_PATH} && sudo chmod 755 {SCRIPT_PATH}"
            ),
            key: format!(
                "sudo install -d -m 700 -o {username} -g {username} {home}/.ssh\n\
                 echo '{key_line}' | sudo tee -a {key_path} > /dev/null\n\
                 sudo chown {username}:{username} {key_path} && sudo chmod 600 {key_path}"
            ),
            home,
            key_path,
        }
    }
}

/// Step 1 of the wizard: the connection.
pub async fn new_form(State(state): State<AppState>, user: CurrentUser) -> Result<Response> {
    let f = HostForm {
        port: "22".to_owned(),
        // Not "opensecmon": on the server that runs opensecmon that is the service user (no login, no home).
        username: DEFAULT_USER.to_owned(),
        ..HostForm::default()
    };
    render_form(&state, &user, None, f, None, None).await
}

fn host_changes(old: Option<&SshHost>, new: &CheckedHost) -> Changes {
    let text = |f: fn(&SshHost) -> String| old.map(f).unwrap_or_default();
    Changes::new()
        .field("audit-field-name", text(|h| h.name.clone()), &new.name)
        .field(
            "audit-field-host",
            text(|h| h.address.clone()),
            &new.address,
        )
        .field(
            "audit-field-port",
            old.map(|h| h.port.to_string()).unwrap_or_default(),
            new.port,
        )
        .field(
            "audit-field-username",
            text(|h| h.username.clone()),
            &new.username,
        )
}

/// Stores a new host and goes on to step 2.
pub async fn create(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(f): Form<HostForm>,
) -> Result<Response> {
    user.verify_csrf(&f.csrf_token)?;
    let t = user.lang;
    let checked = match f.input().check() {
        Ok(c) => c,
        Err(id) => return render_form(&state, &user, None, f, Some(t.get(id)), None).await,
    };
    let Some(id) = inventory::add_host(&state.pool, &checked, now_ms()).await? else {
        let error = Some(t.get("ssh-error-name-taken"));
        return render_form(&state, &user, None, f, error, None).await;
    };
    record(
        &state,
        &user,
        Action::Created,
        Object::new(AuditKind::SshHost, id, &checked.name),
        host_changes(None, &checked),
    )
    .await;
    Ok(Redirect::to(&format!("/assets/hosts/{id}/setup")).into_response())
}

/// The form of a stored host.
pub async fn edit_form(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
    Query(params): Query<MsgParams>,
) -> Result<Response> {
    let h = inventory::host(&state.pool, id)
        .await?
        .ok_or(Error::NotFound)?;
    let f = HostForm {
        name: h.name.clone(),
        address: h.address.clone(),
        port: h.port.to_string(),
        username: h.username.clone(),
        ..HostForm::default()
    };
    let flash = flash_message(user.lang, params.msg.as_deref());
    render_form(&state, &user, Some(h), f, None, flash).await
}

/// Saves changed connection details (a new address or port asks for the host key again).
pub async fn update(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
    Form(f): Form<HostForm>,
) -> Result<Response> {
    user.verify_csrf(&f.csrf_token)?;
    let t = user.lang;
    let old = inventory::host(&state.pool, id)
        .await?
        .ok_or(Error::NotFound)?;
    let checked = match f.input().check() {
        Ok(c) => c,
        Err(e) => return render_form(&state, &user, Some(old), f, Some(t.get(e)), None).await,
    };
    if !inventory::update_host(&state.pool, &old, &checked).await? {
        let error = Some(t.get("ssh-error-name-taken"));
        return render_form(&state, &user, Some(old), f, error, None).await;
    }
    record(
        &state,
        &user,
        Action::Changed,
        Object::new(AuditKind::SshHost, id, &checked.name),
        host_changes(Some(&old), &checked),
    )
    .await;
    let h = inventory::host(&state.pool, id)
        .await?
        .ok_or(Error::NotFound)?;
    if h.host_key.is_empty() && h.enabled {
        return Ok(Redirect::to(&format!("/assets/hosts/{id}/setup")).into_response());
    }
    Ok(Redirect::to("/assets/hosts?msg=host_saved").into_response())
}

#[derive(Template)]
#[template(path = "host_setup.html")]
struct SetupTemplate {
    t: Lang,
    layout: Layout,
    tabs: Vec<Tab>,
    host: SshHost,
    steps: Vec<Step>,
    step: usize,
    commands: SetupCommands,
    fingerprint: String,
    /// The key changed after it had been confirmed.
    changed: bool,
    old_fingerprint: String,
    /// Step 4: the reading worked.
    read_ok: bool,
    result: String,
    open: i64,
    error: Option<String>,
    flash: Option<String>,
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct SetupParams {
    /// `2` shows the instructions again.
    step: Option<usize>,
}

/// Steps 2 to 4 of the wizard, chosen by the state of the host.
pub async fn setup(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
    Query(params): Query<SetupParams>,
) -> Result<Response> {
    let t = user.lang;
    let h = inventory::host(&state.pool, id)
        .await?
        .ok_or(Error::NotFound)?;
    let key_pending = !h.seen_key.is_empty() && h.seen_key != h.host_key;
    let step = if params.step == Some(2) || (h.host_key.is_empty() && !key_pending) {
        2
    } else if key_pending {
        3
    } else {
        4
    };
    let key = inventory::ssh_key(&state.pool, &state.secrets).await?;
    let open = matches::open_per_origin(&state.pool)
        .await?
        .get(&h.origin_ref())
        .map_or(0, |o| o.0);
    let read_ok = h.last_ok_ms.is_some() && h.last_error.is_empty();
    let error = (step != 3 && !h.last_error.is_empty()).then(|| error_text(t, &h.last_error));
    let html = SetupTemplate {
        t,
        layout: user.layout().at("assets"),
        tabs: tabs(&state, t, "hosts").await?,
        steps: steps(t, step),
        step,
        commands: SetupCommands::new(&h.username, &ssh::authorized_keys_line(&key, SCRIPT_PATH)),
        fingerprint: ssh::fingerprint(&h.seen_key),
        changed: key_pending && !h.host_key.is_empty(),
        old_fingerprint: ssh::fingerprint(&h.host_key),
        read_ok,
        result: if read_ok {
            t.get2(
                "hosts-result",
                "system",
                h.os_name.clone(),
                "count",
                h.packages,
            )
        } else {
            String::new()
        },
        open,
        host: h,
        error,
        flash: None,
    }
    .render()?;
    Ok(Html(html).into_response())
}

#[derive(serde::Deserialize)]
pub struct CsrfForm {
    csrf_token: String,
}

/// Reads the host now and shows where the wizard stands.
pub async fn connect(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Response> {
    user.verify_csrf(&form.csrf_token)?;
    runner::read_host(&state.pool, &state.secrets, id).await?;
    Ok(Redirect::to(&format!("/assets/hosts/{id}/setup")).into_response())
}

#[derive(serde::Deserialize)]
pub struct ConfirmForm {
    csrf_token: String,
    /// The key that was shown (a key the host presented in the meantime is not confirmed blindly).
    key: String,
    #[serde(default)]
    ok: Option<String>,
}

/// Trusts the shown host key, then reads the host.
pub async fn confirm(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<ConfirmForm>,
) -> Result<Response> {
    user.verify_csrf(&form.csrf_token)?;
    let h = inventory::host(&state.pool, id)
        .await?
        .ok_or(Error::NotFound)?;
    if form.ok.is_none() || !inventory::confirm_key(&state.pool, id, &form.key).await? {
        return Ok(Redirect::to(&format!("/assets/hosts/{id}/setup")).into_response());
    }
    let old = if h.host_key.is_empty() {
        String::new()
    } else {
        ssh::fingerprint(&h.host_key)
    };
    record(
        &state,
        &user,
        Action::Changed,
        Object::new(AuditKind::SshHost, id, &h.name),
        Changes::new().field("audit-field-host-key", old, ssh::fingerprint(&form.key)),
    )
    .await;
    runner::read_host(&state.pool, &state.secrets, id).await?;
    Ok(Redirect::to(&format!("/assets/hosts/{id}/setup")).into_response())
}

/// "Read now" from the list.
pub async fn run(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Response> {
    user.verify_csrf(&form.csrf_token)?;
    let to = match runner::read_host(&state.pool, &state.secrets, id).await? {
        Outcome::Read { .. } => "/assets/hosts?msg=host_read".to_owned(),
        Outcome::KeyToConfirm => format!("/assets/hosts/{id}/setup"),
        Outcome::Failed(_) => "/assets/hosts".to_owned(),
    };
    Ok(Redirect::to(&to).into_response())
}

#[derive(serde::Deserialize)]
pub struct EnabledForm {
    csrf_token: String,
    enabled: String,
}

/// Switches the regular reading of a host on or off.
pub async fn set_enabled(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<EnabledForm>,
) -> Result<Response> {
    user.verify_csrf(&form.csrf_token)?;
    let h = inventory::host(&state.pool, id)
        .await?
        .ok_or(Error::NotFound)?;
    let enabled = form.enabled == "1";
    inventory::set_enabled(&state.pool, id, enabled).await?;
    let label = |on: bool| if on { "audit-yes" } else { "audit-no" };
    record(
        &state,
        &user,
        Action::Changed,
        Object::new(AuditKind::SshHost, id, &h.name),
        Changes::new().label("audit-field-enabled", label(h.enabled), label(enabled)),
    )
    .await;
    Ok(Redirect::to(&format!("/assets/hosts/{id}/edit?msg=host_saved")).into_response())
}

/// Removes a host with its packages.
pub async fn delete(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Response> {
    user.verify_csrf(&form.csrf_token)?;
    let h = inventory::delete_host(&state.pool, id)
        .await?
        .ok_or(Error::NotFound)?;
    record(
        &state,
        &user,
        Action::Deleted,
        Object::new(AuditKind::SshHost, id, &h.name),
        Changes::new()
            .value("audit-field-host", &h.address)
            .value("audit-field-packages", h.packages),
    )
    .await;
    Ok(Redirect::to("/assets/hosts?msg=host_deleted").into_response())
}

#[cfg(test)]
mod setup_tests {
    use super::*;

    #[test]
    fn the_setup_gives_the_user_a_home_where_sshd_finds_the_key() {
        let line =
            "restrict,command=\"/usr/local/bin/opensecmon-inventory\" ssh-ed25519 AAAA opensecmon";
        let c = SetupCommands::new("opensecmon-inv", line);
        assert_eq!(
            c.user,
            "sudo adduser --system --group --home /var/lib/opensecmon-inv --shell /bin/sh opensecmon-inv"
        );
        assert!(!c.user.contains("nonexistent"));
        assert_eq!(c.key_path, "/var/lib/opensecmon-inv/.ssh/authorized_keys");
        assert!(
            c.key
                .contains(&format!("echo '{line}' | sudo tee -a {}", c.key_path))
        );
        assert!(c.key.contains("chmod 600"));
        // The script is written literally (quoted heredoc), then made root-owned.
        assert!(c.script.starts_with(
            "sudo tee /usr/local/bin/opensecmon-inventory > /dev/null <<'EOF'\n#!/bin/sh"
        ));
        assert!(c.script.contains("\nEOF\nsudo chown root:root"));
        assert_eq!(DEFAULT_USER, "opensecmon-inv");
    }
}
