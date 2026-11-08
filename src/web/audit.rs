//! The audit log page `/settings/audit` and [`record`], which the handlers call after a
//! change succeeded. See [`crate::audit`].

use askama::Template;
use axum::extract::{Query, State};
use axum::response::Html;
use serde::Deserialize;

use crate::audit::{Action, Changes, Kind};
use crate::error::Result;
use crate::i18n::{Lang, Msg};
use crate::storage::audit::{self as store, NewEntry};
use crate::web::auth::CurrentUser;
use crate::web::{AppState, Layout, time_html};

/// Entries shown on the page (the newest).
const SHOWN: u32 = 2_000;

/// What happened to which object, for [`record`].
pub struct Object<'a> {
    pub kind: Kind,
    pub id: Option<i64>,
    pub name: &'a str,
}

impl<'a> Object<'a> {
    pub fn new(kind: Kind, id: i64, name: &'a str) -> Self {
        Self {
            kind,
            id: Some(id),
            name,
        }
    }
}

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> i64 {
    crate::auth::now_secs().saturating_mul(1000)
}

/// Writes an entry for a change by `user`; a change without differences (a form saved unchanged)
/// writes none. A failure is logged and does not fail the request: the change itself has been
/// made already.
pub async fn record(
    state: &AppState,
    user: &CurrentUser,
    action: Action,
    object: Object<'_>,
    changes: Changes,
) {
    if action == Action::Changed && changes.is_empty() {
        return;
    }
    write(
        state,
        &user.username,
        user.address.map(|a| a.to_string()),
        action,
        object,
        &changes.into_msg(),
    )
    .await;
}

/// Like [`record`] without a signed-in user (sign-in attempts).
pub async fn write(
    state: &AppState,
    user: &str,
    address: Option<String>,
    action: Action,
    object: Object<'_>,
    detail: &Msg,
) {
    let entry = NewEntry {
        ts_ms: now_ms(),
        user,
        address,
        action,
        kind: object.kind,
        object_id: object.id,
        object_name: object.name,
        detail,
    };
    if let Err(e) = store::insert(&state.pool, &entry).await {
        tracing::error!(error = %e, "writing the audit log failed");
    }
}

struct Row {
    at: String,
    user: String,
    address: String,
    action: String,
    /// Badge class: changes neutral, deletions and failed sign-ins red.
    level: &'static str,
    kind: String,
    name: String,
    href: Option<String>,
    detail: String,
}

#[derive(Template)]
#[template(path = "audit.html")]
struct AuditTemplate {
    t: Lang,
    layout: Layout,
    rows: Vec<Row>,
    /// "Benutzer anna" when filtered.
    filtered: String,
}

#[derive(Deserialize, Default)]
pub struct AuditQuery {
    user: Option<String>,
}

pub async fn page(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<AuditQuery>,
) -> Result<Html<String>> {
    let t = user.lang;
    let mut entries = store::list(&state.pool, SHOWN).await?;
    if let Some(name) = query.user.as_deref().filter(|n| !n.is_empty()) {
        entries.retain(|e| e.user == name);
    }
    let rows = entries
        .into_iter()
        .map(|e| {
            let action = t.get(e.action.label_id());
            let mut kind = t.get(e.kind.label_id());
            // Objects without a name of their own (the mail settings) show their kind instead.
            let name = if e.object_name.is_empty() {
                std::mem::take(&mut kind)
            } else {
                e.object_name
            };
            let detail = t.msg(&e.detail);
            let address = e.address.unwrap_or_default();
            Row {
                at: time_html(e.ts_ms),
                level: match e.action {
                    Action::Deleted | Action::SignInFailed => "bad",
                    Action::Created => "good",
                    _ => "neutral",
                },
                href: e.object_id.and_then(|id| e.kind.href(id)),
                user: e.user,
                address,
                action,
                kind,
                name,
                detail,
            }
        })
        .collect();
    let page = AuditTemplate {
        layout: user.layout(),
        rows,
        filtered: query
            .user
            .filter(|n| !n.is_empty())
            .map(|n| t.get1("audit-filtered-user", "user", n.as_str()))
            .unwrap_or_default(),
        t,
    };
    Ok(Html(page.render()?))
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::*;
    use crate::web::testutil::*;

    const SMTP_PW: &str = "smtp-passwort-geheim";
    const NEW_PW: &str = "ein-neues-langes-passwort";
    const TYPED_IN_NAME: &str = "passwort-im-benutzerfeld";

    async fn entries(h: &Harness) -> Vec<store::Entry> {
        store::list(&h.state.pool, 1_000).await.unwrap()
    }

    fn has(entries: &[store::Entry], action: Action, kind: Kind, name: &str) -> bool {
        entries
            .iter()
            .any(|e| e.action == action && e.kind == kind && e.object_name == name)
    }

    #[tokio::test]
    async fn changes_sign_ins_and_sign_outs_are_logged_without_any_secret() {
        let h = harness(true).await;
        let (admin, csrf) = login(&h, "anna").await;
        let ok = |status: StatusCode| assert_eq!(status, StatusCode::SEE_OTHER);

        // The mail settings with an SMTP password, then saved unchanged (no entry).
        let form = format!(
            "csrf_token={csrf}&enabled=on&host=mail.example.org&port=587&security=starttls\
             &username=opensecmon&password={SMTP_PW}&from_address=opensecmon%40example.org\
             &recipients=admin%40example.org&language=de"
        );
        ok(send(&h.app, post("/settings/mail", Some(&admin), &form))
            .await
            .status);
        let unchanged = form.replace(SMTP_PW, "");
        ok(
            send(&h.app, post("/settings/mail", Some(&admin), &unchanged))
                .await
                .status,
        );

        // The own password and language.
        let form = format!(
            "csrf_token={csrf}&current={PASSWORD}&password={NEW_PW}&password_repeat={NEW_PW}"
        );
        ok(send(
            &h.app,
            post("/settings/account/password", Some(&admin), &form),
        )
        .await
        .status);
        let form = format!("csrf_token={csrf}&language=en");
        ok(send(
            &h.app,
            post("/settings/account/language", Some(&admin), &form),
        )
        .await
        .status);

        // Failed sign-ins: a known user with a wrong password, and a password typed as user name
        for name in ["bert", TYPED_IN_NAME] {
            let (cookie, login_csrf) = open_login(&h).await;
            let form = format!("username={name}&password=falsch-falsch&csrf_token={login_csrf}");
            let reply = send(&h.app, post("/login", Some(&cookie), &form)).await;
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        }

        let all = entries(&h).await;
        assert_eq!(
            all.iter().filter(|e| e.kind == Kind::Mail).count(),
            1,
            "a form saved unchanged writes nothing"
        );
        assert!(has(&all, Action::SignedIn, Kind::Session, ""));
        let failed: Vec<_> = all
            .iter()
            .filter(|e| e.action == Action::SignInFailed)
            .map(|e| (e.user.as_str(), Lang::De.msg(&e.detail)))
            .collect();
        assert_eq!(
            failed,
            [
                ("", "unbekannter Benutzername".to_owned()),
                ("bert", "falsches Passwort".to_owned())
            ]
        );
        let changed = |kind: Kind, name: &str| {
            all.iter()
                .filter(|e| e.action == Action::Changed && e.kind == kind && e.object_name == name)
                .map(|e| Lang::De.msg(&e.detail))
                .collect::<Vec<_>>()
                .join(" | ")
        };
        assert_eq!(
            changed(Kind::User, "anna"),
            "Sprache: Wie im Browser → English | Passwort geändert"
        );
        assert!(changed(Kind::Mail, "").contains("SMTP-Server: – → mail.example.org"));
        assert!(changed(Kind::Mail, "").contains("Passwort geändert"));

        // Signing out is logged as well.
        let form = format!("csrf_token={csrf}");
        ok(send(&h.app, post("/logout", Some(&admin), &form))
            .await
            .status);
        let all = entries(&h).await;
        assert_eq!(all[0].action, Action::SignedOut);
        assert_eq!(all[0].user, "anna");

        // No secret anywhere: not in the stored entries, not on the page in either language.
        let (bert, _) = login(&h, "bert").await;
        let de = send(&h.app, get("/settings/audit", Some(&bert))).await;
        let en = send(&h.app, accepting(get("/settings/audit", Some(&bert)), "en")).await;
        assert_eq!(de.status, StatusCode::OK);
        assert!(de.body.contains("Passwort geändert"));
        let stored: String = entries(&h)
            .await
            .iter()
            .map(|e| {
                format!(
                    "{} {} {:?} {}",
                    e.user,
                    e.object_name,
                    e.address,
                    e.detail.encode()
                )
            })
            .collect();
        for secret in [SMTP_PW, NEW_PW, TYPED_IN_NAME, PASSWORD] {
            for (what, text) in [
                ("entries", &stored),
                ("page", &de.body),
                ("page en", &en.body),
            ] {
                assert!(!text.contains(secret), "{secret} in the {what}");
            }
        }
    }

    #[tokio::test]
    async fn the_audit_log_filters_by_user() {
        let h = harness(true).await;
        let _ = login(&h, "bert").await;
        let (admin, _) = login(&h, "anna").await;
        let page = send(&h.app, get("/settings/audit", Some(&admin))).await;
        assert_eq!(page.status, StatusCode::OK);
        assert!(page.body.contains("href=\"/settings/audit?user=bert\""));
        assert!(page.body.contains("href=\"/settings/audit?user=anna\""));
        let filtered = send(&h.app, get("/settings/audit?user=bert", Some(&admin))).await;
        assert!(filtered.body.contains("Benutzer bert"));
        assert!(!filtered.body.contains("href=\"/settings/audit?user=anna\""));
    }

    #[tokio::test]
    async fn old_entries_are_removed_by_the_retention() {
        let h = harness(true).await;
        let detail = Msg::List(Vec::new());
        for ts_ms in [1_000, 5_000] {
            let entry = NewEntry {
                ts_ms,
                user: "anna",
                address: None,
                action: Action::SignedIn,
                kind: Kind::Session,
                object_id: None,
                object_name: "",
                detail: &detail,
            };
            store::insert(&h.state.pool, &entry).await.unwrap();
        }
        assert_eq!(
            store::apply_retention(&h.state.pool, 2_000).await.unwrap(),
            1
        );
        let left = entries(&h).await;
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].ts_ms, 5_000);
    }
}
