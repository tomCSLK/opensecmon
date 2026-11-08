//! The audit log: who changed what and when (changes, sign-ins including failed ones, sign-outs). Entries are written by the handlers after a change succeeded
//! ([`crate::web::audit::record`]); storage: `storage::audit`, page `/audit`.
//!
//! Secrets never go in: for passwords and keys the entry only says that they changed ([`Changes::secret`]).

use crate::i18n::{Arg, Msg};

/// What was done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Created,
    Changed,
    Deleted,
    SignedIn,
    SignInFailed,
    SignedOut,
}

impl Action {
    pub const ALL: [Self; 6] = [
        Self::Created,
        Self::Changed,
        Self::Deleted,
        Self::SignedIn,
        Self::SignInFailed,
        Self::SignedOut,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Changed => "changed",
            Self::Deleted => "deleted",
            Self::SignedIn => "signed_in",
            Self::SignInFailed => "sign_in_failed",
            Self::SignedOut => "signed_out",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.as_str() == s)
    }

    pub fn label_id(self) -> &'static str {
        match self {
            Self::Created => "audit-action-created",
            Self::Changed => "audit-action-changed",
            Self::Deleted => "audit-action-deleted",
            Self::SignedIn => "audit-action-signed-in",
            Self::SignInFailed => "audit-action-sign-in-failed",
            Self::SignedOut => "audit-action-signed-out",
        }
    }
}

/// What it was done to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    User,
    Mail,
    Session,
    Source,
    /// A CSAF provider of a vendor.
    Provider,
    /// An own asset (software, package or device).
    Asset,
    /// A keyword of the watchlist.
    Watch,
    /// A host whose packages are read over SSH.
    SshHost,
    /// The connection to opennetmon.
    Opennetmon,
    /// A CSV import of assets.
    CsvImport,
    /// The settings of the instant mail.
    Alerts,
    /// The settings of the daily report.
    Report,
    /// The weights of the priority.
    Priority,
    /// The retention and the size of the database.
    Retention,
    /// A computer that reports its software itself (agent API).
    AgentDevice,
    /// A rule that assigns or ignores a program the computers report.
    ItemRule,
}

impl Kind {
    pub const ALL: [Self; 16] = [
        Self::User,
        Self::Mail,
        Self::Session,
        Self::Source,
        Self::Provider,
        Self::Asset,
        Self::Watch,
        Self::SshHost,
        Self::Opennetmon,
        Self::CsvImport,
        Self::Alerts,
        Self::Report,
        Self::Priority,
        Self::Retention,
        Self::AgentDevice,
        Self::ItemRule,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Mail => "mail",
            Self::Session => "session",
            Self::Source => "source",
            Self::Provider => "provider",
            Self::Asset => "asset",
            Self::Watch => "watch",
            Self::SshHost => "ssh_host",
            Self::Opennetmon => "opennetmon",
            Self::CsvImport => "csv_import",
            Self::Alerts => "alerts",
            Self::Report => "report",
            Self::Priority => "priority",
            Self::Retention => "retention",
            Self::AgentDevice => "agent_device",
            Self::ItemRule => "item_rule",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }

    pub fn label_id(self) -> &'static str {
        match self {
            Self::User => "audit-kind-user",
            Self::Mail => "audit-kind-mail",
            Self::Session => "audit-kind-session",
            Self::Source => "audit-kind-source",
            Self::Provider => "audit-kind-provider",
            Self::Asset => "audit-kind-asset",
            Self::Watch => "audit-kind-watch",
            Self::SshHost => "audit-kind-ssh-host",
            Self::Opennetmon => "audit-kind-opennetmon",
            Self::CsvImport => "audit-kind-csv-import",
            Self::Alerts => "audit-kind-alerts",
            Self::Report => "audit-kind-report",
            Self::Priority => "audit-kind-priority",
            Self::Retention => "audit-kind-retention",
            Self::AgentDevice => "audit-kind-agent-device",
            Self::ItemRule => "audit-kind-item-rule",
        }
    }

    /// The page of an object of this kind, if it has one.
    pub fn href(self, id: i64) -> Option<String> {
        match self {
            Self::Source => Some("/sources".to_owned()),
            Self::Provider => Some("/sources/vendors".to_owned()),
            Self::Asset => Some(format!("/assets/{id}")),
            Self::Watch => Some("/assets/watchlist".to_owned()),
            Self::SshHost => Some(format!("/assets/hosts/{id}/edit")),
            Self::Opennetmon => Some("/assets/opennetmon".to_owned()),
            Self::CsvImport => Some("/assets/csv".to_owned()),
            Self::Alerts => Some("/settings/alerts".to_owned()),
            Self::Report => Some("/settings/report".to_owned()),
            Self::Priority => Some("/settings/priority".to_owned()),
            Self::Retention => Some("/settings/retention".to_owned()),
            Self::AgentDevice => Some(format!("/assets/computers/{id}")),
            Self::ItemRule => Some("/assets/unassigned".to_owned()),
            Self::User | Self::Mail | Self::Session => None,
        }
    }
}

/// The changed fields of an object: old → new, secrets only as "changed".
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Changes(Vec<Msg>);

impl Changes {
    pub fn new() -> Self {
        Self::default()
    }

    /// `field` (a catalog id) changed from `old` to `new`; nothing if they are equal.
    pub fn field(mut self, field: &'static str, old: impl ToString, new: impl ToString) -> Self {
        let (old, new) = (old.to_string(), new.to_string());
        if old != new {
            self.0.push(
                Msg::new("audit-change")
                    .with("field", Msg::new(field))
                    .with("old", shown(old))
                    .with("new", shown(new)),
            );
        }
        self
    }

    /// Like [`Self::field`] for values that are catalog ids (a role, a device type): shown in the
    /// language of the reader.
    pub fn label(mut self, field: &'static str, old: &'static str, new: &'static str) -> Self {
        if old != new {
            self.0.push(
                Msg::new("audit-change")
                    .with("field", Msg::new(field))
                    .with("old", Msg::new(old))
                    .with("new", Msg::new(new)),
            );
        }
        self
    }

    /// Like [`Self::value`] for a value that is a catalog id.
    pub fn value_label(mut self, field: &'static str, value: &'static str) -> Self {
        self.0.push(
            Msg::new("audit-value")
                .with("field", Msg::new(field))
                .with("value", Msg::new(value)),
        );
        self
    }

    /// `field` was set to `value` (on creation).
    pub fn value(mut self, field: &'static str, value: impl ToString) -> Self {
        self.0.push(
            Msg::new("audit-value")
                .with("field", Msg::new(field))
                .with("value", shown(value.to_string())),
        );
        self
    }

    /// A secret field: only whether it changed, never the value.
    pub fn secret(mut self, field: &'static str, changed: bool) -> Self {
        if changed {
            self.0
                .push(Msg::new("audit-secret-changed").with("field", Msg::new(field)));
        }
        self
    }

    /// Any other note.
    pub fn note(mut self, msg: Msg) -> Self {
        self.0.push(msg);
        self
    }

    /// Appends the changes of `other`.
    pub fn merge(mut self, other: Changes) -> Self {
        self.0.extend(other.0);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn into_msg(self) -> Msg {
        Msg::List(self.0)
    }
}

/// An empty value shows as "–".
fn shown(text: String) -> Arg {
    if text.is_empty() {
        Arg::Text("–".to_owned())
    } else {
        Arg::Text(text)
    }
}

#[cfg(test)]
mod tests {
    /// The labels come from functions, which the catalog check in i18n.rs cannot follow.
    #[test]
    fn every_label_exists_in_every_language() {
        let ids = Action::ALL
            .iter()
            .map(|a| a.label_id())
            .chain(Kind::ALL.iter().map(|k| k.label_id()));
        for id in ids {
            for t in crate::i18n::Lang::ALL {
                assert_ne!(t.get(id), id, "{id} is missing");
            }
        }
    }

    use super::*;
    use crate::i18n::Lang;

    #[test]
    fn only_changed_fields_are_listed_and_secrets_never_with_their_value() {
        let msg = Changes::new()
            .field("audit-field-name", "Switch", "Switch Büro")
            .field("audit-field-host", "192.0.2.1", "192.0.2.1")
            .field("audit-field-from", "", "secmon@example.org")
            .secret("audit-field-password", true)
            .secret("audit-field-username", false)
            .into_msg();
        let text = Lang::De.msg(&msg);
        assert_eq!(
            text,
            "Name: Switch → Switch Büro, Absender: – → secmon@example.org, Passwort geändert"
        );
        // Stored and read back.
        assert_eq!(
            Lang::En.msg(&Msg::decode(&msg.encode())),
            "Name: Switch → Switch Büro, Sender: – → secmon@example.org, Password changed"
        );
        for kind in Kind::ALL {
            assert_eq!(Kind::parse(kind.as_str()), Some(kind));
        }
        for action in Action::ALL {
            assert_eq!(Action::parse(action.as_str()), Some(action));
        }
    }
}
