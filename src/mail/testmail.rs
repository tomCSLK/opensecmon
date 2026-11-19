//! The test mail of the e-mail settings: it shows that sending works and what is set up, in the look of the
//! other mails (template `templates/mail/test.html`).

use askama::Template;
use jiff::tz::TimeZone;

use super::view::{self, Button, Chip, Fact, Frame, Tone, filters};
use super::{Mail, MailConfig};
use crate::alerts::compose::{Clock, local_time};
use crate::i18n::Lang;
use crate::storage::alerts::Settings;

#[derive(Template)]
#[template(path = "mail/test.html")]
struct TestMail {
    t: Lang,
    frame: Frame,
    chip: Chip,
    when: String,
    title: String,
    by: String,
    facts: Vec<Fact>,
    buttons: Vec<Button>,
}

/// What the instant mail reacts to ("CISA KEV, Priorität ≥ 85"), empty if nothing.
fn conditions(t: Lang, s: &Settings) -> String {
    let mut out = Vec::new();
    if s.on_kev {
        out.push("CISA KEV".to_owned());
    }
    if s.prio_on {
        out.push(t.get1("mail-test-cond-prio", "min", s.prio_min));
    }
    if s.cvss_on {
        out.push(format!("CVSS ≥ {}", t.decimal(s.cvss_min, 1)));
    }
    if s.epss_on {
        out.push(format!("EPSS ≥ {} %", t.decimal(s.epss_min, 1)));
    }
    if s.bundle {
        out.push(t.get("mail-test-bundle"));
    }
    out.join(", ")
}

/// The test mail, sent by `user` with `config` and the notification settings `s`.
pub fn compose(config: &MailConfig, s: &Settings, user: &str, tz: &TimeZone, now_ms: i64) -> Mail {
    let t = config.language;
    let clock = Clock { tz, now_ms };
    let base = (!s.public_url.is_empty()).then_some(s.public_url.as_str());
    let subject = format!("[opensecmon] {}", t.get("mail-test-subject"));
    let on_off = |on: bool| t.get(if on { "mail-test-on" } else { "mail-test-off" });
    let security = t.get(config.security.label_id());
    let auth = t.get(if config.username.is_some() {
        "mail-test-auth"
    } else {
        "mail-test-no-auth"
    });
    let report_time = format!("{:02}:{:02}", s.report_minute / 60, s.report_minute % 60);
    let zone = view::zone_name(tz);
    let facts = vec![
        Fact::new(
            t.get("mail-test-server"),
            config.host.clone(),
            t.get1("mail-test-port", "port", config.port),
        ),
        Fact::new(t.get("mail-test-security"), security.clone(), auth.clone()),
        Fact::new(
            t.get("mail-test-recipients"),
            config.recipients.join(", "),
            String::new(),
        ),
        Fact::new(
            t.get("mail-test-instant"),
            on_off(s.instant),
            if s.instant {
                conditions(t, s)
            } else {
                String::new()
            },
        ),
        Fact::new(
            t.get("mail-test-report"),
            if s.report {
                t.get1("mail-test-daily", "time", report_time.clone())
            } else {
                on_off(false)
            },
            if s.report {
                zone.clone()
            } else {
                String::new()
            },
        ),
        Fact::new(t.get("mail-test-language"), t.native_name(), String::new()),
    ];
    let mut text = vec![
        format!("[opensecmon] {}", t.get("mail-test-subject")),
        clock.text(t),
        String::new(),
        t.get("mail-test-body"),
        t.get1("mail-test-by", "user", user),
        String::new(),
    ];
    for f in &facts {
        let value = if f.sub.is_empty() {
            f.value.clone()
        } else {
            format!("{} ({})", f.value, f.sub)
        };
        text.push(format!("{}: {value}", f.label));
    }
    text.push(String::new());
    text.push("-- ".to_owned());
    text.push(view::program());
    let mut frame = Frame::new(t, subject.clone(), Tone::Ok, base);
    frame.preheader = format!(
        "{} · {}:{} · {security}",
        t.get("mail-test-title"),
        config.host,
        config.port
    );
    frame.footer = vec![view::program(), clock.text(t)];
    frame.settings = base.map(|b| {
        (
            format!("{b}/settings/mail"),
            t.get("mail-test-settings-link"),
        )
    });
    let template = TestMail {
        t,
        frame,
        chip: Chip {
            tone: Tone::Ok,
            text: format!("✓ {}", t.get("mail-test-subject")),
        },
        when: local_time(t, tz, now_ms),
        title: t.get("mail-test-title"),
        by: user.to_owned(),
        facts,
        buttons: base
            .map(|b| Button {
                label: t.get("mail-test-open"),
                href: format!("{b}/settings/mail"),
                primary: false,
            })
            .into_iter()
            .collect(),
    };
    let text = text.join("\n");
    match template.render() {
        Ok(html) => Mail {
            subject,
            text,
            html: Some(html),
            inline: vec![view::logo()],
        },
        Err(e) => {
            tracing::warn!(error = %e, "HTML part of the test mail failed, sending text only");
            Mail::plain(subject, text)
        }
    }
}
