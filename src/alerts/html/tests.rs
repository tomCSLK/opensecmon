use jiff::civil::date;

use super::*;
use crate::alerts::compose::tests_support::row;
use crate::alerts::compose::{Detail, FailedSource, HostCount, Reason, group};
use crate::situation::{Counts, Day};

const BASE: &str = "https://sec.example.org";
// 2026-11-19 06:12 UTC = 07:12 in Berlin.
const NOW: i64 = 1_795_068_720_000;

fn berlin() -> TimeZone {
    TimeZone::get("Europe/Berlin").unwrap()
}

fn one() -> Vec<Item> {
    let mut a = row(1, "CVE-2026-41872", 96, true, "server01");
    a.product_name = Some("openssh-server".to_owned());
    a.version = Some("1:10.2p1-2ubuntu1".to_owned());
    a.fixed = "1:10.2p1-2ubuntu1.1".to_owned();
    a.distro = Some("ubuntu".to_owned());
    a.release = Some("26.04".to_owned());
    a.title = "OpenSSH: <script>alert(1)</script> overflow in sshd".to_owned();
    let mut b = a.clone();
    b.id = 2;
    b.host = Some("pi01".to_owned());
    b.version = Some("1:10.0p1-7".to_owned());
    b.fixed = "1:10.0p1-7+deb13u2".to_owned();
    b.distro = Some("debian".to_owned());
    b.release = Some("13".to_owned());
    let mut items = group(&[a, b], |_| vec![Reason::Kev, Reason::Prio(96, 85)]);
    items[0].detail = Some(Detail {
        cvss: Some((
            9.8,
            "3.1".to_owned(),
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_owned(),
        )),
        epss: Some((0.714, 0.995)),
        kev: Some(("2026-11-18".to_owned(), "2026-12-09".to_owned())),
        published_ms: Some(NOW - 5 * 86_400_000),
        bsi: Some((
            "WID-SEC-2026-3104".to_owned(),
            "Ein entfernter, anonymer Angreifer kann eine Schwachstelle in OpenSSH ausnutzen <b>."
                .to_owned(),
        )),
    });
    items
}

fn many() -> Vec<Item> {
    let mut rows = vec![
        row(1, "CVE-2026-41872", 96, true, "server01"),
        row(2, "CVE-2026-39005", 88, false, "desktop01"),
        row(3, "osv:DSA-6112-1", 71, false, "pi01"),
    ];
    rows[1].product_name = Some("Google Chrome".to_owned());
    rows[1].version = Some("157.0.8103.39".to_owned());
    rows[1].fixed = "157.0.8103.92".to_owned();
    for (i, host) in ["desktop01", "server01", "pi01", "nas01"]
        .iter()
        .enumerate()
    {
        let mut r = row(10 + i as i64, "adv:7", 66, false, host);
        r.evidence = "WID-SEC-2026-3077".to_owned();
        r.title = "Python: Mehrere Schwachstellen".to_owned();
        rows.push(r);
    }
    group(&rows, |r| vec![Reason::Prio(r.prio(), 65)])
}

fn day(d: jiff::civil::Date, crit: i64, high: i64, med: i64, low: i64) -> Day {
    Day {
        day: d,
        counts: Counts {
            crit,
            high,
            med,
            low,
            kev: 1,
        },
        derived: false,
    }
}

fn full_report() -> Report {
    let mut trend = Vec::new();
    let mut d = date(2026, 11, 6);
    for i in 0..14 {
        trend.push(day(d, 3 + i % 3, 9, 14, 22 - i / 2));
        d = d.tomorrow().unwrap();
    }
    Report {
        now_ms: NOW,
        since_ms: NOW - 86_400_000,
        new: Some(many()),
        open: Some(one()),
        due: Some(Vec::new()),
        sources: Some(vec![FailedSource {
            name: "NVD".to_owned(),
            error: "HTTP 503 <Service Unavailable>".to_owned(),
            last_success_ms: Some(NOW - 12 * 3_600_000),
        }]),
        open_total: 38,
        trend,
        hosts: vec![
            HostCount {
                host: "desktop01".to_owned(),
                open: 14,
                critical: 3,
            },
            HostCount {
                host: "nas01".to_owned(),
                open: 4,
                critical: 0,
            },
        ],
    }
}

fn quiet_report() -> Report {
    Report {
        new: Some(Vec::new()),
        open: Some(Vec::new()),
        due: Some(Vec::new()),
        sources: Some(Vec::new()),
        open_total: 31,
        ..full_report()
    }
}

#[test]
fn a_single_vulnerability_is_shown_in_detail_and_escaped() {
    let tz = berlin();
    let clock = Clock {
        tz: &tz,
        now_ms: NOW,
    };
    let mail = instant(Lang::De, &clock, &one(), &Links(Some(BASE)));
    let html = mail.html.as_deref().unwrap().replace('\u{a0}', " ");
    assert_eq!(mail.inline, vec![view::logo()]);
    assert!(html.contains("cid:logo@opensecmon"));
    assert!(html.contains("Kritisch · Priorität 96"), "{html}");
    assert!(html.contains("KEV · wird ausgenutzt"));
    assert!(html.contains(">CVE-2026-41872<"));
    // Feed text is escaped, never markup.
    assert!(!html.contains("<script>"), "{html}");
    assert!(html.contains("&#60;script&#62;") || html.contains("&lt;script&gt;"));
    assert!(!html.contains("<b>.</b>") && !html.contains("ausnutzen <b>"));
    assert!(html.contains("Kurzfassung des BSI · WID-SEC-2026-3104"));
    assert!(html.contains("CVSS 3.1"));
    assert!(html.contains("Netzwerk · ohne Anmeldung · keine Interaktion"));
    assert!(html.contains("71,4 %"));
    assert!(html.contains("höher als bei 99 % aller CVEs"));
    assert!(html.contains("seit 18.11.2026") && html.contains("Frist der CISA: 09.12.2026"));
    assert!(html.contains("vor 5 Tagen"));
    assert!(html.contains("Betroffen (2)"));
    assert!(html.contains("Ubuntu 26.04") && html.contains("Debian 13"));
    assert!(html.contains("1:10.0p1-7+deb13u2"));
    assert!(html.contains("steht in CISA KEV"));
    assert!(html.contains("href=\"https://sec.example.org/?sel=CVE-2026-41872\""));
    assert!(html.contains("href=\"https://sec.example.org/cves/CVE-2026-41872\""));
    assert!(html.contains("href=\"https://sec.example.org/settings/alerts\""));
    assert!(html.contains("sec.example.org</td>"));
    // The text part has the same detail.
    assert!(
        mail.text.contains("19.11.2026 07:12 (Europe/Berlin)"),
        "{}",
        mail.text
    );
    assert!(
        mail.text.contains("CVSS 3.1: 9,8 (kritisch) · Netzwerk"),
        "{}",
        mail.text
    );
    assert!(
        mail.text
            .contains("EPSS: 71,4 % (höher als bei 99 % aller CVEs)")
    );
    assert!(
        mail.text
            .contains("CISA KEV: seit 18.11.2026, Frist der CISA: 09.12.2026")
    );
    assert!(
        mail.text
            .contains("Kurzfassung des BSI · WID-SEC-2026-3104: Ein entfernter")
    );
    assert!(
        mail.text
            .contains("Veröffentlicht: 14.11.2026 (vor 5 Tagen)")
    );

    // Without the address of the interface: no links at all.
    let mail = instant(Lang::En, &clock, &one(), &Links(None));
    let html = mail.html.unwrap().replace('\u{a0}', " ");
    assert!(!html.contains("href="), "{html}");
    assert!(!html.contains("http"), "{html}");
    assert!(html.contains("Critical · priority 96"));
}

#[test]
fn several_vulnerabilities_become_cards_worst_first() {
    let tz = berlin();
    let clock = Clock {
        tz: &tz,
        now_ms: NOW,
    };
    let mail = instant(Lang::De, &clock, &many(), &Links(Some(BASE)));
    let html = mail.html.unwrap().replace('\u{a0}', " ");
    assert!(
        html.contains("4 neue Treffer für eigene Assets")
            || html.contains("4 neue Treffer für eigene Assets"),
        "{html}"
    );
    assert!(html.contains("Höchste Priorität 96 · 1 in CISA KEV · 4 Hosts betroffen"));
    let first = html.find("CVE-2026-41872</a>").unwrap();
    let second = html.find("CVE-2026-39005</a>").unwrap();
    let third = html.find("WID-SEC-2026-3077</a>").unwrap();
    assert!(first < second && second < third);
    assert!(html.contains("und 1 weitere"), "four hosts, three shown");
    assert!(html.contains("Alle im Eingang öffnen"));
    assert!(html.contains("Priorität 96 ≥ 65"));
}

#[test]
fn the_report_shows_tiles_trend_hosts_and_parts() {
    let tz = berlin();
    let r = full_report();
    let mail = report(Lang::De, &tz, &r, &Links(Some(BASE)));
    let html = mail.html.unwrap().replace('\u{a0}', " ");
    assert!(html.contains("Lage am 19.11.2026"), "{html}");
    assert!(
        html.contains("Im Eingang sind 38 Meldungen offen, 1 mehr als gestern."),
        "{html}"
    );
    assert!(html.contains("Offene Schwachstellen, 14 Tage"));
    assert!(html.contains(">06.11.<") && html.contains(">heute<"));
    assert!(html.contains("Meistbetroffene Hosts") && html.contains(">desktop01<"));
    assert!(html.contains("3 kritisch"));
    assert!(
        html.contains("HTTP 503 &#60;Service Unavailable&#62;")
            || html.contains("HTTP 503 &lt;Service Unavailable&gt;")
    );
    assert!(html.contains("Neu seit 18.11.2026 07:12: 4"));
    assert!(html.contains("Tagesbericht einstellen"));
    assert!(
        mail.text
            .contains("Meistbetroffene Hosts: desktop01 14 (3 kritisch), nas01 4"),
        "{}",
        mail.text
    );

    let mail = report(Lang::De, &tz, &quiet_report(), &Links(None));
    let html = mail.html.unwrap().replace('\u{a0}', " ");
    assert!(html.contains("Ruhiger Tag"));
    assert!(html.contains("Nichts zu melden"));
    assert!(!html.contains("href="));
}

#[test]
fn the_test_mail_names_server_and_settings() {
    let tz = berlin();
    let config = crate::mail::MailConfig {
        enabled: true,
        host: "smtp.example.org".to_owned(),
        port: 587,
        security: crate::mail::Security::StartTls,
        username: Some("monitor".to_owned()),
        password: None,
        from_address: "opensecmon@example.org".to_owned(),
        recipients: vec!["it@example.org".to_owned()],
        language: Lang::De,
    };
    let settings = crate::storage::alerts::Settings {
        public_url: BASE.to_owned(),
        ..Default::default()
    };
    let mail = crate::mail::testmail::compose(&config, &settings, "<admin>", &tz, NOW);
    let html = mail.html.unwrap().replace('\u{a0}', " ");
    assert!(html.contains("Der Mailversand funktioniert"), "{html}");
    assert!(
        html.contains("<b>&#60;admin&#62;</b>") || html.contains("<b>&lt;admin&gt;</b>"),
        "{html}"
    );
    assert!(html.contains("smtp.example.org") && html.contains("Port 587"));
    assert!(html.contains("STARTTLS") && html.contains("mit Anmeldung"));
    assert!(
        mail.text.contains("Server: smtp.example.org (Port 587)"),
        "{}",
        mail.text
    );
    assert!(mail.text.contains("Ausgelöst von <admin>"));
}

/// Writes the mails to `target/mail-preview/` to look at them in a browser:
/// `cargo test --lib mail_preview -- --ignored`
#[test]
#[ignore = "writes preview files"]
fn mail_preview() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/mail-preview");
    std::fs::create_dir_all(&dir).unwrap();
    let tz = berlin();
    let clock = Clock {
        tz: &tz,
        now_ms: NOW,
    };
    let links = Links(Some(BASE));
    let config = crate::mail::MailConfig {
        enabled: true,
        host: "smtp.example.org".to_owned(),
        port: 587,
        security: crate::mail::Security::StartTls,
        username: Some("monitor".to_owned()),
        password: None,
        from_address: "opensecmon@example.org".to_owned(),
        recipients: vec!["it@example.org".to_owned()],
        language: Lang::De,
    };
    let settings = crate::storage::alerts::Settings {
        public_url: BASE.to_owned(),
        ..Default::default()
    };
    let mails = [
        ("one", instant(Lang::De, &clock, &one(), &links)),
        ("many", instant(Lang::De, &clock, &many(), &links)),
        ("report", report(Lang::De, &tz, &full_report(), &links)),
        ("quiet", report(Lang::De, &tz, &quiet_report(), &links)),
        (
            "test",
            crate::mail::testmail::compose(&config, &settings, "admin", &tz, NOW),
        ),
    ];
    for (name, mail) in mails {
        let html = view::with_data_uris(mail.html.as_deref().unwrap(), &mail.inline);
        std::fs::write(dir.join(format!("{name}.html")), html).unwrap();
        std::fs::write(
            dir.join(format!("{name}.txt")),
            format!("Subject: {}\n\n{}", mail.subject, mail.text),
        )
        .unwrap();
        println!("{}", dir.join(format!("{name}.html")).display());
    }
}
