//! The texts of the instant mail and the daily report (plain text, in the language of the mails).
//!
//! Titles, product names, versions, host names and error texts come from feeds, hosts and opennetmon: they are
//! data, so control characters (and bidirectional overrides) are removed and long texts are clipped.

use jiff::tz::TimeZone;

use crate::i18n::{Arg, Lang};
use crate::storage::cve_list::Band;
use crate::storage::matches::Row;

/// Vulnerabilities listed per mail section; the rest is counted.
pub const MAX_ITEMS: usize = 25;
/// Affected assets listed per vulnerability.
const MAX_AFFECTED: usize = 5;
const MAX_TITLE: usize = 160;
const MAX_NAME: usize = 80;
const MAX_ERROR: usize = 200;

/// Why a match is mailed at once.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Reason {
    Kev,
    /// Priority and the threshold.
    Prio(i64, i64),
    /// CVSS and the threshold.
    Cvss(f64, f64),
    /// EPSS in percent and the threshold.
    Epss(f64, f64),
}

/// One affected asset or keyword.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Affected {
    pub asset: String,
    pub host: String,
    pub fixed: String,
    pub keyword: Option<String>,
}

/// A vulnerability with its matches.
#[derive(Debug, Clone, PartialEq)]
pub struct Item {
    pub vuln: String,
    /// What the mail shows (CVE id, DSA/USN id, advisory id).
    pub label: String,
    pub title: String,
    pub prio: i64,
    pub kev: bool,
    pub affected: Vec<Affected>,
    pub reasons: Vec<Reason>,
    /// The match ids.
    pub ids: Vec<i64>,
}

/// Removes control characters and bidirectional overrides, joins lines and clips the text.
pub fn clean(text: &str, max: usize) -> String {
    let bidi = |c: char| matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
    let joined: String = text
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .filter(|c| !c.is_control() && !bidi(*c))
        .collect();
    let words: Vec<&str> = joined.split(' ').filter(|w| !w.is_empty()).collect();
    let text = words.join(" ");
    if text.chars().count() > max {
        let mut cut: String = text.chars().take(max.saturating_sub(1)).collect();
        cut.push('…');
        cut
    } else {
        text
    }
}

/// The id a person knows the vulnerability by.
pub fn label(r: &Row) -> String {
    let text = if let Some(id) = r.vuln.strip_prefix("osv:") {
        id.to_owned()
    } else if r.vuln.starts_with("adv:") {
        r.evidence
            .split(',')
            .find(|e| !e.is_empty())
            .unwrap_or(&r.vuln)
            .to_owned()
    } else {
        r.vuln.clone()
    };
    clean(&text, MAX_NAME)
}

fn affected(r: &Row) -> Affected {
    let name = [
        r.vendor_name.as_deref().unwrap_or_default(),
        r.product_name.as_deref().unwrap_or_default(),
        r.version.as_deref().unwrap_or_default(),
    ]
    .iter()
    .filter(|p| !p.is_empty())
    .copied()
    .collect::<Vec<_>>()
    .join(" ");
    Affected {
        asset: clean(&name, MAX_NAME),
        host: clean(r.host.as_deref().unwrap_or_default(), MAX_NAME),
        fixed: clean(&r.fixed, MAX_NAME),
        keyword: r.keyword.as_deref().map(|k| clean(k, MAX_NAME)),
    }
}

/// Groups matches by vulnerability, highest priority first. `reasons` gives the reasons of a match.
pub fn group(rows: &[Row], reasons: impl Fn(&Row) -> Vec<Reason>) -> Vec<Item> {
    let mut items: Vec<Item> = Vec::new();
    for r in rows {
        let index = match items.iter().position(|i| i.vuln == r.vuln) {
            Some(i) => i,
            None => {
                items.push(Item {
                    vuln: r.vuln.clone(),
                    label: label(r),
                    title: clean(&r.title, MAX_TITLE),
                    prio: 0,
                    kev: false,
                    affected: Vec::new(),
                    reasons: Vec::new(),
                    ids: Vec::new(),
                });
                items.len() - 1
            }
        };
        let item = &mut items[index];
        item.prio = item.prio.max(r.prio());
        item.kev |= r.kev;
        item.ids.push(r.id);
        let a = affected(r);
        if !item.affected.contains(&a) {
            item.affected.push(a);
        }
        for reason in reasons(r) {
            if !item.reasons.contains(&reason) {
                item.reasons.push(reason);
            }
        }
    }
    items.sort_by(|a, b| b.prio.cmp(&a.prio).then_with(|| a.vuln.cmp(&b.vuln)));
    items
}

/// A local time as the mails show it.
pub fn local_time(t: Lang, tz: &TimeZone, ms: i64) -> String {
    let Ok(ts) = jiff::Timestamp::from_millisecond(ms) else {
        return String::new();
    };
    let format = match t {
        Lang::De => "%d.%m.%Y %H:%M",
        Lang::En => "%Y-%m-%d %H:%M",
    };
    ts.to_zoned(tz.clone()).strftime(format).to_string()
}

/// A local date as the mails show it.
pub fn local_date(t: Lang, tz: &TimeZone, ms: i64) -> String {
    let Ok(ts) = jiff::Timestamp::from_millisecond(ms) else {
        return String::new();
    };
    let format = match t {
        Lang::De => "%d.%m.%Y",
        Lang::En => "%Y-%m-%d",
    };
    ts.to_zoned(tz.clone()).strftime(format).to_string()
}

fn encode(value: &str) -> String {
    crate::web::cves::encode(value)
}

/// Links into the interface (`None`: no address set, no links).
pub struct Links<'a>(pub Option<&'a str>);

impl Links<'_> {
    fn inbox(&self) -> Option<String> {
        self.0.map(|base| format!("{base}/"))
    }

    fn item(&self, vuln: &str) -> Option<String> {
        self.0.map(|base| format!("{base}/?sel={}", encode(vuln)))
    }

    fn page(&self, path: &str) -> Option<String> {
        self.0.map(|base| format!("{base}{path}"))
    }
}

fn reason_text(t: Lang, r: &Reason) -> String {
    match *r {
        Reason::Kev => t.get("alert-reason-kev"),
        Reason::Prio(p, min) => t.get2("alert-reason-prio", "prio", p, "min", min),
        Reason::Cvss(v, min) => t.get2(
            "alert-reason-cvss",
            "score",
            t.decimal(v, 1),
            "min",
            t.decimal(min, 1),
        ),
        Reason::Epss(v, min) => t.get2(
            "alert-reason-epss",
            "epss",
            t.decimal(v, 1),
            "min",
            t.decimal(min, 1),
        ),
    }
}

fn affected_text(t: Lang, a: &Affected) -> String {
    let base = if let Some(k) = &a.keyword {
        t.get1("alert-affected-keyword", "keyword", k)
    } else if a.host.is_empty() {
        a.asset.clone()
    } else {
        t.get2("alert-affected-host", "asset", &a.asset, "host", &a.host)
    };
    if a.fixed.is_empty() {
        base
    } else {
        format!("{base} ({})", t.get1("alert-fixed", "version", &a.fixed))
    }
}

/// The head line of an item: priority with band, id, KEV.
fn head(t: Lang, i: &Item) -> String {
    let band = t.get(Band::of_prio(i.prio).label_id());
    let kev = if i.kev { " · KEV" } else { "" };
    format!(
        "[{} {}, {band}] {}{kev}",
        t.get("alert-prio"),
        i.prio,
        i.label
    )
}

/// One item with its affected assets (and the reasons, for the instant mail).
fn item_lines(t: Lang, i: &Item, links: &Links, with_reasons: bool, out: &mut Vec<String>) {
    out.push(head(t, i));
    if !i.title.is_empty() {
        out.push(format!("  {}", i.title));
    }
    for a in i.affected.iter().take(MAX_AFFECTED) {
        out.push(format!("  - {}", affected_text(t, a)));
    }
    if i.affected.len() > MAX_AFFECTED {
        out.push(format!(
            "  - {}",
            t.get1(
                "alert-more-affected",
                "count",
                i.affected.len() - MAX_AFFECTED
            )
        ));
    }
    if with_reasons && !i.reasons.is_empty() {
        let reasons: Vec<String> = i.reasons.iter().map(|r| reason_text(t, r)).collect();
        out.push(format!(
            "  {}",
            t.get1("alert-because", "reasons", reasons.join("; "))
        ));
    }
    if let Some(link) = links.item(&i.vuln) {
        out.push(format!("  {link}"));
    }
}

fn items_lines(t: Lang, items: &[Item], links: &Links, with_reasons: bool, out: &mut Vec<String>) {
    for i in items.iter().take(MAX_ITEMS) {
        item_lines(t, i, links, with_reasons, out);
        out.push(String::new());
    }
    if items.len() > MAX_ITEMS {
        out.push(t.get1("alert-more-items", "count", items.len() - MAX_ITEMS));
        out.push(String::new());
    }
}

fn footer(t: Lang, links: &Links, settings_path: &str, out: &mut Vec<String>) {
    if let Some(inbox) = links.inbox() {
        out.push(t.get1("alert-inbox-link", "url", inbox));
    }
    out.push("-- ".to_owned());
    out.push(match links.page(settings_path) {
        Some(url) => t.get1("alert-footer-link", "url", url),
        None => t.get("alert-footer"),
    });
}

/// A finished mail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mail {
    pub subject: String,
    pub body: String,
}

/// The instant mail for new matches (`items` is not empty).
pub fn instant(t: Lang, items: &[Item], links: &Links) -> Mail {
    let ids: Vec<&str> = items.iter().take(3).map(|i| i.label.as_str()).collect();
    let mut list = ids.join(", ");
    if items.len() > 3 {
        list.push_str(", …");
    }
    let top = items.first().map_or(0, |i| i.prio);
    let subject = if items.len() == 1 {
        let kev = if items[0].kev { " (KEV)" } else { "" };
        format!(
            "[opensecmon] {}{kev}",
            t.get1("alert-subject-one", "id", list)
        )
    } else {
        format!(
            "[opensecmon] {}",
            t.fmt(
                "alert-subject-many",
                &[
                    ("count", Arg::from(items.len())),
                    ("prio", Arg::from(top)),
                    ("ids", Arg::from(list)),
                ]
            )
        )
    };
    let mut out = vec![t.get1("alert-intro", "count", items.len()), String::new()];
    items_lines(t, items, links, true, &mut out);
    footer(t, links, "/settings/alerts", &mut out);
    Mail {
        subject,
        body: out.join("\n"),
    }
}

/// A data source that failed in its last run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedSource {
    pub name: String,
    pub error: String,
    pub last_success_ms: Option<i64>,
}

/// Everything the daily report may carry; a part that is switched off is `None`.
pub struct Report {
    pub now_ms: i64,
    /// Start of "new since" (the previous report, or a day ago).
    pub since_ms: i64,
    pub new: Option<Vec<Item>>,
    pub open: Option<Vec<Item>>,
    pub due: Option<Vec<Item>>,
    pub sources: Option<Vec<FailedSource>>,
    /// Open vulnerabilities in the inbox.
    pub open_total: usize,
}

impl Report {
    /// Whether there is nothing to tell (every part empty or off).
    pub fn is_empty(&self) -> bool {
        self.new.as_ref().is_none_or(Vec::is_empty)
            && self.open.as_ref().is_none_or(Vec::is_empty)
            && self.due.as_ref().is_none_or(Vec::is_empty)
            && self.sources.as_ref().is_none_or(Vec::is_empty)
    }
}

/// The daily report.
pub fn report(t: Lang, tz: &TimeZone, r: &Report, links: &Links) -> Mail {
    let date = local_date(t, tz, r.now_ms);
    let new = r.new.as_ref().map_or(0, Vec::len);
    let open = r.open.as_ref().map_or(0, Vec::len);
    let subject = format!(
        "[opensecmon] {}",
        t.fmt(
            "report-subject",
            &[
                ("date", Arg::from(date.clone())),
                ("new", Arg::from(new)),
                ("open", Arg::from(open)),
            ]
        )
    );
    let mut out = vec![
        t.get1("report-intro", "date", date),
        t.get1("report-open-total", "count", r.open_total),
        String::new(),
    ];
    if r.is_empty() {
        out.push(t.get("report-nothing"));
        out.push(String::new());
    }
    if let Some(items) = r.new.as_ref().filter(|i| !i.is_empty()) {
        let since = local_time(t, tz, r.since_ms);
        out.push(t.get2("report-new", "since", since, "count", items.len()));
        out.push(String::new());
        items_lines(t, items, links, false, &mut out);
    }
    if let Some(items) = r.open.as_ref().filter(|i| !i.is_empty()) {
        // What the part "new" already lists is not repeated.
        let above: Vec<&str> = r
            .new
            .iter()
            .flatten()
            .take(MAX_ITEMS)
            .map(|i| i.vuln.as_str())
            .collect();
        let rest: Vec<Item> = items
            .iter()
            .filter(|i| !above.contains(&i.vuln.as_str()))
            .cloned()
            .collect();
        out.push(t.get1("report-open", "count", items.len()));
        if rest.len() < items.len() {
            out.push(t.get1("report-open-above", "count", items.len() - rest.len()));
        }
        out.push(String::new());
        items_lines(t, &rest, links, false, &mut out);
    }
    if let Some(items) = r.due.as_ref().filter(|i| !i.is_empty()) {
        out.push(t.get1("report-due", "count", items.len()));
        out.push(String::new());
        items_lines(t, items, links, false, &mut out);
    }
    if let Some(sources) = r.sources.as_ref().filter(|s| !s.is_empty()) {
        out.push(t.get1("report-sources", "count", sources.len()));
        out.push(String::new());
        for s in sources {
            let since = s.last_success_ms.map_or_else(
                || t.get("report-source-never"),
                |ms| t.get1("report-source-since", "time", local_time(t, tz, ms)),
            );
            out.push(format!(
                "- {}: {} ({since})",
                s.name,
                clean(&s.error, MAX_ERROR)
            ));
        }
        out.push(String::new());
    }
    footer(t, links, "/settings/report", &mut out);
    Mail {
        subject,
        body: out.join("\n"),
    }
}

/// Rows for the tests of this module and of the notifier.
#[cfg(test)]
pub mod tests_support {
    use crate::storage::matches::Row;

    pub fn row(id: i64, vuln: &str, prio: i64, kev: bool, host: &str) -> Row {
        Row {
            id,
            vuln: vuln.to_owned(),
            asset_id: Some(id),
            watch_id: None,
            confidence: "high".to_owned(),
            method: "distro".to_owned(),
            fixed: "1.2-3".to_owned(),
            evidence: String::new(),
            state: "new".to_owned(),
            until_ms: None,
            reason: String::new(),
            note: String::new(),
            auto: false,
            first_seen_ms: 0,
            state_ms: 0,
            title: format!("Title of {vuln}"),
            kev,
            base: prio,
            published_ms: None,
            cvss_score: Some(9.8),
            epss: Some(0.5),
            alert: String::new(),
            alert_ms: None,
            penalty: 0,
            kev_floor: 90,
            kind: Some("package".to_owned()),
            vendor_name: Some(String::new()),
            product_name: Some("openssh".to_owned()),
            version: Some("1.2-1".to_owned()),
            host: Some(host.to_owned()),
            distro: None,
            release: None,
            pro: None,
            keyword: None,
            min_prio: 0,
            rating: String::new(),
            rating_penalty: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::row;
    use super::*;

    #[test]
    fn feed_text_is_cleaned_and_clipped() {
        assert_eq!(clean("a\nb\t c\u{202e}d\u{7}", 50), "a b cd");
        assert_eq!(clean("abcdef", 4), "abc…");
        assert_eq!(clean("   ", 4), "");
    }

    #[test]
    fn matches_are_grouped_by_vulnerability_highest_first() {
        let rows = [
            row(1, "CVE-2026-0001", 50, false, "a"),
            row(2, "CVE-2026-0002", 95, true, "a"),
            row(3, "CVE-2026-0001", 70, false, "b"),
        ];
        let items = group(&rows, |r| if r.kev { vec![Reason::Kev] } else { vec![] });
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].vuln, "CVE-2026-0002");
        assert_eq!(items[0].reasons, [Reason::Kev]);
        assert_eq!((items[1].prio, items[1].ids.clone()), (70, vec![1, 3]));
        assert_eq!(items[1].affected.len(), 2);
    }

    #[test]
    fn labels_use_the_known_ids() {
        let mut r = row(1, "osv:USN-7000-1", 50, false, "a");
        assert_eq!(label(&r), "USN-7000-1");
        r.vuln = "adv:12".to_owned();
        r.evidence = "WID-SEC-2026-0001,x".to_owned();
        assert_eq!(label(&r), "WID-SEC-2026-0001");
        r.evidence.clear();
        assert_eq!(label(&r), "adv:12");
    }

    #[test]
    fn the_instant_mail_names_ids_reasons_and_links() {
        let rows = [
            row(1, "CVE-2026-0001", 92, true, "server01"),
            row(2, "CVE-2026-0002", 86, false, "pi01"),
        ];
        let items = group(&rows, |r| {
            if r.kev {
                vec![Reason::Kev, Reason::Prio(92, 85)]
            } else {
                vec![Reason::Prio(86, 85)]
            }
        });
        let mail = instant(Lang::De, &items, &Links(Some("https://sec.example.org")));
        assert!(
            mail.subject.starts_with("[opensecmon] 2 neue Treffer"),
            "{}",
            mail.subject
        );
        assert!(mail.subject.contains("CVE-2026-0001, CVE-2026-0002"));
        assert!(
            mail.body
                .contains("[Priorität 92, Kritisch] CVE-2026-0001 · KEV"),
            "{}",
            mail.body
        );
        assert!(
            mail.body
                .contains("openssh 1.2-1 auf server01 (behoben in 1.2-3)")
        );
        assert!(mail.body.contains("steht in CISA KEV"));
        assert!(
            mail.body
                .contains("https://sec.example.org/?sel=CVE-2026-0001")
        );
        assert!(
            mail.body
                .contains("https://sec.example.org/settings/alerts")
        );

        let one = instant(Lang::En, &items[..1], &Links(None));
        assert_eq!(one.subject, "[opensecmon] New match: CVE-2026-0001 (KEV)");
        assert!(!one.body.contains("http"), "{}", one.body);
    }

    #[test]
    fn long_lists_are_cut_with_a_count() {
        let rows: Vec<Row> = (0..30)
            .map(|i| row(i, &format!("CVE-2026-{i:04}"), 90, false, "h"))
            .collect();
        let items = group(&rows, |_| vec![]);
        let mail = instant(Lang::En, &items, &Links(None));
        assert!(
            mail.body.contains("… and 5 more in the inbox"),
            "{}",
            mail.body
        );
        let hosts: Vec<Row> = (0..8)
            .map(|i| row(i, "CVE-2026-0001", 90, false, &format!("h{i}")))
            .collect();
        let items = group(&hosts, |_| vec![]);
        let mail = instant(Lang::En, &items, &Links(None));
        assert!(mail.body.contains("and 3 more"), "{}", mail.body);
    }

    #[test]
    fn the_report_shows_the_parts_that_are_on() {
        let tz = TimeZone::get("Europe/Berlin").unwrap();
        // 2026-11-06 06:00 UTC = 07:00 in Berlin.
        let now = 1_793_944_800_000;
        let items = group(&[row(1, "CVE-2026-0001", 90, true, "a")], |_| vec![]);
        let report_data = Report {
            now_ms: now,
            since_ms: now - 86_400_000,
            new: Some(items.clone()),
            open: Some(items),
            due: None,
            sources: Some(vec![FailedSource {
                name: "Debian Security Tracker".to_owned(),
                error: "HTTP 503\nService Unavailable".to_owned(),
                last_success_ms: Some(now - 3_600_000),
            }]),
            open_total: 4,
        };
        assert!(!report_data.is_empty());
        let mail = report(Lang::De, &tz, &report_data, &Links(None));
        assert_eq!(
            mail.subject,
            "[opensecmon] Tagesbericht 06.11.2026: 1 neuer Treffer, 1 kritisch offen"
        );
        assert!(mail.body.contains("seit 05.11.2026 07:00"), "{}", mail.body);
        assert_eq!(
            mail.body.matches("] CVE-2026-0001").count(),
            1,
            "listed once: {}",
            mail.body
        );
        assert!(
            mail.body
                .contains("(1 davon steht oben bei den neuen Treffern)")
        );
        assert!(mail.body.contains("Debian Security Tracker: HTTP 503 Service Unavailable (letzter Erfolg 06.11.2026 06:00)"), "{}", mail.body);
        let quiet = Report {
            new: Some(vec![]),
            open: None,
            due: Some(vec![]),
            sources: Some(vec![]),
            ..report_data
        };
        assert!(quiet.is_empty());
        let mail = report(Lang::En, &tz, &quiet, &Links(None));
        assert!(mail.body.contains("Nothing to report"), "{}", mail.body);
    }
}
