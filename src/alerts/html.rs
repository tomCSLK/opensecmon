//! The HTML part of the instant mail and the daily report (templates `templates/mail/instant.html` and
//! `report.html`, building blocks in [`crate::mail::view`]). The text part comes from [`super::compose`]; both
//! go out together. Titles, summaries, product and host names are data from feeds and hosts: they are
//! cleaned in `compose` and escaped by the templates. Links only point into the own interface and only with
//! its address set.

use askama::Template;
use jiff::tz::TimeZone;

use super::compose::{
    self, Affected, Clock, HostCount, Item, Links, MAX_ITEMS, Report, iso_date, local_date,
    local_time, percentile_text, reason_text, vector_text,
};
use crate::i18n::Lang;
use crate::mail::Mail;
use crate::mail::view::{self, Button, Chip, Fact, Frame, Tone, filters, meter_width};
use crate::storage::cve_list::Band;
use crate::storage::matches::Confidence;

/// Affected assets a card names; the rest is counted.
const CARD_AFFECTED: usize = 3;
/// Height of the trend in pixels.
const TREND_HEIGHT: u32 = 72;

/// Chips and time, title and a line below (pieces, `true` = bold).
pub struct Head {
    pub chips: Vec<Chip>,
    pub when: String,
    pub title: String,
    pub sub: Vec<(String, bool)>,
}

/// One affected asset in a card.
pub struct CardLine {
    pub what: String,
    pub on: String,
    pub host: String,
    pub fixed_in: String,
    pub fixed: String,
}

/// One vulnerability in a list.
pub struct Card {
    pub chip: Chip,
    pub kev: Option<Chip>,
    pub label: String,
    /// Empty: no link.
    pub href: String,
    pub title: String,
    pub affected: Vec<CardLine>,
    pub more: String,
    pub reasons: Vec<String>,
}

/// The priority scale: where the mark sits (percent) and the four bands with their width.
pub struct Scale {
    pub mark: i64,
    pub cells: Vec<(Tone, u8, bool)>,
}

/// A row of the table "Affected" of a single vulnerability.
pub struct AffectedRow {
    pub name: String,
    pub note: String,
    pub host: String,
    pub have: String,
    pub fixed: String,
    pub confidence: String,
}

/// What the instant mail shows of a single vulnerability.
pub struct Single {
    /// Heading and text of the summary of the BSI.
    pub bsi: Option<(String, String)>,
    pub scale: Scale,
    pub facts: Vec<Fact>,
    pub affected_heading: String,
    pub rows: Vec<AffectedRow>,
    pub more: String,
    pub reasons: Vec<String>,
}

pub struct Tile {
    pub count: String,
    pub label: String,
    pub tone: Tone,
}

#[derive(Template)]
#[template(path = "mail/instant.html")]
struct InstantMail {
    t: Lang,
    frame: Frame,
    head: Head,
    single: Option<Single>,
    tiles: Vec<Tile>,
    cards: Vec<Card>,
    more: String,
    buttons: Vec<Button>,
}

/// The open vulnerabilities per day, stacked by band.
pub struct Trend {
    pub cols: Vec<Vec<(Tone, u32)>>,
    pub start: String,
    pub end: String,
    pub legend: Vec<(Tone, String)>,
    pub height: u32,
}

pub struct HostBar {
    pub host: String,
    pub width: u8,
    pub open: String,
    pub critical: String,
}

/// A part of the report: heading, a note below it, the vulnerabilities and what is left out.
pub struct Section {
    pub heading: String,
    pub note: String,
    pub cards: Vec<Card>,
    pub more: String,
}

pub struct SourceRow {
    pub name: String,
    pub error: String,
    pub since: String,
}

#[derive(Template)]
#[template(path = "mail/report.html")]
struct ReportMail {
    t: Lang,
    frame: Frame,
    head: Head,
    tiles: Vec<Tile>,
    trend: Option<Trend>,
    hosts: Vec<HostBar>,
    sections: Vec<Section>,
    sources: Vec<SourceRow>,
    buttons: Vec<Button>,
}

fn band_name(t: Lang, prio: i64) -> String {
    t.get(Band::of_prio(prio).label_id())
}

/// The chip of a vulnerability ("Kritisch 96").
fn prio_chip(t: Lang, prio: i64) -> Chip {
    Chip {
        tone: Tone::of_prio(prio),
        text: format!("{} {prio}", band_name(t, prio)),
    }
}

fn kev_chip(t: Lang, long: bool) -> Chip {
    Chip {
        tone: Tone::Crit,
        text: if long {
            t.get("alert-kev-exploited")
        } else {
            "KEV".to_owned()
        },
    }
}

fn what(t: Lang, a: &Affected) -> String {
    match &a.keyword {
        Some(k) => t.get1("alert-affected-keyword", "keyword", k),
        None => a.asset.clone(),
    }
}

fn card(t: Lang, item: &Item, links: &Links, with_reasons: bool) -> Card {
    Card {
        chip: prio_chip(t, item.prio),
        kev: item.kev.then(|| kev_chip(t, false)),
        label: item.label.clone(),
        href: links.item(&item.vuln).unwrap_or_default(),
        title: item.title.clone(),
        affected: item
            .affected
            .iter()
            .take(CARD_AFFECTED)
            .map(|a| CardLine {
                what: what(t, a),
                on: t.get("alert-on"),
                host: a.host.clone(),
                fixed_in: t.get("alert-fixed-in"),
                fixed: a.fixed.clone(),
            })
            .collect(),
        more: if item.affected.len() > CARD_AFFECTED {
            t.get1(
                "alert-more-affected",
                "count",
                item.affected.len() - CARD_AFFECTED,
            )
        } else {
            String::new()
        },
        reasons: if with_reasons {
            item.reasons.iter().map(|r| reason_text(t, r)).collect()
        } else {
            Vec::new()
        },
    }
}

fn cards(t: Lang, items: &[Item], links: &Links, with_reasons: bool) -> (Vec<Card>, String) {
    let list = items
        .iter()
        .take(MAX_ITEMS)
        .map(|i| card(t, i, links, with_reasons))
        .collect();
    let more = if items.len() > MAX_ITEMS {
        t.get1("alert-more-items", "count", items.len() - MAX_ITEMS)
    } else {
        String::new()
    };
    (list, more)
}

fn scale(prio: i64) -> Scale {
    let active = Tone::of_prio(prio);
    Scale {
        mark: prio.clamp(0, 98),
        cells: [
            (Tone::Low, 45),
            (Tone::Med, 20),
            (Tone::High, 20),
            (Tone::Crit, 15),
        ]
        .into_iter()
        .map(|(tone, width)| (tone, width, tone == active))
        .collect(),
    }
}

fn epss_tone(epss: f64) -> Tone {
    match epss {
        e if e >= 0.5 => Tone::Crit,
        e if e >= 0.1 => Tone::High,
        e if e >= 0.01 => Tone::Med,
        _ => Tone::Low,
    }
}

fn single(t: Lang, clock: &Clock, item: &Item) -> Single {
    let mut facts = Vec::new();
    let detail = item.detail.clone().unwrap_or_default();
    if let Some((score, version, vector)) = &detail.cvss {
        let tone = Tone::of_cvss(*score);
        facts.push(Fact {
            word: compose::cvss_word(t, *score),
            meter: Some((meter_width(score / 10.0), tone)),
            ..Fact::new(
                t.get1("alert-cvss", "version", compose::clean(version, 10)),
                t.decimal(*score, 1),
                vector_text(t, vector),
            )
        });
    }
    if let Some((epss, percentile)) = detail.epss {
        facts.push(Fact {
            meter: Some((meter_width(epss), epss_tone(epss))),
            ..Fact::new(
                t.get("alert-epss-label"),
                format!("{} %", t.decimal(epss * 100.0, 1)),
                percentile_text(t, percentile),
            )
        });
    }
    if let Some((added, due)) = &detail.kev {
        facts.push(Fact {
            tone: Some(Tone::Crit),
            ..Fact::new(
                "CISA KEV",
                t.get1("alert-kev-since", "date", iso_date(t, added)),
                if due.is_empty() {
                    String::new()
                } else {
                    t.get1("alert-kev-due", "date", iso_date(t, due))
                },
            )
        });
    }
    if let Some(ms) = detail.published_ms {
        facts.push(Fact::new(
            t.get("alert-published"),
            local_date(t, clock.tz, ms),
            compose::days_ago(t, clock.now_ms, ms),
        ));
    }
    let shown = 10;
    Single {
        bsi: detail.bsi.map(|(id, text)| {
            (
                t.get1("alert-bsi", "id", compose::clean(&id, 80)),
                compose::clean(&text, 900),
            )
        }),
        scale: scale(item.prio),
        facts,
        affected_heading: t.get1("alert-affected", "count", item.affected.len()),
        rows: item
            .affected
            .iter()
            .take(shown)
            .map(|a| AffectedRow {
                name: match &a.keyword {
                    Some(_) => what(t, a),
                    None if a.name.is_empty() => a.asset.clone(),
                    None => a.name.clone(),
                },
                note: a.release.clone(),
                host: a.host.clone(),
                have: a.version.clone(),
                fixed: a.fixed.clone(),
                confidence: t.get(Confidence::parse(&a.confidence).label_id()),
            })
            .collect(),
        more: if item.affected.len() > shown {
            t.get1("alert-more-affected", "count", item.affected.len() - shown)
        } else {
            String::new()
        },
        reasons: item.reasons.iter().map(|r| reason_text(t, r)).collect(),
    }
}

fn hosts_of(items: &[Item]) -> usize {
    let mut hosts: Vec<&str> = items
        .iter()
        .flat_map(|i| i.affected.iter().map(|a| a.host.as_str()))
        .filter(|h| !h.is_empty())
        .collect();
    hosts.sort_unstable();
    hosts.dedup();
    hosts.len()
}

/// How many vulnerabilities each band has (bands without any left out).
fn band_counts(items: &[Item]) -> Vec<(Band, usize)> {
    [Band::Crit, Band::High, Band::Med, Band::Low]
        .into_iter()
        .map(|b| {
            (
                b,
                items.iter().filter(|i| Band::of_prio(i.prio) == b).count(),
            )
        })
        .filter(|(_, n)| *n > 0)
        .collect()
}

fn footer(t: Lang, clock: &Clock) -> Vec<String> {
    vec![view::program(), clock.text(t)]
}

fn finish(subject: String, text: String, html: askama::Result<String>) -> Mail {
    match html {
        Ok(html) => Mail {
            subject,
            text,
            html: Some(html),
            inline: vec![view::logo()],
        },
        Err(e) => {
            tracing::warn!(error = %e, "HTML part of the mail failed, sending text only");
            Mail::plain(subject, text)
        }
    }
}

/// The instant mail: one vulnerability in detail, several as cards.
pub fn instant(t: Lang, clock: &Clock, items: &[Item], links: &Links) -> Mail {
    let text = compose::instant(t, clock, items, links);
    let top = items.first().map_or(0, |i| i.prio);
    let when = local_time(t, clock.tz, clock.now_ms);
    let mut frame = Frame::new(t, text.subject.clone(), Tone::of_prio(top), links.base());
    frame.footer = footer(t, clock);
    frame.settings = links
        .page("/settings/alerts")
        .map(|href| (href, t.get("alert-settings-link")));
    let template = if let [item] = items {
        let mut chips = vec![Chip {
            tone: Tone::of_prio(item.prio),
            text: t.get2(
                "alert-chip-prio",
                "band",
                band_name(t, item.prio),
                "prio",
                item.prio,
            ),
        }];
        if item.kev {
            chips.push(kev_chip(t, true));
        }
        let mut pre = vec![format!("{} {}", band_name(t, item.prio), item.prio)];
        if item.kev {
            pre.push("KEV".to_owned());
        }
        if let Some(a) = item.affected.first() {
            pre.push(if a.host.is_empty() {
                what(t, a)
            } else {
                t.get2("alert-affected-host", "asset", what(t, a), "host", &a.host)
            });
        }
        frame.preheader = pre.join(" · ");
        let mut buttons = Vec::new();
        if let Some(href) = links.item(&item.vuln) {
            buttons.push(Button {
                label: t.get("alert-open-inbox"),
                href,
                primary: true,
            });
        }
        if let Some(href) = links.cve(&item.vuln) {
            buttons.push(Button {
                label: t.get("alert-open-cve"),
                href,
                primary: false,
            });
        }
        InstantMail {
            t,
            frame,
            head: Head {
                chips,
                when,
                title: item.label.clone(),
                sub: if item.title.is_empty() {
                    Vec::new()
                } else {
                    vec![(item.title.clone(), false)]
                },
            },
            single: Some(single(t, clock, item)),
            tiles: Vec::new(),
            cards: Vec::new(),
            more: String::new(),
            buttons,
        }
    } else {
        let kev = items.iter().filter(|i| i.kev).count();
        let hosts = hosts_of(items);
        let counts = band_counts(items);
        let mut sub = vec![t.get1("alert-many-top", "prio", top)];
        if kev > 0 {
            sub.push(t.get1("alert-many-kev", "count", kev));
        }
        if hosts > 0 {
            sub.push(t.get1("alert-many-hosts", "count", hosts));
        }
        let mut tiles: Vec<Tile> = counts
            .iter()
            .map(|(b, n)| Tile {
                count: n.to_string(),
                label: t.get(b.label_id()),
                tone: Tone::of_band(*b),
            })
            .collect();
        if kev > 0 {
            tiles.push(Tile {
                count: kev.to_string(),
                label: t.get("alert-tile-kev"),
                tone: Tone::Crit,
            });
        }
        if hosts > 0 {
            tiles.push(Tile {
                count: hosts.to_string(),
                label: t.get("alert-tile-hosts"),
                tone: Tone::Low,
            });
        }
        tiles.truncate(4);
        let mut pre: Vec<String> = counts
            .iter()
            .map(|(b, n)| format!("{n} {}", t.get(b.label_id())))
            .collect();
        if kev > 0 {
            pre.push(t.get1("alert-many-kev", "count", kev));
        }
        frame.preheader = format!(
            "{} · {}",
            pre.join(", "),
            items
                .iter()
                .take(4)
                .map(|i| i.label.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        let (cards, more) = cards(t, items, links, true);
        InstantMail {
            t,
            frame,
            head: Head {
                chips: vec![Chip {
                    tone: Tone::of_prio(top),
                    text: t.get1("alert-many-chip", "count", items.len()),
                }],
                when,
                title: t.get1("alert-many-title", "count", items.len()),
                sub: vec![(sub.join(" · "), false)],
            },
            single: None,
            tiles,
            cards,
            more,
            buttons: links
                .inbox()
                .map(|href| Button {
                    label: t.get("alert-open-all"),
                    href,
                    primary: true,
                })
                .into_iter()
                .collect(),
        }
    };
    finish(text.subject, text.body, template.render())
}

fn trend(t: Lang, r: &Report) -> Option<Trend> {
    let (first, _) = r.trend.split_first()?;
    if r.trend.len() < 2 {
        return None;
    }
    let max = r
        .trend
        .iter()
        .map(|d| d.counts.total())
        .max()
        .unwrap_or(0)
        .max(1);
    let height = |n: i64| -> u32 {
        let h = (n * i64::from(TREND_HEIGHT) + max / 2) / max;
        u32::try_from(h.max(2)).unwrap_or(2)
    };
    let bands = [Band::Crit, Band::High, Band::Med, Band::Low];
    let cols = r
        .trend
        .iter()
        .map(|d| {
            bands
                .iter()
                .map(|b| (Tone::of_band(*b), d.counts.of_band(*b)))
                .filter(|(_, n)| *n > 0)
                .map(|(tone, n)| (tone, height(n)))
                .collect()
        })
        .collect();
    Some(Trend {
        cols,
        start: first
            .day
            .strftime(match t {
                Lang::De => "%d.%m.",
                Lang::En => "%m-%d",
            })
            .to_string(),
        end: t.get("report-today"),
        legend: bands
            .iter()
            .map(|b| (Tone::of_band(*b), t.get(b.label_id())))
            .collect(),
        height: TREND_HEIGHT,
    })
}

fn host_bars(t: Lang, hosts: &[HostCount]) -> Vec<HostBar> {
    let max = hosts.iter().map(|h| h.open).max().unwrap_or(1).max(1);
    hosts
        .iter()
        .map(|h| HostBar {
            host: h.host.clone(),
            width: meter_width(h.open as f64 / max as f64),
            open: t.get1("report-host-open", "count", h.open),
            critical: if h.critical > 0 {
                t.get1("report-host-crit", "count", h.critical)
            } else {
                String::new()
            },
        })
        .collect()
}

/// The daily report.
pub fn report(t: Lang, tz: &TimeZone, r: &Report, links: &Links) -> Mail {
    let text = compose::report(t, tz, r, links);
    let clock = Clock {
        tz,
        now_ms: r.now_ms,
    };
    let date = local_date(t, tz, r.now_ms);
    let quiet = r.is_empty();
    let mut frame = Frame::new(
        t,
        text.subject.clone(),
        if quiet { Tone::Ok } else { Tone::Accent },
        links.base(),
    );
    frame.footer = footer(t, &clock);
    frame.settings = links
        .page("/settings/report")
        .map(|href| (href, t.get("report-settings-link")));
    let new = r.new.as_ref().map_or(0, Vec::len);
    let open = r.open.as_ref().map_or(0, Vec::len);
    let due = r.due.as_ref().map_or(0, Vec::len);
    let failed = r.sources.as_ref().map_or(0, Vec::len);
    let open_line = compose::open_line(t, r);
    let head = if quiet {
        Head {
            chips: vec![Chip {
                tone: Tone::Ok,
                text: format!("✓ {}", t.get("report-nothing-chip")),
            }],
            when: local_time(t, tz, r.now_ms),
            title: t.get("report-nothing-title"),
            sub: vec![
                (t.get("report-nothing"), false),
                (" ".to_owned(), false),
                (open_line.clone(), false),
            ],
        }
    } else {
        Head {
            chips: vec![Chip {
                tone: Tone::Accent,
                text: t.get("report-title"),
            }],
            when: local_time(t, tz, r.now_ms),
            title: t.get1("report-heading", "date", date.clone()),
            sub: vec![(open_line.clone(), false)],
        }
    };
    let since = local_time(t, tz, r.since_ms);
    let mut tiles = Vec::new();
    if !quiet {
        let tone = |n: usize, tone: Tone| if n > 0 { tone } else { Tone::Ok };
        if r.new.is_some() {
            tiles.push(Tile {
                count: new.to_string(),
                label: t.get1("report-tile-new", "since", since.clone()),
                tone: tone(new, Tone::Crit),
            });
        }
        if r.open.is_some() {
            tiles.push(Tile {
                count: open.to_string(),
                label: t.get("report-tile-open"),
                tone: tone(open, Tone::Crit),
            });
        }
        if r.due.is_some() {
            tiles.push(Tile {
                count: due.to_string(),
                label: t.get("report-tile-due"),
                tone: tone(due, Tone::Med),
            });
        }
        if r.sources.is_some() {
            tiles.push(Tile {
                count: failed.to_string(),
                label: t.get("report-tile-sources"),
                tone: tone(failed, Tone::Err),
            });
        }
    }
    let mut sections = Vec::new();
    if let Some(items) = r.new.as_ref().filter(|i| !i.is_empty()) {
        let (list, more) = cards(t, items, links, false);
        sections.push(Section {
            heading: t.get2("report-new", "since", since.clone(), "count", items.len()),
            note: String::new(),
            cards: list,
            more,
        });
    }
    if let Some(items) = r.open.as_ref().filter(|i| !i.is_empty()) {
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
        let (list, more) = cards(t, &rest, links, false);
        sections.push(Section {
            heading: t.get1("report-open", "count", items.len()),
            note: if rest.len() < items.len() {
                t.get1("report-open-above", "count", items.len() - rest.len())
            } else {
                String::new()
            },
            cards: list,
            more,
        });
    }
    if let Some(items) = r.due.as_ref().filter(|i| !i.is_empty()) {
        let (list, more) = cards(t, items, links, false);
        sections.push(Section {
            heading: t.get1("report-due", "count", items.len()),
            note: String::new(),
            cards: list,
            more,
        });
    }
    let sources = r
        .sources
        .iter()
        .flatten()
        .map(|s| SourceRow {
            name: compose::clean(&s.name, 80),
            error: compose::clean(&s.error, 200),
            since: s.last_success_ms.map_or_else(
                || t.get("report-source-never"),
                |ms| t.get1("report-source-since", "time", local_time(t, tz, ms)),
            ),
        })
        .collect();
    let mut pre = Vec::new();
    pre.push(t.get1("report-pre-open", "count", r.open_total));
    if !quiet {
        if r.new.is_some() {
            pre.push(t.get1("report-pre-new", "count", new));
        }
        if r.open.is_some() {
            pre.push(t.get1("report-pre-critical", "count", open));
        }
        if failed > 0 {
            pre.push(t.get1("report-pre-sources", "count", failed));
        }
    } else {
        pre.insert(0, t.get("report-nothing-chip"));
    }
    frame.preheader = pre.join(" · ");
    let mut buttons = Vec::new();
    for (path, id, primary) in [
        ("/", "report-open-inbox", true),
        ("/situation", "report-open-situation", false),
        ("/sources", "report-open-sources", false),
    ] {
        if quiet && !primary {
            continue;
        }
        if let Some(href) = links.page(path) {
            buttons.push(Button {
                label: t.get(id),
                href,
                primary: primary && !quiet,
            });
        }
    }
    let template = ReportMail {
        t,
        frame,
        head,
        tiles,
        trend: trend(t, r),
        hosts: host_bars(t, &r.hosts),
        sections,
        sources,
        buttons,
    };
    finish(text.subject, text.body, template.render())
}

#[cfg(test)]
mod tests;
