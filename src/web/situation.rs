//! The page "Situation" (docs/entwurf/lage.html): a few tiles, the open vulnerabilities of the last 30 days,
//! the most affected hosts, the oldest open matches and the sources. The chart and the bars are SVG drawn here
//! (no script, no style attributes).

use std::collections::{BTreeMap, HashMap, HashSet};

use askama::Template;
use axum::extract::State;
use axum::response::Html;

use crate::error::Result;
use crate::i18n::Lang;
use crate::situation::{self, ALL_STATES, Counts, Day};
use crate::sources::{SourceId, now_ms};
use crate::storage::cve_list::Band;
use crate::storage::matches::{self, Row};
use crate::storage::sources as source_store;
use crate::web::asset_pages::vuln_label;
use crate::web::auth::CurrentUser;
use crate::web::cves::encode;
use crate::web::sources::Health;
use crate::web::{AppState, Layout, time_html};

const DAY_MS: i64 = 86_400_000;
/// Days of the chart.
const TREND_DAYS: i32 = 30;
/// Rows of "most affected" and "open longest".
const TOP_HOSTS: usize = 8;
const TOP_OLDEST: usize = 6;
/// The bands from the top of a stacked bar down.
const BANDS: [Band; 4] = [Band::Crit, Band::High, Band::Med, Band::Low];

pub struct Tile {
    pub href: &'static str,
    pub class: &'static str,
    pub icon: &'static str,
    pub label: String,
    pub value: String,
    pub sub: String,
}

pub struct Segment {
    pub class: &'static str,
    pub x: String,
    pub y: String,
    pub w: String,
    pub h: String,
}

pub struct Bar {
    pub title: String,
    pub derived: bool,
    pub segments: Vec<Segment>,
}

pub struct AxisLabel {
    pub x: String,
    pub y: String,
    pub text: String,
}

pub struct GridLine {
    pub y: String,
}

pub struct Chart {
    pub label: String,
    pub grid: Vec<GridLine>,
    pub labels: Vec<AxisLabel>,
    pub bars: Vec<Bar>,
    pub any_derived: bool,
}

pub struct HostRow {
    pub label: String,
    pub href: Option<String>,
    pub total: i64,
    pub title: String,
    pub segments: Vec<Segment>,
}

pub struct OldRow {
    pub href: String,
    pub label: String,
    pub prio: i64,
    pub band: &'static str,
    pub prio_title: String,
    pub kev: bool,
    pub asset: String,
    pub age: String,
}

pub struct SourceLine {
    pub label: String,
    pub class: &'static str,
    pub icon: &'static str,
    pub state: String,
    pub last: Option<String>,
}

pub struct Legend {
    pub band: &'static str,
    pub label: String,
}

#[derive(Template)]
#[template(path = "situation.html")]
struct SituationTemplate {
    t: Lang,
    layout: Layout,
    subtitle: String,
    tiles: Vec<Tile>,
    chart: Chart,
    legend: Vec<Legend>,
    hosts: Vec<HostRow>,
    oldest: Vec<OldRow>,
    sources: Vec<SourceLine>,
}

/// One open vulnerability with its open matches.
struct Open<'a> {
    vuln: &'a str,
    rows: Vec<&'a Row>,
    prio: i64,
    kev: bool,
    first_seen_ms: i64,
}

fn open_items(rows: &[Row]) -> Vec<Open<'_>> {
    let mut by_vuln: BTreeMap<&str, Open> = BTreeMap::new();
    for r in rows.iter().filter(|r| situation::open_now(r)) {
        let o = by_vuln.entry(r.vuln.as_str()).or_insert_with(|| Open {
            vuln: r.vuln.as_str(),
            rows: Vec::new(),
            prio: 0,
            kev: false,
            first_seen_ms: i64::MAX,
        });
        o.prio = o.prio.max(r.prio());
        o.kev |= r.kev;
        o.first_seen_ms = o.first_seen_ms.min(r.first_seen_ms);
        o.rows.push(r);
    }
    by_vuln.into_values().collect()
}

fn fmt1(v: f64) -> String {
    format!("{v:.1}")
}

/// The band texts of counts: "2 kritisch, 5 hoch, …" (bands with 0 left out; "–" if all are 0).
fn band_text(t: Lang, c: &Counts) -> String {
    let parts: Vec<String> = BANDS
        .iter()
        .filter(|b| c.of_band(**b) > 0)
        .map(|b| {
            format!(
                "{} {}",
                t.number(c.of_band(*b)),
                t.get(b.label_id()).to_lowercase()
            )
        })
        .collect();
    if parts.is_empty() {
        "–".to_owned()
    } else {
        parts.join(", ")
    }
}

/// A step for the y axis that gives at most five lines.
fn axis_step(max: i64) -> i64 {
    let mut base = 1i64;
    loop {
        for f in [1, 2, 5] {
            let step = base * f;
            if max <= step * 5 {
                return step;
            }
        }
        base = base.saturating_mul(10);
    }
}

fn short_date(t: Lang, d: jiff::civil::Date) -> String {
    match t {
        Lang::De => format!("{:02}.{:02}.", d.day(), d.month()),
        Lang::En => format!("{:02}-{:02}", d.month(), d.day()),
    }
}

fn long_date(t: Lang, d: jiff::civil::Date) -> String {
    match t {
        Lang::De => format!("{:02}.{:02}.{}", d.day(), d.month(), d.year()),
        Lang::En => d.to_string(),
    }
}

fn chart(t: Lang, days: &[Day]) -> Chart {
    const W: f64 = 720.0;
    const H: f64 = 230.0;
    const LEFT: f64 = 34.0;
    const RIGHT: f64 = 8.0;
    const TOP: f64 = 8.0;
    const BOTTOM: f64 = 24.0;
    let max = days.iter().map(|d| d.counts.total()).max().unwrap_or(0);
    let step = axis_step(max.max(1));
    let top = ((max.max(1) + step - 1) / step * step).max(step);
    let y = |v: i64| TOP + (H - TOP - BOTTOM) * (1.0 - v as f64 / top as f64);
    let n = days.len().max(1);
    let bw = (W - LEFT - RIGHT) / n as f64;

    let mut grid = Vec::new();
    let mut labels = Vec::new();
    let mut v = 0;
    while v <= top {
        grid.push(GridLine { y: fmt1(y(v)) });
        labels.push(AxisLabel {
            x: fmt1(LEFT - 6.0),
            y: fmt1(y(v) + 4.0),
            text: t.number(v),
        });
        v += step;
    }
    let mut bars = Vec::new();
    for (i, d) in days.iter().enumerate() {
        if (i % 7 == 0 && n - 1 - i >= 4) || i == n - 1 {
            labels.push(AxisLabel {
                x: fmt1(LEFT + i as f64 * bw + bw / 2.0),
                y: fmt1(H - 6.0),
                text: short_date(t, d.day),
            });
        }
        let x = LEFT + i as f64 * bw + 2.0;
        let mut acc = 0;
        let mut segments = Vec::new();
        // Bottom up: low first, critical on top.
        for b in BANDS.iter().rev() {
            let c = d.counts.of_band(*b);
            if c == 0 {
                continue;
            }
            let y0 = y(acc);
            let y1 = y(acc + c);
            segments.push(Segment {
                class: b.as_str(),
                x: fmt1(x),
                y: fmt1(y1),
                w: fmt1((bw - 4.0).max(1.0)),
                h: fmt1((y0 - y1 - 1.0).max(1.0)),
            });
            acc += c;
        }
        let mut title = t.fmt(
            "situation-bar-title",
            &[
                ("date", long_date(t, d.day).into()),
                ("count", d.counts.total().into()),
                ("bands", band_text(t, &d.counts).into()),
            ],
        );
        if d.derived {
            title.push_str(" · ");
            title.push_str(&t.get("situation-derived"));
        }
        bars.push(Bar {
            title,
            derived: d.derived,
            segments,
        });
    }
    let today = days.last().map(|d| d.counts.total()).unwrap_or(0);
    Chart {
        label: t.get1("situation-chart-label", "count", today),
        grid,
        labels,
        bars,
        any_derived: days.iter().any(|d| d.derived),
    }
}

/// The host of a match for "most affected": its host, "watchlist" or "without host".
fn host_key(r: &Row) -> (u8, String) {
    if r.watch_id.is_some() {
        (2, String::new())
    } else {
        match r.host.as_deref().filter(|h| !h.is_empty()) {
            Some(h) => (0, h.to_owned()),
            None => (1, String::new()),
        }
    }
}

fn hosts(t: Lang, items: &[Open]) -> Vec<HostRow> {
    let mut by_host: HashMap<(u8, String), Counts> = HashMap::new();
    for i in items {
        let keys: HashSet<(u8, String)> = i.rows.iter().map(|r| host_key(r)).collect();
        for k in keys {
            let c = by_host.entry(k).or_default();
            match Band::of_prio(i.prio) {
                Band::Crit => c.crit += 1,
                Band::High => c.high += 1,
                Band::Med => c.med += 1,
                Band::Low | Band::None => c.low += 1,
            }
        }
    }
    let mut list: Vec<((u8, String), Counts)> = by_host.into_iter().collect();
    list.sort_by(|a, b| b.1.total().cmp(&a.1.total()).then_with(|| a.0.cmp(&b.0)));
    list.truncate(TOP_HOSTS);
    let max = list.first().map(|(_, c)| c.total()).unwrap_or(1).max(1);
    list.into_iter()
        .map(|((kind, host), c)| {
            let (label, href) = match kind {
                0 => (host.clone(), Some(format!("/?host={}", encode(&host)))),
                2 => (
                    t.get("situation-watchlist"),
                    Some("/?kind=watch".to_owned()),
                ),
                _ => (t.get("situation-no-host"), None),
            };
            let scale = 100.0 * c.total() as f64 / max as f64;
            let mut x = 0.0;
            let mut segments = Vec::new();
            for b in BANDS {
                let n = c.of_band(b);
                if n == 0 {
                    continue;
                }
                let w = scale * n as f64 / c.total() as f64;
                segments.push(Segment {
                    class: b.as_str(),
                    x: fmt1(x),
                    y: "0".to_owned(),
                    w: fmt1(w),
                    h: "8".to_owned(),
                });
                x += w;
            }
            HostRow {
                label,
                href,
                total: c.total(),
                title: band_text(t, &c),
                segments,
            }
        })
        .collect()
}

fn asset_text(t: Lang, rows: &[&Row]) -> String {
    let first = rows[0];
    let name = if let Some(k) = &first.keyword {
        t.get1("inbox-keyword", "keyword", k.as_str())
    } else {
        first.product_name.clone().unwrap_or_default()
    };
    let hosts: Vec<&str> = rows
        .iter()
        .filter_map(|r| r.host.as_deref())
        .filter(|h| !h.is_empty())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut s = name;
    if !hosts.is_empty() {
        s.push_str(" · ");
        s.push_str(&hosts.join(", "));
    }
    if rows.len() > 1 {
        s.push_str(" · ");
        s.push_str(&t.get1("inbox-assets", "count", rows.len()));
    }
    s
}

fn oldest(t: Lang, items: &[Open], now: i64) -> Vec<OldRow> {
    let mut list: Vec<&Open> = items.iter().collect();
    list.sort_by(|a, b| {
        a.first_seen_ms
            .cmp(&b.first_seen_ms)
            .then_with(|| b.prio.cmp(&a.prio))
    });
    list.into_iter()
        .take(TOP_OLDEST)
        .map(|i| {
            let band = Band::of_prio(i.prio);
            OldRow {
                href: format!("/?sel={}", encode(i.vuln)),
                label: vuln_label(i.vuln, &i.rows[0].evidence),
                prio: i.prio,
                band: band.as_str(),
                prio_title: t.fmt(
                    "cve-prio-title",
                    &[
                        ("prio", i.prio.into()),
                        ("band", t.get(band.label_id()).into()),
                    ],
                ),
                kev: i.kev,
                asset: asset_text(t, &i.rows),
                age: t.get1(
                    "situation-days-open",
                    "count",
                    ((now - i.first_seen_ms).max(0) / DAY_MS).max(0),
                ),
            }
        })
        .collect()
}

/// KEV entries of open vulnerabilities whose deadline has passed.
async fn kev_overdue(pool: &sqlx::SqlitePool, items: &[Open<'_>], today: &str) -> Result<i64> {
    let due: Vec<(String, String)> =
        sqlx::query_as("SELECT cve_id, due_date FROM kev WHERE due_date != ''")
            .fetch_all(pool)
            .await?;
    let due: HashMap<String, String> = due.into_iter().collect();
    Ok(items
        .iter()
        .filter(|i| i.kev)
        .filter(|i| due.get(i.vuln).is_some_and(|d| d.as_str() < today))
        .count() as i64)
}

pub async fn page(State(state): State<AppState>, user: CurrentUser) -> Result<Html<String>> {
    let t = user.lang;
    let now = now_ms();
    let pool = &state.pool;
    matches::wake_later_for_page(pool, now).await;
    // Muted matches (below the priority from which their asset shows matches) are left out, as in the inbox.
    let rows: Vec<Row> = matches::rows(pool, &ALL_STATES)
        .await?
        .into_iter()
        .filter(|r| !r.muted())
        .collect();
    let items = open_items(&rows);

    let critical: Vec<&Open> = items
        .iter()
        .filter(|i| Band::of_prio(i.prio) == Band::Crit || i.kev)
        .collect();
    let critical_new = critical
        .iter()
        .filter(|i| i.rows.iter().any(|r| r.state() == matches::State::New))
        .count();
    let kev = items.iter().filter(|i| i.kev).count();
    let today = situation::local_day(&state.time_zone, now);
    let overdue = kev_overdue(pool, &items, &today.to_string()).await?;
    let fresh = items
        .iter()
        .filter(|i| i.first_seen_ms >= now - DAY_MS)
        .count();

    let source_states = source_store::all(pool).await?;
    let running = state.sources.running().map(|r| r.source);
    let mut sources = Vec::new();
    let (mut enabled, mut fine, mut failed, mut stale) = (0, 0, 0, 0);
    for id in SourceId::ALL {
        let Some(s) = source_states.iter().find(|s| s.source == id.as_str()) else {
            continue;
        };
        let health = Health::of(s, running == Some(id), now);
        if s.enabled {
            enabled += 1;
            match health {
                Health::Ok | Health::Running => fine += 1,
                Health::Failed => failed += 1,
                Health::Stale => stale += 1,
                _ => {}
            }
        }
        if !s.enabled {
            continue;
        }
        sources.push(SourceLine {
            label: t.get(id.label_id()),
            class: health.class(),
            icon: health.icon(),
            state: t.get(health.label_id()),
            last: s
                .last_finished_ms
                .map(|ms| time_html(ms).replacen("class=\"ts\"", "class=\"ts short\"", 1)),
        });
    }

    let tiles = vec![
        Tile {
            href: "/?view=critical",
            class: "crit",
            icon: "crit",
            label: t.get("situation-tile-critical"),
            value: t.number(critical.len() as i64),
            sub: t.get1("situation-tile-critical-new", "count", critical_new),
        },
        Tile {
            href: "/?kev=1",
            class: "",
            icon: "flame",
            label: t.get("situation-tile-kev"),
            value: t.number(kev as i64),
            sub: if overdue > 0 {
                t.get1("situation-tile-kev-overdue", "count", overdue)
            } else {
                t.get("situation-tile-kev-none-overdue")
            },
        },
        Tile {
            href: "/?view=new",
            class: "",
            icon: "star",
            label: t.get("situation-tile-new"),
            value: t.number(fresh as i64),
            sub: t.get("situation-tile-new-sub"),
        },
        Tile {
            href: "/sources",
            class: if failed > 0 { "warn" } else { "" },
            icon: "rss",
            label: t.get("situation-tile-sources"),
            value: t.get2("situation-tile-sources-value", "ok", fine, "count", enabled),
            sub: if failed + stale == 0 {
                t.get("situation-tile-sources-fine")
            } else {
                t.get2(
                    "situation-tile-sources-sub",
                    "failed",
                    failed,
                    "stale",
                    stale,
                )
            },
        },
    ];

    let days = situation::trend(pool, &rows, &state.time_zone, now, TREND_DAYS).await?;
    let host_count = items
        .iter()
        .flat_map(|i| i.rows.iter().filter_map(|r| r.host.as_deref()))
        .filter(|h| !h.is_empty())
        .collect::<HashSet<_>>()
        .len();
    let subtitle = t.fmt(
        "situation-subtitle-now",
        &[
            ("count", (items.len() as i64).into()),
            ("shown", t.number(items.len() as i64).into()),
            ("hosts", (host_count as i64).into()),
        ],
    );
    Ok(Html(
        SituationTemplate {
            t,
            layout: user.layout().at("situation"),
            subtitle,
            tiles,
            chart: chart(t, &days),
            legend: BANDS
                .iter()
                .map(|b| Legend {
                    band: b.as_str(),
                    label: t.get(b.label_id()),
                })
                .collect(),
            hosts: hosts(t, &items),
            oldest: oldest(t, &items, now),
            sources,
        }
        .render()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::matches::{Confidence, Found, Method, Subject};
    use crate::web::testutil::*;
    use axum::http::StatusCode;

    #[test]
    fn the_axis_has_at_most_five_steps() {
        for (max, step) in [
            (1, 1),
            (5, 1),
            (6, 2),
            (10, 2),
            (11, 5),
            (25, 5),
            (26, 10),
            (2000, 500),
        ] {
            assert_eq!(axis_step(max), step, "{max}");
        }
    }

    #[tokio::test]
    async fn the_situation_counts_the_open_vulnerabilities() {
        let h = harness(true).await;
        let pool = &h.state.pool;
        sqlx::raw_sql(
            "INSERT INTO cves (id, state, title, prio, kev_added) VALUES
               ('CVE-2026-1', 'published', 'one', 90, '2026-01-01'),
               ('CVE-2026-2', 'published', 'two', 50, NULL);
             INSERT INTO kev (cve_id, date_added, due_date) VALUES ('CVE-2026-1', '2026-01-01', '2026-01-21');
             INSERT INTO assets (kind, product, product_name, host, created_ms, updated_ms)
               VALUES ('software', 'a', 'Alpha', 'server01', 0, 0), ('software', 'b', 'Beta', '', 0, 0);",
        )
        .execute(pool)
        .await
        .unwrap();
        let f = |v: &str| Found {
            vuln: v.to_owned(),
            title: String::new(),
            confidence: Confidence::High,
            method: Method::Nvd,
            fixed: String::new(),
            evidence: Vec::new(),
            base_prio: 0,
            rating: crate::storage::matches::Rating::None,
        };
        let now = now_ms();
        matches::sync(
            pool,
            Subject::Asset(1),
            &[f("CVE-2026-1"), f("CVE-2026-2")],
            now - 3 * DAY_MS,
        )
        .await
        .unwrap();
        matches::sync(pool, Subject::Asset(2), &[f("CVE-2026-1")], now)
            .await
            .unwrap();
        let (session, _) = login(&h, "anna").await;
        let reply = send(&h.app, get("/situation", Some(&session))).await;
        assert_eq!(reply.status, StatusCode::OK);
        let body = reply.body;
        assert!(
            body.contains("2 offene Schwachstellen auf 1 Host"),
            "{body}"
        );
        assert!(body.contains("1 Frist abgelaufen"));
        assert!(body.contains("href=\"/?host=server01\""));
        assert!(body.contains("Ohne Host"));
        assert!(body.contains("href=\"/?sel=CVE-2026-2\""));
        assert!(body.contains("3 Tage"));
        assert!(body.contains("<rect class=\"crit\""));
        // Without matches the page still opens.
        sqlx::query("DELETE FROM matches")
            .execute(pool)
            .await
            .unwrap();
        let reply = send(&h.app, get("/situation", Some(&session))).await;
        assert_eq!(reply.status, StatusCode::OK);
        assert!(reply.body.contains("Keine offenen Treffer"));
    }
    #[tokio::test]
    async fn a_vulnerability_of_two_packages_counts_once_for_their_host() {
        let h = harness(true).await;
        let pool = &h.state.pool;
        sqlx::raw_sql(
            "INSERT INTO cves (id, state, title, prio) VALUES ('CVE-2026-1', 'published', 'one', 50);
             INSERT INTO assets (kind, product, product_name, host, created_ms, updated_ms)
               VALUES ('software', 'qemu', 'qemu', 'server01', 0, 0),
                      ('software', 'qemu-hwe', 'qemu-hwe', 'server01', 0, 0);",
        )
        .execute(pool)
        .await
        .unwrap();
        let found = Found {
            vuln: "CVE-2026-1".to_owned(),
            title: String::new(),
            confidence: Confidence::High,
            method: Method::Nvd,
            fixed: String::new(),
            evidence: Vec::new(),
            base_prio: 0,
            rating: crate::storage::matches::Rating::None,
        };
        for id in [1, 2] {
            matches::sync(
                pool,
                Subject::Asset(id),
                std::slice::from_ref(&found),
                now_ms(),
            )
            .await
            .unwrap();
        }
        let (session, _) = login(&h, "anna").await;
        let body = send(&h.app, get("/situation", Some(&session))).await.body;
        let bar = body
            .split("href=\"/?host=server01\"")
            .nth(1)
            .expect("the host has a bar");
        assert!(bar.contains("<span class=\"n\">1</span>"), "{bar}");
    }
}
