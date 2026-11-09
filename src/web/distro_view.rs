//! Debian and Ubuntu in the section "Operating systems" of the CVE detail: what they say about the CVE, one row per
//! release and source package, built from the OSV records and the Debian Security Tracker.

use std::collections::BTreeMap;

use crate::i18n::Lang;
use crate::sources::debian_tracker::{codename_of, version_of};
use crate::storage::distros::{AffectedForCve, TrackerRow};

/// Texts that only templates use, for the catalog check: "cve-section-distros" "cve-distros-help"
/// "distro-priority".
///
/// Rows shown per distribution (Ubuntu lists dozens of kernel packages per release for some CVEs).
const MAX_ROWS: usize = 40;

/// One distribution in the CVE detail.
#[derive(Debug, Clone, PartialEq)]
pub struct DistroView {
    pub name: &'static str,
    /// Ubuntu's priority of the CVE, in words.
    pub priority: String,
    /// The distribution's page about the CVE.
    pub link: String,
    pub link_label: String,
    /// Notes of the vendor for the whole group (Apple's security notes); empty for Debian and Ubuntu.
    pub refs: Vec<AdvisoryRef>,
    pub rows: Vec<DistroRow>,
    /// "12 more entries …", empty when all rows are shown.
    pub more: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DistroRow {
    pub release: String,
    pub package: String,
    /// `state` class: ok (fixed), err (open), warn (last affected, undetermined), off (not affected).
    pub class: &'static str,
    pub state: String,
    /// The version that fixes it, or the last affected one.
    pub version: String,
    /// Urgency and notes (no DSA planned …), joined.
    pub note: String,
    pub advisories: Vec<AdvisoryRef>,
    /// Own assets of this system version (Windows, Apple, Android) and what the matching says about them.
    pub own: Vec<OwnMark>,
}

/// An own asset at a row of the operating systems.
#[derive(Debug, Clone, PartialEq)]
pub struct OwnMark {
    pub name: String,
    pub href: String,
    pub version: String,
    /// `state` class: err (affected), warn (affected, version not checkable), ok (not affected).
    pub class: &'static str,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryRef {
    pub id: String,
    pub url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum State {
    Open,
    Undetermined,
    LastAffected,
    Fixed,
    NotAffected,
}

/// What the rows of one (distribution, ecosystem, package) say.
#[derive(Default)]
struct Acc {
    release: String,
    ecosystem: String,
    /// Ranges of the distribution's CVE record; advisories only count when there is none.
    cve_ranges: Vec<(String, String)>,
    adv_ranges: Vec<(String, String)>,
    urgency: String,
    advisories: Vec<AdvisoryRef>,
}

/// The distributions that know the CVE, Debian first.
pub fn build(
    t: Lang,
    cve_id: &str,
    rows: Vec<AffectedForCve>,
    tracker: &[TrackerRow],
) -> Vec<DistroView> {
    let mut groups: BTreeMap<(String, String, String), Acc> = BTreeMap::new();
    let mut ubuntu_priority = String::new();
    for r in rows.into_iter().filter(|r| !r.withdrawn) {
        let acc = groups
            .entry((r.source.clone(), r.ecosystem.clone(), r.package.clone()))
            .or_default();
        acc.release = r.release;
        acc.ecosystem = r.ecosystem;
        let range = (r.fixed, r.last_affected);
        if r.kind == "cve" {
            acc.cve_ranges.push(range);
            if r.source == "ubuntu" && !r.priority.is_empty() {
                ubuntu_priority = r.priority;
            }
        } else {
            acc.adv_ranges.push(range);
            if !acc.advisories.iter().any(|a| a.id == r.id) {
                acc.advisories.push(AdvisoryRef {
                    id: r.id,
                    url: r.url,
                });
            }
        }
        if acc.urgency.is_empty() && meaningful(&r.urgency) {
            acc.urgency = r.urgency;
        }
    }

    let mut debian = Vec::new();
    let mut ubuntu = Vec::new();
    let mut tracker_used = vec![false; tracker.len()];
    for ((source, _, package), acc) in groups {
        let ranges = if acc.cve_ranges.is_empty() {
            &acc.adv_ranges
        } else {
            &acc.cve_ranges
        };
        let (mut state, version) = state_of(ranges);
        let mut notes = Vec::new();
        let mut urgency = acc.urgency.clone();
        let release;
        if source == "debian" {
            let codename = codename_of(&acc.release);
            release = match codename {
                Some(c) => format!("{} ({c})", acc.release),
                None => acc.release.clone(),
            };
            if let Some(i) = tracker
                .iter()
                .position(|tr| tr.package == package && Some(tr.release.as_str()) == codename)
            {
                tracker_used[i] = true;
                let tr = &tracker[i];
                if tr.status == "undetermined" && state == State::Open {
                    state = State::Undetermined;
                }
                if urgency.is_empty() && meaningful(&tr.urgency) {
                    urgency.clone_from(&tr.urgency);
                }
                if let Some(n) = nodsa_note(t, tr) {
                    notes.push(n);
                }
            }
        } else {
            release = ubuntu_release(t, &acc.ecosystem, &acc.release);
        }
        if !urgency.is_empty() {
            notes.insert(
                0,
                format!("{} {}", t.get("distro-urgency"), level(t, &urgency)),
            );
        }
        let row = DistroRow {
            release,
            package,
            class: class_of(state),
            state: t.get(state_id(state)),
            version,
            note: notes.join(" · "),
            advisories: acc.advisories,
            own: Vec::new(),
        };
        let key = sort_key(&acc.ecosystem, &acc.release);
        if source == "debian" {
            debian.push((key, row));
        } else {
            ubuntu.push((key, row));
        }
    }

    // Tracker issues of a release that OSV does not list (sid is left out: no one runs it as a server).
    for (tr, used) in tracker.iter().zip(&tracker_used) {
        let Some(version) = version_of(&tr.release) else {
            continue;
        };
        if *used {
            continue;
        }
        let state = if tr.status == "undetermined" {
            State::Undetermined
        } else {
            State::Open
        };
        let mut notes = Vec::new();
        if meaningful(&tr.urgency) {
            notes.push(format!(
                "{} {}",
                t.get("distro-urgency"),
                level(t, &tr.urgency)
            ));
        }
        notes.extend(nodsa_note(t, tr));
        debian.push((
            sort_key("Debian", version),
            DistroRow {
                release: format!("{version} ({})", tr.release),
                package: tr.package.clone(),
                class: class_of(state),
                state: t.get(state_id(state)),
                version: String::new(),
                note: notes.join(" · "),
                advisories: Vec::new(),
                own: Vec::new(),
            },
        ));
    }

    let mut out = Vec::new();
    for (name, mut rows, link, label) in [
        (
            "Debian",
            debian,
            format!("https://security-tracker.debian.org/tracker/{cve_id}"),
            "distro-open-debian",
        ),
        (
            "Ubuntu",
            ubuntu,
            format!("https://ubuntu.com/security/{cve_id}"),
            "distro-open-ubuntu",
        ),
    ] {
        if rows.is_empty() {
            continue;
        }
        rows.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.package.cmp(&b.1.package)));
        let hidden = rows.len().saturating_sub(MAX_ROWS);
        rows.truncate(MAX_ROWS);
        out.push(DistroView {
            name,
            priority: if name == "Ubuntu" && !ubuntu_priority.is_empty() {
                level(t, &ubuntu_priority)
            } else {
                String::new()
            },
            link,
            link_label: t.get(label),
            refs: Vec::new(),
            rows: rows.into_iter().map(|(_, r)| r).collect(),
            more: if hidden > 0 {
                t.get1("distro-more", "count", t.number(hidden as i64))
            } else {
                String::new()
            },
        });
    }
    out
}

/// The state of a package from its ranges: open if any range is open.
fn state_of(ranges: &[(String, String)]) -> (State, String) {
    let mut fixed = None;
    let mut last = None;
    for (f, l) in ranges {
        if f.is_empty() && l.is_empty() {
            return (State::Open, String::new());
        }
        if !f.is_empty() {
            fixed = Some(f.clone());
        } else {
            last = Some(l.clone());
        }
    }
    match (fixed, last) {
        (_, Some(l)) => (State::LastAffected, l),
        (Some(f), None) if f == "0" => (State::NotAffected, String::new()),
        (Some(f), None) => (State::Fixed, f),
        (None, None) => (State::Open, String::new()),
    }
}

fn class_of(state: State) -> &'static str {
    match state {
        State::Fixed => "ok",
        State::Open => "err",
        State::LastAffected | State::Undetermined => "warn",
        State::NotAffected => "off",
    }
}

fn state_id(state: State) -> &'static str {
    match state {
        State::Fixed => "distro-fixed",
        State::Open => "distro-open",
        State::LastAffected => "distro-last-affected",
        State::Undetermined => "distro-undetermined",
        State::NotAffected => "distro-not-affected",
    }
}

/// An urgency worth showing ("not yet assigned" says nothing).
fn meaningful(urgency: &str) -> bool {
    !urgency.is_empty() && !urgency.starts_with("not yet") && urgency != "unknown"
}

/// Catalog id of a known urgency or priority.
fn level_id(level: &str) -> Option<&'static str> {
    Some(match level.trim_end_matches('*') {
        "unimportant" => "distro-level-unimportant",
        "negligible" => "distro-level-negligible",
        "low" => "distro-level-low",
        "medium" => "distro-level-medium",
        "high" => "distro-level-high",
        "critical" => "distro-level-critical",
        "end-of-life" => "distro-level-eol",
        _ => return None,
    })
}

/// A Debian urgency or Ubuntu priority in words; unknown ones as published.
fn level(t: Lang, level: &str) -> String {
    level_id(level).map_or_else(|| level.to_owned(), |id| t.get(id))
}

/// "No DSA planned (postponed): Minor issue".
fn nodsa_note(t: Lang, tr: &TrackerRow) -> Option<String> {
    if tr.nodsa.is_empty() && tr.nodsa_reason.is_empty() {
        return None;
    }
    let mut note = t.get("distro-nodsa");
    match tr.nodsa_reason.as_str() {
        "postponed" => note = format!("{note} ({})", t.get("distro-nodsa-postponed")),
        "ignored" => note = format!("{note} ({})", t.get("distro-nodsa-ignored")),
        _ => {}
    }
    if !tr.nodsa.is_empty() {
        note = format!("{note}: {}", tr.nodsa);
    }
    Some(note)
}

/// "26.04 LTS", "20.04 LTS · Ubuntu Pro", "22.04 LTS FIPS · Ubuntu Pro".
fn ubuntu_release(t: Lang, ecosystem: &str, release: &str) -> String {
    let parts: Vec<&str> = ecosystem.split(':').skip(1).collect();
    let pro = parts.contains(&"Pro");
    let mut words = vec![release.to_owned()];
    words.extend(
        parts
            .iter()
            .filter(|p| **p != "Pro" && **p != release)
            .map(|p| (*p).to_owned()),
    );
    let mut label = words.join(" ");
    if pro {
        label = format!("{label} · {}", t.get("distro-pro"));
    }
    label
}

/// Newest release first; the plain release before its Pro and FIPS variants.
fn sort_key(ecosystem: &str, release: &str) -> (Vec<u32>, bool) {
    let numbers = release.split('.').map(|p| p.parse().unwrap_or(0)).collect();
    (
        numbers,
        ecosystem.split(':').count() <= 3 && !ecosystem.contains(":Pro"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn affected(
        id: &str,
        kind: &str,
        eco: &str,
        package: &str,
        fixed: &str,
        urgency: &str,
    ) -> AffectedForCve {
        let source = if eco.starts_with("Debian") {
            "debian"
        } else {
            "ubuntu"
        };
        AffectedForCve {
            id: id.to_owned(),
            source: source.to_owned(),
            kind: kind.to_owned(),
            priority: if source == "ubuntu" {
                "medium".to_owned()
            } else {
                String::new()
            },
            url: format!("https://example.test/{id}"),
            withdrawn: false,
            ecosystem: eco.to_owned(),
            release: eco
                .split(':')
                .find(|p| p.starts_with(|c: char| c.is_ascii_digit()))
                .unwrap()
                .to_owned(),
            package: package.to_owned(),
            introduced: "0".to_owned(),
            fixed: fixed.to_owned(),
            last_affected: String::new(),
            urgency: urgency.to_owned(),
        }
    }

    #[test]
    fn rows_merge_cve_records_advisories_and_the_tracker() {
        let t = Lang::De;
        let rows = vec![
            affected(
                "DEBIAN-CVE-2026-1",
                "cve",
                "Debian:12",
                "nginx",
                "1.22.1-9+deb12u3",
                "medium",
            ),
            affected(
                "DEBIAN-CVE-2026-1",
                "cve",
                "Debian:13",
                "nginx",
                "",
                "not yet assigned",
            ),
            affected(
                "DSA-6000-1",
                "advisory",
                "Debian:12",
                "nginx",
                "1.22.1-9+deb12u3",
                "",
            ),
            affected(
                "UBUNTU-CVE-2026-1",
                "cve",
                "Ubuntu:26.04:LTS",
                "nginx",
                "1.28.0-1ubuntu1.2",
                "",
            ),
            affected(
                "UBUNTU-CVE-2026-1",
                "cve",
                "Ubuntu:Pro:20.04:LTS",
                "nginx",
                "",
                "",
            ),
            affected(
                "USN-9000-1",
                "advisory",
                "Ubuntu:26.04:LTS",
                "nginx",
                "1.28.0-1ubuntu1.2",
                "",
            ),
        ];
        let tracker = vec![
            TrackerRow {
                cve_id: "CVE-2026-1".to_owned(),
                package: "nginx".to_owned(),
                release: "trixie".to_owned(),
                status: "open".to_owned(),
                urgency: "low".to_owned(),
                nodsa: "Minor issue".to_owned(),
                nodsa_reason: "postponed".to_owned(),
                fixed_version: String::new(),
            },
            TrackerRow {
                cve_id: "CVE-2026-1".to_owned(),
                package: "nginx".to_owned(),
                release: "sid".to_owned(),
                status: "open".to_owned(),
                urgency: String::new(),
                nodsa: String::new(),
                nodsa_reason: String::new(),
                fixed_version: String::new(),
            },
        ];
        let views = build(t, "CVE-2026-1", rows, &tracker);
        assert_eq!(views.len(), 2);
        let d = &views[0];
        assert_eq!(d.name, "Debian");
        assert_eq!(
            d.link,
            "https://security-tracker.debian.org/tracker/CVE-2026-1"
        );
        assert_eq!(d.rows.len(), 2, "sid is left out");
        assert_eq!(d.rows[0].release, "13 (trixie)");
        assert_eq!(d.rows[0].class, "err");
        assert_eq!(
            d.rows[0].note,
            "Dringlichkeit niedrig · kein DSA geplant (verschoben): Minor issue"
        );
        assert_eq!(d.rows[1].release, "12 (bookworm)");
        assert_eq!(d.rows[1].class, "ok");
        assert_eq!(d.rows[1].version, "1.22.1-9+deb12u3");
        assert_eq!(d.rows[1].note, "Dringlichkeit mittel");
        assert_eq!(d.rows[1].advisories[0].id, "DSA-6000-1");

        let u = &views[1];
        assert_eq!(u.priority, "mittel");
        assert_eq!(u.rows[0].release, "26.04 LTS");
        assert_eq!(u.rows[0].advisories[0].id, "USN-9000-1");
        assert_eq!(u.rows[1].release, "20.04 LTS · Ubuntu Pro");
        assert_eq!(u.rows[1].class, "err");
        assert!(u.more.is_empty());
    }

    #[test]
    fn many_rows_are_cut_and_counted() {
        let rows = (0..45)
            .map(|i| {
                affected(
                    "UBUNTU-CVE-2026-2",
                    "cve",
                    "Ubuntu:24.04:LTS",
                    &format!("linux-{i:02}"),
                    "6.8.0-1",
                    "",
                )
            })
            .collect();
        let views = build(Lang::En, "CVE-2026-2", rows, &[]);
        assert_eq!(views[0].rows.len(), MAX_ROWS);
        assert!(views[0].more.contains('5'), "{}", views[0].more);
    }

    #[test]
    fn states_follow_the_ranges() {
        let r = |f: &str, l: &str| (f.to_owned(), l.to_owned());
        assert_eq!(state_of(&[r("1.2", "")]).0, State::Fixed);
        assert_eq!(state_of(&[r("1.2", ""), r("", "")]).0, State::Open);
        assert_eq!(
            state_of(&[r("", "2.0")]),
            (State::LastAffected, "2.0".to_owned())
        );
        assert_eq!(state_of(&[r("0", "")]).0, State::NotAffected);
        assert_eq!(state_of(&[]).0, State::Open);
    }

    #[test]
    fn every_text_exists_in_every_language() {
        for lang in Lang::ALL {
            let mut ids = vec![
                "distro-urgency",
                "distro-nodsa",
                "distro-nodsa-postponed",
                "distro-nodsa-ignored",
                "distro-pro",
                "distro-more",
                "distro-open-debian",
                "distro-open-ubuntu",
            ];
            ids.extend(
                [
                    State::Open,
                    State::Undetermined,
                    State::LastAffected,
                    State::Fixed,
                    State::NotAffected,
                ]
                .map(state_id),
            );
            ids.extend(
                [
                    "unimportant",
                    "negligible",
                    "low",
                    "medium",
                    "high",
                    "critical",
                    "end-of-life",
                ]
                .map(|l| level_id(l).unwrap()),
            );
            for id in ids {
                assert_ne!(lang.get(id), id, "{id} missing in {lang:?}");
            }
        }
    }
}
