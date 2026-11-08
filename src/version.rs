//! Comparing versions: Debian package versions by the algorithm of dpkg (`epoch:upstream-revision`), and
//! the versions of other products (`10.6p2`, `8.20`, `4.32.1f`, `v3.7.1`) by the same character rules
//! without epoch and revision. Version texts come from the sources and the user; nothing here panics.

use std::cmp::Ordering;

/// How the versions of a product are written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// Debian and Ubuntu packages: `[epoch:]upstream[-revision]`.
    Deb,
    /// Everything else: compared like the upstream part of a Debian version, ignoring case and a leading
    /// "v".
    Generic,
}

/// Compares two versions.
pub fn compare(scheme: Scheme, a: &str, b: &str) -> Ordering {
    match scheme {
        Scheme::Deb => compare_deb(a, b),
        Scheme::Generic => {
            let (a, b) = (generic_form(a), generic_form(b));
            verrevcmp(a.as_bytes(), b.as_bytes())
        }
    }
}

/// Whether `text` can be compared as a version at all (starts with a digit, after an optional "v").
pub fn is_version(scheme: Scheme, text: &str) -> bool {
    let text = text.trim();
    match scheme {
        Scheme::Deb => {
            let rest = text.split_once(':').map_or(text, |(_, r)| r);
            rest.starts_with(|c: char| c.is_ascii_digit())
        }
        Scheme::Generic => generic_form(text).starts_with(|c: char| c.is_ascii_digit()),
    }
}

/// The comparable part of a product version: the first word, lower case, without a leading "v".
fn generic_form(text: &str) -> String {
    let word = text.split_whitespace().next().unwrap_or_default();
    let word = word
        .strip_prefix(['v', 'V'])
        .filter(|r| r.starts_with(|c: char| c.is_ascii_digit()))
        .unwrap_or(word);
    word.to_ascii_lowercase()
}

/// A Debian version split into its parts.
struct Deb<'a> {
    epoch: u64,
    upstream: &'a str,
    revision: &'a str,
}

fn parse_deb(text: &str) -> Deb<'_> {
    let text = text.trim();
    let (epoch, rest) = match text.split_once(':') {
        Some((e, rest)) if !e.is_empty() && e.bytes().all(|b| b.is_ascii_digit()) => {
            (e.parse().unwrap_or(u64::MAX), rest)
        }
        _ => (0, text),
    };
    let (upstream, revision) = rest.rsplit_once('-').unwrap_or((rest, ""));
    Deb {
        epoch,
        upstream,
        revision,
    }
}

fn compare_deb(a: &str, b: &str) -> Ordering {
    let (a, b) = (parse_deb(a), parse_deb(b));
    a.epoch
        .cmp(&b.epoch)
        .then_with(|| verrevcmp(a.upstream.as_bytes(), b.upstream.as_bytes()))
        .then_with(|| verrevcmp(a.revision.as_bytes(), b.revision.as_bytes()))
}

/// The weight of a character outside a number: `~` sorts before everything (even the end), letters
/// before other characters.
fn order(c: Option<u8>) -> i32 {
    match c {
        None => 0,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) if c.is_ascii_alphabetic() => i32::from(c),
        Some(b'~') => -1,
        Some(c) => i32::from(c) + 256,
    }
}

/// dpkg's `verrevcmp`: alternating runs of non-digits (by [`order`]) and numbers (by value).
fn verrevcmp(a: &[u8], b: &[u8]) -> Ordering {
    let (mut i, mut j) = (0, 0);
    let digit = |s: &[u8], k: usize| s.get(k).is_some_and(u8::is_ascii_digit);
    while i < a.len() || j < b.len() {
        while (i < a.len() && !digit(a, i)) || (j < b.len() && !digit(b, j)) {
            let (ac, bc) = (order(a.get(i).copied()), order(b.get(j).copied()));
            if ac != bc {
                return ac.cmp(&bc);
            }
            i += 1;
            j += 1;
        }
        while a.get(i) == Some(&b'0') {
            i += 1;
        }
        while b.get(j) == Some(&b'0') {
            j += 1;
        }
        let mut first_diff = Ordering::Equal;
        while digit(a, i) && digit(b, j) {
            if first_diff == Ordering::Equal {
                first_diff = a[i].cmp(&b[j]);
            }
            i += 1;
            j += 1;
        }
        if digit(a, i) {
            return Ordering::Greater;
        }
        if digit(b, j) {
            return Ordering::Less;
        }
        if first_diff != Ordering::Equal {
            return first_diff;
        }
    }
    Ordering::Equal
}

/// One end of a version range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bound {
    pub version: String,
    pub inclusive: bool,
}

/// A range of versions; an open end has no bound.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Range {
    pub start: Option<Bound>,
    pub end: Option<Bound>,
}

impl Range {
    /// Exactly one version.
    pub fn exact(version: &str) -> Self {
        let bound = Some(Bound {
            version: version.to_owned(),
            inclusive: true,
        });
        Self {
            start: bound.clone(),
            end: bound,
        }
    }

    /// Whether `version` lies in the range.
    pub fn contains(&self, scheme: Scheme, version: &str) -> bool {
        let after_start = self.start.as_ref().is_none_or(|b| {
            let o = compare(scheme, version, &b.version);
            o == Ordering::Greater || (b.inclusive && o == Ordering::Equal)
        });
        let before_end = self.end.as_ref().is_none_or(|b| {
            let o = compare(scheme, version, &b.version);
            o == Ordering::Less || (b.inclusive && o == Ordering::Equal)
        });
        after_start && before_end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deb(a: &str, b: &str) -> Ordering {
        compare(Scheme::Deb, a, b)
    }

    #[test]
    fn debian_versions_compare_like_dpkg() {
        // Cases from dpkg's own tests (lib/dpkg/t/t-version.c) and the Debian policy.
        use Ordering::*;
        for (a, b, want) in [
            ("0", "0", Equal),
            ("0", "00", Equal),
            ("1.0", "1.0", Equal),
            ("1:0", "0:0", Greater),
            ("1:1.0", "2.0", Greater),
            ("1.0", "1.0-0", Equal),
            ("1.0-1", "1.0", Greater),
            ("1.0", "1.1", Less),
            ("1.2", "1.10", Less),
            ("1.0~rc1", "1.0", Less),
            ("1.0~rc1", "1.0~rc2", Less),
            ("1.0~~", "1.0~", Less),
            ("1.0~", "1.0", Less),
            ("1.0+b1", "1.0", Greater),
            ("1.0a", "1.0", Greater),
            ("1.0a", "1.0+", Less),
            ("1.0.", "1.0a", Greater),
            ("2.30-1", "2.4-1", Greater),
            ("1:9.6p1-3ubuntu13.19", "1:9.6p1-3ubuntu13.20", Less),
            ("1:9.6p1-3ubuntu13.4", "1:9.6p1-3ubuntu13.20", Less),
            ("1:10.0p1-5ubuntu1", "1:9.6p1-3ubuntu13.20", Greater),
            ("1.2.3-1+deb12u1", "1.2.3-1", Greater),
            ("1.2.3-1+deb12u1", "1.2.3-1+deb13u1", Less),
            ("3.5.3-1ubuntu2", "3.5.3-1ubuntu2.1", Less),
            ("2.42-0ubuntu3", "2.42-0ubuntu3", Equal),
            ("1.0-1~bpo12+1", "1.0-1", Less),
        ] {
            assert_eq!(deb(a, b), want, "{a} vs {b}");
            assert_eq!(deb(b, a), want.reverse(), "{b} vs {a}");
        }
    }

    #[test]
    fn product_versions_compare_by_their_numbers() {
        use Ordering::*;
        let g = |a, b| compare(Scheme::Generic, a, b);
        assert_eq!(g("10.6p2", "10.6p1"), Greater);
        assert_eq!(g("9.9", "9.10"), Less);
        assert_eq!(g("v3.7.1", "3.7.1"), Equal);
        assert_eq!(g("4.32.1F", "4.32.1f"), Equal);
        assert_eq!(g("4.32.1f", "4.32.1"), Greater);
        assert_eq!(g("8.20", "8.2"), Greater);
        assert_eq!(g("8.20 (build 1)", "8.20"), Equal);
        assert_eq!(g("", "1"), Less);
        assert!(is_version(Scheme::Generic, "v3"));
        assert!(!is_version(Scheme::Generic, "*"));
        assert!(!is_version(Scheme::Generic, "-"));
        assert!(is_version(Scheme::Deb, "1:2.0-1"));
        assert!(!is_version(Scheme::Deb, "unknown"));
    }

    #[test]
    fn ranges_honour_their_bounds() {
        let r = Range {
            start: Some(Bound {
                version: "8.5p1".into(),
                inclusive: true,
            }),
            end: Some(Bound {
                version: "9.8p1".into(),
                inclusive: false,
            }),
        };
        assert!(r.contains(Scheme::Generic, "8.5p1"));
        assert!(r.contains(Scheme::Generic, "9.7p1"));
        assert!(!r.contains(Scheme::Generic, "9.8p1"));
        assert!(!r.contains(Scheme::Generic, "8.4"));
        assert!(Range::default().contains(Scheme::Generic, "1"));
        assert!(Range::exact("1.0").contains(Scheme::Deb, "1.0-0"));
        assert!(!Range::exact("1.0").contains(Scheme::Deb, "1.0-1"));
    }

    #[test]
    fn strange_input_does_not_panic() {
        for s in [
            "",
            ":",
            "-",
            "::-",
            "1:",
            ":1",
            "~",
            "99999999999999999999999:1",
            "ä-ö",
        ] {
            let _ = compare(Scheme::Deb, s, "1.0");
            let _ = compare(Scheme::Generic, s, "1.0");
        }
    }
}
