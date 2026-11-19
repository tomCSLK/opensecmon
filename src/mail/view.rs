//! Building blocks of the HTML mails (instant mail, daily report, test mail): tones of the priority
//! bands, chips, facts, buttons and the frame around every mail. The templates are in `templates/mail/`;
//! they use tables and styles on the elements, because mail programs ignore most style sheets (the "no
//! inline styles" rule of the web pages comes from their CSP and does not apply to mails). Everything a
//! mail shows is in it: the logo is an inline image (`cid:`), there are no external resources and no
//! scripts. Texts from feeds and hosts reach the templates as plain strings and are escaped there.

use jiff::tz::TimeZone;

use crate::i18n::Lang;
use crate::mail::InlineImage;
use crate::storage::cve_list::Band;

/// Content id of the logo in the HTML part.
pub const LOGO_CID: &str = "logo@opensecmon";
/// The icon of the interface (`static/favicon.svg`) as a 64×64 PNG, shown at 22×22. Not under `static/`,
/// which is served.
const LOGO_PNG: &[u8] = include_bytes!("logo.png");

/// The logo as an inline image of the mail.
pub fn logo() -> InlineImage {
    InlineImage {
        content_id: LOGO_CID.to_owned(),
        content_type: "image/png",
        data: LOGO_PNG.to_vec(),
    }
}

/// Colours of a mail element: foreground, background, border, a strong colour for bars and the class
/// the dark mode rules of `templates/mail/base.html` use. The light values are the tokens of the
/// interface (`static/tokens.css`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Crit,
    High,
    Med,
    Low,
    Ok,
    /// The accent (daily report).
    Accent,
    /// Failures (sources).
    Err,
}

impl Tone {
    pub fn of_band(band: Band) -> Self {
        match band {
            Band::Crit => Self::Crit,
            Band::High => Self::High,
            Band::Med => Self::Med,
            Band::Low | Band::None => Self::Low,
        }
    }

    pub fn of_prio(prio: i64) -> Self {
        Self::of_band(Band::of_prio(prio))
    }

    /// The tone of a CVSS score (the severity ratings of CVSS).
    pub fn of_cvss(score: f64) -> Self {
        match score {
            s if s >= 9.0 => Self::Crit,
            s if s >= 7.0 => Self::High,
            s if s >= 4.0 => Self::Med,
            _ => Self::Low,
        }
    }

    /// The band whose name goes with the tone.
    pub fn band(self) -> Band {
        match self {
            Self::Crit | Self::Err => Band::Crit,
            Self::High => Band::High,
            Self::Med => Band::Med,
            Self::Low | Self::Ok | Self::Accent => Band::Low,
        }
    }

    pub fn fg(self) -> &'static str {
        match self {
            Self::Crit | Self::Err => "#a1132c",
            Self::High => "#a6400c",
            Self::Med => "#7a5600",
            Self::Low => "#46596d",
            Self::Ok => "#1d6b3c",
            Self::Accent => "#1c5ea8",
        }
    }

    pub fn bg(self) -> &'static str {
        match self {
            Self::Crit | Self::Err => "#fbe8eb",
            Self::High => "#fcefe6",
            Self::Med => "#fbf3d9",
            Self::Low => "#edf1f5",
            Self::Ok => "#e6f3ea",
            Self::Accent => "#e6eef8",
        }
    }

    pub fn line(self) -> &'static str {
        match self {
            Self::Crit | Self::Err => "#e7a3ae",
            Self::High => "#eab595",
            Self::Med => "#dcc275",
            Self::Low => "#b5c2cf",
            Self::Ok => "#a8d2b8",
            Self::Accent => "#b9cfe9",
        }
    }

    /// Strong colour for the colour band, bars and the priority scale.
    pub fn bar(self) -> &'static str {
        match self {
            Self::Crit | Self::Err => "#c8364e",
            Self::High => "#d9773f",
            Self::Med => "#d7b23f",
            Self::Low => "#9aaabb",
            Self::Ok => "#2f8a55",
            Self::Accent => "#1c5ea8",
        }
    }

    pub fn cls(self) -> &'static str {
        match self {
            Self::Crit => "crit",
            Self::High => "high",
            Self::Med => "med",
            Self::Low => "low",
            Self::Ok => "ok",
            Self::Accent => "acc",
            Self::Err => "err",
        }
    }
}

/// A label in the colours of a tone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chip {
    pub tone: Tone,
    pub text: String,
}

/// A key figure: label, value, a line below and optionally a short bar (0–100 %).
#[derive(Debug, Clone, PartialEq)]
pub struct Fact {
    pub label: String,
    pub value: String,
    /// A word after the value in the colour of `tone` ("kritisch").
    pub word: String,
    pub sub: String,
    /// Colour of the value (and the word); `None`: plain.
    pub tone: Option<Tone>,
    /// Width of the bar in percent (2–100) and its tone.
    pub meter: Option<(u8, Tone)>,
}

impl Fact {
    pub fn new(label: impl Into<String>, value: impl Into<String>, sub: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
            word: String::new(),
            sub: sub.into(),
            tone: None,
            meter: None,
        }
    }
}

/// The width of a bar for `fraction` (0–1) in percent, at least 2 so that it shows.
pub fn meter_width(fraction: f64) -> u8 {
    let percent = (fraction.clamp(0.0, 1.0) * 100.0).round();
    // In range 0..=100 after the clamp.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let percent = percent as u8;
    percent.max(2)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Button {
    pub label: String,
    pub href: String,
    pub primary: bool,
}

/// What every mail has around its content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub lang_code: &'static str,
    pub title: String,
    /// The line mail programs show after the subject.
    pub preheader: String,
    /// The host of the interface (top right), empty without an address.
    pub host: String,
    /// The colour band at the top of the card.
    pub band: Tone,
    /// Footer lines, joined with " · ".
    pub footer: Vec<String>,
    /// Link to the settings of this mail: address and text.
    pub settings: Option<(String, String)>,
}

impl Frame {
    pub fn new(t: Lang, title: impl Into<String>, band: Tone, base: Option<&str>) -> Self {
        Self {
            lang_code: t.code(),
            title: title.into(),
            preheader: String::new(),
            host: base.map(host_of).unwrap_or_default(),
            band,
            footer: Vec::new(),
            settings: None,
        }
    }
}

/// The host (with port) of an address like `https://sec.example.org:8444/x`.
pub fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    rest.split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// "opensecmon 0.3.7".
pub fn program() -> String {
    format!("opensecmon {}", env!("CARGO_PKG_VERSION"))
}

/// The name of a time zone for people ("Europe/Berlin"), empty if it has none.
pub fn zone_name(tz: &TimeZone) -> String {
    tz.iana_name().unwrap_or_default().to_owned()
}

/// Text for HTML: a space after a digit becomes a no-break space, so "71,4 %", "3 Hosts" or "≥ 85" never
/// wrap between number and unit; also around "≥", "≤" and before "%".
pub fn nb(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut after_digit = false;
    while let Some(c) = chars.next() {
        if c == ' ' && (after_digit || matches!(chars.peek(), Some('%' | '≥' | '≤'))) {
            out.push('\u{a0}');
        } else {
            out.push(c);
        }
        after_digit = c.is_ascii_digit() || matches!(c, '≥' | '≤');
    }
    out
}

/// The template filter `nb` ([`nb`]); the result is escaped like any other text.
pub mod filters {
    #[askama::filter_fn]
    pub fn nb<T: std::fmt::Display>(text: T, _: &dyn askama::Values) -> askama::Result<String> {
        Ok(super::nb(&text.to_string()))
    }
}

/// The HTML with the inline images as `data:` addresses, to look at a mail in a browser (previews).
#[cfg(test)]
pub fn with_data_uris(html: &str, images: &[InlineImage]) -> String {
    use base64::Engine;
    let mut out = html.to_owned();
    for image in images {
        let data = base64::engine::general_purpose::STANDARD.encode(&image.data);
        out = out.replace(
            &format!("cid:{}", image.content_id),
            &format!("data:{};base64,{data}", image.content_type),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_keep_their_unit() {
        assert_eq!(nb("71,4 % ab 3 Hosts"), "71,4\u{a0}% ab 3\u{a0}Hosts");
        assert_eq!(nb("Priorität 96 ≥ 85"), "Priorität 96\u{a0}≥\u{a0}85");
        assert_eq!(nb("a b"), "a b");
    }

    #[test]
    fn hosts_and_bars() {
        assert_eq!(
            host_of("https://sec.example.org:8444/x?y"),
            "sec.example.org:8444"
        );
        assert_eq!(host_of("sec.example.org"), "sec.example.org");
        assert_eq!(meter_width(0.0), 2);
        assert_eq!(meter_width(0.714), 71);
        assert_eq!(meter_width(3.0), 100);
        assert_eq!(Tone::of_prio(96), Tone::Crit);
        assert_eq!(Tone::of_prio(50), Tone::Med);
        assert_eq!(Tone::of_cvss(9.8), Tone::Crit);
        assert_eq!(Tone::of_cvss(7.5), Tone::High);
    }

    #[test]
    fn the_logo_is_a_png() {
        assert!(logo().data.starts_with(b"\x89PNG"));
    }
}
