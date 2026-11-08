//! CSV files for download ("All CVEs", the inbox): UTF-8 with a byte order mark, in the conventions of the
//! user's language so that a spreadsheet opens them directly (German: `;` and a decimal comma; English: `,`
//! and a decimal point). Texts from the sources are data: a cell that a spreadsheet would read as a formula
//! (`=`, `+`, `-`, `@`, tab, carriage return at the start) gets a leading apostrophe.

use axum::http::header;
use axum::response::{IntoResponse, Response};

use crate::i18n::Lang;

/// Most rows of one file (as many as the pages of the list show).
pub const MAX_ROWS: i64 = 10_000;

pub struct Csv {
    lang: Lang,
    sep: char,
    out: String,
}

impl Csv {
    pub fn new(lang: Lang) -> Self {
        Self {
            lang,
            sep: match lang {
                Lang::De => ';',
                Lang::En => ',',
            },
            out: String::from("\u{feff}"),
        }
    }

    /// A text cell, quoted when needed and protected against formulas.
    pub fn text(&self, s: &str) -> String {
        let clean: String = s
            .chars()
            .map(|c| if c.is_control() && c != '\t' { ' ' } else { c })
            .collect();
        let guarded = if clean.starts_with(['=', '+', '-', '@', '\t', '\r']) {
            format!("'{clean}")
        } else {
            clean
        };
        if guarded.contains([self.sep, '"', '\n', '\r']) || guarded.starts_with(' ') {
            format!("\"{}\"", guarded.replace('"', "\"\""))
        } else {
            guarded
        }
    }

    /// A number with `digits` decimals in the language's notation; empty if there is none.
    pub fn num(&self, x: Option<f64>, digits: usize) -> String {
        x.map(|x| {
            let s = format!("{x:.digits$}");
            match self.lang {
                Lang::De => s.replace('.', ","),
                Lang::En => s,
            }
        })
        .unwrap_or_default()
    }

    /// Appends one line of prepared cells (from [`Csv::text`], [`Csv::num`] or plain integers).
    pub fn line(&mut self, cells: &[String]) {
        let sep = self.sep.to_string();
        self.out.push_str(&cells.join(&sep));
        self.out.push_str("\r\n");
    }

    /// The download: `<name>-<date>.csv`, never cached.
    pub fn into_response(self, name: &str, date: &str) -> Response {
        (
            [
                (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_owned()),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"opensecmon-{name}-{date}.csv\""),
                ),
                (header::CACHE_CONTROL, "no-store".to_owned()),
            ],
            self.out,
        )
            .into_response()
    }
}

/// `2026-11-06` of Unix milliseconds in a time zone; empty without a value.
pub fn day(tz: &jiff::tz::TimeZone, ms: Option<i64>) -> String {
    ms.and_then(|ms| jiff::Timestamp::from_millisecond(ms).ok())
        .map(|ts| ts.to_zoned(tz.clone()).date().to_string())
        .unwrap_or_default()
}

/// `2026-11-06 14:05` of Unix milliseconds in a time zone; empty without a value.
pub fn minute(tz: &jiff::tz::TimeZone, ms: Option<i64>) -> String {
    ms.and_then(|ms| jiff::Timestamp::from_millisecond(ms).ok())
        .map(|ts| {
            ts.to_zoned(tz.clone())
                .strftime("%Y-%m-%d %H:%M")
                .to_string()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cells_are_quoted_and_formulas_defused() {
        let de = Csv::new(Lang::De);
        assert_eq!(de.text("plain"), "plain");
        assert_eq!(de.text("a;b"), "\"a;b\"");
        assert_eq!(de.text("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(de.text("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(de.text("-1+2"), "'-1+2");
        assert_eq!(de.text("@SUM(A1)"), "'@SUM(A1)");
        assert_eq!(de.text("line\nbreak"), "line break");
        assert_eq!(de.num(Some(9.81), 1), "9,8");
        assert_eq!(de.num(None, 1), "");
        let en = Csv::new(Lang::En);
        assert_eq!(en.text("a;b"), "a;b");
        assert_eq!(en.text("a,b"), "\"a,b\"");
        assert_eq!(en.num(Some(0.5), 2), "0.50");
    }

    #[test]
    fn the_file_starts_with_a_byte_order_mark_and_ends_lines_with_crlf() {
        let mut c = Csv::new(Lang::En);
        c.line(&["a".to_owned(), "1".to_owned()]);
        assert_eq!(c.out, "\u{feff}a,1\r\n");
    }
}
