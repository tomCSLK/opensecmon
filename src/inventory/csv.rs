//! CSV import of assets: a header line names the columns (German or English), the separator is a
//! semicolon or a comma, fields may be quoted ("" inside quotes is a quote). Every row goes through the
//! same check as the form; the preview says per row whether it is new, changes an asset or has an error.

use std::collections::HashMap;

use crate::storage::assets::{Asset, Checked, Input};

/// Most bytes of a file.
pub const MAX_BYTES: usize = 1024 * 1024;
/// Most rows (without the header).
pub const MAX_ROWS: usize = 5_000;

/// The example shown on the page.
pub const EXAMPLE: &str = "typ;hersteller;produkt;version;host;cpe;distro;release
hardware;AVM;FRITZ!OS;8.20;router;;;
software;Traefik Labs;Traefik;3.7.1;server01;cpe:2.3:a:traefik:traefik:3.7.1:*:*:*:*:*:*:*;;
paket;;openssl;3.0.17-1~deb12u2;pi01;;debian;12";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Column {
    Kind,
    Vendor,
    Product,
    Version,
    Host,
    Cpe,
    Distro,
    Release,
    Note,
}

fn column(name: &str) -> Option<Column> {
    Some(match name.trim().to_lowercase().as_str() {
        "typ" | "art" | "kind" | "type" => Column::Kind,
        "hersteller" | "vendor" => Column::Vendor,
        "produkt" | "product" | "paket" | "package" | "name" => Column::Product,
        "version" => Column::Version,
        "host" | "gerät" | "geraet" | "device" => Column::Host,
        "cpe" => Column::Cpe,
        "distro" | "distribution" => Column::Distro,
        "release" => Column::Release,
        "notiz" | "note" | "kennung" | "comment" => Column::Note,
        _ => return None,
    })
}

/// "paket", "Hardware/Firmware" … as the kind of the form.
fn kind(value: &str) -> String {
    let v = value.trim().to_lowercase();
    match v.as_str() {
        "paket" | "package" | "deb" => "package",
        "software" | "anwendung" | "application" => "software",
        "hardware" | "firmware" | "hardware/firmware" | "gerät" | "geraet" | "device" => {
            "hardware"
        }
        _ => return v,
    }
    .to_owned()
}

/// Splits CSV text into rows of fields (quotes, doubled quotes, line breaks inside quotes).
fn split(text: &str, sep: char) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if quoted {
            match c {
                '"' if chars.peek() == Some(&'"') => {
                    chars.next();
                    field.push('"');
                }
                '"' => quoted = false,
                c => field.push(c),
            }
            continue;
        }
        match c {
            '"' if field.is_empty() => quoted = true,
            c if c == sep => row.push(std::mem::take(&mut field)),
            '\r' => {}
            '\n' => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            c => field.push(c),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows.retain(|r| r.iter().any(|f| !f.trim().is_empty()));
    rows
}

/// What happens to a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowState {
    New,
    /// Changes the asset with this id.
    Update(i64),
    /// The asset exists as it is.
    Same(i64),
    /// The id of the error text.
    Error(&'static str),
}

/// One row of the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// Line number in the file (the header is line 1).
    pub line: usize,
    pub input: Input,
    pub checked: Option<Checked>,
    pub state: RowState,
}

/// The rows of a file, or the id of an error with the whole file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub rows: Vec<Row>,
}

impl Parsed {
    pub fn count(&self, f: impl Fn(&RowState) -> bool) -> usize {
        self.rows.iter().filter(|r| f(&r.state)).count()
    }
}

/// The key under which a row and an asset are the same thing: kind, vendor, product, host (and the
/// release of a package).
fn key(c: &Checked) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}",
        c.kind.as_str(),
        c.vendor,
        c.product,
        c.host.to_lowercase(),
        c.distro,
        c.release
    )
}

fn asset_key(a: &Asset) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}",
        a.kind,
        a.vendor,
        a.product,
        a.host.to_lowercase(),
        a.distro,
        a.release
    )
}

/// Reads a file and compares its rows with the assets entered by hand or by CSV (assets that follow a
/// host or a device are left to their source).
pub fn parse(text: &str, existing: &[Asset]) -> Result<Parsed, &'static str> {
    if text.len() > MAX_BYTES {
        return Err("csv-error-size");
    }
    let text = text.trim_start_matches('\u{feff}');
    let header_line = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .ok_or("csv-error-empty")?;
    let sep = if header_line.matches(';').count() >= header_line.matches(',').count() {
        ';'
    } else {
        ','
    };
    let mut rows = split(text, sep).into_iter();
    let header = rows.next().ok_or("csv-error-empty")?;
    let columns: Vec<Option<Column>> = header.iter().map(|h| column(h)).collect();
    if !columns.contains(&Some(Column::Product)) {
        return Err("csv-error-header");
    }
    let mut known: HashMap<String, &Asset> = HashMap::new();
    for a in existing.iter().filter(|a| a.origin_ref.is_empty()) {
        known.entry(asset_key(a)).or_insert(a);
    }
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut out = Vec::new();
    for (i, fields) in rows.enumerate() {
        if out.len() == MAX_ROWS {
            return Err("csv-error-rows");
        }
        let mut input = Input::default();
        let mut values: HashMap<Column, String> = HashMap::new();
        for (col, value) in columns.iter().zip(fields.iter()) {
            if let Some(c) = col {
                values.insert(*c, value.trim().to_owned());
            }
        }
        let get = |c: Column| values.get(&c).cloned().unwrap_or_default();
        input.kind = match get(Column::Kind) {
            k if k.is_empty() && !get(Column::Distro).is_empty() => "package".into(),
            k if k.is_empty() => "software".into(),
            k => kind(&k),
        };
        input.vendor_name = get(Column::Vendor);
        input.product_name = get(Column::Product);
        input.version = get(Column::Version);
        input.host = get(Column::Host);
        input.cpe = get(Column::Cpe);
        input.distro = get(Column::Distro).to_lowercase();
        input.release = get(Column::Release);
        input.note = get(Column::Note);
        let line = i + 2;
        let (checked, state) = match input.check() {
            Err(id) => (None, RowState::Error(id)),
            Ok(c) => {
                let k = key(&c);
                let state = if seen.insert(k.clone(), line).is_some() {
                    RowState::Error("csv-error-twice")
                } else {
                    match known.get(&k) {
                        Some(a)
                            if a.version == c.version
                                && a.cpe == c.cpe
                                && a.note == c.note
                                && a.pro == c.pro =>
                        {
                            RowState::Same(a.id)
                        }
                        Some(a) => RowState::Update(a.id),
                        None => RowState::New,
                    }
                };
                (Some(c), state)
            }
        };
        out.push(Row {
            line,
            input,
            checked,
            state,
        });
    }
    if out.is_empty() {
        return Err("csv-error-empty");
    }
    Ok(Parsed { rows: out })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset(id: i64, kind: &str, vendor: &str, product: &str, version: &str, host: &str) -> Asset {
        Asset {
            id,
            kind: kind.into(),
            vendor: vendor.into(),
            product: product.into(),
            vendor_name: String::new(),
            product_name: product.into(),
            version: version.into(),
            host: host.into(),
            cpe: String::new(),
            distro: String::new(),
            release: String::new(),
            pro: false,
            origin: "manual".into(),
            origin_ref: String::new(),
            note: String::new(),
            created_ms: 0,
            updated_ms: 0,
            matched_ms: None,
            min_prio: 0,
        }
    }

    #[test]
    fn splits_quoted_fields() {
        assert_eq!(
            split("a;\"b;c\";\"say \"\"hi\"\"\"\r\n\n\"multi\nline\";x\n", ';'),
            vec![
                vec!["a".to_owned(), "b;c".into(), "say \"hi\"".into()],
                vec!["multi\nline".into(), "x".into()],
            ]
        );
    }

    #[test]
    fn rows_are_new_changed_unchanged_or_wrong() {
        let existing = [
            asset(1, "hardware", "avm", "fritzos", "8.10", "router"),
            asset(2, "software", "traefiklabs", "traefik", "3.7.1", "server01"),
        ];
        let p = parse(
            "\u{feff}Typ,Hersteller,Produkt,Version,Host,Unbekannt\n\
             Hardware/Firmware,AVM,FRITZ!OS,8.20,router,x\n\
             software,Traefik Labs,Traefik,3.7.1,Server01\n\
             software,Grafana Labs,Grafana,12.1.0,server01\n\
             software,Grafana Labs,Grafana,12.1.1,server01\n\
             paket,,openssl,3.0.17-1~deb12u2,pi01\n\
             rocket,,x,1,\n",
            &existing,
        )
        .unwrap();
        let states: Vec<(usize, RowState)> =
            p.rows.iter().map(|r| (r.line, r.state.clone())).collect();
        assert_eq!(
            states,
            [
                (2, RowState::Update(1)),
                (3, RowState::Same(2)),
                (4, RowState::New),
                (5, RowState::Error("csv-error-twice")),
                (6, RowState::Error("asset-error-distro")),
                (7, RowState::Error("asset-error-kind")),
            ]
        );
        assert_eq!(p.count(|s| *s == RowState::New), 1);
    }

    #[test]
    fn the_example_is_valid() {
        let p = parse(EXAMPLE, &[]).unwrap();
        assert!(p.rows.iter().all(|r| r.state == RowState::New), "{p:?}");
        let pkg = p.rows[2].checked.as_ref().unwrap();
        assert_eq!(
            (pkg.distro.as_str(), pkg.release.as_str()),
            ("debian", "12")
        );
    }

    #[test]
    fn whole_file_errors() {
        assert_eq!(parse("", &[]), Err("csv-error-empty"));
        assert_eq!(parse("a;b\n1;2\n", &[]), Err("csv-error-header"));
        assert_eq!(parse("produkt\n", &[]), Err("csv-error-empty"));
        let big = format!("produkt\n{}", "x\n".repeat(MAX_ROWS + 1));
        assert_eq!(parse(&big, &[]), Err("csv-error-rows"));
    }
}
