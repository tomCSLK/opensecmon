//! The own assets and the watchlist: storing, checking what the user entered, and the suggestions shown
//! while typing (vendors and products from the CVE and CSAF data, packages from the distributions).

use sqlx::SqlitePool;

use crate::error::Result;
use crate::sources::name_key;

/// Longest names, versions and other texts of an asset.
const MAX_NAME: usize = 200;
const MAX_VERSION: usize = 100;
const MAX_HOST: usize = 100;
const MAX_CPE: usize = 300;
const MAX_NOTE: usize = 1000;
const MAX_KEYWORD: usize = 100;
/// Suggestions per request.
const SUGGESTIONS: i64 = 12;

/// What an asset is (see migrations/0007_assets.sql).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Package,
    Software,
    Hardware,
}

impl Kind {
    pub const ALL: [Self; 3] = [Self::Package, Self::Software, Self::Hardware];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Package => "package",
            Self::Software => "software",
            Self::Hardware => "hardware",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }

    pub fn label_id(self) -> &'static str {
        match self {
            Self::Package => "asset-kind-package",
            Self::Software => "asset-kind-software",
            Self::Hardware => "asset-kind-hardware",
        }
    }

    pub fn icon(self) -> &'static str {
        match self {
            Self::Package => "package",
            Self::Software => "server",
            Self::Hardware => "router",
        }
    }
}

/// A Debian or Ubuntu release a package asset can name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Distro {
    Debian,
    Ubuntu,
}

impl Distro {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Debian => "debian",
            Self::Ubuntu => "ubuntu",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "debian" => Some(Self::Debian),
            "ubuntu" => Some(Self::Ubuntu),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Debian => "Debian",
            Self::Ubuntu => "Ubuntu",
        }
    }
}

/// A stored asset.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct Asset {
    pub id: i64,
    pub kind: String,
    pub vendor: String,
    pub product: String,
    pub vendor_name: String,
    pub product_name: String,
    pub version: String,
    pub host: String,
    pub cpe: String,
    pub distro: String,
    pub release: String,
    pub pro: bool,
    pub origin: String,
    /// The object that keeps this asset up to date ("ssh:<host id>", "onm:<device id>"), or empty.
    pub origin_ref: String,
    pub note: String,
    pub created_ms: i64,
    pub updated_ms: i64,
    pub matched_ms: Option<i64>,
    /// Matches below this priority are muted (0: none), see migration 0014.
    #[sqlx(default)]
    pub min_prio: i64,
}

/// The priority from which a new asset shows its matches: kernel source packages (hundreds to thousands of
/// matches, mostly without a fix) start at 65, everything else at 0 (all). The same rule is in migration 0014.
pub fn default_min_prio(kind: Kind, product: &str) -> i64 {
    let kernel = product == "linux"
        || (product.starts_with("linux-")
            && !matches!(product, "linux-firmware" | "linux-base" | "linux-atm")
            && !product.starts_with("linux-meta"));
    if kind == Kind::Package && kernel {
        65
    } else {
        0
    }
}

/// The source packages of the kernel and its firmware that Raspberry Pi builds itself.
fn is_pi_kernel_package(product: &str) -> bool {
    matches!(product, "linux" | "raspi-firmware" | "linux-firmware")
        || product.starts_with("linux-signed-")
}

/// Sets the priority from which the asset shows its matches.
pub async fn set_min_prio<'e, E: sqlx::SqliteExecutor<'e>>(
    executor: E,
    id: i64,
    min_prio: i64,
) -> Result<()> {
    sqlx::query("UPDATE assets SET min_prio = ? WHERE id = ?")
        .bind(min_prio.clamp(0, 100))
        .bind(id)
        .execute(executor)
        .await?;
    Ok(())
}

impl Asset {
    pub fn kind(&self) -> Kind {
        Kind::parse(&self.kind).unwrap_or(Kind::Software)
    }

    pub fn distro(&self) -> Option<Distro> {
        Distro::parse(&self.distro)
    }

    /// "openssh-server" or "OpenBSD OpenSSH".
    pub fn display_name(&self) -> String {
        let repeats_vendor = self
            .product_name
            .to_lowercase()
            .starts_with(&self.vendor_name.to_lowercase());
        if self.kind() == Kind::Package || self.vendor_name.is_empty() || repeats_vendor {
            self.product_name.clone()
        } else {
            format!("{} {}", self.vendor_name, self.product_name)
        }
    }

    /// A kernel or firmware source package of Raspberry Pi OS (`+rpt` in the version): built by Raspberry Pi
    /// from its own sources, so the data of Debian does not fit it and nothing is matched. Other `+rpt`
    /// packages (glibc, bluez …) are rebuilds of Debian and are matched.
    pub fn pi_kernel(&self) -> bool {
        self.kind() == Kind::Package
            && self.distro() == Some(Distro::Debian)
            && self.version.contains("+rpt")
            && is_pi_kernel_package(&self.product)
    }

    /// "Debian 13", "Ubuntu 24.04 · Pro" for a package, else empty.
    pub fn release_label(&self) -> String {
        match self.distro() {
            Some(d) if self.pro => format!("{} {} · Pro", d.name(), self.release),
            Some(d) => format!("{} {}", d.name(), self.release),
            None => String::new(),
        }
    }
}

/// What the form gives for a new or changed asset.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Input {
    pub kind: String,
    pub vendor_name: String,
    pub product_name: String,
    pub version: String,
    pub host: String,
    pub cpe: String,
    pub distro: String,
    pub release: String,
    pub pro: bool,
    pub note: String,
}

/// An input that passed [`Input::check`]: trimmed, with its keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    pub kind: Kind,
    pub vendor: String,
    pub product: String,
    pub vendor_name: String,
    pub product_name: String,
    pub version: String,
    pub host: String,
    pub cpe: String,
    pub distro: String,
    pub release: String,
    pub pro: bool,
    pub note: String,
}

impl Checked {
    /// The asset this input would become (for the preview of the matches before it is saved).
    pub fn as_asset(&self, id: i64, created_ms: i64) -> Asset {
        Asset {
            id,
            kind: self.kind.as_str().to_owned(),
            vendor: self.vendor.clone(),
            product: self.product.clone(),
            vendor_name: self.vendor_name.clone(),
            product_name: self.product_name.clone(),
            version: self.version.clone(),
            host: self.host.clone(),
            cpe: self.cpe.clone(),
            distro: self.distro.clone(),
            release: self.release.clone(),
            pro: self.pro,
            origin: "manual".to_owned(),
            origin_ref: String::new(),
            note: self.note.clone(),
            created_ms,
            updated_ms: created_ms,
            matched_ms: None,
            min_prio: 0,
        }
    }
}

/// Whether `name` is a valid Debian package name.
pub fn is_package_name(name: &str) -> bool {
    (2..=MAX_NAME).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'+' | b'-')
        })
}

/// Whether `release` looks like "13" or "24.04".
fn is_release(release: &str) -> bool {
    (1..=10).contains(&release.len())
        && release.starts_with(|c: char| c.is_ascii_digit())
        && release.bytes().all(|b| b.is_ascii_digit() || b == b'.')
}

/// The vendor and product of a CPE 2.3 name (`cpe:2.3:a:openbsd:openssh:9.6:*:…`), as keys.
pub fn cpe_keys(cpe: &str) -> Option<(String, String)> {
    let mut parts = cpe.strip_prefix("cpe:2.3:")?.split(':');
    let part = parts.next()?;
    if !matches!(part, "a" | "o" | "h") {
        return None;
    }
    let vendor = name_key(&parts.next()?.replace('\\', ""));
    let product = name_key(&parts.next()?.replace('\\', ""));
    (!vendor.is_empty() && !product.is_empty()).then_some((vendor, product))
}

/// The version a CPE names, if it names one.
pub fn cpe_version(cpe: &str) -> Option<String> {
    let version = cpe.strip_prefix("cpe:2.3:")?.split(':').nth(3)?;
    (!matches!(version, "" | "*" | "-")).then(|| version.replace('\\', ""))
}

fn trimmed(s: &str, max: usize) -> std::result::Result<String, &'static str> {
    let s = s.trim();
    if s.chars().count() > max {
        return Err("asset-error-too-long");
    }
    if s.chars().any(char::is_control) {
        return Err("asset-error-control");
    }
    Ok(s.to_owned())
}

impl Input {
    /// Checks and normalises the input; the error is the id of a text for the form.
    pub fn check(&self) -> std::result::Result<Checked, &'static str> {
        let kind = Kind::parse(&self.kind).ok_or("asset-error-kind")?;
        let mut version = trimmed(&self.version, MAX_VERSION)?;
        let host = trimmed(&self.host, MAX_HOST)?;
        let note = trimmed(&self.note, MAX_NOTE)?;
        if kind == Kind::Package {
            let distro = Distro::parse(self.distro.trim()).ok_or("asset-error-distro")?;
            let release = self.release.trim().to_owned();
            if !is_release(&release) {
                return Err("asset-error-release");
            }
            let package = self.product_name.trim().to_owned();
            if !is_package_name(&package) {
                return Err("asset-error-package");
            }
            if !crate::version::is_version(crate::version::Scheme::Deb, &version) {
                return Err("asset-error-package-version");
            }
            return Ok(Checked {
                kind,
                vendor: distro.as_str().to_owned(),
                product: package.clone(),
                vendor_name: distro.name().to_owned(),
                product_name: package,
                version,
                host,
                cpe: String::new(),
                distro: distro.as_str().to_owned(),
                release,
                pro: self.pro && distro == Distro::Ubuntu,
                note,
            });
        }
        let cpe = trimmed(&self.cpe, MAX_CPE)?;
        let mut vendor_name = trimmed(&self.vendor_name, MAX_NAME)?;
        let mut product_name = trimmed(&self.product_name, MAX_NAME)?;
        if !cpe.is_empty() {
            let (vendor, product) = cpe_keys(&cpe).ok_or("asset-error-cpe")?;
            if vendor_name.is_empty() {
                vendor_name = vendor;
            }
            if product_name.is_empty() {
                product_name = product;
            }
            if version.is_empty() {
                version = cpe_version(&cpe).unwrap_or_default();
            }
        }
        let product = name_key(&product_name);
        if product.is_empty() {
            return Err("asset-error-product");
        }
        Ok(Checked {
            kind,
            vendor: name_key(&vendor_name),
            product,
            vendor_name,
            product_name,
            version,
            host,
            cpe,
            distro: String::new(),
            release: String::new(),
            pro: false,
            note,
        })
    }
}

/// Stores a new asset entered by hand; returns its id.
pub async fn add(pool: &SqlitePool, a: &Checked, now_ms: i64) -> Result<i64> {
    add_from(pool, a, "manual", "", now_ms).await
}

/// Stores a new asset from `origin` ('manual', 'csv', 'ssh', 'opennetmon'); returns its id.
pub async fn add_from<'e, E: sqlx::SqliteExecutor<'e>>(
    executor: E,
    a: &Checked,
    origin: &str,
    origin_ref: &str,
    now_ms: i64,
) -> Result<i64> {
    Ok(sqlx::query(
        "INSERT INTO assets (kind, vendor, product, vendor_name, product_name, version, host, cpe, distro,
             release, pro, origin, origin_ref, note, created_ms, updated_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(a.kind.as_str())
    .bind(&a.vendor)
    .bind(&a.product)
    .bind(&a.vendor_name)
    .bind(&a.product_name)
    .bind(&a.version)
    .bind(&a.host)
    .bind(&a.cpe)
    .bind(&a.distro)
    .bind(&a.release)
    .bind(a.pro)
    .bind(origin)
    .bind(origin_ref)
    .bind(&a.note)
    .bind(now_ms)
    .bind(now_ms)
    .execute(executor)
    .await?
    .last_insert_rowid())
}

/// Changes an asset; false if there is none with this id.
pub async fn update<'e, E: sqlx::SqliteExecutor<'e>>(
    executor: E,
    id: i64,
    a: &Checked,
    now_ms: i64,
) -> Result<bool> {
    Ok(sqlx::query(
        "UPDATE assets SET kind = ?, vendor = ?, product = ?, vendor_name = ?, product_name = ?, version = ?,
             host = ?, cpe = ?, distro = ?, release = ?, pro = ?, note = ?, updated_ms = ?
         WHERE id = ?",
    )
    .bind(a.kind.as_str())
    .bind(&a.vendor)
    .bind(&a.product)
    .bind(&a.vendor_name)
    .bind(&a.product_name)
    .bind(&a.version)
    .bind(&a.host)
    .bind(&a.cpe)
    .bind(&a.distro)
    .bind(&a.release)
    .bind(a.pro)
    .bind(&a.note)
    .bind(now_ms)
    .bind(id)
    .execute(executor)
    .await?
    .rows_affected()
        > 0)
}

/// Removes an asset with its matches; returns it if it existed.
pub async fn delete(pool: &SqlitePool, id: i64) -> Result<Option<Asset>> {
    let asset = get(pool, id).await?;
    if asset.is_some() {
        sqlx::query("DELETE FROM assets WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;
    }
    Ok(asset)
}

pub async fn get(pool: &SqlitePool, id: i64) -> Result<Option<Asset>> {
    Ok(sqlx::query_as("SELECT * FROM assets WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await?)
}

/// All assets, by host and name.
pub async fn all(pool: &SqlitePool) -> Result<Vec<Asset>> {
    Ok(sqlx::query_as(
        "SELECT * FROM assets ORDER BY host = '', host COLLATE NOCASE, product_name COLLATE NOCASE, id",
    )
    .fetch_all(pool)
    .await?)
}

/// The assets with these (vendor, product) keys, for the operating systems in the CVE detail (a CVE of
/// Microsoft names up to some 40 Windows versions; the assets of a vendor are few).
pub async fn of_products(pool: &SqlitePool, keys: &[(String, String)]) -> Result<Vec<Asset>> {
    let mut vendors: Vec<&str> = keys.iter().map(|(v, _)| v.as_str()).collect();
    vendors.sort_unstable();
    vendors.dedup();
    let mut out = Vec::new();
    for vendor in vendors {
        let rows: Vec<Asset> = sqlx::query_as(
            "SELECT * FROM assets WHERE vendor = ? ORDER BY host = '', host COLLATE NOCASE, id",
        )
        .bind(vendor)
        .fetch_all(pool)
        .await?;
        out.extend(
            rows.into_iter()
                .filter(|a| keys.iter().any(|(v, p)| *v == a.vendor && *p == a.product)),
        );
    }
    Ok(out)
}

/// The host names in use, for the form.
pub async fn hosts(pool: &SqlitePool) -> Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT DISTINCT host FROM assets WHERE host != '' ORDER BY host COLLATE NOCASE",
    )
    .fetch_all(pool)
    .await?)
}

pub async fn set_matched(pool: &SqlitePool, id: i64, now_ms: i64) -> Result<()> {
    sqlx::query("UPDATE assets SET matched_ms = ? WHERE id = ?")
        .bind(now_ms)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// A keyword of the watchlist.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct Watch {
    pub id: i64,
    pub keyword: String,
    pub created_ms: i64,
    pub since_ms: i64,
    pub matched_ms: Option<i64>,
}

/// How far back a new keyword (or an asset whose version cannot be checked) looks: 30 days.
pub const LOOK_BACK_MS: i64 = 30 * 86_400_000;

/// Checks a keyword: 3 to 100 characters, not only punctuation.
pub fn check_keyword(keyword: &str) -> std::result::Result<String, &'static str> {
    let k = trimmed(keyword, MAX_KEYWORD)?;
    let k = k.split_whitespace().collect::<Vec<_>>().join(" ");
    if k.chars().filter(|c| c.is_alphanumeric()).count() < 3 {
        return Err("watch-error-short");
    }
    Ok(k)
}

/// Adds a keyword; `None` if it is on the list already.
pub async fn add_watch(pool: &SqlitePool, keyword: &str, now_ms: i64) -> Result<Option<i64>> {
    let done = sqlx::query(
        "INSERT INTO watchlist (keyword, created_ms, since_ms) VALUES (?, ?, ?)
         ON CONFLICT (keyword) DO NOTHING",
    )
    .bind(keyword)
    .bind(now_ms)
    .bind(now_ms - LOOK_BACK_MS)
    .execute(pool)
    .await?;
    Ok((done.rows_affected() > 0).then(|| done.last_insert_rowid()))
}

pub async fn delete_watch(pool: &SqlitePool, id: i64) -> Result<Option<Watch>> {
    let watch: Option<Watch> = sqlx::query_as("SELECT * FROM watchlist WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    if watch.is_some() {
        sqlx::query("DELETE FROM watchlist WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;
    }
    Ok(watch)
}

pub async fn watches(pool: &SqlitePool) -> Result<Vec<Watch>> {
    Ok(
        sqlx::query_as("SELECT * FROM watchlist ORDER BY keyword COLLATE NOCASE")
            .fetch_all(pool)
            .await?,
    )
}

pub async fn get_watch(pool: &SqlitePool, id: i64) -> Result<Option<Watch>> {
    Ok(sqlx::query_as("SELECT * FROM watchlist WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await?)
}

pub async fn set_watch_matched(pool: &SqlitePool, id: i64, now_ms: i64) -> Result<()> {
    sqlx::query("UPDATE watchlist SET matched_ms = ? WHERE id = ?")
        .bind(now_ms)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// A suggestion while typing: the name to fill in and where it comes from.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Suggestion {
    pub name: String,
    pub hint: String,
}

/// The end of a range of keys that start with `prefix` (keys are compared byte by byte).
fn upper(prefix: &str) -> String {
    format!("{prefix}\u{10FFFF}")
}

/// Vendors whose key starts with the key of `typed` (at least two letters or digits).
pub async fn suggest_vendors(pool: &SqlitePool, typed: &str) -> Result<Vec<Suggestion>> {
    let key = name_key(typed);
    if key.chars().count() < 2 {
        return Ok(Vec::new());
    }
    let rows: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT name, SUM(cves), SUM(advisories) FROM (
             SELECT vendor AS k, COALESCE(MAX(CASE WHEN origin = 'cna' THEN vendor_name END), MAX(vendor_name))
                 AS name, COUNT(*) AS cves, 0 AS advisories
             FROM cve_products WHERE vendor >= ?1 AND vendor < ?2 GROUP BY vendor
             UNION ALL
             SELECT vendor, MAX(vendor_name), 0, COUNT(*)
             FROM advisory_products WHERE vendor >= ?1 AND vendor < ?2 GROUP BY vendor)
         GROUP BY k ORDER BY SUM(cves) + SUM(advisories) DESC, k LIMIT ?3",
    )
    .bind(&key)
    .bind(upper(&key))
    .bind(SUGGESTIONS)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(name, cves, advisories)| Suggestion {
            name,
            hint: hint(cves, advisories),
        })
        .collect())
}

/// "CVE 146 · CSAF 64": how often a name occurs in the data.
fn hint(cves: i64, advisories: i64) -> String {
    let mut parts = Vec::new();
    if cves > 0 {
        parts.push(format!("CVE {cves}"));
    }
    if advisories > 0 {
        parts.push(format!("CSAF {advisories}"));
    }
    parts.join(" · ")
}

/// Products of a vendor whose key starts with the key of `typed` (all products of the vendor for an empty
/// `typed`).
pub async fn suggest_products(
    pool: &SqlitePool,
    vendor: &str,
    typed: &str,
) -> Result<Vec<Suggestion>> {
    let vendor = name_key(vendor);
    let key = name_key(typed);
    if vendor.is_empty() && key.chars().count() < 2 {
        return Ok(Vec::new());
    }
    let rows: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT name, SUM(cves), SUM(advisories) FROM (
             SELECT product AS k, COALESCE(MAX(CASE WHEN origin = 'cna' THEN product_name END),
                 MAX(product_name)) AS name, COUNT(*) AS cves, 0 AS advisories
             FROM cve_products
             WHERE (?1 = '' OR vendor = ?1) AND product >= ?2 AND product < ?3
             GROUP BY product
             UNION ALL
             SELECT product, MAX(product_name), 0, COUNT(DISTINCT advisory_seq)
             FROM advisory_products
             WHERE (?1 = '' OR vendor = ?1) AND product >= ?2 AND product < ?3
             GROUP BY product)
         GROUP BY k ORDER BY SUM(cves) + SUM(advisories) DESC, k LIMIT ?4",
    )
    .bind(&vendor)
    .bind(&key)
    .bind(upper(&key))
    .bind(SUGGESTIONS)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(name, cves, advisories)| Suggestion {
            name,
            hint: hint(cves, advisories),
        })
        .collect())
}

/// Source packages of a release whose name starts with `typed`.
pub async fn suggest_packages(
    pool: &SqlitePool,
    distro: Distro,
    release: &str,
    typed: &str,
) -> Result<Vec<Suggestion>> {
    let typed = typed.trim().to_ascii_lowercase();
    if typed.len() < 2 || !is_release(release) {
        return Ok(Vec::new());
    }
    let ecosystem = match distro {
        Distro::Debian => format!("Debian:{release}"),
        Distro::Ubuntu => format!("Ubuntu:{release}%"),
    };
    let names: Vec<(String, i64)> = sqlx::query_as(
        "SELECT package, COUNT(*) FROM osv_affected
         WHERE package >= ?1 AND package < ?2 AND release = ?3 AND ecosystem LIKE ?4
         GROUP BY package ORDER BY package LIMIT ?5",
    )
    .bind(&typed)
    .bind(upper(&typed))
    .bind(release)
    .bind(ecosystem)
    .bind(SUGGESTIONS)
    .fetch_all(pool)
    .await?;
    Ok(names
        .into_iter()
        .map(|(name, n)| Suggestion {
            name,
            hint: format!("{} {n}", distro.name()),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(kind: &str) -> Input {
        Input {
            kind: kind.to_owned(),
            ..Input::default()
        }
    }

    #[test]
    fn packages_need_a_release_a_name_and_a_version() {
        let mut i = input("package");
        i.distro = "ubuntu".into();
        i.release = "24.04".into();
        i.product_name = " openssh ".into();
        i.version = "1:9.6p1-3ubuntu13.4".into();
        i.pro = true;
        let c = i.check().unwrap();
        assert_eq!(c.product, "openssh");
        assert_eq!(c.vendor, "ubuntu");
        assert!(c.pro);
        i.distro = "debian".into();
        i.release = "13".into();
        assert!(!i.check().unwrap().pro, "Pro is for Ubuntu only");
        for (field, value, error) in [
            ("release", "trixie", "asset-error-release"),
            ("product", "../etc", "asset-error-package"),
            ("version", "", "asset-error-package-version"),
            ("distro", "arch", "asset-error-distro"),
        ] {
            let mut j = i.clone();
            match field {
                "release" => j.release = value.into(),
                "product" => j.product_name = value.into(),
                "version" => j.version = value.into(),
                _ => j.distro = value.into(),
            }
            assert_eq!(j.check(), Err(error), "{field}");
        }
    }

    #[test]
    fn products_get_their_keys_also_from_a_cpe() {
        let mut i = input("software");
        i.vendor_name = "Traefik Labs".into();
        i.product_name = "Traefik".into();
        i.version = " 3.7.1 ".into();
        let c = i.check().unwrap();
        assert_eq!(
            (c.vendor.as_str(), c.product.as_str()),
            ("traefiklabs", "traefik")
        );
        assert_eq!(c.version, "3.7.1");

        let mut i = input("hardware");
        i.cpe = r"cpe:2.3:o:avm:fritz\!os:8.20:*:*:*:*:*:*:*".into();
        let c = i.check().unwrap();
        assert_eq!((c.vendor.as_str(), c.product.as_str()), ("avm", "fritzos"));
        assert_eq!(c.version, "8.20");

        i.cpe = "cpe:/o:avm:fritz_os".into();
        assert_eq!(i.check(), Err("asset-error-cpe"));
        assert_eq!(input("software").check(), Err("asset-error-product"));
        assert_eq!(input("other").check(), Err("asset-error-kind"));
        let mut i = input("software");
        i.product_name = "x\u{7}".into();
        assert_eq!(i.check(), Err("asset-error-control"));
    }

    #[test]
    fn display_names_do_not_repeat_the_vendor() {
        let mut a = Input {
            kind: "software".into(),
            vendor_name: "AVM".into(),
            product_name: "AVM FRITZ!Box".into(),
            ..Input::default()
        }
        .check()
        .unwrap()
        .as_asset(1, 0);
        assert_eq!(a.display_name(), "AVM FRITZ!Box");
        a.product_name = "FRITZ!OS".into();
        assert_eq!(a.display_name(), "AVM FRITZ!OS");
    }

    #[test]
    fn the_kernel_of_raspberry_pi_os_is_known_by_its_version() {
        let pi = |kind: &str, distro: &str, product: &str, version: &str| {
            Input {
                kind: kind.into(),
                distro: distro.into(),
                release: if distro == "ubuntu" { "24.04" } else { "13" }.into(),
                product_name: product.into(),
                version: version.into(),
                ..Input::default()
            }
            .check()
            .unwrap()
            .as_asset(1, 0)
            .pi_kernel()
        };
        assert!(pi("package", "debian", "linux", "1:6.18.60-1+rpt1"));
        assert!(pi(
            "package",
            "debian",
            "linux-signed-arm64",
            "6.12.47+rpt1"
        ));
        assert!(pi(
            "package",
            "debian",
            "raspi-firmware",
            "1:1.20250915-1+rpt1"
        ));
        assert!(
            !pi("package", "debian", "linux", "6.12.57-1"),
            "Debian's kernel"
        );
        assert!(
            !pi("package", "debian", "glibc", "2.41-12+rpt1"),
            "a rebuild of Debian"
        );
        assert!(!pi("package", "debian", "linux-meta", "1:6.18.60-1+rpt1"));
        assert!(!pi("package", "ubuntu", "linux", "6.8.0-40.40+rpt1"));
        assert!(!pi("software", "", "linux", "6.18.60+rpt1"));
    }

    #[test]
    fn keywords_need_some_letters() {
        assert_eq!(
            check_keyword("  Huawei   5G CPE "),
            Ok("Huawei 5G CPE".into())
        );
        assert_eq!(check_keyword("a-b"), Err("watch-error-short"));
    }

    #[tokio::test]
    async fn suggestions_come_from_the_data() {
        let dir = tempfile::tempdir().unwrap();
        let pool = crate::storage::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        crate::storage::migrate(&pool).await.unwrap();
        for (cve, origin, vendor, product, vn, pn) in [
            (
                "CVE-2026-1",
                "nvd",
                "openbsd",
                "openssh",
                "openbsd",
                "openssh",
            ),
            (
                "CVE-2026-1",
                "cna",
                "openbsd",
                "openssh",
                "OpenBSD",
                "OpenSSH",
            ),
            (
                "CVE-2026-2",
                "nvd",
                "openbsd",
                "openssh",
                "openbsd",
                "openssh",
            ),
            (
                "CVE-2026-3",
                "nvd",
                "openssl",
                "openssl",
                "openssl",
                "openssl",
            ),
        ] {
            sqlx::query("INSERT INTO cve_products VALUES (?, ?, ?, ?, ?, ?)")
                .bind(cve)
                .bind(origin)
                .bind(vendor)
                .bind(product)
                .bind(vn)
                .bind(pn)
                .execute(&pool)
                .await
                .unwrap();
        }
        let v = suggest_vendors(&pool, "Open").await.unwrap();
        assert_eq!(v[0].name, "OpenBSD");
        assert_eq!(v[0].hint, "CVE 3");
        assert_eq!(v.len(), 2);
        assert!(suggest_vendors(&pool, "o").await.unwrap().is_empty());
        let p = suggest_products(&pool, "OpenBSD", "").await.unwrap();
        assert_eq!(p[0].name, "OpenSSH");
    }
}
