//! The output of the inventory command on a host: `/etc/os-release`, a line `---`, then one line per
//! package from `dpkg-query` (status, package, version, source package, source version, tab separated).
//! Since opensecmon 0.3.1 the script adds lines of its own before `---`: `OPENSECMON_KERNEL=<uname -r>`,
//! `OPENSECMON_REBOOT=1` and `OPENSECMON_PRO=1`. Outputs without them stay valid.
//! Since opensecmon 0.3.2 sections follow the packages, each after a line `--- <name>`: `--- snap` with the output
//! of `snap list` (a header, then name, version, revision, tracking, publisher, notes separated by spaces) and
//! `--- flatpak` with `flatpak list --app --columns=application,name,version,installation` (tab separated).
//! Older opensecmon count their lines as skipped package lines; lines of unknown sections are ignored.
//!
//! The output comes from another machine and is only parsed: lines that do not fit are skipped, sizes are
//! limited, nothing is interpreted beyond the fields named here.

use std::collections::BTreeMap;

use crate::inventory::items::{Item, ItemType};
use crate::storage::assets::{Distro, is_package_name};
use crate::version::{Scheme, compare, is_version};

/// The script that the host runs instead of any command (shown in the wizard, copied by the user).
pub const SCRIPT: &str = "#!/bin/sh
# opensecmon-inventory: prints the system details and the lists of installed packages, snaps and Flatpaks, nothing
# else.
cat /etc/os-release
echo \"OPENSECMON_KERNEL=$(uname -r)\"
if [ -e /var/run/reboot-required ]; then echo \"OPENSECMON_REBOOT=1\"; fi
for f in /etc/apt/sources.list.d/ubuntu-esm-infra.* /etc/apt/sources.list.d/ubuntu-esm-apps.*; do
    if [ -e \"$f\" ]; then echo \"OPENSECMON_PRO=1\"; break; fi
done
echo \"---\"
dpkg-query -W -f='${db:Status-Abbrev}\\t${Package}\\t${Version}\\t${source:Package}\\t${source:Version}\\n' || exit
if command -v snap >/dev/null 2>&1; then
    echo \"--- snap\"
    LC_ALL=C snap list --unicode=never --color=never 2>/dev/null || true
fi
if command -v flatpak >/dev/null 2>&1; then
    echo \"--- flatpak\"
    # flatpak needs a cache it can write to, which a user without a home of its own lacks.
    cache=$(mktemp -d 2>/dev/null) || cache=\"\"
    XDG_CACHE_HOME=${cache:-/tmp} LC_ALL=C flatpak list --app --columns=application,name,version,installation 2>/dev/null || true
    if [ -n \"$cache\" ]; then rm -rf \"$cache\"; fi
fi
";

/// Where the wizard suggests to put the script.
pub const SCRIPT_PATH: &str = "/usr/local/bin/opensecmon-inventory";

/// Most bytes read from a host (a server has a few thousand packages, about 100 bytes each).
pub const MAX_BYTES: usize = 8 * 1024 * 1024;
/// Most package lines taken.
pub const MAX_PACKAGES: usize = 50_000;

/// What a host told about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    /// `PRETTY_NAME` (or `NAME VERSION`), for the list of hosts.
    pub os_name: String,
    /// Debian or Ubuntu, or a system based on one of them; `None` for anything else.
    pub distro: Option<Distro>,
    /// "13", "24.04" ('' if unknown).
    pub release: String,
    /// The host gets Ubuntu Pro (ESM) updates: the script found the sources of esm-infra or esm-apps, or some
    /// installed version says "esm".
    pub pro: bool,
    /// The running kernel (`uname -r`), '' if the script does not say.
    pub kernel: String,
    /// The highest installed version of a kernel source package (`linux`, `linux-signed*`, `linux-hwe-*`), or ''.
    pub kernel_installed: String,
    /// The system waits for a reboot (`/var/run/reboot-required`).
    pub reboot: bool,
    /// Installed binary packages.
    pub binaries: usize,
    /// Source package → the highest installed version of it.
    pub sources: BTreeMap<String, String>,
    /// Snaps and Flatpak apps (the sections after the packages), at most [`MAX_PACKAGES`].
    pub items: Vec<Item>,
    /// Package, snap and Flatpak lines that were not taken: malformed, invalid names or versions, or beyond the
    /// limit (lines of packages that are not installed do not count).
    pub skipped: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ListingError {
    #[error("the output has no line \"---\" between os-release and the package list")]
    NoSeparator,
    #[error("the system is neither Debian nor Ubuntu nor based on one of them")]
    Unsupported,
    #[error("the package list is empty")]
    NoPackages,
}

impl ListingError {
    /// The text for the user.
    pub fn text_id(self) -> &'static str {
        match self {
            Self::NoSeparator => "ssh-error-output",
            Self::Unsupported => "ssh-error-system",
            Self::NoPackages => "ssh-error-no-packages",
        }
    }
}

/// The value of an os-release line, without quotes (`NAME="Debian GNU/Linux"`).
fn unquote(value: &str) -> String {
    let v = value.trim();
    let inner = if v.len() >= 2
        && ((v.starts_with('"') && v.ends_with('"')) || (v.starts_with('\'') && v.ends_with('\'')))
    {
        &v[1..v.len() - 1]
    } else {
        v
    };
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else if !c.is_control() {
            out.push(c);
        }
    }
    out.chars().take(200).collect()
}

/// Ubuntu releases by code name, for systems based on Ubuntu (Mint, Pop!_OS, Zorin …).
const UBUNTU: [(&str, &str); 10] = [
    ("bionic", "18.04"),
    ("focal", "20.04"),
    ("jammy", "22.04"),
    ("kinetic", "22.10"),
    ("lunar", "23.04"),
    ("mantic", "23.10"),
    ("noble", "24.04"),
    ("oracular", "24.10"),
    ("plucky", "25.04"),
    ("questing", "25.10"),
];

/// Debian releases by code name, for testing and systems based on Debian without `VERSION_ID`.
const DEBIAN: [(&str, &str); 6] = [
    ("buster", "10"),
    ("bullseye", "11"),
    ("bookworm", "12"),
    ("trixie", "13"),
    ("forky", "14"),
    ("duke", "15"),
];

/// The code name of a Debian release ("13" → "trixie"), as the Security Tracker names it.
pub fn debian_codename(release: &str) -> Option<&'static str> {
    DEBIAN.iter().find(|(_, r)| *r == release).map(|(c, _)| *c)
}

fn by_codename(table: &[(&str, &str)], codename: &str) -> Option<String> {
    table
        .iter()
        .find(|(c, _)| *c == codename)
        .map(|(_, r)| (*r).to_owned())
}

/// The distribution and release from the fields of os-release.
fn system(fields: &BTreeMap<String, String>) -> (Option<Distro>, String) {
    let get = |k: &str| fields.get(k).map(String::as_str).unwrap_or_default();
    let id = get("ID").to_ascii_lowercase();
    let like: Vec<String> = get("ID_LIKE")
        .split_whitespace()
        .map(str::to_ascii_lowercase)
        .collect();
    let version_id = get("VERSION_ID");
    let is_release = |r: &str| {
        !r.is_empty()
            && r.starts_with(|c: char| c.is_ascii_digit())
            && r.bytes().all(|b| b.is_ascii_digit() || b == b'.')
    };
    if id == "ubuntu" && is_release(version_id) {
        return (Some(Distro::Ubuntu), version_id.to_owned());
    }
    if id == "ubuntu" || like.iter().any(|l| l == "ubuntu") {
        let codename = match get("UBUNTU_CODENAME") {
            "" => get("VERSION_CODENAME"),
            c => c,
        };
        return match by_codename(&UBUNTU, &codename.to_ascii_lowercase()) {
            Some(r) => (Some(Distro::Ubuntu), r),
            // An Ubuntu release newer than this table: its own VERSION_ID if it is Ubuntu itself.
            None => (None, String::new()),
        };
    }
    if matches!(id.as_str(), "debian" | "raspbian") || like.iter().any(|l| l == "debian") {
        let codename = match get("DEBIAN_CODENAME") {
            "" => get("VERSION_CODENAME"),
            c => c,
        };
        if matches!(id.as_str(), "debian" | "raspbian") && is_release(version_id) {
            // "12" or "12.5": Debian's releases are the major number.
            let major = version_id.split('.').next().unwrap_or_default();
            return (Some(Distro::Debian), major.to_owned());
        }
        return match by_codename(&DEBIAN, &codename.to_ascii_lowercase()) {
            Some(r) => (Some(Distro::Debian), r),
            None => (None, String::new()),
        };
    }
    (None, String::new())
}

/// Whether a text looks like a kernel release as `uname -r` gives it ("6.8.0-40-generic", "6.18.60+rpt-rpi-v8").
pub fn is_kernel_release(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-' | b'_' | b'~'))
}

/// A source package that builds the kernel itself (not its firmware or meta packages).
fn is_kernel_source(name: &str) -> bool {
    name == "linux" || name.starts_with("linux-signed") || name.starts_with("linux-hwe-")
}

/// Whether a dpkg status (`ii `, `hi `, `iU `) means the package is installed.
fn installed(status: &str) -> bool {
    matches!(status.as_bytes().get(1), Some(b'i' | b't' | b'W'))
}

/// What the lines after the package list are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Packages,
    /// `snap list`; the first line is its header.
    Snap {
        header: bool,
    },
    Flatpak,
    /// A section of a later script: its lines are not read.
    Unknown,
}

impl Section {
    /// The section a line starts (`--- snap`), if it starts one.
    fn start(line: &str) -> Option<Self> {
        let name = line.trim().strip_prefix("--- ")?.trim();
        Some(match name {
            "snap" => Self::Snap { header: true },
            "flatpak" => Self::Flatpak,
            _ => Self::Unknown,
        })
    }
}

/// A snap name as the store allows it (lower case letters, digits, hyphens).
fn is_snap_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A Flatpak application ID (reverse DNS: `org.mozilla.firefox`).
fn is_flatpak_id(s: &str) -> bool {
    s.len() <= 255
        && s.contains('.')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A line of `snap list`: name, version, revision, tracking, publisher (a trailing `*` or `**` marks a
/// verified one), notes.
fn snap_item(line: &str) -> Option<Item> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let [name, version, _rev, _tracking, publisher, ..] = fields.as_slice() else {
        return None;
    };
    if !is_snap_name(name) {
        return None;
    }
    let publisher = match publisher.trim_end_matches('*') {
        "-" => "",
        p => p,
    };
    Item::new(ItemType::Snap, name, name, version, publisher, "", false)
}

/// A line of `flatpak list --app --columns=application,name,version,installation`.
fn flatpak_item(line: &str) -> Option<Item> {
    let fields: Vec<&str> = line.split('\t').collect();
    let [id, name, version, installation, ..] = fields.as_slice() else {
        return None;
    };
    let id = id.trim();
    if !is_flatpak_id(id) {
        return None;
    }
    Item::new(
        ItemType::Flatpak,
        id,
        name,
        version,
        "",
        "",
        installation.trim() == "user",
    )
}

/// Reads the output of the inventory command.
pub fn parse(output: &str) -> Result<Listing, ListingError> {
    let mut lines = output.lines();
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    let mut separated = false;
    for line in lines.by_ref() {
        if line.trim() == "---" {
            separated = true;
            break;
        }
        if let Some((key, value)) = line.split_once('=')
            && !key.is_empty()
            && key
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            && (fields.len() < 100 || key.starts_with("OPENSECMON_"))
        {
            fields.insert(key.to_owned(), unquote(value));
        }
    }
    if !separated {
        return Err(ListingError::NoSeparator);
    }
    let (distro, release) = system(&fields);
    let distro = distro.ok_or(ListingError::Unsupported)?;
    let os_name = match fields.get("PRETTY_NAME") {
        Some(p) if !p.is_empty() => p.clone(),
        _ => format!(
            "{} {}",
            fields.get("NAME").map(String::as_str).unwrap_or_default(),
            fields
                .get("VERSION")
                .map(String::as_str)
                .unwrap_or_default()
        )
        .trim()
        .to_owned(),
    };
    let mut sources: BTreeMap<String, String> = BTreeMap::new();
    let mut binaries = 0;
    let mut pro = false;
    let mut skipped = 0;
    let mut section = Section::Packages;
    let mut package_lines = 0;
    let mut items: Vec<Item> = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        if let Some(s) = Section::start(line) {
            section = s;
            continue;
        }
        let item = match section {
            Section::Packages => None,
            Section::Snap { header: true } => {
                section = Section::Snap { header: false };
                continue;
            }
            Section::Snap { header: false } => Some(snap_item(line)),
            Section::Flatpak => Some(flatpak_item(line)),
            Section::Unknown => continue,
        };
        if let Some(item) = item {
            match item {
                Some(i) if items.len() < MAX_PACKAGES => items.push(i),
                _ => skipped += 1,
            }
            continue;
        }
        package_lines += 1;
        if package_lines > MAX_PACKAGES {
            skipped += 1;
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        let [status, package, version, source, source_version, ..] = parts.as_slice() else {
            skipped += 1;
            continue;
        };
        if !installed(status) {
            continue;
        }
        if !is_package_name(package) {
            skipped += 1;
            continue;
        }
        // An empty source field: the source package has the binary package's name and version.
        let source = match source.trim() {
            "" => *package,
            s => s,
        };
        let version = match source_version.trim() {
            "" => version.trim(),
            v => v,
        };
        if !is_package_name(source) || version.len() > 100 || !is_version(Scheme::Deb, version) {
            skipped += 1;
            continue;
        }
        binaries += 1;
        pro |= version.contains("esm");
        match sources.get_mut(source) {
            Some(known) => {
                if compare(Scheme::Deb, version, known).is_gt() {
                    *known = version.to_owned();
                }
            }
            None => {
                sources.insert(source.to_owned(), version.to_owned());
            }
        }
    }
    if sources.is_empty() {
        return Err(ListingError::NoPackages);
    }
    let own = |k: &str| fields.get(k).map(String::as_str).unwrap_or_default();
    pro |= own("OPENSECMON_PRO") == "1";
    let kernel = match own("OPENSECMON_KERNEL") {
        k if is_kernel_release(k) => k.to_owned(),
        _ => String::new(),
    };
    let kernel_installed = sources
        .iter()
        .filter(|(name, _)| is_kernel_source(name))
        .map(|(_, v)| v)
        .max_by(|a, b| compare(Scheme::Deb, a, b))
        .cloned()
        .unwrap_or_default();
    Ok(Listing {
        os_name,
        distro: Some(distro),
        release,
        pro: pro && distro == Distro::Ubuntu,
        reboot: !kernel.is_empty() && own("OPENSECMON_REBOOT") == "1",
        kernel,
        kernel_installed,
        binaries,
        sources,
        items,
        skipped,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const UBUNTU_OUT: &str = "PRETTY_NAME=\"Ubuntu 24.04.3 LTS\"
NAME=\"Ubuntu\"
VERSION_ID=\"24.04\"
ID=ubuntu
ID_LIKE=debian
UBUNTU_CODENAME=noble
---
ii \topenssh-server\t1:9.6p1-3ubuntu13.4\topenssh\t1:9.6p1-3ubuntu13.4
ii \topenssh-client\t1:9.6p1-3ubuntu13.4\topenssh\t1:9.6p1-3ubuntu13.4
ii \tlinux-image-6.8.0-40-generic\t6.8.0-40.40\tlinux-signed\t6.8.0-40.40
ii \tlinux-image-6.8.0-45-generic\t6.8.0-45.45\tlinux-signed\t6.8.0-45.45
rc \tlinux-image-6.8.0-31-generic\t6.8.0-31.31\tlinux-signed\t6.8.0-31.31
ii \tlibssl3t64\t3.0.13-0ubuntu3.5\topenssl\t3.0.13-0ubuntu3.5
ii \tzlib1g\t1:1.3.dfsg-3.1ubuntu2.1\t\t
ii \tbroken line
ii \tEvil Name\t1.0\tx\t1.0
";

    #[test]
    fn reads_ubuntu_and_groups_by_source_package() {
        let l = parse(UBUNTU_OUT).unwrap();
        assert_eq!(l.os_name, "Ubuntu 24.04.3 LTS");
        assert_eq!(l.distro, Some(Distro::Ubuntu));
        assert_eq!(l.release, "24.04");
        assert!(!l.pro);
        assert_eq!(l.binaries, 6);
        let expected: BTreeMap<String, String> = [
            ("linux-signed", "6.8.0-45.45"),
            ("openssh", "1:9.6p1-3ubuntu13.4"),
            ("openssl", "3.0.13-0ubuntu3.5"),
            ("zlib1g", "1:1.3.dfsg-3.1ubuntu2.1"),
        ]
        .into_iter()
        .map(|(a, b)| (a.to_owned(), b.to_owned()))
        .collect();
        assert_eq!(l.sources, expected);
        assert_eq!(
            l.skipped, 2,
            "the broken line and the evil name; rc does not count"
        );
    }

    #[test]
    fn knows_the_systems_based_on_debian_and_ubuntu() {
        let release = |os: &str| {
            let l = parse(&format!("{os}\n---\nii \tbash\t5.2-1\tbash\t5.2-1\n"));
            l.map(|l| (l.distro.unwrap().as_str(), l.release))
        };
        assert_eq!(
            release(
                "ID=zorin\nID_LIKE=\"ubuntu debian\"\nVERSION_ID=\"18\"\nUBUNTU_CODENAME=noble"
            ),
            Ok(("ubuntu", "24.04".to_owned()))
        );
        assert_eq!(
            release("ID=debian\nVERSION_ID=\"13\"\nVERSION_CODENAME=trixie"),
            Ok(("debian", "13".to_owned()))
        );
        assert_eq!(
            release("ID=raspbian\nID_LIKE=debian\nVERSION_ID=\"12\""),
            Ok(("debian", "12".to_owned()))
        );
        assert_eq!(
            release("ID=debian\nVERSION_CODENAME=forky"),
            Ok(("debian", "14".to_owned()))
        );
        assert_eq!(
            release("ID=linuxmint\nID_LIKE=\"ubuntu debian\"\nUBUNTU_CODENAME=jammy"),
            Ok(("ubuntu", "22.04".to_owned()))
        );
        assert_eq!(
            release("ID=fedora\nVERSION_ID=43"),
            Err(ListingError::Unsupported)
        );
        assert_eq!(
            parse("ID=debian\nVERSION_ID=13\n"),
            Err(ListingError::NoSeparator)
        );
        assert_eq!(
            parse("ID=debian\nVERSION_ID=13\n---\n"),
            Err(ListingError::NoPackages)
        );
    }

    #[test]
    fn notices_ubuntu_pro_and_strips_quotes_and_controls() {
        let l = parse(
            "PRETTY_NAME='Ubuntu \\\"Pro\\\"\u{1b}[31m'\nID=ubuntu\nVERSION_ID=\"20.04\"\n---\n\
             ii \tcurl\t7.68.0-1ubuntu2.25+esm1\tcurl\t7.68.0-1ubuntu2.25+esm1\n",
        )
        .unwrap();
        assert!(l.pro);
        assert_eq!(l.os_name, "Ubuntu \"Pro\"[31m");
    }

    #[test]
    fn the_script_prints_what_parse_reads() {
        assert!(
            SCRIPT.contains("${db:Status-Abbrev}\\t${Package}\\t${Version}\\t${source:Package}")
        );
        // On a system with dpkg (the CI runs on Ubuntu) the script itself runs.
        if !std::path::Path::new("/usr/bin/dpkg-query").exists()
            || !std::path::Path::new("/etc/os-release").exists()
        {
            return;
        }
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(SCRIPT)
            .output()
            .unwrap();
        assert!(out.status.success());
        let text = String::from_utf8_lossy(&out.stdout);
        if let Ok(l) = parse(&text) {
            let uname = std::process::Command::new("uname")
                .arg("-r")
                .output()
                .unwrap();
            assert_eq!(l.kernel, String::from_utf8_lossy(&uname.stdout).trim());
            assert!(!l.sources.is_empty());
        }
    }

    #[test]
    fn reads_snaps_and_flatpaks_after_the_packages() {
        let l = parse(&format!(
            "{UBUNTU_OUT}--- snap\n\
             Name      Version          Rev    Tracking         Publisher   Notes\n\
             core22    20250923         2139   latest/stable    canonical** base\n\
             firefox   144.0.2-1        7177   latest/stable/…  mozilla**   -\n\
             lxd       5.21.3-c5ae129   33110  5.21/stable      canonical** -\n\
             hello     2.10             42     latest/stable    -           -\n\
             Bad_Name  1.0              1      latest/stable    someone*    -\n\
             short\n\
             --- flatpak\n\
             org.gimp.GIMP\tGNU Image Manipulation Program\t3.0.4\tsystem\n\
             com.example.Tool\tTool\t\tuser\n\
             not an id\tx\t1\tsystem\n\
             --- rpm\n\
             anything at all\n"
        ))
        .unwrap();
        // The packages are read as before.
        assert_eq!(l.sources.len(), 4);
        let items: Vec<(ItemType, &str, &str, &str, bool)> = l
            .items
            .iter()
            .map(|i| {
                (
                    i.item_type,
                    i.key.as_str(),
                    i.version.as_str(),
                    i.publisher.as_str(),
                    i.user_scope,
                )
            })
            .collect();
        assert_eq!(
            items,
            [
                (ItemType::Snap, "core22", "20250923", "canonical", false),
                (ItemType::Snap, "firefox", "144.0.2-1", "mozilla", false),
                (ItemType::Snap, "lxd", "5.21.3-c5ae129", "canonical", false),
                (ItemType::Snap, "hello", "2.10", "", false),
                (ItemType::Flatpak, "org.gimp.gimp", "3.0.4", "", false),
                (ItemType::Flatpak, "com.example.tool", "", "", true),
            ]
        );
        assert_eq!(l.items[4].name, "GNU Image Manipulation Program");
        assert_eq!(l.items[0].name, "core22", "snap list has no titles");
        assert_eq!(
            l.skipped,
            2 + 3,
            "the two package lines as before, a bad snap name, a short snap line, a bad Flatpak ID"
        );
        // Without sections (an older script, a host without snapd) there are no items.
        assert!(parse(UBUNTU_OUT).unwrap().items.is_empty());
        // A section without lines (no snaps installed) is fine, the header is never an entry.
        let l = parse(&format!("{UBUNTU_OUT}--- snap\n--- flatpak\n")).unwrap();
        assert!(l.items.is_empty());
        assert_eq!(l.skipped, 2);
    }

    #[test]
    fn reads_the_kernel_the_reboot_and_pro_from_the_lines_of_the_script() {
        let with =
            |own: &str| parse(&UBUNTU_OUT.replacen("---\n", &format!("{own}---\n"), 1)).unwrap();
        let l = with("OPENSECMON_KERNEL=6.8.0-40-generic\nOPENSECMON_REBOOT=1\nOPENSECMON_PRO=1\n");
        assert_eq!(l.kernel, "6.8.0-40-generic");
        assert_eq!(
            l.kernel_installed, "6.8.0-45.45",
            "the highest installed kernel source"
        );
        assert!(l.reboot);
        assert!(l.pro);
        // An older script says nothing of it.
        let l = parse(UBUNTU_OUT).unwrap();
        assert_eq!((l.kernel.as_str(), l.reboot, l.pro), ("", false, false));
        assert_eq!(l.kernel_installed, "6.8.0-45.45");
        // A kernel release that is none is left out, a reboot without a kernel too.
        let l = with("OPENSECMON_KERNEL=6.8 $(reboot)\nOPENSECMON_REBOOT=1\n");
        assert_eq!((l.kernel.as_str(), l.reboot), ("", false));
        // Pro only counts for Ubuntu.
        let l = parse(
            "ID=debian\nVERSION_ID=13\nOPENSECMON_KERNEL=6.18.60+rpt-rpi-v8\nOPENSECMON_PRO=1\n---\n\
             ii \tlinux-image-rpi-v8\t1:6.18.60-1+rpt1\tlinux\t1:6.18.60-1+rpt1\n\
             ii \tlinux-firmware-free\t20260101-1\tlinux-firmware\t20260101-1\n",
        )
        .unwrap();
        assert!(!l.pro);
        assert_eq!(l.kernel, "6.18.60+rpt-rpi-v8");
        assert_eq!(
            l.kernel_installed, "1:6.18.60-1+rpt1",
            "firmware is no kernel"
        );
    }
}
