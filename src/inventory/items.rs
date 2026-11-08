//! The software a computer reports beside its packages (agent API, `items`): programs and store apps of Windows,
//! snaps and Flatpaks. Each entry gets a key that stays the same across versions and computers (for Windows
//! programs the display name without versions, architecture and language), and is resolved to a product by a rule
//! of the user, by a rule built into opensecmon, or stays unassigned (page "Unassigned" under "Assets").

/// The kinds of entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ItemType {
    /// Windows itself (from `os`, not sent as an item).
    Os,
    /// An entry under `…\CurrentVersion\Uninstall`.
    Win,
    /// A store app.
    Appx,
    Snap,
    Flatpak,
}

impl ItemType {
    /// The types an agent may send (not `os`).
    pub const SENT: [Self; 4] = [Self::Win, Self::Appx, Self::Snap, Self::Flatpak];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Os => "os",
            Self::Win => "win",
            Self::Appx => "appx",
            Self::Snap => "snap",
            Self::Flatpak => "flatpak",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [Self::Os, Self::Win, Self::Appx, Self::Snap, Self::Flatpak]
            .into_iter()
            .find(|t| t.as_str() == s)
    }

    /// An agent may send this type.
    pub fn parse_sent(s: &str) -> Option<Self> {
        Self::SENT.into_iter().find(|t| t.as_str() == s)
    }

    pub fn label_id(self) -> &'static str {
        match self {
            Self::Os => "items-type-os",
            Self::Win => "items-type-win",
            Self::Appx => "items-type-appx",
            Self::Snap => "items-type-snap",
            Self::Flatpak => "items-type-flatpak",
        }
    }
}

/// Limits of the fields (characters), as the API documents them.
pub const MAX_ID: usize = 200;
pub const MAX_NAME: usize = 200;
pub const MAX_VERSION: usize = 100;
pub const MAX_PUBLISHER: usize = 200;

/// One entry as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub item_type: ItemType,
    pub id: String,
    pub key: String,
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub winget_id: String,
    pub user_scope: bool,
}

/// A text field: without control characters, trimmed, at most `max` characters.
pub fn clean_text(s: &str, max: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(max)
        .collect::<String>()
        .trim()
        .to_owned()
}

impl Item {
    /// An entry from the fields an agent sent; `None` without an id. The name falls back to the id.
    pub fn new(
        item_type: ItemType,
        id: &str,
        name: &str,
        version: &str,
        publisher: &str,
        winget_id: &str,
        user_scope: bool,
    ) -> Option<Self> {
        let id = clean_text(id, MAX_ID);
        if id.is_empty() {
            return None;
        }
        let mut name = clean_text(name, MAX_NAME);
        if name.is_empty() {
            name = id.clone();
        }
        let key = key(item_type, &id, &name);
        if key.is_empty() {
            return None;
        }
        Some(Self {
            item_type,
            key,
            id,
            name,
            version: clean_text(version, MAX_VERSION),
            publisher: clean_text(publisher, MAX_PUBLISHER),
            winget_id: clean_text(winget_id, MAX_ID),
            user_scope,
        })
    }

    /// Windows itself as the entry of type `os`: the product as the CNA names it.
    pub fn os(system: &super::windows::WindowsSystem) -> Self {
        Self {
            item_type: ItemType::Os,
            id: "windows".into(),
            key: "windows".into(),
            name: system.product.clone(),
            version: system.version.clone(),
            publisher: "Microsoft".into(),
            winget_id: String::new(),
            user_scope: false,
        }
    }
}

/// Whether a word of a display name is a version ("24.08", "v3.2", "4.4.1"), or a plain number after "update",
/// "build" and the like ("Java 8 Update 431"); other numbers belong to the name ("Microsoft 365").
fn is_version_word(w: &str, previous: Option<&str>) -> bool {
    let v = w.strip_prefix('v').unwrap_or(w);
    let Some(first) = v.chars().next() else {
        return false;
    };
    if !first.is_ascii_digit() {
        return false;
    }
    if v.contains('.') {
        return v
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    }
    v.chars().all(|c| c.is_ascii_digit())
        && previous.is_some_and(|p| {
            matches!(
                p.to_lowercase().as_str(),
                "update" | "build" | "version" | "release" | "rev" | "patch"
            )
        })
}

/// A display name without anything in brackets, versions, architecture and language, in its own case.
fn strip_name(name: &str) -> String {
    let mut out = String::new();
    let mut depth = 0usize;
    for c in name.chars() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    let words: Vec<&str> = out.split_whitespace().collect();
    let kept: Vec<&str> = words
        .iter()
        .enumerate()
        .filter(|(i, w)| {
            let previous = i.checked_sub(1).map(|p| words[p]);
            !is_version_word(w, previous) && !is_noise_word(&w.to_lowercase())
        })
        .map(|(_, w)| *w)
        .collect();
    kept.join(" ")
        .trim_matches(|c: char| c == '-' || c == ',' || c == ':' || c.is_whitespace())
        .to_owned()
}

/// Whether a word names an architecture or a language ("x64", "64-bit", "de-de", "en-us").
fn is_noise_word(w: &str) -> bool {
    matches!(
        w,
        "x64"
            | "x86"
            | "x86_64"
            | "amd64"
            | "arm64"
            | "64-bit"
            | "32-bit"
            | "64bit"
            | "32bit"
            | "win64"
            | "win32"
    ) || (w.len() == 5
        && w.as_bytes()[2] == b'-'
        && w[..2].chars().all(|c| c.is_ascii_lowercase())
        && w[3..].chars().all(|c| c.is_ascii_lowercase()))
}

/// The key of a Windows program: its display name in lower case without anything in brackets, versions,
/// architecture and language ("7-Zip 24.08 (x64)" and "7-Zip 23.01" are both "7-zip").
pub fn name_key(name: &str) -> String {
    strip_name(name).to_lowercase()
}

/// The key of an entry: the name key for Windows programs (their registry key is often a GUID that changes with
/// every version), the name of a store app (without the publisher's hash), the snap name, the Flatpak ID.
pub fn key(item_type: ItemType, id: &str, name: &str) -> String {
    match item_type {
        ItemType::Win => name_key(name),
        ItemType::Appx => name.to_lowercase(),
        ItemType::Os | ItemType::Snap | ItemType::Flatpak => id.to_lowercase(),
    }
}

/// The version of an asset from what the system shows: the first piece that looks like a version ("144.0.2-1"
/// becomes "144.0.2", "Version 6.3.5 build 1" becomes "6.3.5"); "" if there is none.
pub fn clean_version(v: &str) -> String {
    let Some(start) = v.find(|c: char| c.is_ascii_digit()) else {
        return String::new();
    };
    let piece: String = v[start..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '~'))
        .collect();
    piece.trim_end_matches('.').to_owned()
}

/// The first version with at least one dot in a display name, outside brackets ("Python 3.12.10 (64-bit)" →
/// "3.12.10").
fn name_version(name: &str) -> Option<String> {
    let mut out = String::new();
    let mut depth = 0usize;
    for c in name.chars() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    let words: Vec<&str> = out.split_whitespace().collect();
    words.iter().enumerate().find_map(|(i, w)| {
        let previous = i.checked_sub(1).map(|p| words[p]);
        (w.contains('.') && is_version_word(w, previous))
            .then(|| clean_version(w.strip_prefix('v').unwrap_or(w)))
    })
}

/// The version of the asset an entry becomes: the first piece of the reported version (see [`clean_version`]),
/// Windows itself as reported. A Windows program takes the version from its display name when the installer
/// encodes it differently: same major and minor version, the name with three or more numbers, and the reported
/// version not just a longer form of it. The Python installer reports 3.12.10 as "3.12.10150.0" (it folds the
/// release level into the third number), which would lie above every fixed version of 3.12.
pub fn item_version(item_type: ItemType, name: &str, version: &str) -> String {
    if item_type == ItemType::Os {
        return version.to_owned();
    }
    let reported = clean_version(version);
    if item_type != ItemType::Win {
        return reported;
    }
    let Some(named) = name_version(name) else {
        return reported;
    };
    if reported.is_empty() {
        return named;
    }
    let pieces = |v: &str| v.split('.').map(str::to_owned).collect::<Vec<_>>();
    let (n, r) = (pieces(&named), pieces(&reported));
    let encoded_otherwise = n.len() >= 3
        && r.len() >= 2
        && n[..2] == r[..2]
        && reported != named
        && !reported.starts_with(&format!("{named}."));
    if encoded_otherwise { named } else { reported }
}

/// What becomes of an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// An asset of this product (names as in the asset form).
    Asset {
        vendor_name: String,
        product_name: String,
    },
    Ignore,
    Unassigned,
}

/// Who decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Rule,
    BuiltIn,
    None,
}

/// A rule of the user (table `item_rules`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub id: i64,
    pub item_type: ItemType,
    pub key: String,
    pub resolution: Resolution,
    pub created_ms: i64,
}

/// Rules built in, by type and key; a key ending in `*` matches all keys that start with the rest.
/// Vendor and product as the CVE list names them, so that the matching finds them (checked against the data).
const BUILT_IN: &[(ItemType, &str, &str, &str)] = &[
    (ItemType::Win, "mozilla firefox", "Mozilla", "Firefox"),
    (
        ItemType::Win,
        "mozilla firefox esr",
        "Mozilla",
        "Firefox ESR",
    ),
    (
        ItemType::Win,
        "mozilla thunderbird",
        "Mozilla",
        "Thunderbird",
    ),
    (ItemType::Win, "google chrome", "Google", "Chrome"),
    (
        ItemType::Win,
        "microsoft edge",
        "Microsoft",
        "Edge Chromium",
    ),
    (
        ItemType::Win,
        "microsoft visual studio code",
        "Microsoft",
        "Visual Studio Code",
    ),
    (ItemType::Win, "7-zip", "7-Zip", "7-Zip"),
    (ItemType::Win, "winrar", "RARLAB", "WinRAR"),
    (ItemType::Win, "notepad++", "notepad-plus-plus", "notepad++"),
    (
        ItemType::Win,
        "vlc media player",
        "VideoLAN",
        "VLC media player",
    ),
    (ItemType::Win, "putty*", "PuTTY", "PuTTY"),
    (ItemType::Win, "winscp", "WinSCP", "WinSCP"),
    (
        ItemType::Win,
        "filezilla",
        "filezilla-project",
        "FileZilla Client",
    ),
    (ItemType::Win, "keepass password safe", "KeePass", "KeePass"),
    (ItemType::Win, "keepassxc", "KeePassXC", "KeePassXC"),
    (ItemType::Win, "libreoffice", "LibreOffice", "LibreOffice"),
    (
        ItemType::Win,
        "adobe acrobat reader*",
        "Adobe",
        "Acrobat Reader DC",
    ),
    (ItemType::Win, "adobe acrobat", "Adobe", "Acrobat DC"),
    (
        ItemType::Win,
        "foxit pdf reader",
        "Foxit Software",
        "Foxit Reader",
    ),
    (
        ItemType::Win,
        "sumatrapdf",
        "SumatraPDF Reader",
        "SumatraPDF",
    ),
    (ItemType::Win, "irfanview*", "IrfanView", "IrfanView"),
    (ItemType::Win, "gimp", "GIMP", "GIMP"),
    (ItemType::Win, "inkscape", "Inkscape", "Inkscape"),
    (ItemType::Win, "teamviewer", "TeamViewer", "TeamViewer"),
    (ItemType::Win, "anydesk", "AnyDesk", "AnyDesk"),
    (ItemType::Win, "zoom workplace", "Zoom", "Zoom"),
    (ItemType::Win, "openvpn", "OpenVPN", "OpenVPN"),
    (ItemType::Win, "wireshark", "Wireshark", "Wireshark"),
    (ItemType::Win, "git", "git-scm", "Git"),
    (ItemType::Win, "node.js", "Node.js", "Node.js"),
    (ItemType::Win, "python", "Python", "Python"),
    (
        ItemType::Win,
        "oracle virtualbox",
        "Oracle",
        "VM VirtualBox",
    ),
    (ItemType::Win, "docker desktop", "Docker", "Docker Desktop"),
    (ItemType::Snap, "firefox", "Mozilla", "Firefox"),
    (ItemType::Snap, "thunderbird", "Mozilla", "Thunderbird"),
    (ItemType::Snap, "code", "Microsoft", "Visual Studio Code"),
    (ItemType::Snap, "vlc", "VideoLAN", "VLC media player"),
    (ItemType::Snap, "libreoffice", "LibreOffice", "LibreOffice"),
    (ItemType::Snap, "gimp", "GIMP", "GIMP"),
    (ItemType::Snap, "inkscape", "Inkscape", "Inkscape"),
    (ItemType::Snap, "keepassxc", "KeePassXC", "KeePassXC"),
    (ItemType::Snap, "snapd", "Canonical", "snapd"),
    (ItemType::Snap, "lxd", "Canonical", "LXD"),
    (ItemType::Snap, "microk8s", "Canonical", "MicroK8s"),
    (ItemType::Snap, "multipass", "Canonical", "Multipass"),
    (ItemType::Snap, "juju", "Canonical", "Juju"),
    (
        ItemType::Flatpak,
        "org.mozilla.firefox",
        "Mozilla",
        "Firefox",
    ),
    (
        ItemType::Flatpak,
        "org.mozilla.thunderbird",
        "Mozilla",
        "Thunderbird",
    ),
    (
        ItemType::Flatpak,
        "com.visualstudio.code",
        "Microsoft",
        "Visual Studio Code",
    ),
    (
        ItemType::Flatpak,
        "org.videolan.vlc",
        "VideoLAN",
        "VLC media player",
    ),
    (
        ItemType::Flatpak,
        "org.libreoffice.libreoffice",
        "LibreOffice",
        "LibreOffice",
    ),
    (ItemType::Flatpak, "org.gimp.gimp", "GIMP", "GIMP"),
    (
        ItemType::Flatpak,
        "org.inkscape.inkscape",
        "Inkscape",
        "Inkscape",
    ),
    (
        ItemType::Flatpak,
        "org.keepassxc.keepassxc",
        "KeePassXC",
        "KeePassXC",
    ),
    (
        ItemType::Flatpak,
        "org.wireshark.wireshark",
        "Wireshark",
        "Wireshark",
    ),
];

/// The publishers of the store apps that come with Windows: updated by the Microsoft Store, not listed.
const STORE_PUBLISHERS_IGNORED: [&str; 2] = ["Microsoft Corporation", "Microsoft Windows"];

/// Publishers of Windows programs that are no program of their own: web apps installed from Chrome ("GitHub",
/// "Gemini Notebook") are listed with the publisher `Google\Chrome` and run inside the browser.
const WIN_PUBLISHERS_IGNORED: [&str; 1] = ["Google\\Chrome"];

/// Snaps that are no program of their own (bases, runtimes, themes) or small tools of Ubuntu itself without
/// entries in the CVE list; a trailing `*` matches a prefix.
const SNAPS_IGNORED: [&str; 17] = [
    "bare",
    "core",
    "core16",
    "core18",
    "core20",
    "core22",
    "core24",
    "core26",
    "gnome-*",
    "gtk-common-themes",
    "gtk2-common-themes",
    "kf5-*",
    "kf6-*",
    "mesa-*",
    "snapd-desktop-integration",
    "snap-store",
    "firmware-updater",
];

/// Whether a key fits a pattern of the built-in rules (`*` at the end for a prefix).
fn fits(pattern: &str, key: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => key.starts_with(prefix),
        None => key == pattern,
    }
}

/// The built-in rule of an entry, if there is one.
pub fn built_in(item_type: ItemType, key: &str, publisher: &str, name: &str) -> Option<Resolution> {
    if item_type == ItemType::Os {
        return Some(Resolution::Asset {
            vendor_name: "Microsoft".into(),
            product_name: name.to_owned(),
        });
    }
    let found = BUILT_IN
        .iter()
        .find(|(t, pattern, ..)| *t == item_type && fits(pattern, key));
    if let Some((_, _, vendor, product)) = found {
        return Some(Resolution::Asset {
            vendor_name: (*vendor).to_owned(),
            product_name: (*product).to_owned(),
        });
    }
    if item_type == ItemType::Appx && STORE_PUBLISHERS_IGNORED.contains(&publisher) {
        return Some(Resolution::Ignore);
    }
    if item_type == ItemType::Win && WIN_PUBLISHERS_IGNORED.contains(&publisher) {
        return Some(Resolution::Ignore);
    }
    if item_type == ItemType::Snap && SNAPS_IGNORED.iter().any(|p| fits(p, key)) {
        return Some(Resolution::Ignore);
    }
    None
}

/// How an entry is resolved: a rule of the user first, then the built-in rules.
pub fn resolve(
    rules: &std::collections::HashMap<(ItemType, String), Rule>,
    item_type: ItemType,
    key: &str,
    publisher: &str,
    name: &str,
) -> (Resolution, Source) {
    if item_type != ItemType::Os
        && let Some(rule) = rules.get(&(item_type, key.to_owned()))
    {
        return (rule.resolution.clone(), Source::Rule);
    }
    match built_in(item_type, key, publisher, name) {
        Some(r) => (r, Source::BuiltIn),
        None => (Resolution::Unassigned, Source::None),
    }
}

/// The display name without versions and the like, as a proposal for the product ("7-Zip 24.08 (x64)" → "7-Zip").
pub fn product_proposal(name: &str) -> String {
    strip_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn the_key_of_a_windows_program_stays_across_versions() {
        assert_eq!(name_key("7-Zip 24.08 (x64)"), "7-zip");
        assert_eq!(name_key("7-Zip 23.01"), "7-zip");
        assert_eq!(name_key("Mozilla Firefox (x64 de)"), "mozilla firefox");
        assert_eq!(
            name_key("Mozilla Firefox ESR (x64 de)"),
            "mozilla firefox esr"
        );
        assert_eq!(name_key("Notepad++ (64-bit x86)"), "notepad++");
        assert_eq!(name_key("Wireshark 4.4.1 x64"), "wireshark");
        assert_eq!(name_key("PuTTY release 0.81 (64-bit)"), "putty release");
        assert_eq!(
            name_key("Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.40.33810"),
            "microsoft visual c++ 2015-2022 redistributable"
        );
        assert_eq!(name_key("Java 8 Update 431 (64-bit)"), "java 8 update");
        assert_eq!(
            name_key("Microsoft 365 Apps for enterprise - de-de"),
            "microsoft 365 apps for enterprise"
        );
        assert_eq!(name_key("Python 3.12.7 (64-bit)"), "python");
        assert_eq!(name_key("(x64)"), "");
        assert_eq!(
            key(ItemType::Flatpak, "org.mozilla.Firefox", "Firefox"),
            "org.mozilla.firefox"
        );
        assert_eq!(
            key(
                ItemType::Appx,
                "Microsoft.WindowsTerminal_8wekyb3d8bbwe",
                "Microsoft.WindowsTerminal"
            ),
            "microsoft.windowsterminal"
        );
    }

    #[test]
    fn versions_are_cut_to_their_first_piece() {
        assert_eq!(clean_version("144.0.2-1"), "144.0.2");
        assert_eq!(clean_version("24.08"), "24.08");
        assert_eq!(clean_version("Version 6.3.5 build 1"), "6.3.5");
        assert_eq!(clean_version("8.0.4310.11"), "8.0.4310.11");
        assert_eq!(clean_version("2.10.38."), "2.10.38");
        assert_eq!(clean_version("9.6p1"), "9.6p1");
        assert_eq!(clean_version("latest"), "");
        assert_eq!(clean_version(""), "");
    }

    #[test]
    fn windows_programs_take_the_version_of_their_name_when_the_installer_encodes_it() {
        let v = |name, version| item_version(ItemType::Win, name, version);
        // The Python installer folds the release level into the third number.
        assert_eq!(v("Python 3.12.10 (64-bit)", "3.12.10150.0"), "3.12.10");
        assert_eq!(v("Python 3.13.0rc2 (64-bit)", "3.13.122.0"), "3.13.0rc2");
        // A longer form of the same version stays.
        assert_eq!(
            v("Microsoft .NET Runtime - 8.0.33 (x64)", "8.0.33.36622"),
            "8.0.33.36622"
        );
        assert_eq!(v("FileZilla 3.71.1", "3.71.1"), "3.71.1");
        // Two numbers in the name, another major version or no version in the name: as reported.
        assert_eq!(v("7-Zip 24.08 (x64)", "24.08.00.0"), "24.08.00.0");
        assert_eq!(
            v(
                "Windows Software Development Kit - Windows 10.0.26100.9457",
                "10.1.26100.9457"
            ),
            "10.1.26100.9457"
        );
        assert_eq!(v("Python Launcher", "3.14.7150.0"), "3.14.7150.0");
        assert_eq!(v("Google Chrome", "156.0.8078.80"), "156.0.8078.80");
        assert_eq!(
            v("Java 8 Update 431 (64-bit)", "8.0.4310.11"),
            "8.0.4310.11"
        );
        // Nothing reported: the name.
        assert_eq!(v("KeePass Password Safe 2.57", ""), "2.57");
        // Versions in brackets are no names.
        assert_eq!(v("Foo (1.2.3)", "1.2.30"), "1.2.30");
        // Other types and Windows itself as reported (cut to the first piece, Windows not at all).
        assert_eq!(
            item_version(ItemType::Snap, "firefox 1.2.3", "144.0.2-1"),
            "144.0.2"
        );
        assert_eq!(
            item_version(ItemType::Os, "Windows 11 Version 26H2", "10.0.26300.9711"),
            "10.0.26300.9711"
        );
    }

    #[test]
    fn entries_without_an_id_or_with_control_characters() {
        assert_eq!(Item::new(ItemType::Win, " ", "x", "", "", "", false), None);
        let i = Item::new(
            ItemType::Win,
            "{A}",
            "Fire\u{7}fox\n 1.2",
            "1.2\t",
            "Moz",
            "",
            true,
        )
        .unwrap();
        assert_eq!(i.name, "Firefox 1.2");
        assert_eq!(i.version, "1.2");
        assert_eq!(i.key, "firefox");
        assert!(i.user_scope);
        let long = "a".repeat(500);
        let i = Item::new(ItemType::Snap, &long, "", "", "", "", false).unwrap();
        assert_eq!(i.id.chars().count(), MAX_ID);
        assert_eq!(i.name, i.id);
        // Nothing left of the name: no key, no entry.
        assert_eq!(
            Item::new(ItemType::Win, "{B}", "(x64)", "", "", "", false),
            None
        );
    }

    #[test]
    fn rules_of_the_user_come_before_the_built_in_ones() {
        let mut rules = HashMap::new();
        let (r, s) = resolve(
            &rules,
            ItemType::Win,
            "mozilla firefox",
            "Mozilla",
            "Mozilla Firefox",
        );
        assert_eq!(s, Source::BuiltIn);
        assert_eq!(
            r,
            Resolution::Asset {
                vendor_name: "Mozilla".into(),
                product_name: "Firefox".into()
            }
        );
        assert_eq!(
            resolve(&rules, ItemType::Win, "putty release", "", "").1,
            Source::BuiltIn
        );
        assert_eq!(
            resolve(&rules, ItemType::Win, "unknown tool", "", ""),
            (Resolution::Unassigned, Source::None)
        );
        assert_eq!(
            resolve(
                &rules,
                ItemType::Appx,
                "microsoft.windowscalculator",
                "Microsoft Corporation",
                ""
            )
            .0,
            Resolution::Ignore
        );
        rules.insert(
            (ItemType::Win, "mozilla firefox".to_owned()),
            Rule {
                id: 1,
                item_type: ItemType::Win,
                key: "mozilla firefox".into(),
                resolution: Resolution::Ignore,
                created_ms: 0,
            },
        );
        assert_eq!(
            resolve(&rules, ItemType::Win, "mozilla firefox", "", ""),
            (Resolution::Ignore, Source::Rule)
        );
        // Windows itself is always the product the agent API named.
        assert_eq!(
            resolve(
                &rules,
                ItemType::Os,
                "windows",
                "Microsoft",
                "Windows 11 Version 24H2"
            )
            .0,
            Resolution::Asset {
                vendor_name: "Microsoft".into(),
                product_name: "Windows 11 Version 24H2".into()
            }
        );
    }

    #[test]
    fn web_apps_of_chrome_are_ignored() {
        let rules = HashMap::new();
        assert_eq!(
            resolve(&rules, ItemType::Win, "github", "Google\\Chrome", "GitHub"),
            (Resolution::Ignore, Source::BuiltIn)
        );
        // Chrome itself is assigned, another program called GitHub stays unassigned.
        assert!(matches!(
            resolve(
                &rules,
                ItemType::Win,
                "google chrome",
                "Google LLC",
                "Google Chrome"
            )
            .0,
            Resolution::Asset { .. }
        ));
        assert_eq!(
            resolve(&rules, ItemType::Win, "github", "GitHub, Inc.", "GitHub"),
            (Resolution::Unassigned, Source::None)
        );
    }

    #[test]
    fn base_snaps_are_ignored_and_canonicals_tools_assigned() {
        let rules = HashMap::new();
        for key in [
            "core22",
            "bare",
            "gnome-46-2404",
            "gtk-common-themes",
            "mesa-2404",
            "snap-store",
        ] {
            assert_eq!(
                resolve(&rules, ItemType::Snap, key, "canonical", key),
                (Resolution::Ignore, Source::BuiltIn),
                "{key}"
            );
        }
        // Only these names: a snap that starts like a base is a program of its own.
        for key in ["coredns", "corectrl", "gnome"] {
            assert_eq!(
                resolve(&rules, ItemType::Snap, key, "", key).0,
                Resolution::Unassigned,
                "{key}"
            );
        }
        assert_eq!(
            resolve(&rules, ItemType::Snap, "lxd", "canonical", "lxd").0,
            Resolution::Asset {
                vendor_name: "Canonical".into(),
                product_name: "LXD".into()
            }
        );
        // The same names among Flatpaks are not snaps.
        assert_eq!(
            resolve(&rules, ItemType::Flatpak, "core22", "", "core22").0,
            Resolution::Unassigned
        );
    }

    #[test]
    fn the_built_in_products_have_names_the_matching_knows() {
        // Each built-in product resolves to non-empty keys (the matching compares keys).
        for (_, pattern, vendor, product) in BUILT_IN {
            assert!(!crate::sources::name_key(vendor).is_empty(), "{pattern}");
            assert!(!crate::sources::name_key(product).is_empty(), "{pattern}");
            assert_eq!(*pattern, pattern.to_lowercase(), "keys are lower case");
        }
        for pattern in SNAPS_IGNORED {
            assert!(
                BUILT_IN
                    .iter()
                    .all(|(t, p, ..)| *t != ItemType::Snap || !fits(pattern, p))
            );
        }
        assert_eq!(product_proposal("7-Zip 24.08 (x64)"), "7-Zip");
        assert_eq!(
            product_proposal("Mozilla Firefox (x64 de)"),
            "Mozilla Firefox"
        );
    }
}
