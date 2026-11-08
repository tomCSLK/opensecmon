//! Windows as an asset, from what an agent reads in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`
//! (`ProductName`, `DisplayVersion`, `CurrentBuild`, `UBR`, `InstallationType`).
//!
//! The product is named as Microsoft names it as CNA in the CVE list ("Windows 11 Version 24H2", "Windows Server
//! 2022"), the version is `10.0.<build>.<UBR>`, as the ranges there are written ("10.0.26100.0" to less than
//! "10.0.26100.9711"). So the matching needs nothing of its own, and the version follows every patch day.

/// Windows 10 and 11: the release of a build (feature updates keep their build for good).
const CLIENT: [(u32, &str); 19] = [
    (10240, "1507"),
    (10586, "1511"),
    (14393, "1607"),
    (15063, "1703"),
    (16299, "1709"),
    (17134, "1803"),
    (17763, "1809"),
    (18362, "1903"),
    (18363, "1909"),
    (19041, "2004"),
    (19042, "20H2"),
    (19043, "21H1"),
    (19044, "21H2"),
    (19045, "22H2"),
    (22000, "21H2"),
    (22621, "22H2"),
    (22631, "23H2"),
    (26100, "24H2"),
    (26200, "25H2"),
];

/// Windows Server by build, as the CNA names the products.
const SERVER: [(u32, &str); 5] = [
    (14393, "Windows Server 2016"),
    (17763, "Windows Server 2019"),
    (20348, "Windows Server 2022"),
    (25398, "Windows Server 2022, 23H2 Edition"),
    (26100, "Windows Server 2025"),
];

/// The first build of Windows 11 (`ProductName` still says "Windows 10" there).
const WINDOWS_11: u32 = 22000;

/// Windows as the asset of a computer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSystem {
    /// For the list of computers: "Windows 11 Pro 24H2".
    pub os_name: String,
    /// The product as the CNA names it: "Windows 11 Version 24H2".
    pub product: String,
    /// `10.0.<build>.<UBR>`.
    pub version: String,
    /// "24H2", or "" for a server without one.
    pub release: String,
}

/// Whether a text is a release as `DisplayVersion` gives it ("24H2", "1809").
fn is_release(s: &str) -> bool {
    let b = s.as_bytes();
    match b.len() {
        4 => {
            b[..2].iter().all(u8::is_ascii_digit)
                && ((b[2] == b'H' && b[3].is_ascii_digit())
                    || b[2..].iter().all(u8::is_ascii_digit))
        }
        _ => false,
    }
}

/// The asset of a Windows system; `None` for Windows before 10 or a server build this version does not know.
pub fn system(
    product_name: &str,
    display_version: &str,
    build: u32,
    ubr: u32,
    installation_type: &str,
) -> Option<WindowsSystem> {
    let display_version = display_version.trim();
    let version = format!("10.0.{build}.{ubr}");
    let server = product_name.to_ascii_lowercase().contains("server")
        || installation_type.to_ascii_lowercase().starts_with("server");
    if server {
        let name = SERVER.iter().find(|(b, _)| *b == build)?.1;
        let core = installation_type.eq_ignore_ascii_case("server core");
        // The 23H2 edition only exists as Server Core, the CNA names it so.
        let product = if core || build == 25398 {
            format!("{name} (Server Core installation)")
        } else {
            name.to_owned()
        };
        return Some(WindowsSystem {
            os_name: product_name.trim().to_owned(),
            product,
            version,
            release: if is_release(display_version) {
                display_version.to_owned()
            } else {
                String::new()
            },
        });
    }
    if build < 10240 {
        return None;
    }
    let release = match CLIENT.iter().find(|(b, _)| *b == build) {
        Some((_, r)) => (*r).to_owned(),
        None if is_release(display_version) => display_version.to_owned(),
        None => return None,
    };
    let major = if build >= WINDOWS_11 { "11" } else { "10" };
    let os_name = product_name
        .trim()
        .replacen("Windows 10", &format!("Windows {major}"), 1);
    Some(WindowsSystem {
        os_name: format!("{os_name} {release}").trim().to_owned(),
        product: format!("Windows {major} Version {release}"),
        version,
        release,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_windows_as_microsoft_does_in_the_cve_list() {
        // Windows 11 still calls itself "Windows 10" in ProductName.
        let s = system("Windows 10 Pro", "24H2", 26100, 4652, "Client").unwrap();
        assert_eq!(s.product, "Windows 11 Version 24H2");
        assert_eq!(s.version, "10.0.26100.4652");
        assert_eq!(s.os_name, "Windows 11 Pro 24H2");
        assert_eq!(s.release, "24H2");
        let s = system("Windows 10 Home", "22H2", 19045, 6456, "Client").unwrap();
        assert_eq!(s.product, "Windows 10 Version 22H2");
        // LTSC 2021 is 21H2 for the CNA; the build decides, not the text.
        let s = system("Windows 10 Enterprise LTSC 2021", "", 19044, 6575, "Client").unwrap();
        assert_eq!(s.product, "Windows 10 Version 21H2");
        // A build newer than the table: its DisplayVersion.
        let s = system("Windows 10 Pro", "26H1", 28000, 1, "Client").unwrap();
        assert_eq!(s.product, "Windows 11 Version 26H1");
        assert_eq!(system("Windows 10 Pro", "", 28000, 1, "Client"), None);
        assert_eq!(system("Windows 10 Pro", "evil\n", 28000, 1, "Client"), None);
        assert_eq!(
            system("Windows 7 Professional", "", 7601, 0, "Client"),
            None
        );
    }

    #[test]
    fn names_the_servers_by_their_build() {
        let s = system(
            "Windows Server 2025 Standard",
            "24H2",
            26100,
            4652,
            "Server",
        )
        .unwrap();
        assert_eq!(s.product, "Windows Server 2025");
        assert_eq!(s.os_name, "Windows Server 2025 Standard");
        let s = system(
            "Windows Server 2022 Datacenter",
            "21H2",
            20348,
            4405,
            "Server Core",
        )
        .unwrap();
        assert_eq!(s.product, "Windows Server 2022 (Server Core installation)");
        let s = system("Windows Server Datacenter", "23H2", 25398, 1, "Server Core").unwrap();
        assert_eq!(
            s.product,
            "Windows Server 2022, 23H2 Edition (Server Core installation)"
        );
        assert_eq!(
            system("Windows Server 2012 R2", "", 9600, 0, "Server"),
            None
        );
    }
}
