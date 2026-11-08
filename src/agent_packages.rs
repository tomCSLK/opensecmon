//! The packages of opensecagent that come with opensecmon (`docs/agent-api.md`, "Updates of opensecagent"): read
//! once at start from `agent_packages_dir`, offered for download on the computers' pages and as updates to agents
//! that can install them. Only files with the expected names and a signature beside them are taken; opensecmon
//! passes the signature on and does not check it (the agent does, against the publisher's key).

use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::version::{Scheme, compare};

/// Where the package of opensecmon puts them.
pub const DEFAULT_DIR: &str = "/usr/share/opensecmon/agent";
/// The name of the agent program, as it reports itself (`agent.name`).
pub const AGENT_NAME: &str = "opensecagent";
/// Largest package file.
const FILE_MAX: u64 = 256 * 1024 * 1024;
/// Largest signature file.
const SIGNATURE_MAX: u64 = 4096;

/// The system a package is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum System {
    /// Debian, Ubuntu and systems based on them (`.deb`).
    Debian,
    Windows,
}

/// A package of opensecagent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    pub system: System,
    /// `amd64`/`arm64` (Debian), `x64`/`arm64` (Windows).
    pub arch: &'static str,
    /// The version of the agent (without the Debian revision).
    pub version: String,
    /// The file name, as offered for download.
    pub file: String,
    pub path: PathBuf,
    pub size: u64,
    /// SHA-256, hex.
    pub sha256: String,
    /// The SSH signature (`ssh-keygen -Y sign`), armored.
    pub signature: String,
}

/// The packages found at start.
#[derive(Debug, Clone, Default)]
pub struct Catalog {
    packages: Vec<Package>,
}

/// Two to four numbers with dots.
fn valid_version(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    (2..=4).contains(&parts.len())
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 6 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// System, architecture and version of a file name, if it is one of a package.
pub fn parse_name(name: &str) -> Option<(System, &'static str, String)> {
    if let Some(rest) = name
        .strip_prefix("opensecagent_")
        .and_then(|r| r.strip_suffix(".deb"))
    {
        let (version, arch) = rest.rsplit_once('_')?;
        let arch = match arch {
            "amd64" => "amd64",
            "arm64" => "arm64",
            _ => return None,
        };
        let upstream = match version.split_once('-') {
            Some((v, revision))
                if !revision.is_empty()
                    && revision.len() <= 6
                    && revision.bytes().all(|b| b.is_ascii_digit()) =>
            {
                v
            }
            Some(_) => return None,
            None => version,
        };
        return valid_version(upstream).then(|| (System::Debian, arch, upstream.to_owned()));
    }
    let rest = name
        .strip_prefix("opensecagent-")?
        .strip_suffix("-setup.exe")?;
    let (version, arch) = rest.rsplit_once('-')?;
    let arch = match arch {
        "x64" => "x64",
        "arm64" => "arm64",
        _ => return None,
    };
    valid_version(version).then(|| (System::Windows, arch, version.to_owned()))
}

/// The architecture of a package for what a computer reports (`os.arch`).
pub fn package_arch(system: System, reported: &str) -> Option<&'static str> {
    match (system, reported.trim().to_ascii_lowercase().as_str()) {
        (System::Debian, "x86_64" | "amd64") => Some("amd64"),
        (System::Debian, "aarch64" | "arm64") => Some("arm64"),
        (System::Windows, "x64" | "amd64" | "x86_64") => Some("x64"),
        (System::Windows, "arm64" | "aarch64") => Some("arm64"),
        _ => None,
    }
}

fn read_signature(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > SIGNATURE_MAX {
        return None;
    }
    let text = std::fs::read_to_string(path).ok()?;
    let trimmed = text.trim();
    (trimmed.is_ascii()
        && trimmed.starts_with("-----BEGIN SSH SIGNATURE-----")
        && trimmed.ends_with("-----END SSH SIGNATURE-----"))
    .then(|| format!("{trimmed}\n"))
}

fn digest(path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buffer).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Some(crate::auth::hex(&hasher.finalize()))
}

impl Catalog {
    /// Reads the folder; a missing folder is an empty catalogue. Files that do not fit are skipped with a warning.
    pub fn load(dir: &Path) -> Self {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Self::default();
        };
        let mut names: Vec<String> = entries
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .collect();
        names.sort();
        let mut packages = Vec::new();
        for name in names {
            // Signatures are read with their package; other files (the README of the folder) are no packages.
            if name.ends_with(".sig") || !name.starts_with("opensecagent") {
                continue;
            }
            let Some((system, arch, version)) = parse_name(&name) else {
                tracing::warn!(file = %name, folder = %dir.display(), "agent package skipped: unknown name");
                continue;
            };
            let path = dir.join(&name);
            let Ok(meta) = std::fs::metadata(&path) else {
                continue;
            };
            if !meta.is_file() || meta.len() > FILE_MAX || meta.len() == 0 {
                tracing::warn!(file = %name, "agent package skipped: not a file, empty or too large");
                continue;
            }
            let Some(signature) = read_signature(&dir.join(format!("{name}.sig"))) else {
                tracing::warn!(file = %name, "agent package skipped: no signature beside it");
                continue;
            };
            let Some(sha256) = digest(&path) else {
                tracing::warn!(file = %name, "agent package skipped: cannot be read");
                continue;
            };
            packages.push(Package {
                system,
                arch,
                version,
                file: name,
                path,
                size: meta.len(),
                sha256,
                signature,
            });
        }
        if !packages.is_empty() {
            tracing::info!(count = packages.len(), folder = %dir.display(), "agent packages found");
        }
        Self { packages }
    }

    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }

    /// The highest version for a system and architecture.
    pub fn latest(&self, system: System, arch: &str) -> Option<&Package> {
        self.packages
            .iter()
            .filter(|p| p.system == system && p.arch == arch)
            .max_by(|a, b| compare(Scheme::Generic, &a.version, &b.version))
    }

    /// The newest package of each system and architecture, for download (Windows x64 and Debian amd64 first).
    pub fn downloads(&self) -> Vec<&Package> {
        let mut out: Vec<&Package> = Vec::new();
        for (system, arch) in [
            (System::Windows, "x64"),
            (System::Debian, "amd64"),
            (System::Windows, "arm64"),
            (System::Debian, "arm64"),
        ] {
            out.extend(self.latest(system, arch));
        }
        out
    }

    /// A package by its file name (only those in the catalogue, so no path ever comes from a request).
    pub fn file(&self, name: &str) -> Option<&Package> {
        self.packages.iter().find(|p| p.file == name)
    }

    /// The package a computer would be updated to: its agent can install updates, and there is a higher version
    /// for its system and architecture than the one it reports.
    pub fn update_for(
        &self,
        windows: bool,
        arch: &str,
        agent_name: &str,
        agent_version: &str,
        can_update: bool,
    ) -> Option<&Package> {
        if !can_update || agent_name != AGENT_NAME {
            return None;
        }
        let system = if windows {
            System::Windows
        } else {
            System::Debian
        };
        let package = self.latest(system, package_arch(system, arch)?)?;
        (compare(Scheme::Generic, &package.version, agent_version).is_gt()).then_some(package)
    }

    #[cfg(test)]
    pub fn with(packages: Vec<Package>) -> Self {
        Self { packages }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIG: &str = "-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\n-----END SSH SIGNATURE-----\n";

    #[test]
    fn names_are_read_strictly() {
        assert_eq!(
            parse_name("opensecagent_0.2.0-1_amd64.deb"),
            Some((System::Debian, "amd64", "0.2.0".to_owned()))
        );
        assert_eq!(
            parse_name("opensecagent_1.10_arm64.deb"),
            Some((System::Debian, "arm64", "1.10".to_owned()))
        );
        assert_eq!(
            parse_name("opensecagent-0.2.0-x64-setup.exe"),
            Some((System::Windows, "x64", "0.2.0".to_owned()))
        );
        for bad in [
            "opensecagent_0.2.0-1_i386.deb",
            "opensecagent_0.2.0-1a_amd64.deb",
            "opensecagent_0.2.0-_amd64.deb",
            "opensecagent_2_amd64.deb",
            "opensecagent_0.2.0.1.5_amd64.deb",
            "opensecagent_../x_amd64.deb",
            "opensecagent-0.2.0-x86-setup.exe",
            "opensecagent-0.2.0-x64.exe",
            "opensecagent-v0.2.0-x64-setup.exe",
            "other_0.2.0-1_amd64.deb",
            "opensecagent_0.2.0-1_amd64.deb.sig",
        ] {
            assert_eq!(parse_name(bad), None, "{bad}");
        }
    }

    #[test]
    fn architectures_follow_what_the_computer_reports() {
        assert_eq!(package_arch(System::Debian, "x86_64"), Some("amd64"));
        assert_eq!(package_arch(System::Debian, "aarch64"), Some("arm64"));
        assert_eq!(package_arch(System::Windows, "x64"), Some("x64"));
        assert_eq!(package_arch(System::Windows, "AMD64"), Some("x64"));
        assert_eq!(package_arch(System::Windows, "ARM64"), Some("arm64"));
        assert_eq!(package_arch(System::Debian, ""), None);
        assert_eq!(package_arch(System::Debian, "riscv64"), None);
    }

    #[test]
    fn the_folder_is_read_with_signatures_and_checksums() {
        let dir = tempfile::tempdir().unwrap();
        let put =
            |name: &str, content: &[u8]| std::fs::write(dir.path().join(name), content).unwrap();
        put("opensecagent_0.1.0-1_amd64.deb", b"old");
        put("opensecagent_0.1.0-1_amd64.deb.sig", SIG.as_bytes());
        put("opensecagent_0.10.0-1_amd64.deb", b"new");
        put("opensecagent_0.10.0-1_amd64.deb.sig", SIG.as_bytes());
        put("opensecagent_0.11.0-1_amd64.deb", b"unsigned");
        put("opensecagent_0.12.0-1_amd64.deb", b"bad signature");
        put("opensecagent_0.12.0-1_amd64.deb.sig", b"not a signature");
        put("opensecagent-0.10.0-x64-setup.exe", b"setup");
        put("opensecagent-0.10.0-x64-setup.exe.sig", SIG.as_bytes());
        put("readme.txt", b"other");
        put("opensecagent_0.13.0-1_arm64.deb", b"");
        put("opensecagent_0.13.0-1_arm64.deb.sig", SIG.as_bytes());
        let c = Catalog::load(dir.path());
        let deb = c.latest(System::Debian, "amd64").unwrap();
        assert_eq!(
            deb.version, "0.10.0",
            "0.10 is newer than 0.1; unsigned or badly signed are skipped"
        );
        assert_eq!(deb.size, 3);
        assert_eq!(deb.sha256, crate::auth::hex(&Sha256::digest(b"new")));
        assert_eq!(deb.signature, SIG);
        assert!(c.latest(System::Debian, "arm64").is_none(), "empty file");
        assert_eq!(c.downloads().len(), 2);
        assert_eq!(c.downloads()[0].system, System::Windows);
        assert!(c.file("opensecagent_0.1.0-1_amd64.deb").is_some());
        assert!(c.file("opensecagent_0.11.0-1_amd64.deb").is_none());
        assert!(c.file("../opensecagent_0.1.0-1_amd64.deb").is_none());
        assert!(Catalog::load(&dir.path().join("missing")).is_empty());
    }

    #[test]
    fn an_update_needs_an_agent_that_can_install_it_and_a_higher_version() {
        let p = |system, arch, version: &str| Package {
            system,
            arch,
            version: version.to_owned(),
            file: format!("f-{version}-{arch}"),
            path: PathBuf::new(),
            size: 1,
            sha256: String::new(),
            signature: SIG.to_owned(),
        };
        let c = Catalog::with(vec![
            p(System::Debian, "amd64", "0.2.0"),
            p(System::Windows, "x64", "0.3.0"),
        ]);
        assert_eq!(
            c.update_for(false, "x86_64", AGENT_NAME, "0.1.0", true)
                .unwrap()
                .version,
            "0.2.0"
        );
        assert_eq!(
            c.update_for(true, "x64", AGENT_NAME, "0.2.9", true)
                .unwrap()
                .version,
            "0.3.0"
        );
        assert!(
            c.update_for(false, "x86_64", AGENT_NAME, "0.2.0", true)
                .is_none(),
            "same"
        );
        assert!(
            c.update_for(false, "x86_64", AGENT_NAME, "0.3.0", true)
                .is_none(),
            "newer"
        );
        assert!(
            c.update_for(false, "x86_64", AGENT_NAME, "0.1.0", false)
                .is_none(),
            "cannot"
        );
        assert!(
            c.update_for(false, "x86_64", "opensecmon-agent.sh", "0.1.0", true)
                .is_none(),
            "script"
        );
        assert!(
            c.update_for(false, "aarch64", AGENT_NAME, "0.1.0", true)
                .is_none(),
            "no package"
        );
        assert!(
            c.update_for(false, "", AGENT_NAME, "0.1.0", true).is_none(),
            "unknown arch"
        );
    }
}
