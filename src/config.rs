//! Configuration: TOML file with environment overrides.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::auth::throttle::ClientIpHeader;

/// Environment variable with the path of the config file (used when `--config` is not given).
pub const ENV_CONFIG: &str = "OPENSECMON_CONFIG";
const ENV_LISTEN: &str = "OPENSECMON_LISTEN";
const ENV_TLS_CERT_FILE: &str = "OPENSECMON_TLS_CERT_FILE";
const ENV_TLS_KEY_FILE: &str = "OPENSECMON_TLS_KEY_FILE";
const ENV_DATABASE_PATH: &str = "OPENSECMON_DATABASE_PATH";
const ENV_LOG_FILTER: &str = "OPENSECMON_LOG_FILTER";
const ENV_SECRET_KEY_FILE: &str = "OPENSECMON_SECRET_KEY_FILE";
const ENV_GENERATE_MISSING: &str = "OPENSECMON_GENERATE_MISSING";
const ENV_COOKIE_SECURE: &str = "OPENSECMON_COOKIE_SECURE";
const ENV_SESSION_TTL_HOURS: &str = "OPENSECMON_SESSION_TTL_HOURS";
const ENV_SESSION_IDLE_MINUTES: &str = "OPENSECMON_SESSION_IDLE_MINUTES";
const ENV_CLIENT_IP_HEADER: &str = "OPENSECMON_CLIENT_IP_HEADER";
const ENV_ALLOWED_HOSTS: &str = "OPENSECMON_ALLOWED_HOSTS";
const ENV_RETENTION_AUDIT_DAYS: &str = "OPENSECMON_RETENTION_AUDIT_DAYS";
const ENV_TIME_ZONE: &str = "OPENSECMON_TIME_ZONE";
const ENV_FETCH_SOURCES: &str = "OPENSECMON_FETCH_SOURCES";
const ENV_AGENT_NETWORKS: &str = "OPENSECMON_AGENT_NETWORKS";
const ENV_AGENT_PACKAGES_DIR: &str = "OPENSECMON_AGENT_PACKAGES_DIR";
const ENV_BACKUP_DIR: &str = "OPENSECMON_BACKUP_DIR";
const ENV_BACKUP_KEEP: &str = "OPENSECMON_BACKUP_KEEP";
const ENV_BACKUP_TIME: &str = "OPENSECMON_BACKUP_TIME";
/// Most backups `backup_keep` may ask for.
const MAX_BACKUP_KEEP: u32 = 1_000;
const MAX_SESSION_TTL_HOURS: u64 = 24 * 90;
const MAX_SESSION_IDLE_MINUTES: u64 = 24 * 60;
const MAX_ALLOWED_HOSTS: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read config file {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid config file: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid value in {name}: {reason}")]
    InvalidEnv { name: &'static str, reason: String },
    #[error("invalid configuration: {0}")]
    Invalid(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Address the web server binds to. Without `tls_cert_file`/`tls_key_file` it speaks plain HTTP and belongs
    /// on loopback behind a TLS reverse proxy (the default, `127.0.0.1:8090`); with them it speaks only HTTPS and
    /// may be any address, e.g. `0.0.0.0:8444`.
    pub listen: SocketAddr,
    /// Certificate chain (PEM) for the built-in HTTPS; together with `tls_key_file` the server speaks only HTTPS
    /// on `listen`, and plain HTTP there gets a redirect.
    pub tls_cert_file: Option<PathBuf>,
    /// Private key (PEM, mode 0600) of the certificate.
    pub tls_key_file: Option<PathBuf>,
    /// Path of the SQLite database file.
    pub database_path: PathBuf,
    /// `tracing` filter directive, e.g. `info,opensecmon=debug`. `RUST_LOG` takes precedence.
    pub log_filter: String,
    /// File with the 256-bit key (64 hex characters, mode 0600) that encrypts stored secrets (SMTP password,
    /// later the SSH key). Create it with `opensecmon key generate`; losing it makes stored secrets unreadable.
    pub secret_key_file: PathBuf,
    /// Create a missing `secret_key_file` and a missing certificate (self-signed, when both TLS files are
    /// set and neither exists) when the server starts. Off by default: the `.deb` creates them during the
    /// installation; the container image switches it on.
    pub generate_missing: bool,
    /// Mark session cookies `Secure`. Keep `true` behind a TLS reverse proxy; only plain-HTTP development needs `false`.
    pub cookie_secure: bool,
    /// Absolute session lifetime in hours.
    pub session_ttl_hours: u64,
    /// Sign users out after this many minutes without a click or key press; `0` switches it off.
    pub session_idle_minutes: u64,
    /// Header that carries the real client address behind a reverse proxy (`x-forwarded-for`, last entry, or
    /// `x-real-ip`). Only set it if the proxy always overwrites/appends it and the service is not reachable
    /// directly; the login throttling uses this address. Unset: the TCP peer address.
    pub client_ip_header: Option<ClientIpHeader>,
    /// Host names (optionally with port) the interface may be opened under, e.g. `["secmon.example.org"]`.
    /// Other `Host` headers are refused, which blocks DNS rebinding. Empty: any host name.
    pub allowed_hosts: Vec<String>,
    /// Days entries of the audit log (changes, sign-ins) are kept (1 to 36500).
    pub retention_audit_days: u32,
    /// Time zone of the daily report, the mails and the backup time, e.g. `Europe/Berlin`; unset = the
    /// system's (`TZ`, else `/etc/localtime`).
    pub time_zone: Option<String>,
    /// Fetch the sources on their schedule. `false` only shows what the database has (e.g. a test instance
    /// with a copied database); "fetch now" on the sources page still works.
    pub fetch_sources: bool,
    /// Networks (CIDR) computers may enroll and report from (agent API). Unset: private and local addresses;
    /// `[]` switches the agent API off.
    pub agent_networks: Option<Vec<String>>,
    /// Folder with the packages of opensecagent that are offered for download and as updates (the package of
    /// opensecmon installs them there). Unset: `/usr/share/opensecmon/agent`.
    pub agent_packages_dir: Option<PathBuf>,
    /// Directory for a daily backup made by the server itself (the container image sets it); unset = none
    /// (the `.deb` uses a systemd timer instead).
    pub backup_dir: Option<PathBuf>,
    /// How many of those backups are kept (1 to 1000); older ones are deleted.
    pub backup_keep: u32,
    /// Local time of that backup, `HH:MM` (24 hours).
    pub backup_time: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 8090)),
            tls_cert_file: None,
            tls_key_file: None,
            database_path: PathBuf::from("/var/lib/opensecmon/opensecmon.db"),
            log_filter: "info".to_owned(),
            secret_key_file: PathBuf::from("/etc/opensecmon/secret.key"),
            generate_missing: false,
            cookie_secure: true,
            session_ttl_hours: 168,
            session_idle_minutes: 30,
            client_ip_header: None,
            allowed_hosts: Vec::new(),
            retention_audit_days: 730,
            time_zone: None,
            fetch_sources: true,
            agent_networks: None,
            agent_packages_dir: None,
            backup_dir: None,
            backup_keep: 14,
            backup_time: "03:30".to_owned(),
        }
    }
}

impl Config {
    /// Where downloads of the sources are kept while they are processed: `downloads/` next to the database.
    /// The time zone of reports and mails: `time_zone`, else the system's.
    pub fn zone(&self) -> jiff::tz::TimeZone {
        self.time_zone
            .as_deref()
            .and_then(|name| jiff::tz::TimeZone::get(name).ok())
            .unwrap_or_else(jiff::tz::TimeZone::system)
    }

    pub fn download_dir(&self) -> PathBuf {
        self.database_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .join("downloads")
    }

    /// The networks of the agent API (checked by `validate`).
    pub fn agent_networks(&self) -> Vec<crate::agent::Network> {
        match &self.agent_networks {
            None => crate::agent::default_networks(),
            Some(list) => list
                .iter()
                .filter_map(|n| crate::agent::Network::parse(n))
                .collect(),
        }
    }

    /// The folder of the opensecagent packages.
    pub fn agent_packages_dir(&self) -> PathBuf {
        self.agent_packages_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from(crate::agent_packages::DEFAULT_DIR))
    }

    /// Certificate and key of the built-in HTTPS, if both are set.
    pub fn tls_files(&self) -> Option<(&Path, &Path)> {
        Some((
            self.tls_cert_file.as_deref()?,
            self.tls_key_file.as_deref()?,
        ))
    }

    /// Loads the config from an optional file, then applies `OPENSECMON_*` environment overrides.
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        let text = match path {
            Some(path) => Some(
                fs::read_to_string(path).map_err(|source| ConfigError::Read {
                    path: path.to_owned(),
                    source,
                })?,
            ),
            None => None,
        };
        Self::from_sources(text.as_deref(), |name| std::env::var(name).ok())
    }

    /// Builds the config from TOML text and an environment lookup (injectable for tests).
    pub fn from_sources(
        toml_text: Option<&str>,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, ConfigError> {
        let mut config: Self = match toml_text {
            Some(text) => toml::from_str(text)?,
            None => Self::default(),
        };

        let env = Env(&env);
        if let Some(value) = env.parsed(ENV_LISTEN)? {
            config.listen = value;
        }
        if let Some(value) = env.optional(ENV_TLS_CERT_FILE) {
            config.tls_cert_file = value.map(PathBuf::from);
        }
        if let Some(value) = env.optional(ENV_TLS_KEY_FILE) {
            config.tls_key_file = value.map(PathBuf::from);
        }
        if let Some(value) = env.text(ENV_DATABASE_PATH) {
            config.database_path = PathBuf::from(value);
        }
        if let Some(value) = env.text(ENV_LOG_FILTER) {
            config.log_filter = value;
        }
        if let Some(value) = env.text(ENV_SECRET_KEY_FILE) {
            config.secret_key_file = PathBuf::from(value);
        }
        if let Some(value) = env.parsed(ENV_GENERATE_MISSING)? {
            config.generate_missing = value;
        }
        if let Some(value) = env.parsed(ENV_COOKIE_SECURE)? {
            config.cookie_secure = value;
        }
        if let Some(value) = env.parsed(ENV_SESSION_TTL_HOURS)? {
            config.session_ttl_hours = value;
        }
        if let Some(value) = env.parsed(ENV_SESSION_IDLE_MINUTES)? {
            config.session_idle_minutes = value;
        }
        if let Some(value) = env.optional(ENV_CLIENT_IP_HEADER) {
            config.client_ip_header = value
                .map(|v| env.keyword(ENV_CLIENT_IP_HEADER, &v))
                .transpose()?;
        }
        if let Some(value) = env.text(ENV_ALLOWED_HOSTS) {
            config.allowed_hosts = list(&value);
        }
        if let Some(value) = env.parsed(ENV_RETENTION_AUDIT_DAYS)? {
            config.retention_audit_days = value;
        }
        if let Some(value) = env.optional(ENV_TIME_ZONE) {
            config.time_zone = value;
        }
        if let Some(value) = env.parsed(ENV_FETCH_SOURCES)? {
            config.fetch_sources = value;
        }
        if let Some(value) = env.optional(ENV_AGENT_NETWORKS) {
            // Empty: the default (private and local addresses); "none": the agent API is off, like `[]`.
            config.agent_networks = value.map(|v| {
                if v.trim().eq_ignore_ascii_case("none") {
                    Vec::new()
                } else {
                    list(&v)
                }
            });
        }
        if let Some(value) = env.optional(ENV_AGENT_PACKAGES_DIR) {
            config.agent_packages_dir = value.map(PathBuf::from);
        }
        if let Some(value) = env.optional(ENV_BACKUP_DIR) {
            config.backup_dir = value.map(PathBuf::from);
        }
        if let Some(value) = env.parsed(ENV_BACKUP_KEEP)? {
            config.backup_keep = value;
        }
        if let Some(value) = env.text(ENV_BACKUP_TIME) {
            config.backup_time = value;
        }

        config.validate()?;
        Ok(config)
    }

    /// Minutes after local midnight of the daily backup (`backup_time`, checked by [`Config::validate`]).
    pub fn backup_minute(&self) -> u16 {
        parse_time_of_day(&self.backup_time).unwrap_or(3 * 60 + 30)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.database_path.as_os_str().is_empty() {
            return Err(ConfigError::Invalid("database_path must not be empty"));
        }
        if self.secret_key_file.as_os_str().is_empty() {
            return Err(ConfigError::Invalid("secret_key_file must not be empty"));
        }
        if self.log_filter.trim().is_empty() {
            return Err(ConfigError::Invalid("log_filter must not be empty"));
        }
        match (&self.tls_cert_file, &self.tls_key_file) {
            (None, None) => {}
            (Some(cert), Some(key)) => {
                if cert.as_os_str().is_empty() || key.as_os_str().is_empty() {
                    return Err(ConfigError::Invalid(
                        "tls_cert_file and tls_key_file must not be empty",
                    ));
                }
            }
            _ => {
                return Err(ConfigError::Invalid(
                    "set both tls_cert_file and tls_key_file, or neither",
                ));
            }
        }
        if !(1..=MAX_SESSION_TTL_HOURS).contains(&self.session_ttl_hours) {
            return Err(ConfigError::Invalid(
                "session_ttl_hours must be between 1 and 2160",
            ));
        }
        if self.session_idle_minutes > MAX_SESSION_IDLE_MINUTES {
            return Err(ConfigError::Invalid(
                "session_idle_minutes must be between 0 (off) and 1440",
            ));
        }
        if self.allowed_hosts.len() > MAX_ALLOWED_HOSTS {
            return Err(ConfigError::Invalid(
                "allowed_hosts takes at most 32 entries",
            ));
        }
        let host_ok = |h: &String| {
            !h.is_empty()
                && h.len() <= 260
                && h.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-.:[]".contains(&b))
        };
        if !self.allowed_hosts.iter().all(host_ok) {
            return Err(ConfigError::Invalid(
                "allowed_hosts must contain host names, optionally with a port (e.g. \"secmon.example.org\")",
            ));
        }
        if !(1..=36_500).contains(&self.retention_audit_days) {
            return Err(ConfigError::Invalid(
                "retention_audit_days must be between 1 and 36500",
            ));
        }
        if let Some(list) = &self.agent_networks {
            if list.len() > crate::agent::MAX_NETWORKS {
                return Err(ConfigError::Invalid(
                    "agent_networks takes at most 64 entries",
                ));
            }
            if list
                .iter()
                .any(|n| crate::agent::Network::parse(n).is_none())
            {
                return Err(ConfigError::Invalid(
                    "agent_networks must contain networks in CIDR notation (e.g. \"192.168.1.0/24\") or addresses",
                ));
            }
        }
        if let Some(zone) = &self.time_zone
            && jiff::tz::TimeZone::get(zone).is_err()
        {
            return Err(ConfigError::Invalid(
                "time_zone is not a known time zone (e.g. \"Europe/Berlin\", see timedatectl list-timezones)",
            ));
        }
        if self
            .backup_dir
            .as_ref()
            .is_some_and(|dir| dir.as_os_str().is_empty())
        {
            return Err(ConfigError::Invalid("backup_dir must not be empty"));
        }
        if !(1..=MAX_BACKUP_KEEP).contains(&self.backup_keep) {
            return Err(ConfigError::Invalid(
                "backup_keep must be between 1 and 1000",
            ));
        }
        if parse_time_of_day(&self.backup_time).is_none() {
            return Err(ConfigError::Invalid(
                "backup_time must be a time of day like \"03:30\"",
            ));
        }
        Ok(())
    }
}

/// `HH:MM` (24 hours) as minutes after midnight.
fn parse_time_of_day(text: &str) -> Option<u16> {
    let (hours, minutes) = text.trim().split_once(':')?;
    let digits = |s: &str| (1..=2).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(hours) || minutes.len() != 2 || !digits(minutes) {
        return None;
    }
    let (hours, minutes): (u16, u16) = (hours.parse().ok()?, minutes.parse().ok()?);
    (hours < 24 && minutes < 60).then_some(hours * 60 + minutes)
}

/// A list in a variable: entries separated by commas or white space.
fn list(value: &str) -> Vec<String> {
    value
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Reads the `OPENSECMON_*` variables. An empty value of an optional setting (a path, the proxy header,
/// the time zone, the agent networks) unsets it, e.g. `OPENSECMON_TLS_CERT_FILE=` switches off a
/// certificate from the file.
struct Env<'a, F: Fn(&str) -> Option<String>>(&'a F);

impl<F: Fn(&str) -> Option<String>> Env<'_, F> {
    fn text(&self, name: &str) -> Option<String> {
        (self.0)(name)
    }

    /// `Some(None)` for an empty value.
    fn optional(&self, name: &str) -> Option<Option<String>> {
        self.text(name)
            .map(|value| Some(value).filter(|v| !v.trim().is_empty()))
    }

    fn parsed<T>(&self, name: &'static str) -> Result<Option<T>, ConfigError>
    where
        T: std::str::FromStr,
        T::Err: std::fmt::Display,
    {
        self.text(name)
            .map(|value| {
                value
                    .trim()
                    .parse()
                    .map_err(|e: T::Err| ConfigError::InvalidEnv {
                        name,
                        reason: e.to_string(),
                    })
            })
            .transpose()
    }

    /// A value of a setting that takes one of a few words (as in the file, e.g. `x-forwarded-for`).
    fn keyword<T: serde::de::DeserializeOwned>(
        &self,
        name: &'static str,
        value: &str,
    ) -> Result<T, ConfigError> {
        use serde::de::IntoDeserializer;
        let word: serde::de::value::StrDeserializer<'_, serde::de::value::Error> =
            value.trim().into_deserializer();
        T::deserialize(word).map_err(|e| ConfigError::InvalidEnv {
            name,
            reason: e.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn https_needs_both_files() {
        let config = Config::from_sources(None, no_env).unwrap();
        assert_eq!(config.tls_files(), None);
        let both = "listen = \"0.0.0.0:8444\"\ntls_cert_file = \"/etc/c.pem\"\ntls_key_file = \"/etc/k.pem\"";
        let config = Config::from_sources(Some(both), no_env).unwrap();
        assert_eq!(
            config.tls_files(),
            Some((Path::new("/etc/c.pem"), Path::new("/etc/k.pem")))
        );
        for bad in [
            "tls_cert_file = \"/etc/c.pem\"",
            "tls_key_file = \"/etc/k.pem\"",
            "tls_cert_file = \"\"\ntls_key_file = \"/etc/k.pem\"",
        ] {
            let err = Config::from_sources(Some(bad), no_env).unwrap_err();
            assert!(matches!(err, ConfigError::Invalid(_)), "{bad}");
        }
    }

    #[test]
    fn the_audit_log_is_kept_for_two_years_by_default() {
        assert_eq!(
            Config::from_sources(None, no_env)
                .unwrap()
                .retention_audit_days,
            730
        );
        assert!(Config::from_sources(Some("retention_audit_days = 0"), no_env).is_err());
    }

    #[test]
    fn the_time_zone_must_exist() {
        assert_eq!(Config::from_sources(None, no_env).unwrap().time_zone, None);
        let berlin = Config::from_sources(Some("time_zone = \"Europe/Berlin\""), no_env).unwrap();
        assert_eq!(berlin.time_zone.as_deref(), Some("Europe/Berlin"));
        assert!(Config::from_sources(Some("time_zone = \"Mars/Olympus\""), no_env).is_err());
    }

    #[test]
    fn allowed_hosts_are_empty_by_default_and_checked() {
        assert!(
            Config::from_sources(None, no_env)
                .unwrap()
                .allowed_hosts
                .is_empty()
        );
        let ok = Config::from_sources(
            Some("allowed_hosts = [\"secmon.example.org\", \"127.0.0.1:8090\", \"[::1]:8090\"]"),
            no_env,
        )
        .unwrap();
        assert_eq!(ok.allowed_hosts.len(), 3);
        for bad in [
            "allowed_hosts = [\"\"]",
            "allowed_hosts = [\"a b\"]",
            "allowed_hosts = [\"https://x\"]",
        ] {
            assert!(Config::from_sources(Some(bad), no_env).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_shipped_example_config_is_valid() {
        let text = include_str!("../deploy/config.example.toml");
        let config = Config::from_sources(Some(text), no_env).unwrap();
        // Direct HTTPS: the generated certificate, no proxy header (clients could forge it).
        assert_eq!(config.listen, "0.0.0.0:8444".parse().unwrap());
        assert!(config.tls_files().is_some());
        assert_eq!(config.client_ip_header, None);
        assert!(config.cookie_secure);
    }

    #[test]
    fn the_proxy_header_is_off_by_default_and_accepts_known_names_only() {
        assert_eq!(
            Config::from_sources(None, no_env).unwrap().client_ip_header,
            None
        );
        let xff =
            Config::from_sources(Some("client_ip_header = \"x-forwarded-for\""), no_env).unwrap();
        assert_eq!(xff.client_ip_header, Some(ClientIpHeader::XForwardedFor));
        let real = Config::from_sources(Some("client_ip_header = \"x-real-ip\""), no_env).unwrap();
        assert_eq!(real.client_ip_header, Some(ClientIpHeader::XRealIp));
        assert!(Config::from_sources(Some("client_ip_header = \"forwarded\""), no_env).is_err());
    }

    #[test]
    fn defaults_bind_to_loopback() {
        let config = Config::from_sources(None, no_env).unwrap();
        assert_eq!(config.listen, "127.0.0.1:8090".parse().unwrap());
        assert_eq!(config, Config::default());
    }

    #[test]
    fn file_values_override_defaults() {
        let config = Config::from_sources(
            Some("listen = \"0.0.0.0:9000\"\ndatabase_path = \"/tmp/x.db\""),
            no_env,
        )
        .unwrap();
        assert_eq!(config.listen, "0.0.0.0:9000".parse().unwrap());
        assert_eq!(config.database_path, PathBuf::from("/tmp/x.db"));
        assert_eq!(config.log_filter, "info");
    }

    #[test]
    fn env_overrides_file() {
        let env = |name: &str| match name {
            ENV_LISTEN => Some("127.0.0.1:9999".to_owned()),
            ENV_DATABASE_PATH => Some("/data/env.db".to_owned()),
            _ => None,
        };
        let config = Config::from_sources(Some("listen = \"0.0.0.0:9000\""), env).unwrap();
        assert_eq!(config.listen, "127.0.0.1:9999".parse().unwrap());
        assert_eq!(config.database_path, PathBuf::from("/data/env.db"));
    }

    #[test]
    fn secret_key_file_default_and_override() {
        let config = Config::from_sources(None, no_env).unwrap();
        assert_eq!(
            config.secret_key_file,
            PathBuf::from("/etc/opensecmon/secret.key")
        );
        let env = |name: &str| (name == ENV_SECRET_KEY_FILE).then(|| "/k/x.key".to_owned());
        let config = Config::from_sources(None, env).unwrap();
        assert_eq!(config.secret_key_file, PathBuf::from("/k/x.key"));
        let err = Config::from_sources(Some("secret_key_file = \"\""), no_env).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = Config::from_sources(Some("lissen = \"x\""), no_env).unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn invalid_listen_is_rejected() {
        let err = Config::from_sources(Some("listen = \"not-an-address\""), no_env).unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)));
        let env = |name: &str| (name == ENV_LISTEN).then(|| "nope".to_owned());
        let err = Config::from_sources(None, env).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidEnv {
                name: ENV_LISTEN,
                ..
            }
        ));
    }

    #[test]
    fn empty_database_path_is_rejected() {
        let err = Config::from_sources(Some("database_path = \"\""), no_env).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn cookies_are_secure_by_default_and_ttl_is_validated() {
        let config = Config::from_sources(None, no_env).unwrap();
        assert!(config.cookie_secure);
        assert_eq!(config.session_ttl_hours, 168);
        assert_eq!(config.session_idle_minutes, 30);
        let config = Config::from_sources(Some("session_idle_minutes = 0"), no_env).unwrap();
        assert_eq!(config.session_idle_minutes, 0);
        let config = Config::from_sources(Some("cookie_secure = false"), no_env).unwrap();
        assert!(!config.cookie_secure);
        for bad in [
            "session_ttl_hours = 0",
            "session_ttl_hours = 2161",
            "session_idle_minutes = 1441",
        ] {
            let err = Config::from_sources(Some(bad), no_env).unwrap_err();
            assert!(matches!(err, ConfigError::Invalid(_)), "{bad}");
        }
    }

    #[test]
    fn agent_networks_default_to_private_addresses_and_are_checked() {
        let ip = |s: &str| Some(s.parse().unwrap());
        let config = Config::from_sources(None, no_env).unwrap();
        assert_eq!(config.agent_networks, None);
        let nets = config.agent_networks();
        assert!(crate::agent::allowed(&nets, ip("192.168.1.20")));
        assert!(!crate::agent::allowed(&nets, ip("203.0.113.5")));
        let config = Config::from_sources(
            Some("agent_networks = [\"192.168.1.0/24\", \"fd00::1\"]"),
            no_env,
        )
        .unwrap();
        let nets = config.agent_networks();
        assert!(crate::agent::allowed(&nets, ip("192.168.1.20")));
        assert!(!crate::agent::allowed(&nets, ip("10.0.0.1")));
        assert!(crate::agent::allowed(&nets, ip("fd00::1")));
        let off = Config::from_sources(Some("agent_networks = []"), no_env).unwrap();
        assert!(off.agent_networks().is_empty());
        for bad in [
            "agent_networks = [\"lan\"]",
            "agent_networks = [\"10.0.0.0/40\"]",
        ] {
            let err = Config::from_sources(Some(bad), no_env).unwrap_err();
            assert!(matches!(err, ConfigError::Invalid(_)), "{bad}");
        }
    }

    #[test]
    fn every_setting_can_come_from_the_environment() {
        let vars = [
            (ENV_LISTEN, "0.0.0.0:8444"),
            (ENV_TLS_CERT_FILE, "/c/cert.pem"),
            (ENV_TLS_KEY_FILE, "/c/key.pem"),
            (ENV_GENERATE_MISSING, "true"),
            (ENV_COOKIE_SECURE, "false"),
            (ENV_SESSION_TTL_HOURS, "24"),
            (ENV_SESSION_IDLE_MINUTES, "0"),
            (ENV_CLIENT_IP_HEADER, "x-real-ip"),
            (ENV_ALLOWED_HOSTS, "secmon.example.org, 192.0.2.5:8444"),
            (ENV_RETENTION_AUDIT_DAYS, "90"),
            (ENV_TIME_ZONE, "Europe/Berlin"),
            (ENV_FETCH_SOURCES, "false"),
            (ENV_AGENT_NETWORKS, "192.168.1.0/24 fd00::/8"),
            (ENV_AGENT_PACKAGES_DIR, "/var/lib/opensecmon/agent"),
            (ENV_BACKUP_DIR, "/var/lib/opensecmon/backups"),
            (ENV_BACKUP_KEEP, "3"),
            (ENV_BACKUP_TIME, "4:05"),
        ];
        let env = |name: &str| {
            vars.iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| (*v).to_owned())
        };
        let c = Config::from_sources(None, env).unwrap();
        assert_eq!(c.listen, "0.0.0.0:8444".parse().unwrap());
        assert_eq!(
            c.tls_files(),
            Some((Path::new("/c/cert.pem"), Path::new("/c/key.pem")))
        );
        assert!(c.generate_missing && !c.cookie_secure && !c.fetch_sources);
        assert_eq!((c.session_ttl_hours, c.session_idle_minutes), (24, 0));
        assert_eq!(c.client_ip_header, Some(ClientIpHeader::XRealIp));
        assert_eq!(c.allowed_hosts, ["secmon.example.org", "192.0.2.5:8444"]);
        assert_eq!(c.retention_audit_days, 90);
        assert_eq!(c.time_zone.as_deref(), Some("Europe/Berlin"));
        assert_eq!(
            c.agent_networks,
            Some(vec!["192.168.1.0/24".to_owned(), "fd00::/8".to_owned()])
        );
        assert_eq!(
            c.agent_packages_dir(),
            PathBuf::from("/var/lib/opensecmon/agent")
        );
        assert_eq!(
            c.backup_dir.as_deref(),
            Some(Path::new("/var/lib/opensecmon/backups"))
        );
        assert_eq!((c.backup_keep, c.backup_minute()), (3, 4 * 60 + 5));
    }

    #[test]
    fn an_empty_variable_unsets_an_optional_setting() {
        let file = "listen = \"0.0.0.0:8444\"\ntls_cert_file = \"/c.pem\"\ntls_key_file = \"/k.pem\"\n\
                    time_zone = \"Europe/Berlin\"\nagent_networks = [\"10.0.0.0/8\"]\nallowed_hosts = [\"a\"]";
        let empty = |name: &str| {
            [
                ENV_TLS_CERT_FILE,
                ENV_TLS_KEY_FILE,
                ENV_TIME_ZONE,
                ENV_AGENT_NETWORKS,
                ENV_ALLOWED_HOSTS,
            ]
            .contains(&name)
            .then(String::new)
        };
        let c = Config::from_sources(Some(file), empty).unwrap();
        assert_eq!(c.tls_files(), None);
        assert_eq!(c.time_zone, None);
        assert_eq!(c.agent_networks, None, "back to the default networks");
        assert!(c.allowed_hosts.is_empty());
        let off = |name: &str| (name == ENV_AGENT_NETWORKS).then(|| "none".to_owned());
        let c = Config::from_sources(None, off).unwrap();
        assert_eq!(c.agent_networks, Some(Vec::new()), "agent API off");
    }

    #[test]
    fn bad_variables_name_themselves() {
        for (name, value) in [
            (ENV_GENERATE_MISSING, "yes"),
            (ENV_SESSION_TTL_HOURS, "a day"),
            (ENV_CLIENT_IP_HEADER, "forwarded"),
            (ENV_BACKUP_KEEP, "-1"),
        ] {
            let env = |n: &str| (n == name).then(|| value.to_owned());
            match Config::from_sources(None, env) {
                Err(ConfigError::InvalidEnv { name: got, .. }) => assert_eq!(got, name),
                other => panic!("{name}={value}: {other:?}"),
            }
        }
        for (name, value) in [
            (ENV_BACKUP_TIME, "24:00"),
            (ENV_BACKUP_KEEP, "0"),
            (ENV_AGENT_NETWORKS, "lan"),
            (ENV_ALLOWED_HOSTS, "https://x"),
            (ENV_TIME_ZONE, "Mars/Olympus"),
        ] {
            let env = |n: &str| (n == name).then(|| value.to_owned());
            assert!(
                matches!(
                    Config::from_sources(None, env),
                    Err(ConfigError::Invalid(_))
                ),
                "{name}={value}"
            );
        }
    }

    #[test]
    fn the_backup_is_off_by_default_and_its_time_is_checked() {
        let c = Config::from_sources(None, no_env).unwrap();
        assert_eq!(c.backup_dir, None);
        assert!(!c.generate_missing);
        assert_eq!((c.backup_keep, c.backup_minute()), (14, 210));
        for (text, minute) in [
            ("00:00", Some(0)),
            ("23:59", Some(1439)),
            ("7:30", Some(450)),
        ] {
            assert_eq!(parse_time_of_day(text), minute, "{text}");
        }
        for bad in ["24:00", "12:60", "12:5", "1230", "", "ab:cd"] {
            assert_eq!(parse_time_of_day(bad), None, "{bad}");
        }
        assert!(Config::from_sources(Some("backup_dir = \"\""), no_env).is_err());
    }

    #[test]
    fn missing_file_reports_path() {
        let err = Config::load(Some(Path::new("/nonexistent/opensecmon.toml"))).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }));
    }
}
