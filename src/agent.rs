//! Building blocks of the agent API (`docs/agent-api.md`): the networks agents may connect from, the
//! one-time codes of the enrollment and the tokens of the computers. Storage in `storage::agents`, the
//! endpoints in `web::agent_api`, the pages in `web::computers`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rand::{Rng, RngCore};

/// Networks allowed when `agent_networks` is not set: private and local addresses.
pub const DEFAULT_NETWORKS: [&str; 7] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "fc00::/7",
    "fe80::/10",
    "::1/128",
];

/// Most entries of `agent_networks`.
pub const MAX_NETWORKS: usize = 64;

/// An address range in CIDR notation (`192.168.1.0/24`, `fd00::/8`, or a single address).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    addr: IpAddr,
    prefix: u8,
}

impl Network {
    /// Reads `address/prefix` or a single address. Host bits are cleared (`192.168.1.5/24` is the /24).
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let (addr, prefix) = match text.split_once('/') {
            Some((a, p)) => {
                if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                (a.parse::<IpAddr>().ok()?, Some(p.parse::<u8>().ok()?))
            }
            None => (text.parse::<IpAddr>().ok()?, None),
        };
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        if prefix > max {
            return None;
        }
        let addr = match addr {
            IpAddr::V4(v4) => IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask32(prefix))),
            IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask128(prefix))),
        };
        Some(Self { addr, prefix })
    }

    /// Whether `ip` lies in this range. IPv4 addresses written as IPv6 (`::ffff:192.0.2.1`, as a server that
    /// listens on `[::]` sees them) count as IPv4.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                u32::from(ip) & mask32(self.prefix) == u32::from(net)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                u128::from(ip) & mask128(self.prefix) == u128::from(net)
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

fn mask32(prefix: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
}

fn mask128(prefix: u8) -> u128 {
    u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0)
}

/// The default networks, parsed.
pub fn default_networks() -> Vec<Network> {
    DEFAULT_NETWORKS
        .iter()
        .filter_map(|n| Network::parse(n))
        .collect()
}

/// Whether a client may use the agent API. An unknown address is never allowed.
pub fn allowed(networks: &[Network], ip: Option<IpAddr>) -> bool {
    ip.is_some_and(|ip| networks.iter().any(|n| n.contains(ip)))
}

/// Crockford's Base32 without `I`, `L`, `O` and `U`: the characters of a one-time code.
pub(crate) const CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Characters of a code (40 random bits).
pub const CODE_LEN: usize = 8;
/// How long a code is valid.
pub const CODE_VALID_MS: i64 = 15 * 60 * 1000;

/// A new one-time code as shown: `K7FQ-29XM`.
pub fn new_code() -> String {
    let mut rng = rand::rng();
    let chars: String = (0..CODE_LEN)
        .map(|_| char::from(CODE_ALPHABET[rng.random_range(0..CODE_ALPHABET.len())]))
        .collect();
    format!("{}-{}", &chars[..4], &chars[4..])
}

/// The code as typed (any case, with or without dash and spaces, `O` for `0`, `I`/`L` for `1`) in the form it
/// is stored under; `None` if it cannot be a code.
pub fn normalize_code(text: &str) -> Option<String> {
    if text.len() > 32 {
        return None;
    }
    let code: String = text
        .chars()
        .filter(|c| !matches!(c, '-' | ' ' | '\t'))
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        })
        .collect();
    (code.len() == CODE_LEN && code.bytes().all(|b| CODE_ALPHABET.contains(&b))).then_some(code)
}

/// Prefix of a computer's token.
pub const TOKEN_PREFIX: &str = "osm1_";
/// Characters after the prefix: 32 random bytes in Base64url without padding.
const TOKEN_CHARS: usize = 43;

/// A new token for a computer: `osm1_` and 32 random bytes.
pub fn new_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    format!("{TOKEN_PREFIX}{}", base64url(&bytes))
}

/// The token of an `Authorization: Bearer …` header, if it has the form of one.
pub fn bearer_token(header: &str) -> Option<&str> {
    let (scheme, token) = header.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    let rest = token.strip_prefix(TOKEN_PREFIX)?;
    (rest.len() == TOKEN_CHARS
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')))
    .then_some(token)
}

/// How often opensecagent reports (it sends the short form unless something changed, and learns of an update
/// the user asked for with the answer).
pub const AGENT_PROGRAM_INTERVAL_SECS: i64 = 15 * 60;

/// When a computer is asked to report next, by the name of its agent: opensecagent every 15 minutes, the scripts
/// as the SSH hosts are read.
pub fn report_interval_secs(agent_name: &str) -> i64 {
    if agent_name == crate::agent_packages::AGENT_NAME {
        AGENT_PROGRAM_INTERVAL_SECS
    } else {
        crate::storage::agents::REPORT_INTERVAL_SECS
    }
}

/// Most bytes of a report, compressed and after decompression.
pub const REPORT_MAX_BYTES: usize = 8 * 1024 * 1024;
/// Most bytes of `os_release` in a JSON report.
pub const OS_RELEASE_MAX_BYTES: usize = 16 * 1024;
/// A full report at most this often per computer.
pub const FULL_EVERY_MS: i64 = 5 * 60 * 1000;
/// The short form (`unchanged`) at most this often per computer.
pub const SHORT_EVERY_MS: i64 = 60 * 1000;

/// What kind of report a computer sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportKind {
    Full,
    Short,
}

/// When each computer last reported, to turn away reports that come too often. Kept in memory only: after a
/// restart every computer may report at once, which is harmless.
#[derive(Debug, Default)]
pub struct Pace(std::sync::Mutex<std::collections::HashMap<i64, [i64; 2]>>);

impl Pace {
    fn slot(kind: ReportKind) -> (usize, i64) {
        match kind {
            ReportKind::Full => (0, FULL_EVERY_MS),
            ReportKind::Short => (1, SHORT_EVERY_MS),
        }
    }

    /// How long the computer has to wait before it may send this kind of report (`None`: now).
    pub fn wait_ms(&self, device: i64, kind: ReportKind, now_ms: i64) -> Option<i64> {
        let (slot, every) = Self::slot(kind);
        let last = self.0.lock().ok()?.get(&device).map(|s| s[slot])?;
        let wait = last.saturating_add(every).saturating_sub(now_ms);
        (wait > 0).then_some(wait)
    }

    /// Notes an accepted report.
    pub fn record(&self, device: i64, kind: ReportKind, now_ms: i64) {
        let (slot, _) = Self::slot(kind);
        if let Ok(mut map) = self.0.lock() {
            map.entry(device).or_insert([i64::MIN / 2; 2])[slot] = now_ms;
        }
    }
}

/// Base64url without padding (RFC 4648, section 5).
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn networks_are_read_and_matched() {
        let lan = Network::parse("192.168.1.5/24").unwrap();
        assert_eq!(lan.to_string(), "192.168.1.0/24");
        assert!(lan.contains(ip("192.168.1.200")));
        assert!(!lan.contains(ip("192.168.2.1")));
        assert!(lan.contains(ip("::ffff:192.168.1.9")), "IPv4 seen as IPv6");
        assert!(!lan.contains(ip("fd00::1")));
        let one = Network::parse("192.0.2.7").unwrap();
        assert!(one.contains(ip("192.0.2.7")) && !one.contains(ip("192.0.2.8")));
        let all = Network::parse("0.0.0.0/0").unwrap();
        assert!(all.contains(ip("203.0.113.1")));
        let ula = Network::parse("fc00::/7").unwrap();
        assert!(ula.contains(ip("fd12:3456::1")) && !ula.contains(ip("2001:db8::1")));
        for bad in [
            "",
            "192.168.0.0/33",
            "fd00::/129",
            "192.168.0.0/",
            "lan",
            "10.0.0.0/+8",
            "1.2.3.4/24/1",
        ] {
            assert_eq!(Network::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_default_allows_only_private_and_local_addresses() {
        let nets = default_networks();
        assert_eq!(nets.len(), DEFAULT_NETWORKS.len());
        for ok in [
            "192.168.1.20",
            "10.1.2.3",
            "172.31.0.1",
            "127.0.0.1",
            "::1",
            "fd00::5",
            "fe80::1",
        ] {
            assert!(allowed(&nets, Some(ip(ok))), "{ok}");
        }
        for no in ["203.0.113.1", "172.32.0.1", "2001:db8::1", "8.8.8.8"] {
            assert!(!allowed(&nets, Some(ip(no))), "{no}");
        }
        assert!(!allowed(&nets, None), "no address, no access");
        assert!(
            !allowed(&[], Some(ip("192.168.0.1"))),
            "an empty list switches the API off"
        );
    }

    #[test]
    fn codes_are_shown_with_a_dash_and_read_forgivingly() {
        let code = new_code();
        assert_eq!(code.len(), CODE_LEN + 1);
        assert_eq!(&code[4..5], "-");
        let plain = normalize_code(&code).unwrap();
        assert_eq!(plain, code.replace('-', ""));
        assert_ne!(new_code(), code, "random");
        assert_eq!(normalize_code("k7fq-29xm").as_deref(), Some("K7FQ29XM"));
        assert_eq!(normalize_code(" K7FQ 29XM ").as_deref(), Some("K7FQ29XM"));
        assert_eq!(normalize_code("o1lI-abcd").as_deref(), Some("0111ABCD"));
        for bad in [
            "",
            "K7FQ-29X",
            "K7FQ-29XMN",
            "K7FQ-29XU",
            "K7FQ_29XM",
            "K7FQ-29XÄ",
        ] {
            assert_eq!(normalize_code(bad), None, "{bad}");
        }
    }

    #[test]
    fn tokens_have_their_form_and_are_found_in_the_header() {
        let token = new_token();
        assert!(token.starts_with("osm1_"));
        assert_eq!(token.len(), 5 + 43);
        assert_ne!(new_token(), token);
        assert_eq!(
            bearer_token(&format!("Bearer {token}")),
            Some(token.as_str())
        );
        assert_eq!(
            bearer_token(&format!("bearer  {token} ")),
            Some(token.as_str())
        );
        assert_eq!(bearer_token(&format!("Basic {token}")), None);
        assert_eq!(bearer_token("Bearer osm1_short"), None);
        assert_eq!(
            bearer_token(&format!("Bearer {}", token.replace("osm1_", "osm2_"))),
            None
        );
        assert_eq!(
            bearer_token(&format!("Bearer {}!", &token[..token.len() - 1])),
            None
        );
    }

    #[test]
    fn reports_are_paced_per_computer_and_kind() {
        let pace = Pace::default();
        assert_eq!(pace.wait_ms(1, ReportKind::Full, 1_000_000), None);
        pace.record(1, ReportKind::Full, 1_000_000);
        assert_eq!(
            pace.wait_ms(1, ReportKind::Full, 1_000_000 + 1000),
            Some(FULL_EVERY_MS - 1000)
        );
        assert_eq!(
            pace.wait_ms(1, ReportKind::Short, 1_000_000 + 1000),
            None,
            "the short form has its own pace"
        );
        assert_eq!(pace.wait_ms(2, ReportKind::Full, 1_000_000), None);
        assert_eq!(
            pace.wait_ms(1, ReportKind::Full, 1_000_000 + FULL_EVERY_MS),
            None
        );
    }

    #[test]
    fn base64url_matches_the_rfc_examples() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
        assert_eq!(base64url(&[0u8; 32]).len(), 43);
    }
}
