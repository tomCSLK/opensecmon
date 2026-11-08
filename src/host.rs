//! Host names and IP addresses entered by the user (mail server, later SSH hosts).

use std::net::IpAddr;

use crate::i18n::Msg;

pub const MAX_HOST_LEN: usize = 253;

/// Validates an IP address or a hostname (RFC 1123) and returns the normalized form.
/// Hostnames are lowercased; unspecified, multicast and broadcast addresses are rejected.
pub fn validate_host(host: &str) -> Result<String, Msg> {
    let invalid = || Msg::new("host-invalid");
    let host = host.trim();
    if host.is_empty() || host.len() > MAX_HOST_LEN {
        return Err(invalid());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        let bad = ip.is_unspecified()
            || ip.is_multicast()
            || matches!(ip, IpAddr::V4(v4) if v4.is_broadcast());
        return if bad {
            Err(invalid())
        } else {
            Ok(ip.to_string())
        };
    }
    let host = host.to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    // A numeric last label (e.g. "300.1.1.1") is a malformed IP address, not a hostname.
    let last_numeric = labels
        .last()
        .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()));
    if labels.iter().all(|l| label_ok(l)) && !last_numeric {
        Ok(host)
    } else {
        Err(invalid())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_are_validated_and_normalized() {
        for ok in [
            "192.0.2.253",
            "fe80::1",
            "switch-keller.lan",
            "Router",
            "a.b-c.example.org",
            " localhost ",
        ] {
            assert!(validate_host(ok).is_ok(), "{ok}");
        }
        assert_eq!(
            validate_host("Switch-KELLER.lan").unwrap(),
            "switch-keller.lan"
        );
        assert_eq!(validate_host("FE80:0:0:0:0:0:0:1").unwrap(), "fe80::1");
        for bad in [
            "",
            " ",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "::",
            "300.1.1.1",
            "1.2.3",
            "-a.lan",
            "a-.lan",
            "a..lan",
            "a b",
            "a_b.lan",
            "bücher.lan",
            "http://x",
            "a/b",
            &"a".repeat(64),
            &format!("{}.lan", "a".repeat(250)),
        ] {
            assert!(validate_host(bad).is_err(), "{bad:?}");
        }
    }
}
