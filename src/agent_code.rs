//! The enrollment code of opensecagent (`docs/agent-api.md`, "Enrollment code"): the address of this server, the
//! fingerprint of its certificate and the one-time code in one word to copy, `osa1_` and Crockford's Base32.
//! opensecmon only writes it; the reader is here as the reference for the agent and for the tests.

use sha2::{Digest, Sha256};

/// The prefix of an enrollment code (format version 1).
pub const PREFIX: &str = "osa1_";
/// Crockford's Base32 in lower case, as written.
const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";
/// Flag: a certificate fingerprint follows.
const WITH_FINGERPRINT: u8 = 1;
/// Longest address (host name or IP address with port).
const ADDRESS_MAX: usize = 255;

/// What an enrollment code carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentCode {
    /// Host name or IP address with an optional port, e.g. `192.0.2.10:8444`; always HTTPS.
    pub address: String,
    /// The SHA-256 fingerprint of the certificate of the built-in HTTPS.
    pub fingerprint: Option<[u8; 32]>,
    /// The one-time code as shown, e.g. `K7FQ-29XM`.
    pub code: String,
}

/// Why a text is no enrollment code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeError {
    /// Does not start with `osa1_` (another format or no code at all).
    Prefix,
    /// Wrong characters, too short or too long, unknown flags or a checksum that does not match: incomplete or
    /// damaged.
    Damaged,
}

/// The fingerprint as the certificate shows it (`AB:CD:…`, 32 bytes) as bytes.
pub fn parse_fingerprint(text: &str) -> Option<[u8; 32]> {
    let hex: String = text.chars().filter(|c| *c != ':').collect();
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// The address of a base URL (`https://host:port`) for the code; `None` if it is no plain host name or IP address
/// with an optional port.
pub fn address_of(base_url: &str) -> Option<&str> {
    let address = base_url.strip_prefix("https://")?;
    (!address.is_empty()
        && address.len() <= ADDRESS_MAX
        && address
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-.:[]".contains(&b)))
    .then_some(address)
}

/// Writes the enrollment code; `None` if the address or the one-time code cannot be part of one.
pub fn encode(address: &str, fingerprint: Option<&[u8; 32]>, code: &str) -> Option<String> {
    if address.is_empty() || address.len() > ADDRESS_MAX || !address.is_ascii() {
        return None;
    }
    let code_bits = code_to_bytes(code)?;
    let mut payload = Vec::with_capacity(1 + 32 + 5 + address.len() + 4);
    payload.push(if fingerprint.is_some() {
        WITH_FINGERPRINT
    } else {
        0
    });
    if let Some(fp) = fingerprint {
        payload.extend_from_slice(fp);
    }
    payload.extend_from_slice(&code_bits);
    payload.extend_from_slice(address.as_bytes());
    let sum = Sha256::digest(&payload);
    payload.extend_from_slice(&sum[..4]);
    Some(format!("{PREFIX}{}", base32(&payload)))
}

/// Reads an enrollment code as the agent does.
pub fn decode(text: &str) -> Result<EnrollmentCode, CodeError> {
    let text = text.trim();
    let rest = text
        .get(..PREFIX.len())
        .filter(|p| p.eq_ignore_ascii_case(PREFIX))
        .map(|_| &text[PREFIX.len()..])
        .ok_or(CodeError::Prefix)?;
    let payload = unbase32(rest).ok_or(CodeError::Damaged)?;
    // Flags, the code, at least one character of the address and the checksum.
    if payload.len() < 1 + 5 + 1 + 4 {
        return Err(CodeError::Damaged);
    }
    let (body, sum) = payload.split_at(payload.len() - 4);
    if Sha256::digest(body)[..4] != *sum {
        return Err(CodeError::Damaged);
    }
    let flags = body[0];
    if flags & !WITH_FINGERPRINT != 0 {
        return Err(CodeError::Damaged);
    }
    let mut rest = &body[1..];
    let fingerprint = if flags & WITH_FINGERPRINT != 0 {
        let (fp, after) = rest.split_at_checked(32).ok_or(CodeError::Damaged)?;
        rest = after;
        Some(<[u8; 32]>::try_from(fp).map_err(|_| CodeError::Damaged)?)
    } else {
        None
    };
    let (code, address) = rest.split_at_checked(5).ok_or(CodeError::Damaged)?;
    let address = std::str::from_utf8(address).map_err(|_| CodeError::Damaged)?;
    if address_of(&format!("https://{address}")).is_none() {
        return Err(CodeError::Damaged);
    }
    Ok(EnrollmentCode {
        address: address.to_owned(),
        fingerprint,
        code: bytes_to_code(code.try_into().map_err(|_| CodeError::Damaged)?),
    })
}

/// The 8 characters of a one-time code (as shown or typed) as 40 bits.
fn code_to_bytes(code: &str) -> Option<[u8; 5]> {
    let plain = crate::agent::normalize_code(code)?;
    let mut bits: u64 = 0;
    for b in plain.bytes() {
        let value = crate::agent::CODE_ALPHABET.iter().position(|c| *c == b)?;
        bits = (bits << 5) | value as u64;
    }
    let all = bits.to_be_bytes();
    Some([all[3], all[4], all[5], all[6], all[7]])
}

/// 40 bits as the one-time code is shown (`K7FQ-29XM`).
fn bytes_to_code(bytes: [u8; 5]) -> String {
    let bits = bytes.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
    let chars: String = (0..crate::agent::CODE_LEN)
        .rev()
        .map(|i| char::from(crate::agent::CODE_ALPHABET[((bits >> (5 * i)) & 31) as usize]))
        .collect();
    format!("{}-{}", &chars[..4], &chars[4..])
}

/// Crockford's Base32, lower case, without padding.
fn base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &b in bytes {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

/// Reads Crockford's Base32 in any case; spaces, line breaks and `-` are skipped, `o` reads as `0`, `i` and `l`
/// as `1`. `None` for other characters or bits left over that are not zero.
fn unbase32(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    let mut count = 0usize;
    for c in text.chars() {
        if c.is_whitespace() || c == '-' {
            continue;
        }
        let c = match c.to_ascii_lowercase() {
            'o' => '0',
            'i' | 'l' => '1',
            c => c,
        };
        let value = ALPHABET.iter().position(|a| char::from(*a) == c)? as u32;
        count += 1;
        if count > 1024 {
            return None;
        }
        buffer = ((buffer << 5) | value) & 0xffff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    (buffer & ((1 << bits) - 1) == 0).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F";

    #[test]
    fn the_example_of_the_api_document() {
        let fp = parse_fingerprint(FP).unwrap();
        assert_eq!(fp[0], 0);
        assert_eq!(fp[31], 0x1f);
        let code = encode("192.0.2.10:8444", Some(&fp), "K7FQ-29XM").unwrap();
        // The same value stands in docs/agent-api.md.
        assert_eq!(code, EXAMPLE);
        let doc = include_str!("../docs/agent-api.md");
        assert!(
            doc.contains(EXAMPLE),
            "update the example in docs/agent-api.md"
        );
        assert!(code.starts_with(PREFIX));
        assert!(code[PREFIX.len()..].bytes().all(|b| ALPHABET.contains(&b)));
        assert_eq!(
            decode(&code).unwrap(),
            EnrollmentCode {
                address: "192.0.2.10:8444".to_owned(),
                fingerprint: Some(fp),
                code: "K7FQ-29XM".to_owned(),
            }
        );
    }

    const EXAMPLE: &str = "osa1_040020g30g2gc1r81450p30d1r7h048j2ca1a5gq30chm6rw3mf1z6eze4kv8c9s68q30bhj5rrk0ehr6gt38epxvbd0";

    #[test]
    fn codes_round_trip_with_and_without_fingerprint() {
        let fp = [0xab; 32];
        for (address, fp) in [
            ("192.0.2.10:8444", Some(fp)),
            ("[fd00::2]:8444", Some(fp)),
            ("secmon.example.org", None),
            ("a", None),
        ] {
            for code in ["K7FQ-29XM", "00000000", "ZZZZ-ZZZZ", "k7fq29xm"] {
                let text = encode(address, fp.as_ref(), code).unwrap();
                let back = decode(&text).unwrap();
                assert_eq!(back.address, address);
                assert_eq!(back.fingerprint, fp);
                assert_eq!(
                    crate::agent::normalize_code(&back.code),
                    crate::agent::normalize_code(code)
                );
            }
        }
    }

    #[test]
    fn a_code_survives_how_people_copy_it() {
        let text = encode("192.0.2.10:8444", Some(&[7; 32]), "K7FQ-29XM").unwrap();
        let expected = decode(&text).unwrap();
        // Upper case, spaces, line breaks of a mail, surrounding blanks.
        let upper = text.to_ascii_uppercase();
        assert_eq!(decode(&upper).unwrap(), expected);
        let (a, b) = text.split_at(40);
        assert_eq!(decode(&format!("  {a}\n  {b} \n")).unwrap(), expected);
        assert_eq!(decode(&format!("{a}-{b}")).unwrap(), expected);
    }

    #[test]
    fn damaged_codes_are_refused() {
        let text = encode("192.0.2.10:8444", Some(&[7; 32]), "K7FQ-29XM").unwrap();
        assert_eq!(decode("K7FQ-29XM"), Err(CodeError::Prefix));
        assert_eq!(decode(""), Err(CodeError::Prefix));
        assert_eq!(decode("osa2_abc"), Err(CodeError::Prefix));
        // Cut off at the end or in the middle, one character changed, one missing, one too many.
        assert_eq!(decode(&text[..text.len() - 1]), Err(CodeError::Damaged));
        assert_eq!(decode(&text[..60]), Err(CodeError::Damaged));
        assert_eq!(decode(PREFIX), Err(CodeError::Damaged));
        for i in PREFIX.len()..text.len() {
            let mut changed = text.clone().into_bytes();
            changed[i] = if changed[i] == b'x' { b'y' } else { b'x' };
            let changed = String::from_utf8(changed).unwrap();
            assert_eq!(decode(&changed), Err(CodeError::Damaged), "position {i}");
            let mut missing = text.clone();
            missing.remove(i);
            assert_eq!(decode(&missing), Err(CodeError::Damaged), "position {i}");
        }
        assert_eq!(decode(&format!("{text}0")), Err(CodeError::Damaged));
        assert_eq!(decode(&format!("{text}u")), Err(CodeError::Damaged));
        assert_eq!(decode("osa1_ "), Err(CodeError::Damaged));
        assert_eq!(
            decode(&format!("{PREFIX}{}", "0".repeat(5000))),
            Err(CodeError::Damaged)
        );
    }

    #[test]
    fn unknown_flags_and_bad_addresses_are_refused() {
        let mut payload = vec![2u8];
        payload.extend_from_slice(&[0; 5]);
        payload.extend_from_slice(b"host");
        let sum = Sha256::digest(&payload);
        payload.extend_from_slice(&sum[..4]);
        assert_eq!(
            decode(&format!("{PREFIX}{}", base32(&payload))),
            Err(CodeError::Damaged)
        );
        let mut payload = vec![0u8];
        payload.extend_from_slice(&[0; 5]);
        payload.extend_from_slice(b"host/$(reboot)");
        let sum = Sha256::digest(&payload);
        payload.extend_from_slice(&sum[..4]);
        assert_eq!(
            decode(&format!("{PREFIX}{}", base32(&payload))),
            Err(CodeError::Damaged)
        );
    }

    #[test]
    fn nothing_is_written_for_what_cannot_be_read() {
        assert_eq!(encode("", None, "K7FQ-29XM"), None);
        assert_eq!(encode(&"a".repeat(256), None, "K7FQ-29XM"), None);
        assert_eq!(encode("host", None, "K7FQ-29X"), None);
        assert_eq!(encode("höst", None, "K7FQ-29XM"), None);
    }

    #[test]
    fn addresses_come_from_the_base_url() {
        assert_eq!(
            address_of("https://192.0.2.10:8444"),
            Some("192.0.2.10:8444")
        );
        assert_eq!(address_of("https://[fd00::2]:8444"), Some("[fd00::2]:8444"));
        assert_eq!(address_of("https://<server>"), None);
        assert_eq!(address_of("http://host"), None);
        assert_eq!(address_of("https://"), None);
    }

    #[test]
    fn fingerprints_are_read_as_the_certificate_shows_them() {
        assert_eq!(parse_fingerprint(FP).unwrap()[10], 0x0a);
        assert_eq!(
            parse_fingerprint(&FP.to_ascii_lowercase()).unwrap()[10],
            0x0a
        );
        assert_eq!(parse_fingerprint("AB:CD"), None);
        assert_eq!(parse_fingerprint(&FP.replace("0A", "0G")), None);
    }

    #[test]
    fn base32_reads_what_it_writes() {
        for len in 0..40 {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(unbase32(&base32(&bytes)).unwrap(), bytes, "{len}");
        }
        assert_eq!(base32(b"f"), "cr");
        assert_eq!(unbase32("cr").unwrap(), b"f");
        assert_eq!(unbase32("cs"), None, "bits left over must be zero");
    }
}
