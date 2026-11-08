//! Reading a host over SSH (russh, in the process): the app's own ed25519 key, the host key learned once
//! and confirmed by the user, then only compared, and one command whose output is read with size and time
//! limits. The host decides what runs (`command=` in `authorized_keys`); the app asks for nothing else.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::keys::ssh_key::LineEnding;
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect, client};

use super::listing::MAX_BYTES;

/// Longest a whole reading may take (connect, key exchange, sign-in, output).
pub const TIMEOUT: Duration = Duration::from_secs(60);
/// Longest wait for the next message from the host.
const IDLE: Duration = Duration::from_secs(20);
/// Most bytes of the host's error output kept for the message.
const MAX_STDERR: usize = 2_000;

/// Where to connect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub address: String,
    pub port: u16,
    pub username: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SshError {
    #[error("connecting failed: {0}")]
    Connect(String),
    #[error("no answer in time")]
    Timeout,
    /// The host presented a key, but none is confirmed yet (the key is in [`SshError::host_key`]).
    #[error("the host key is not confirmed yet")]
    HostKeyUnknown(String),
    /// The host presented another key than the confirmed one.
    #[error("the host key changed")]
    HostKeyChanged(String),
    #[error("the host did not accept the key")]
    Auth,
    #[error("the command failed: {0}")]
    Command(String),
    #[error("the output is larger than {MAX_BYTES} bytes")]
    TooLarge,
}

impl SshError {
    /// The text for the user (the detail, if any, is shown beside it).
    pub fn text_id(&self) -> &'static str {
        match self {
            Self::Connect(_) => "ssh-error-connect",
            Self::Timeout => "ssh-error-timeout",
            Self::HostKeyUnknown(_) => "ssh-error-key-unknown",
            Self::HostKeyChanged(_) => "ssh-error-key-changed",
            Self::Auth => "ssh-error-auth",
            Self::Command(_) => "ssh-error-command",
            Self::TooLarge => "ssh-error-too-large",
        }
    }

    /// The details that are safe to show: the cause of a connection or command failure.
    pub fn detail(&self) -> &str {
        match self {
            Self::Connect(d) | Self::Command(d) => d,
            _ => "",
        }
    }

    /// The key the host presented, if this error is about it.
    pub fn host_key(&self) -> Option<&str> {
        match self {
            Self::HostKeyUnknown(k) | Self::HostKeyChanged(k) => Some(k),
            _ => None,
        }
    }
}

/// A new key for the app (ed25519 from 32 random bytes).
pub fn generate_key() -> PrivateKey {
    let seed: [u8; 32] = rand::random();
    let mut key = PrivateKey::from(Ed25519Keypair::from_seed(&seed));
    key.set_comment("opensecmon");
    key
}

/// The private key as stored (OpenSSH format, to be encrypted by the caller).
pub fn encode_key(key: &PrivateKey) -> String {
    key.to_openssh(LineEnding::LF)
        .map(|s| s.to_string())
        .unwrap_or_default()
}

pub fn decode_key(text: &str) -> Option<PrivateKey> {
    PrivateKey::from_openssh(text).ok()
}

/// "ssh-ed25519 AAAA… opensecmon".
pub fn public_line(key: &PrivateKey) -> String {
    key.public_key().to_openssh().unwrap_or_default()
}

/// The line for `authorized_keys` on the host: only the inventory command, no terminal, no forwarding.
pub fn authorized_keys_line(key: &PrivateKey, command: &str) -> String {
    format!("restrict,command=\"{command}\" {}", public_line(key))
}

/// "ED25519 SHA256:…" for a host key in OpenSSH format, as `ssh-keygen -lf` prints it.
pub fn fingerprint(host_key: &str) -> String {
    match PublicKey::from_openssh(host_key) {
        Ok(k) => format!(
            "{} {}",
            algorithm_label(k.algorithm().as_str()),
            k.fingerprint(HashAlg::Sha256)
        ),
        Err(_) => String::new(),
    }
}

fn algorithm_label(name: &str) -> &'static str {
    match name {
        "ssh-ed25519" => "ED25519",
        n if n.starts_with("ecdsa-") => "ECDSA",
        n if n.starts_with("ssh-rsa") || n.starts_with("rsa-") => "RSA",
        _ => "KEY",
    }
}

/// The host key in OpenSSH format without comment.
fn key_text(key: &PublicKey) -> String {
    let mut key = key.clone();
    key.set_comment("");
    key.to_openssh().unwrap_or_default().trim().to_owned()
}

/// Whether two host keys in OpenSSH format are the same key (comments aside).
fn same_key(a: &str, b: &str) -> bool {
    match (PublicKey::from_openssh(a), PublicKey::from_openssh(b)) {
        (Ok(a), Ok(b)) => a.key_data() == b.key_data(),
        _ => false,
    }
}

struct Handler {
    /// The confirmed host key; `None`: only learn the key.
    expected: Option<String>,
    /// The key the host presented.
    seen: Arc<Mutex<Option<String>>>,
}

impl client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // Certificates are not trusted as such: only the plain key of a confirmed host counts.
        let PublicKeyOrCertificate::PublicKey { key, .. } = server_key else {
            return Ok(false);
        };
        let text = key_text(key);
        let ok = self.expected.as_deref().is_some_and(|e| same_key(e, &text));
        if let Ok(mut seen) = self.seen.lock() {
            *seen = Some(text);
        }
        Ok(ok)
    }
}

fn config() -> Arc<client::Config> {
    Arc::new(client::Config {
        client_id: russh::SshId::Standard(
            concat!("SSH-2.0-opensecmon_", env!("CARGO_PKG_VERSION")).into(),
        ),
        inactivity_timeout: Some(IDLE),
        ..Default::default()
    })
}

/// Text of an error for the user: one line, without control characters, short.
fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(300)
        .collect()
}

/// Connects, signs in with `key` and returns the output of the forced command. `host_key` is the
/// confirmed key; without one only the host's key is learned ([`SshError::HostKeyUnknown`]).
pub async fn read(
    target: &Target,
    key: &PrivateKey,
    host_key: Option<&str>,
) -> Result<String, SshError> {
    match tokio::time::timeout(TIMEOUT, read_inner(target, key, host_key)).await {
        Ok(r) => r,
        Err(_) => Err(SshError::Timeout),
    }
}

async fn read_inner(
    target: &Target,
    key: &PrivateKey,
    host_key: Option<&str>,
) -> Result<String, SshError> {
    let seen = Arc::new(Mutex::new(None));
    let handler = Handler {
        expected: host_key.map(str::to_owned),
        seen: seen.clone(),
    };
    let addr = (target.address.as_str(), target.port);
    let connected = client::connect(config(), addr, handler).await;
    let seen_key = seen.lock().ok().and_then(|s| s.clone());
    let mut session = match connected {
        Ok(s) => s,
        Err(russh::Error::UnknownKey) => {
            let seen_key = seen_key.unwrap_or_default();
            return Err(if host_key.is_some() {
                SshError::HostKeyChanged(seen_key)
            } else {
                SshError::HostKeyUnknown(seen_key)
            });
        }
        Err(russh::Error::IO(e)) => return Err(SshError::Connect(clean(&e.to_string()))),
        Err(e) => return Err(SshError::Connect(clean(&e.to_string()))),
    };
    let auth = session
        .authenticate_publickey(
            target.username.clone(),
            PrivateKeyWithHashAlg::new(Arc::new(key.clone()), None),
        )
        .await
        .map_err(|e| SshError::Connect(clean(&e.to_string())))?;
    if !auth.success() {
        return Err(SshError::Auth);
    }
    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|e| SshError::Command(clean(&e.to_string())))?;
    // The host runs its forced command whatever is asked; the name only helps reading its logs.
    channel
        .exec(true, "opensecmon-inventory")
        .await
        .map_err(|e| SshError::Command(clean(&e.to_string())))?;
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let mut status = None;
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { data } => {
                if out.len() + data.len() > MAX_BYTES {
                    let _ = session
                        .disconnect(Disconnect::ByApplication, "", "en")
                        .await;
                    return Err(SshError::TooLarge);
                }
                out.extend_from_slice(&data);
            }
            ChannelMsg::ExtendedData { data, .. } => {
                let room = MAX_STDERR.saturating_sub(err.len());
                err.extend_from_slice(&data[..data.len().min(room)]);
            }
            ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    let _ = session
        .disconnect(Disconnect::ByApplication, "", "en")
        .await;
    match status {
        Some(0) => {}
        Some(code) => {
            let text = clean(&String::from_utf8_lossy(&err));
            return Err(SshError::Command(if text.is_empty() {
                format!("exit status {code}")
            } else {
                format!("exit status {code}: {text}")
            }));
        }
        None if out.is_empty() => {
            return Err(SshError::Command(clean(&String::from_utf8_lossy(&err))));
        }
        None => {}
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

#[cfg(any(test, feature = "fake-host"))]
pub mod testserver;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_round_trip_and_make_an_authorized_keys_line() {
        let key = generate_key();
        let text = encode_key(&key);
        assert!(text.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        let back = decode_key(&text).unwrap();
        assert_eq!(public_line(&back), public_line(&key));
        let line = authorized_keys_line(&key, "/usr/local/bin/opensecmon-inventory");
        assert!(line.starts_with(
            "restrict,command=\"/usr/local/bin/opensecmon-inventory\" ssh-ed25519 AAAA"
        ));
        assert!(line.ends_with(" opensecmon"));
        assert!(decode_key("nonsense").is_none());
    }

    #[test]
    fn fingerprints_look_like_ssh_keygen() {
        let key = generate_key();
        let host = public_line(&key);
        let fp = fingerprint(&host);
        assert!(fp.starts_with("ED25519 SHA256:"), "{fp}");
        assert_eq!(fingerprint("garbage"), "");
        assert!(same_key(&host, &key_text(key.public_key())));
        assert!(!same_key(&host, &public_line(&generate_key())));
    }

    #[test]
    fn errors_are_cleaned() {
        assert_eq!(clean("a\nb\t\u{1b}[31m  c"), "a b [31m c");
        assert_eq!(clean(&"x".repeat(500)).len(), 300);
    }

    #[tokio::test]
    async fn reads_a_host_after_its_key_is_confirmed() {
        let client_key = generate_key();
        let server = testserver::start(
            &public_line(&client_key),
            testserver::Reply::Output(
                "ID=debian\nVERSION_ID=13\n---\nii \tbash\t5.2-1\tbash\t5.2-1\n",
            ),
        )
        .await;
        let target = Target {
            address: "127.0.0.1".to_owned(),
            port: server.port,
            username: "opensecmon".to_owned(),
        };
        // First contact: only the key is learned.
        let err = read(&target, &client_key, None).await.unwrap_err();
        let SshError::HostKeyUnknown(seen) = &err else {
            panic!("{err:?}");
        };
        assert!(same_key(seen, &server.host_key));
        // Confirmed: the output.
        let out = read(&target, &client_key, Some(seen)).await.unwrap();
        assert!(out.contains("bash\t5.2-1"));
        // Another key on the host side: refused.
        let other = public_line(&generate_key());
        let err = read(&target, &client_key, Some(&other)).await.unwrap_err();
        assert!(matches!(err, SshError::HostKeyChanged(_)), "{err:?}");
        // A key the host does not know.
        let err = read(&target, &generate_key(), Some(seen))
            .await
            .unwrap_err();
        assert_eq!(err, SshError::Auth);
    }

    #[tokio::test]
    async fn reports_failing_commands_and_closed_ports() {
        let client_key = generate_key();
        let server = testserver::start(
            &public_line(&client_key),
            testserver::Reply::Fail("dpkg-query: not found"),
        )
        .await;
        let target = Target {
            address: "127.0.0.1".to_owned(),
            port: server.port,
            username: "x".to_owned(),
        };
        let err = read(&target, &client_key, Some(&server.host_key))
            .await
            .unwrap_err();
        assert_eq!(
            err,
            SshError::Command("exit status 127: dpkg-query: not found".to_owned())
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let target = Target { port, ..target };
        let err = read(&target, &client_key, None).await.unwrap_err();
        assert!(matches!(err, SshError::Connect(_)), "{err:?}");
    }
}
