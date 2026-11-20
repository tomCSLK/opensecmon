//! Warns once when a container's port forwarding hides the addresses of the clients.
//!
//! Some forwarders (rootless Podman with `slirp4netns`, the default before Podman 5) hand every connection
//! to the container from the container's own address. Then the sign-in throttling treats all clients as
//! one, the audit log shows that address, and `agent_networks` sees it instead of the computers. Docker and
//! Podman with `pasta` keep the addresses. The check runs only inside a container (`/.dockerenv` or
//! `/run/.containerenv`) and only without `client_ip_header` (behind a reverse proxy its address is
//! expected).

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Default)]
pub struct HiddenPeer {
    /// The container's own address; `None` outside a container (then nothing is checked).
    own: Option<IpAddr>,
    warned: AtomicBool,
}

impl HiddenPeer {
    /// Looks at where the server runs.
    pub fn detect() -> Self {
        let in_container =
            Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists();
        Self {
            own: in_container.then(own_address).flatten(),
            warned: AtomicBool::new(false),
        }
    }

    /// For a container with the address `own`.
    pub fn with_own(own: IpAddr) -> Self {
        Self {
            own: Some(own),
            warned: AtomicBool::new(false),
        }
    }

    /// Checks the address of a client; `true` when it is the container's own (warned once).
    pub fn observe(&self, peer: Option<IpAddr>) -> bool {
        let hidden = self.own.is_some() && peer == self.own;
        if hidden && !self.warned.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                address = %peer.map(|ip| ip.to_string()).unwrap_or_default(),
                "requests arrive from the container's own address: the port forwarding hides the clients, so the \
                 sign-in throttling, the audit log and agent_networks cannot tell them apart; use Docker, Podman \
                 with --network pasta or network_mode: host (docs/docker.md)"
            );
        }
        hidden
    }
}

/// The address this host would send from (a UDP socket that is connected but never sends).
fn own_address() -> Option<IpAddr> {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).ok()?;
    // TEST-NET-1: nothing is sent, connect only picks the route.
    socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).ok()?;
    let ip = socket.local_addr().ok()?.ip();
    (!ip.is_unspecified() && !ip.is_loopback()).then_some(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_own_address_in_a_container_counts() {
        let own: IpAddr = "10.0.2.100".parse().unwrap();
        let check = HiddenPeer::with_own(own);
        assert!(!check.observe(Some("192.168.1.20".parse().unwrap())));
        assert!(!check.observe(None));
        assert!(check.observe(Some(own)));
        assert!(check.observe(Some(own)), "still reported, warned only once");
        assert!(check.warned.load(Ordering::Relaxed));

        let outside = HiddenPeer::default();
        assert!(!outside.observe(Some(own)));
    }
}
