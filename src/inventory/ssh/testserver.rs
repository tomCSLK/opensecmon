//! A small SSH server for the tests and for trying the wizard without a real host
//! (`cargo run --features fake-host --example fake_ssh_host`): it accepts one client key and answers every
//! command with a fixed output, like a host with the forced inventory command.

use std::net::SocketAddr;
use std::sync::Arc;

use russh::keys::PublicKey;
use russh::server::{Auth, Msg, Server as _, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId};

/// What the server answers.
#[derive(Debug, Clone, Copy)]
pub enum Reply {
    /// The output, exit status 0.
    Output(&'static str),
    /// A message on stderr, exit status 127.
    Fail(&'static str),
}

/// A running server.
pub struct Running {
    pub port: u16,
    /// Its host key in OpenSSH format.
    pub host_key: String,
}

#[derive(Clone)]
struct Fake {
    client: PublicKey,
    reply: Arc<String>,
    fail: bool,
}

impl russh::server::Server for Fake {
    type Handler = Self;
    fn new_client(&mut self, _: Option<SocketAddr>) -> Self {
        self.clone()
    }
}

impl russh::server::Handler for Fake {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(if key.public_key.key_data() == self.client.key_data() {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        if self.fail {
            session.extended_data(channel, 1, self.reply.as_bytes().to_vec())?;
            session.exit_status_request(channel, 127)?;
        } else {
            for chunk in self.reply.as_bytes().chunks(16 * 1024) {
                session.data(channel, chunk.to_vec())?;
            }
            session.exit_status_request(channel, 0)?;
        }
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

/// Starts a server on 127.0.0.1 (`port` 0: any free port) that accepts `client_key` (OpenSSH format).
pub async fn start_on(port: u16, client_key: &str, reply: String, fail: bool) -> Running {
    let host = super::generate_key();
    let host_key = super::public_line(&host);
    let config = Arc::new(russh::server::Config {
        keys: vec![host],
        auth_rejection_time: std::time::Duration::from_millis(10),
        auth_rejection_time_initial: Some(std::time::Duration::ZERO),
        inactivity_timeout: Some(std::time::Duration::from_secs(30)),
        ..Default::default()
    });
    let mut fake = Fake {
        client: PublicKey::from_openssh(client_key).expect("client key"),
        reply: Arc::new(reply),
        fail,
    };
    let socket = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("bind");
    let port = socket.local_addr().expect("address").port();
    tokio::spawn(async move {
        let _ = fake.run_on_socket(config, &socket).await;
    });
    Running { port, host_key }
}

/// [`start_on`] on a free port.
pub async fn start(client_key: &str, reply: Reply) -> Running {
    match reply {
        Reply::Output(text) => start_on(0, client_key, text.to_owned(), false).await,
        Reply::Fail(text) => start_on(0, client_key, text.to_owned(), true).await,
    }
}
