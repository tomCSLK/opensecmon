use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use opensecmon::auth;
use opensecmon::config::Config;
use opensecmon::crypto::SecretBox;
use opensecmon::i18n::Lang;
use opensecmon::maintenance::Maintenance;
use opensecmon::storage::{self, users};
use opensecmon::tls;
use opensecmon::web::{self, AppState};
use sqlx::SqlitePool;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    version,
    about = "Security advisories for your own software and hardware"
)]
struct Args {
    /// Path to the TOML config file (defaults and OPENSECMON_* environment variables apply without it)
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the web server (default)
    Serve,
    /// Manage the users (every user is an administrator)
    #[command(subcommand)]
    User(UserCommand),
    /// Manage the key that encrypts stored secrets
    #[command(subcommand)]
    Key(KeyCommand),
    /// Manage the certificate of the built-in HTTPS
    #[command(subcommand)]
    Tls(TlsCommand),
    /// Write a consistent copy of the database (safe while the server runs; never overwrites)
    Backup {
        /// Target file; created with mode 0600
        target: PathBuf,
    },
}

#[derive(Subcommand)]
enum KeyCommand {
    /// Create a new random key file (mode 0600); never overwrites an existing file
    Generate,
}

#[derive(Subcommand)]
enum TlsCommand {
    /// Create a self-signed certificate (ten years) for this server; never overwrites existing files
    Generate {
        /// Host name or IP address the server is opened under (repeatable); the host name, localhost and the
        /// loopback addresses are always added
        #[arg(long = "name", value_name = "NAME")]
        names: Vec<String>,
        /// Certificate file (default: tls_cert_file from the config)
        #[arg(long)]
        cert: Option<PathBuf>,
        /// Key file, created with mode 0600 (default: tls_key_file from the config)
        #[arg(long)]
        key: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum UserCommand {
    /// Create a user; the password is prompted for (or read from stdin when piped)
    Add {
        username: String,
        /// Language of the user interface (de, en); without it the browser's language is used
        #[arg(long, value_parser = parse_language)]
        language: Option<Lang>,
    },
    /// Set a new password and end all sessions of the user
    Passwd { username: String },
    /// Delete a user and end their sessions
    Delete { username: String },
    /// List users
    List,
}

fn parse_language(code: &str) -> Result<Lang, String> {
    Lang::parse(code).ok_or_else(|| {
        let known: Vec<_> = Lang::ALL.iter().map(|l| l.code()).collect();
        format!("unknown language '{code}' (known: {})", known.join(", "))
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config = Config::load(args.config.as_deref()).context("loading configuration")?;

    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&config.log_filter))
        .context("invalid log filter")?;
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    let command = args.command.unwrap_or(Command::Serve);
    if let Command::Key(KeyCommand::Generate) = command {
        SecretBox::generate_key_file(&config.secret_key_file).context("creating key file")?;
        println!("Key file created: {}", config.secret_key_file.display());
        println!(
            "Back it up separately from the database: without it, stored secrets cannot be decrypted."
        );
        return Ok(());
    }

    if let Command::Tls(TlsCommand::Generate { names, cert, key }) = &command {
        let cert = cert.clone().or_else(|| config.tls_cert_file.clone());
        let key = key.clone().or_else(|| config.tls_key_file.clone());
        let (Some(cert), Some(key)) = (cert, key) else {
            bail!(
                "no certificate files: set tls_cert_file and tls_key_file in the config, or pass --cert and --key"
            );
        };
        // Names found on the system (e.g. a host name with "_") must not make the installation fail.
        let (valid, skipped): (Vec<_>, Vec<_>) = tls::certificate_names(names)
            .into_iter()
            .partition(|name| tls::is_valid_name(name));
        for name in &skipped {
            eprintln!("Skipping '{name}': not a valid host name or IP address.");
        }
        let generated = tls::generate(&cert, &key, &valid).context("creating the certificate")?;
        println!(
            "Certificate created: {} (key: {})",
            cert.display(),
            key.display()
        );
        println!("Valid for: {}", generated.names.join(", "));
        println!("SHA-256 fingerprint: {}", generated.fingerprint);
        println!(
            "It is self-signed: browsers warn on the first visit; compare the fingerprint before accepting it."
        );
        return Ok(());
    }

    if let Command::Backup { target } = &command {
        let pool = storage::connect(&config.database_path)
            .await
            .context("opening database")?;
        storage::backup_to(&pool, target)
            .await
            .context("writing the backup")?;
        println!("Backup written: {}", target.display());
        println!(
            "It contains the encrypted secrets but not the key file ({}); back that up separately.",
            config.secret_key_file.display()
        );
        return Ok(());
    }

    let pool = storage::connect(&config.database_path)
        .await
        .context("opening database")?;
    storage::migrate(&pool)
        .await
        .context("running migrations")?;

    match command {
        Command::Serve => serve(config, pool).await,
        Command::User(cmd) => manage_users(&pool, cmd).await,
        Command::Key(_) | Command::Tls(_) | Command::Backup { .. } => Ok(()),
    }
}

async fn serve(config: Config, pool: SqlitePool) -> anyhow::Result<()> {
    let secrets = SecretBox::from_key_file(&config.secret_key_file).with_context(|| {
        format!(
            "loading the encryption key (create one with `opensecmon key generate`; config key secret_key_file = {})",
            config.secret_key_file.display()
        )
    })?;
    if users::count_users(&pool).await? == 0 {
        tracing::warn!("no users exist yet; create one with `opensecmon user add <name>`");
    }
    let tls = match config.tls_files() {
        Some((cert, key)) => Some(tls::load(cert, key).with_context(|| {
            format!(
                "loading the HTTPS certificate (create one with `opensecmon tls generate`; config keys \
                 tls_cert_file = {}, tls_key_file = {})",
                cert.display(),
                key.display()
            )
        })?),
        None => None,
    };
    if tls.is_none() && !config.listen.ip().is_loopback() {
        tracing::warn!(
            listen = %config.listen,
            "serving plain HTTP on a non-loopback address; set tls_cert_file and tls_key_file or put a \
             TLS-terminating reverse proxy in front"
        );
    }
    if !config.cookie_secure {
        if tls.is_some() {
            tracing::warn!("cookie_secure is disabled although HTTPS is on; set it to true");
        } else {
            tracing::warn!("cookie_secure is disabled; only use this for plain-HTTP development");
        }
    }
    if tls.is_some() && !config.listen.ip().is_loopback() && config.client_ip_header.is_some() {
        tracing::warn!(
            "client_ip_header is set although browsers connect directly: a client can write that header itself \
             and so escape the sign-in throttling; remove it unless a reverse proxy is the only way in"
        );
    }
    if config.allowed_hosts.is_empty() {
        tracing::warn!(
            "allowed_hosts is empty; set it to the host name(s) of this server to block DNS rebinding"
        );
    }
    if tls.is_none()
        && config.listen.ip().is_loopback()
        && config.client_ip_header.is_none()
        && config.cookie_secure
    {
        tracing::warn!(
            "client_ip_header is not set: behind the reverse proxy every sign-in comes from the proxy's address, \
             so failed attempts of one client delay the sign-in for everybody; set it to \"x-forwarded-for\""
        );
    }
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .with_context(|| {
            let hint = if config.listen.port() < 1024 {
                " (ports below 1024 need CAP_NET_BIND_SERVICE, see docs/operations.md)"
            } else {
                ""
            };
            format!("binding {}{hint}", config.listen)
        })?;
    if let Some(tls) = &tls {
        tracing::info!(fingerprint = %tls.fingerprint, "HTTPS only; plain HTTP is redirected");
    }
    tracing::info!(listen = %config.listen, db = %config.database_path.display(), "opensecmon started");

    let db = pool.clone();
    // New weights of the priority whose recomputation a stop interrupted.
    if opensecmon::storage::prio::pending(&pool).await? {
        opensecmon::storage::prio::spawn_recompute(pool.clone());
    }
    // A "compact the database" that a stop cut off.
    opensecmon::storage::retention::recover(&pool, opensecmon::sources::now_ms()).await?;
    // JSON columns of rows written before migration 0013 are packed in the background.
    opensecmon::storage::packed::spawn_convert(pool.clone());
    let state = AppState::new(pool.clone(), &config, Arc::new(secrets));
    let maintenance = Maintenance::spawn(
        pool,
        config.retention_audit_days,
        state.session_idle_secs,
        state.time_zone.clone(),
    );
    let scheduler = state.sources.spawn();
    // Hosts and opennetmon are read in the background where the sources are fetched (`fetch_sources`).
    let inventory = state.sources.scheduled().then(|| {
        opensecmon::inventory::runner::Runner::spawn(state.pool.clone(), Arc::clone(&state.secrets))
    });
    // Rules built into this version reach the programs computers and hosts reported before (their reports may
    // not change for a long time); only where the sources are fetched, like the reading of the hosts.
    if state.sources.scheduled() {
        let now = opensecmon::sources::now_ms();
        match opensecmon::storage::items::resync_all(&state.pool, now).await {
            Ok(changed) => {
                if !changed.is_empty() {
                    tracing::info!(assets = changed.len(), "reported programs assigned anew");
                }
                opensecmon::inventory::runner::match_in_background(
                    state.pool.clone(),
                    changed,
                    "start-up".into(),
                );
            }
            Err(e) => {
                tracing::error!(error = %e, "applying the rules to the reported programs failed")
            }
        }
    }
    // Mails go out where the sources are fetched, so a second instance on the same database sends none.
    let notifier = state.sources.scheduled().then(|| {
        opensecmon::alerts::Notifier::spawn(
            state.pool.clone(),
            Arc::clone(&state.secrets),
            state.time_zone.clone(),
        )
    });
    let app = web::router(state);
    let served = match tls {
        Some(tls) => {
            tls::serve(listener, app, tls.config, shutdown_signal()).await;
            Ok(())
        }
        None => axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serving"),
    };
    scheduler.stop().await;
    if let Some(inventory) = inventory {
        inventory.stop().await;
    }
    if let Some(notifier) = notifier {
        notifier.stop().await;
    }
    maintenance.stop().await;
    // Closing the pool checkpoints the WAL into the database file.
    db.close().await;
    served?;
    tracing::info!("opensecmon stopped");
    Ok(())
}

async fn manage_users(pool: &SqlitePool, cmd: UserCommand) -> anyhow::Result<()> {
    match cmd {
        UserCommand::Add { username, language } => {
            auth::validate_username(&username).map_err(|m| anyhow::anyhow!(Lang::En.msg(&m)))?;
            if users::find_by_username(pool, &username).await?.is_some() {
                bail!("user '{username}' exists already");
            }
            let password = read_new_password()?;
            let hash = auth::hash_password(&password)?;
            users::create_user(pool, &username, &hash, language).await?;
            println!("User '{username}' created.");
        }
        UserCommand::Passwd { username } => {
            if users::find_by_username(pool, &username).await?.is_none() {
                bail!("user '{username}' does not exist");
            }
            let password = read_new_password()?;
            let hash = auth::hash_password(&password)?;
            users::set_password_hash(pool, &username, &hash).await?;
            users::delete_sessions_of_user(pool, &username).await?;
            println!("Password for '{username}' changed; existing sessions were ended.");
        }
        UserCommand::Delete { username } => {
            if !users::delete_user(pool, &username).await? {
                bail!("user '{username}' does not exist");
            }
            println!("User '{username}' deleted; their sessions were ended.");
        }
        UserCommand::List => {
            for user in users::list_users(pool).await? {
                let language = user.language.map_or("browser", |l| l.code());
                println!("{:<32} {language}", user.username);
            }
        }
    }
    Ok(())
}

/// Prompts twice on a terminal; reads a single line from stdin when piped.
fn read_new_password() -> anyhow::Result<String> {
    let password = if std::io::stdin().is_terminal() {
        let first = rpassword::prompt_password("New password: ")?;
        let second = rpassword::prompt_password("Repeat password: ")?;
        if first != second {
            bail!("passwords do not match");
        }
        first
    } else {
        let mut line = String::new();
        std::io::stdin().take(1024).read_to_string(&mut line)?;
        line.lines().next().unwrap_or_default().to_owned()
    };
    auth::validate_password(&password).map_err(|m| anyhow::anyhow!(Lang::En.msg(&m)))?;
    Ok(password)
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let ctrl_c = tokio::signal::ctrl_c();
    match signal(SignalKind::terminate()) {
        Ok(mut term) => {
            tokio::select! {
                _ = ctrl_c => {}
                _ = term.recv() => {}
            }
        }
        Err(_) => {
            let _ = ctrl_c.await;
        }
    }
}
