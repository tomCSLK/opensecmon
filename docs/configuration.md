# Configuration

opensecmon reads its settings from a TOML file and from environment variables. Every setting can be given either way; a variable wins over the
file. Without a file the defaults below apply, so a server can also be configured with variables alone (that is how a container is set up).

- **File:** `--config <file>`, else the file named in `OPENSECMON_CONFIG`, else none. The `.deb` uses `/etc/opensecmon/config.toml`;
  [`deploy/config.example.toml`](../deploy/config.example.toml) is that file with comments. An unknown key is an error, so typos do not go unnoticed.
- **Variables:** `OPENSECMON_` plus the key in capitals, e.g. `OPENSECMON_TIME_ZONE=Europe/Berlin`. Switches take `true` or `false`. Lists
  (`allowed_hosts`, `agent_networks`) take their entries separated by commas or spaces.
- An **empty** variable unsets an optional setting (the ones that are "unset" by default below), e.g. `OPENSECMON_TLS_CERT_FILE=` and
  `OPENSECMON_TLS_KEY_FILE=` switch off built-in HTTPS that the file sets. `OPENSECMON_ALLOWED_HOSTS=` empties the list;
  `OPENSECMON_AGENT_NETWORKS=` goes back to the default networks and `OPENSECMON_AGENT_NETWORKS=none` switches the agent API off.
- The subcommands (`user add`, `backup`, `healthcheck` …) read the same file and variables as the server, so they find the same database.
- Changes take effect when the server starts again (`sudo systemctl restart opensecmon`). The mail settings, thresholds, priority weights,
  retention and the sources are not here but in the interface, and take effect at once.

## Settings

| Key | Variable | Default | Meaning |
|---|---|---|---|
| `listen` | `OPENSECMON_LISTEN` | `127.0.0.1:8090` | Address and port of the web interface. Without the `tls_` keys only loopback is sensible (plain HTTP behind a reverse proxy); with them any address, e.g. `0.0.0.0:8444` or `[::]:8444`. |
| `tls_cert_file` | `OPENSECMON_TLS_CERT_FILE` | unset | Certificate chain for built-in HTTPS (PEM). Together with `tls_key_file` the port speaks only HTTPS; plain HTTP there is redirected. |
| `tls_key_file` | `OPENSECMON_TLS_KEY_FILE` | unset | Its private key (PEM, mode 0600). |
| `database_path` | `OPENSECMON_DATABASE_PATH` | `/var/lib/opensecmon/opensecmon.db` | The SQLite database. Its directory must be writable: SQLite adds `-wal` and `-shm` files, and the downloads of the sources go to `downloads/` next to it while they are processed. |
| `log_filter` | `OPENSECMON_LOG_FILTER` | `info` | What is logged, e.g. `info,opensecmon=debug`. `RUST_LOG` takes precedence. |
| `secret_key_file` | `OPENSECMON_SECRET_KEY_FILE` | `/etc/opensecmon/secret.key` | Key that encrypts the stored secrets (SMTP password, SSH key for the hosts, tokens), 64 hex characters, mode 0600. Back it up separately from the database. |
| `generate_missing` | `OPENSECMON_GENERATE_MISSING` | `false` | Create a missing key file and, when both `tls_` files are set and neither exists, a self-signed certificate at startup (the log shows its fingerprint). Existing files are never changed; a certificate without its key stops the start. For containers; the `.deb` creates both files during installation instead. |
| `cookie_secure` | `OPENSECMON_COOKIE_SECURE` | `true` | Mark the session cookie `Secure`. Keep it on with HTTPS and behind a TLS proxy; off only for plain-HTTP development. |
| `session_ttl_hours` | `OPENSECMON_SESSION_TTL_HOURS` | `168` | Longest session, 1 to 2160 hours. |
| `session_idle_minutes` | `OPENSECMON_SESSION_IDLE_MINUTES` | `30` | Sign out after this many minutes without activity, 0 to 1440 (`0` = never). |
| `client_ip_header` | `OPENSECMON_CLIENT_IP_HEADER` | unset | Only behind a reverse proxy: `x-forwarded-for` (last entry) or `x-real-ip`, for the sign-in throttling, the audit log and `agent_networks`. Never with direct access: clients could write the header themselves (the server warns). |
| `allowed_hosts` | `OPENSECMON_ALLOWED_HOSTS` | empty (any name) | Host names, with the port unless it is 80/443, the interface is opened under, e.g. `["192.168.0.10:8444", "secmon.lan:8444"]`. Other `Host` headers get 421, which blocks DNS rebinding; `/healthz` answers under any name. At most 32. |
| `retention_audit_days` | `OPENSECMON_RETENTION_AUDIT_DAYS` | `730` | Days the audit log is kept, 1 to 36500; *Settings > Retention* may override it. |
| `time_zone` | `OPENSECMON_TIME_ZONE` | unset (the system's) | Zone of the daily report, the times in mails and the backup time, e.g. `Europe/Berlin`. Unset: `TZ`, else `/etc/localtime`, else UTC. The program carries its own copy of the time zone database for systems without `/usr/share/zoneinfo`. |
| `fetch_sources` | `OPENSECMON_FETCH_SOURCES` | `true` | Fetch the sources on their schedule, read the hosts and send the mails. `false` only fetches on "Fetch now" (for a second instance that looks at a copied database). |
| `agent_networks` | `OPENSECMON_AGENT_NETWORKS` | unset (private and local addresses) | Networks computers may use the agent API from ([`agent-api.md`](agent-api.md)), as addresses or CIDR ranges, e.g. `["192.168.1.0/24"]`. `[]` (variable: `none`) switches the API off. At most 64. |
| `agent_packages_dir` | `OPENSECMON_AGENT_PACKAGES_DIR` | `/usr/share/opensecmon/agent` | Folder with the opensecagent packages offered for download and as updates; the `.deb` fills it. Read at start; packages with a missing or wrong name or signature are left out. |
| `backup_dir` | `OPENSECMON_BACKUP_DIR` | unset (no backup by the server) | Directory for a daily backup made by the server itself, for containers. The `.deb` leaves it unset and uses its systemd timer (`opensecmon-backup.timer`) instead. |
| `backup_keep` | `OPENSECMON_BACKUP_KEEP` | `14` | How many of those backups are kept, 1 to 1000. One backup is about as large as the database (often 1.5 GB or more), so keep few. |
| `backup_time` | `OPENSECMON_BACKUP_TIME` | `03:30` | Local time of that backup, `HH:MM` (24 hours), in `time_zone`. |

## The backup made by the server

With `backup_dir` set, the server writes a consistent copy of the database once a day, the same as `opensecmon backup` and the timer of the
`.deb`: `opensecmon-YYYYMMDD-HHMMSS.db` (local time, mode 0600) in that directory. The copy is written as `….db.part` and renamed when it is
complete, then all but the newest `backup_keep` copies are deleted. Other files in the directory (e.g. a copy taken before an update) are never
touched. If the newest copy is older than 25 hours when the server starts, it makes one five minutes later, like the timer with
`Persistent=true`. The key file is not part of the copy: back it up separately.

## Health check

`opensecmon healthcheck` asks the running server for `/healthz` on its own address (an address that listens on every interface is reached over
loopback) and exits with 0 when it answers 200, else with 1 and a line on stderr. With built-in HTTPS the server must present the certificate
of `tls_cert_file`; its fingerprint is checked, not its name or dates. A container image without a shell uses it as its health check.

## Client addresses in containers

The sign-in throttling, the audit log and `agent_networks` use the address of the client. Some port forwardings hand every connection to the
container from the container's own address (rootless Podman with `slirp4netns`, the default before Podman 5). Inside a container, and
without `client_ip_header`, the server notices this and warns once in the log. Docker, Podman with `--network pasta` and `network_mode: host`
keep the addresses.
