# Running opensecmon on a server

opensecmon is a single static binary with an SQLite database. It runs as a hardened systemd service on a Debian or
Ubuntu server and serves its web interface over HTTPS itself, with a self-signed certificate created during the
installation. A reverse proxy (Traefik, Caddy, nginx) is optional. This guide covers the installation from the Debian
package, HTTPS and certificates, the configuration, users, backups, updates and the setup behind a reverse proxy.

## Requirements

- Debian 12/13 or Ubuntu 22.04 or later, `amd64`, with systemd.
- **Disk:** about 2 GB for the database (some 420,000 CVEs, BSI and vendor advisories, Debian and Ubuntu data) plus
  up to 1 GB of downloads during a source run (kept in `/var/lib/opensecmon/downloads/` and emptied afterwards), plus
  the daily backups (14 copies of the database by default, in `/var/backups/opensecmon/`). Plan for 10 GB or more for
  the backups, or keep fewer (below).
- **Memory:** about 200 MB while the CVE list is imported, well under that afterwards.
- **Network:** incoming HTTPS on port 8444 from the machines that open the interface; outgoing HTTPS to the sources
  (`api.github.com` and GitHub's download hosts for the CVE list, `nvd.nist.gov`, `www.cisa.gov`,
  `epss.empiricalsecurity.com`, `wid.cert-bund.de`, the vendors' CSAF servers,
  `osv-vulnerabilities.storage.googleapis.com`, `security-tracker.debian.org`), outgoing SMTP to your mail server and
  outgoing SSH (port 22) to the hosts whose packages it reads.

## Installing the Debian package

```bash
sudo apt install ./opensecmon_<version>-1_amd64.deb
```

The package

- creates the system user `opensecmon` (no shell, no home directory),
- installs `/usr/bin/opensecmon`, the configuration `/etc/opensecmon/config.toml` (root:opensecmon, 0640) and the units
  `opensecmon.service`, `opensecmon-backup.service` and `opensecmon-backup.timer`,
- generates the encryption key `/etc/opensecmon/secret.key` (0600, owned by `opensecmon`) unless it exists,
- generates a self-signed certificate `/etc/opensecmon/tls-cert.pem` with the key `tls-key.pem` (0600, owned by
  `opensecmon`) for the host name and the IP addresses of the server, and prints its SHA-256 fingerprint,
- enables the service, but **does not start it** on the first installation (there is no user yet), and starts the
  backup timer.

Then:

```bash
sudo -u opensecmon opensecmon --config /etc/opensecmon/config.toml user add anna     # 1. first user
sudo systemctl start opensecmon               # 2. start (the first import begins on its own)
journalctl -u opensecmon -f                   #    watch it
sudo ufw allow 8444/tcp                       #    only if ufw is active
```

3. Open `https://<server>:8444`, compare the certificate's fingerprint with the one the installation printed (see
   "HTTPS" below) and accept it.
4. Enter the mail server under *Settings > Mail* and send a test mail; then switch on the instant mail and the daily
   report (*Settings > Instant mail*, *Settings > Daily report*) and enter the address of the interface there, so the
   mails can link to it.
5. Add assets: by hand, from CSV, from opennetmon or by reading hosts over SSH (*Assets*; the SSH wizard shows the
   script and the `authorized_keys` line with the forced command for every host).
   **opennetmon on the same server:** use `https://127.0.0.1:8443` with the fingerprint of its self-signed
   certificate (`journalctl -u opennetmon -b | grep fingerprint`, or the error message of the first attempt, after
   comparing it). A host name is resolved by the server's own DNS: if that name leads through a proxy with a sign-in
   (such as Cloudflare Access), the request is redirected and refused, because the token never follows a redirect.

**The first import** runs one source after the other: the CVE list (about 650 MB, 15–20 minutes), the NVD feeds, CISA
KEV, EPSS, the BSI advisories (about 15,000 documents, some 5 minutes), Debian and Ubuntu from OSV (about 900 MB,
some 3 minutes) and the Debian Security Tracker; *Sources* shows the progress. After that only changes are fetched
(conditional requests, change lists, checksums) at the intervals shown on that page. The interface can be used
during the import; matches appear as the sources arrive.

## HTTPS

With `tls_cert_file` and `tls_key_file` set (as in the shipped configuration), the port in `listen` speaks only
HTTPS (TLS 1.2 and 1.3); a plain-HTTP request on it gets a redirect to `https://`, so pages, passwords and cookies
never cross the network unencrypted.

### The generated certificate

It is **self-signed**, valid for ten years, for the host name, the IP addresses of the server (`hostname -I` at the
time of the installation), `localhost` and the loopback addresses. The installation prints its SHA-256 fingerprint,
and the service writes it to the log on every start:

```bash
journalctl -u opensecmon -b | grep fingerprint
openssl x509 -in /etc/opensecmon/tls-cert.pem -noout -fingerprint -sha256 -ext subjectAltName
```

On the first visit the browser warns because no certificate authority it knows has signed the certificate. Show the
certificate (click the warning), compare the fingerprint and accept the exception. The connection is encrypted just
as well as with a bought certificate; the warning only says that the browser cannot check the server's identity on
its own. To get rid of it, use your own certificate (below).

**Generate it again**, e.g. after the address or host name changed. The command never overwrites, so move the old files
aside first; add one `--name` per address or name the server is opened under:

```bash
sudo mv /etc/opensecmon/tls-cert.pem /etc/opensecmon/tls-cert.pem.old
sudo mv /etc/opensecmon/tls-key.pem /etc/opensecmon/tls-key.pem.old
sudo opensecmon --config /etc/opensecmon/config.toml tls generate --name 192.168.0.10 --name secmon.lan
sudo chown opensecmon:opensecmon /etc/opensecmon/tls-key.pem
sudo systemctl restart opensecmon
```

### Your own certificate

Any certificate in PEM format works (a company CA, your own small CA, Let's Encrypt through the DNS challenge):

- **Certificate file:** PEM, the server certificate first, then any intermediates (like `fullchain.pem`), with the
  names or addresses the browsers use in the Subject Alternative Name.
- **Key file:** PEM without a password (PKCS#8, RSA or EC), mode **0600**, owner `opensecmon`; otherwise the service
  refuses to start and says why.

```bash
sudo install -m 0644 -o root -g root my-certificate.pem /etc/opensecmon/tls-cert.pem
sudo install -m 0600 -o opensecmon -g opensecmon my-key.pem /etc/opensecmon/tls-key.pem
sudo systemctl restart opensecmon
journalctl -u opensecmon -n 5          # "HTTPS only …" with the fingerprint of the new certificate
```

Certificates are only read at startup: restart the service after a renewal (a Let's Encrypt deploy hook can copy the
files and restart it).

### Port 443

The service may not open ports below 1024 because of the hardening. For `https://<server>` without a port, allow
exactly this capability with `sudo systemctl edit opensecmon`:

```ini
[Service]
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

Then `listen = "0.0.0.0:443"` and `sudo systemctl restart opensecmon`.

In general the interface should not be reachable from the internet. For access on the road a VPN into your own
network, or a reverse proxy with an access check in front, is the better choice.

## Configuration

`/etc/opensecmon/config.toml`; every key is explained in
[`deploy/config.example.toml`](../deploy/config.example.toml). After a change: `sudo systemctl restart opensecmon`.
The mail settings, thresholds, priority weights, retention and the sources are settings in the interface and take
effect at once.

| Key | In the package | Meaning |
|---|---|---|
| `listen` | `0.0.0.0:8444` | Address and port. With the `tls_` keys: HTTPS only. Without them: plain HTTP, only for loopback behind a reverse proxy. |
| `tls_cert_file`, `tls_key_file` | `/etc/opensecmon/tls-cert.pem`, `tls-key.pem` | Built-in HTTPS (both or neither). |
| `allowed_hosts` | `[]` (any name) | Host names (with the port unless it is 443) the interface is opened under, e.g. `["192.168.0.10:8444", "secmon.lan:8444"]`. Other `Host` headers get 421, which blocks DNS rebinding. Recommended; `/healthz` answers under any name. |
| `client_ip_header` | not set | **Only behind a reverse proxy:** `"x-forwarded-for"` (the last entry) or `"x-real-ip"`, so the sign-in throttle counts per client and not per proxy. Never with direct access: clients could write the header themselves (the service warns). |
| `agent_networks` | not set | Networks computers may use the agent API from ([`agent-api.md`](agent-api.md)), e.g. `["192.168.1.0/24"]`. Unset: private and local addresses. `[]` switches the API off. Other addresses get 403. |
| `agent_packages_dir` | `/usr/share/opensecmon/agent` | Folder with the opensecagent packages offered for download and as updates ([`agent-api.md`](agent-api.md), "Updates of opensecagent"); the package of opensecmon fills it. Read at start. |
| `cookie_secure` | `true` | Session cookie only over HTTPS. |
| `session_ttl_hours`, `session_idle_minutes` | 168, 30 | Absolute lifetime of a session and sign-out after inactivity (0 = off). |
| `time_zone` | the system's | Zone of the daily report, e.g. `"Europe/Berlin"`; servers often run in UTC (`timedatectl`). |
| `fetch_sources` | `true` | Fetch the sources on their schedule and run the mails and the SSH reading. `false` only fetches on "Fetch now" (for a second instance that looks at a copied database). |
| `retention_audit_days` | 730 | Audit log; also adjustable under *Settings > Retention* (at least 90 days). |

Environment variables `OPENSECMON_LISTEN`, `OPENSECMON_DATABASE_PATH`, `OPENSECMON_LOG_FILTER` and
`OPENSECMON_SECRET_KEY_FILE` override the file (e.g. in a drop-in with `systemctl edit opensecmon`).

## Behind a reverse proxy (optional)

If a reverse proxy already serves your other services, it can take over TLS:

1. In `config.toml`: `listen = "127.0.0.1:8090"`, remove (or comment out) the two `tls_` lines, set
   `client_ip_header = "x-forwarded-for"` and `allowed_hosts = ["secmon.example.org"]`; then restart.
2. Point the proxy to `http://127.0.0.1:8090` and let it keep the `Host` header the browser sent.

opensecmon sends its own security headers (CSP `default-src 'self'`, `X-Frame-Options: DENY`, `nosniff`,
`Referrer-Policy`, `no-store`); the proxy only adds TLS and HSTS. Traefik (file provider, Traefik on the host network):

```yaml
http:
  routers:
    opensecmon:
      rule: "Host(`secmon.example.org`)"
      entryPoints: [websecure]
      service: opensecmon
      middlewares: [opensecmon-hsts]
      tls:
        certResolver: letsencrypt        # or a wildcard certificate you already have
  services:
    opensecmon:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8090"
  middlewares:
    opensecmon-hsts:
      headers:
        stsSeconds: 31536000
```

- Traefik replaces an `X-Forwarded-For` from an untrusted client and adds the client address, so the last entry is
  the real client. Do not list the clients' networks under `forwardedHeaders.trustedIPs` of the entry point.
- **Traefik in a Docker container** (bridge network) cannot reach `127.0.0.1` of the host: let opensecmon listen on
  the bridge address (e.g. `listen = "172.17.0.1:8090"`) and make sure that port is not reachable from the network.
- Caddy: `reverse_proxy 127.0.0.1:8090`. nginx: `proxy_pass http://127.0.0.1:8090;` with
  `proxy_set_header Host $host;` and `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`.
- Keeping the built-in HTTPS and pointing the proxy to `https://127.0.0.1:8444` (without checking the self-signed
  certificate) also works, but then port 8444 stays open and `client_ip_header` must still be set; only do that if
  direct access is wanted as well.

## Users

Every user is an administrator; users are managed on the command line as the service user:

```bash
sudo -u opensecmon opensecmon --config /etc/opensecmon/config.toml user add anna [--language de|en]
sudo -u opensecmon opensecmon --config /etc/opensecmon/config.toml user passwd anna   # also ends her sessions
sudo -u opensecmon opensecmon --config /etc/opensecmon/config.toml user delete anna
sudo -u opensecmon opensecmon --config /etc/opensecmon/config.toml user list
```

Passwords are prompted twice on a terminal or read as one line from stdin. Users change their own password under
*Account*. After 5 failed sign-ins for a user name the next attempt waits (5 s, doubling up to 60 s); after 10 from
one address, that address waits (30 s, doubling up to 15 minutes). Sign-ins and changes are in the audit log.

## Day to day

```bash
systemctl status opensecmon
journalctl -u opensecmon -f                       # live log (never passwords or tokens)
journalctl -u opensecmon --since today -p warning
curl -sk https://127.0.0.1:8444/healthz           # ok / unavailable
systemctl list-timers opensecmon-backup
```

*Sources* shows the state of every source (last and next run, errors, counts); the top bar of every page shows
whether a source failed. A failing source is retried with growing intervals; the daily report lists failed sources.

## Computers that report themselves

Desktops and laptops that opensecmon cannot reach over SSH report their packages themselves over the agent API
([`agent-api.md`](agent-api.md)). Add the computer under *Assets > Computers (agent)*; its page shows a one-time
code (15 minutes, once), the certificate to download and the command for Debian, Ubuntu and systems based on them:

```bash
sudo sh opensecmon-agent.sh enroll https://<server>:8444 <code> opensecmon.pem
systemctl list-timers opensecmon-agent.timer      # on the computer: a report every 6 hours
journalctl -u opensecmon-agent                    # on the computer: the answers of opensecmon
```

The script ([`contrib/opensecmon-agent.sh`](../contrib/opensecmon-agent.sh)) keeps the token in
`/etc/opensecmon-agent` (root only) and runs the reports as a systemd service without root. The computer's page shows
the last report and why a report was refused; *Revoke* stops its token at once, *Remove* also deletes its assets.
Requests are only taken from `agent_networks`.

Windows computers (10 from 1803 on, 11, Server 2019 and later) use the PowerShell script from the same page, in a
PowerShell window as administrator:

```powershell
powershell -ExecutionPolicy Bypass -File .\opensecmon-agent.ps1 enroll https://<server>:8444 <code> opensecmon.pem
Get-ScheduledTaskInfo opensecmon-agent                       # last and next run
Get-Content C:\ProgramData\opensecmon-agent\last-report.txt  # the last answer of opensecmon
```

The script ([`contrib/opensecmon-agent.ps1`](../contrib/opensecmon-agent.ps1)) copies itself to
`C:\ProgramData\opensecmon-agent` (SYSTEM and administrators only, with the token) and adds the scheduled task
`opensecmon-agent`, which runs as SYSTEM. Windows becomes one asset ("Windows 11 Version 24H2", version
`10.0.<build>.<UBR>`) matched against Microsoft's ranges in the CVE list; the script also sends the installed programs
and store apps.

**Programs, store apps, snaps and Flatpaks** become assets only when a rule assigns them to a product. Rules built
into opensecmon cover common programs (Firefox, Chrome, Edge, 7-Zip, Notepad++, VLC, Acrobat Reader, PuTTY, …) and
ignore the store apps of Windows, web apps installed from Chrome (publisher `Google\Chrome`) and the base snaps of
Ubuntu (`core*`, `gnome-*`, `mesa-*`, …). Built-in rules that come with an update apply to all computers when the
service starts, not only after their next changed report. Everything else is listed under *Assets > Unassigned*, once for all computers:
*Assign* (vendor and product with suggestions from the CVE list and a preview of the matches) or *Ignore*. The rule
applies to all computers and hosts at once and is listed below the entries; removing it takes the assets away again. A newer script replaces the old one with
`powershell -ExecutionPolicy Bypass -File .\opensecmon-agent.ps1 update`.

**Ubuntu Pro:** the page of an Ubuntu host (SSH) or computer has the setting *Ubuntu Pro*. *Detect automatically*
sees Pro by the sources of esm-infra or esm-apps in `/etc/apt/sources.list.d` (scripts from 0.3.1 on) or once a
package from Ubuntu Pro (ESM) is installed; with an older script choose *yes* for an attached machine. All its packages follow the setting at once, readings do not overwrite it. With Pro the
fixes from Ubuntu Pro count where OSV lists them.

**Kernel and reboot:** from 0.3.1 on both scripts also print the running kernel (`uname -r`), whether
`/var/run/reboot-required` exists and whether the sources of Ubuntu Pro are set up, as lines `OPENSECMON_*` before
`---`. The lists of hosts and computers then show "Kernel X", or "Reboot needed, running kernel X, installed Y".
Older scripts keep working without these details. To get them, copy the script from the wizard to
`/usr/local/bin/opensecmon-inventory` on the host again (the `authorized_keys` line stays); on a computer download
the script from its page and run `sudo install -m 755 opensecmon-agent.sh /usr/local/sbin/opensecmon-agent` (the
enrollment stays).

**Snaps and Flatpaks:** from 0.3.2 on both scripts also print the installed snaps (`snap list`) and Flatpak apps
(`flatpak list --app`) after the packages, if `snap` or `flatpak` is installed; they go through the same rules as the
programs of Windows, also for hosts read over SSH (`lxd` on an Ubuntu server becomes the asset Canonical LXD). The
agent's service sees only system-wide Flatpaks. To get them, update the scripts as described for the kernel above
(the agent script says `VERSION=4`; version 3 found no Flatpaks under its service); opensecmon before 0.3.2 counts the new lines as skipped and takes the packages
as before.

## Backup and restore

- **Automatic:** `opensecmon-backup.timer` runs every day at about 03:30 and writes a consistent copy (SQLite
  `VACUUM INTO`, mode 0600) to `/var/backups/opensecmon/opensecmon-YYYYMMDD-HHMMSS.db`, keeping the newest 14
  (`Environment=KEEP=7` in a drop-in for `opensecmon-backup.service` keeps fewer). It works while the service runs.
- **Manual:** `sudo systemctl start opensecmon-backup`, or
  `sudo -u opensecmon opensecmon --config /etc/opensecmon/config.toml backup /var/backups/opensecmon/before-update.db`
  (the target must not exist, or be an empty regular file).
- **The key:** `/etc/opensecmon/secret.key` is **not** in the backup. It encrypts the SMTP password, the private SSH
  key of the service and the opennetmon token. Keep a copy elsewhere (password manager, offline medium). Database
  plus key restore everything; without the key you enter the SMTP password and the token again and give the hosts a
  new SSH key. The certificate can always be generated again.
- **Off the server:** the backups lie on the same disk. Copy them to another machine regularly (e.g. `rsync -a
  /var/backups/opensecmon/ backup-host:opensecmon/`). The CVE and advisory data can always be fetched again; what
  matters are the assets, triage decisions, settings and the audit log.
- **Restore:**

  ```bash
  sudo systemctl stop opensecmon
  sudo install -m 0600 -o opensecmon -g opensecmon /var/backups/opensecmon/opensecmon-20261107-033000.db \
       /var/lib/opensecmon/opensecmon.db
  sudo rm -f /var/lib/opensecmon/opensecmon.db-wal /var/lib/opensecmon/opensecmon.db-shm
  sudo systemctl start opensecmon
  ```

  Restore the matching key as well if it was lost.

## Update and rollback

```bash
sudo systemctl start opensecmon-backup             # a fresh backup first
sudo apt install ./opensecmon_<new version>-1_amd64.deb
journalctl -u opensecmon -n 20                     # migrations run at startup
```

The package restarts the running service. Key and certificate stay. A changed `config.toml` is kept (`dpkg` asks; the
new version lands next to it as `config.toml.dpkg-dist`, compare it for new keys). Database migrations only go
forward: after an update that brought a new migration, an older version can only run with the backup taken before
the update:

```bash
sudo systemctl stop opensecmon
sudo apt install ./opensecmon_<old version>-1_amd64.deb
# restore the backup taken before the update (see above), then
sudo systemctl start opensecmon
```

Assets and triage made after the backup are lost then. The release notes say whether a version has a new migration.

## Data volume

*Settings > Retention* shows the size of the database per area (measured once a day) and can compact the file
(`VACUUM`, a minute or so, during which the interface waits). CVEs and advisories are never deleted; the audit log and
done or ignored matches that no longer apply are removed after the configured time. The largest JSON columns are
stored deflated.

## The unit at a glance

`opensecmon.service` runs as `opensecmon` without capabilities, with `ProtectSystem=strict`, `ProtectHome`,
`PrivateTmp`, `PrivateDevices`, `MemoryDenyWriteExecute`, a system call filter (`@system-service` without
`@privileged` and `@resources`), only the address families `AF_INET`, `AF_INET6` and `AF_UNIX`, and write access only to
`/var/lib/opensecmon`. `UMask=0077` keeps the database private. The backup service is hardened the same way, has no
network and can only write the database directory and `/var/backups/opensecmon`. `systemd-analyze security
opensecmon` shows the details.

## Uninstalling

```bash
sudo apt remove opensecmon        # keeps configuration, key, certificate, database and backups
sudo apt purge opensecmon         # also removes the configuration, the key and the certificate
# the database, the backups and the user stay; to delete them as well:
# sudo rm -r /var/lib/opensecmon /var/backups/opensecmon && sudo userdel opensecmon
```

## Checklist before production use

- [ ] The certificate's fingerprint was compared on the first visit, or your own certificate is installed.
- [ ] `allowed_hosts` names the addresses the interface is opened under; `client_ip_header` is only set behind a
      reverse proxy.
- [ ] A copy of `/etc/opensecmon/secret.key` is kept outside the server.
- [ ] The backups are copied off the server; a restore was tried once.
- [ ] A test mail arrived; the instant mail and the daily report are switched on with the address of the interface.
- [ ] *Sources* shows every source without errors after the first import.
- [ ] `agent_networks` only names your own networks (or `[]` if no computer reports by itself); computers that
      no longer report are revoked or removed under *Assets > Computers (agent)*.
- [ ] Hosts read over SSH use the forced command from the wizard (`restrict,command=…`), and their host keys were
      compared with the fingerprints shown.
