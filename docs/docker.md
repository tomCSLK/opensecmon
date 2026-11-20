# Running in a container

opensecmon is also available as a container image for Docker and Podman, next to the `.deb` package ([`operations.md`](operations.md)).
It runs on any Linux host with amd64 or arm64 (Raspberry Pi 4/5, many NAS, ARM servers) and under Docker Desktop.

| | |
|---|---|
| Image | `ghcr.io/tomcslk/opensecmon` (GitHub Container Registry), from the next release on |
| Tags | `X.Y.Z` (one release), `X.Y` (newest patch release of that line), `latest` (newest release) |
| Architectures | `linux/amd64`, `linux/arm64` |
| Content | The static binary, `LICENSE` and `THIRD-PARTY-LICENSES.txt` in `/usr/share/doc/opensecmon/`, and the signed opensecagent packages of a release in `/usr/share/opensecmon/agent/` (when one is named, see [Computers](#computers-with-opensecagent)). Nothing else: no shell, no package manager, about 20 MB (25 MB with the packages) |
| User | UID/GID `10001`, never root |
| Port | `8444`, HTTPS (8443 is opennetmon's, so both run side by side) |
| Volumes | `/etc/opensecmon` (key, certificate), `/var/lib/opensecmon` (database, downloads while fetching, daily backups) |

The image is built from [`Containerfile`](../Containerfile) by the workflow `.github/workflows/container.yml` when a release is tagged; every
architecture is built on its own hardware and smoke-tested before it is pushed.

## Space and the first start

opensecmon keeps the public vulnerability data locally, so it needs room:

- **Database:** about 2 GB after the first fetch, growing slowly.
- **First fetch:** about 2 GB of downloads (CVE list, NVD, OSV of Debian and Ubuntu, BSI and vendor advisories) and about 25 minutes on
  an amd64 laptop with a fast line, on a Raspberry Pi longer. The downloads land in `downloads/` next to the database and are deleted after each run. The interface works
  meanwhile; *Sources* shows the state of each source.
- **Backups:** each about as large as the database; the image keeps three (see [Backups](#backups)).

Plan for **10 GB** free in the data volume. Memory: about 200 MB during the first fetch, much less afterwards (measured on amd64;
measurements on a Raspberry Pi are still to come).

## Quick start

Take [`compose.yaml`](../compose.yaml) from the repository (or from the release), put it into an empty folder, set
`OPENSECMON_ALLOWED_HOSTS` in it to the address you will type (see [HTTPS and certificates](#https-and-certificates)) and run there:

```bash
docker compose up -d
docker compose exec opensecmon opensecmon user add admin     # asks for the password twice
docker compose logs opensecmon | grep fingerprint
```

Then open `https://<address of this computer>:8444`. On the first start the server creates the encryption key and a self-signed certificate in
the config volume; the browser warns once. Compare the fingerprint in the warning with the one from the log before you accept it.
There is no default user: until you create one, nobody can sign in. Every user can change everything.

Without Compose, the same as one command:

```bash
docker run -d --name opensecmon --restart unless-stopped -p 8444:8444 \
  -v opensecmon-config:/etc/opensecmon -v opensecmon-data:/var/lib/opensecmon \
  -e TZ=Europe/Berlin -e OPENSECMON_ALLOWED_HOSTS=192.168.1.10:8444 \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true \
  ghcr.io/tomcslk/opensecmon:latest
docker exec -it opensecmon opensecmon user add admin
```

The other subcommands work the same way: `opensecmon user list`, `user passwd <name>`, `user delete <name>`, `backup <file>`, `healthcheck`
(`docker compose exec opensecmon opensecmon …`). They read the same settings as the server.

## Settings

The image sets everything through variables ([`configuration.md`](configuration.md) lists all of them); add or override them under
`environment:` in `compose.yaml`. What the image sets:

| Variable | Value in the image |
|---|---|
| `OPENSECMON_LISTEN` | `0.0.0.0:8444` |
| `OPENSECMON_DATABASE_PATH` | `/var/lib/opensecmon/opensecmon.db` |
| `OPENSECMON_SECRET_KEY_FILE` | `/etc/opensecmon/secret.key` |
| `OPENSECMON_TLS_CERT_FILE`, `OPENSECMON_TLS_KEY_FILE` | `/etc/opensecmon/tls-cert.pem`, `/etc/opensecmon/tls-key.pem` |
| `OPENSECMON_GENERATE_MISSING` | `true` (key and certificate on the first start) |
| `OPENSECMON_BACKUP_DIR` | `/var/lib/opensecmon/backups` (daily backup at 03:30) |
| `OPENSECMON_BACKUP_KEEP` | `3` (the `.deb` keeps 14 with its timer) |
| `OPENSECMON_AGENT_PACKAGES_DIR` | `/usr/share/opensecmon/agent` |

Worth setting yourself:

- **`TZ`** (e.g. `Europe/Berlin`): the zone of the daily report, the times in mails and the backup time; without it the container runs in UTC.
  The image carries its own time zone database. `OPENSECMON_TIME_ZONE` does the same for opensecmon alone.
- **`OPENSECMON_ALLOWED_HOSTS`**: the addresses you open opensecmon under, with the port, separated by commas, e.g.
  `192.168.1.10:8444,secmon.lan:8444`. Other host names are refused (against DNS rebinding); without it the log warns at every start.

The mail server, the daily report, the sources, priorities and retention are set in the interface, as with the `.deb`.
A config file still works: mount it and name it in `OPENSECMON_CONFIG`; variables win over it.

## HTTPS and certificates

The certificate created on the first start is valid for ten years and names the hosts of `OPENSECMON_ALLOWED_HOSTS`, the container's host name,
`localhost` and the loopback addresses. Browsers warn once anyway, because nobody signed it; compare the fingerprint.

**Set `OPENSECMON_ALLOWED_HOSTS` before the first start.** The scripts for computers (`opensecmon-agent.sh`, `opensecmon-agent.ps1`) check the
name in the certificate; a certificate without the address the computers use makes them fail. opensecagent itself checks only the fingerprint.
If the certificate was created without the right names, remove the two files and restart, or create them yourself:

```bash
docker compose run --rm --no-deps opensecmon tls generate --name 192.168.1.10 --name secmon.lan
```

(after removing `tls-cert.pem` and `tls-key.pem` from the config volume; the command never overwrites). A new certificate has a new
fingerprint: computers enrolled with the old one stop reporting until they are enrolled again (*Assets → Computers*, new code), unless the
new certificate comes from a CA they trust.

To use your own certificate (from your own small CA or Let's Encrypt, see [`operations.md`](operations.md#your-own-certificate)), mount it and
point the variables to it:

```yaml
    volumes:
      - ./certs:/certs:ro
    environment:
      OPENSECMON_TLS_CERT_FILE: /certs/fullchain.pem
      OPENSECMON_TLS_KEY_FILE: /certs/privkey.pem
```

The key must belong to UID 10001 and have mode 0600, otherwise the server does not start: `sudo chown 10001:10001 certs/privkey.pem && chmod 600 certs/privkey.pem`
(rootless Podman: `podman unshare chown 10001:10001 certs/privkey.pem`). Restart with `docker compose up -d`.

### Behind a reverse proxy

If a reverse proxy (Traefik, Caddy, nginx) terminates HTTPS, switch the built-in HTTPS off with **empty** variables and let opensecmon speak
plain HTTP inside the container network:

```yaml
    environment:
      OPENSECMON_TLS_CERT_FILE: ""
      OPENSECMON_TLS_KEY_FILE: ""
      OPENSECMON_LISTEN: 0.0.0.0:8090
      OPENSECMON_CLIENT_IP_HEADER: x-forwarded-for
      OPENSECMON_ALLOWED_HOSTS: secmon.example.org
    # no "ports:" - only the proxy reaches the container
```

Keep `OPENSECMON_COOKIE_SECURE` at its default (`true`): the browser talks HTTPS to the proxy. The log warns about plain HTTP on a non-loopback
address; that is expected here. Set `OPENSECMON_CLIENT_IP_HEADER` only when nothing but the proxy can reach port 8090, because the sign-in
throttling, the audit log and `agent_networks` trust that header. The health check of the image follows the setting and asks over HTTP.
Computers then enroll through the proxy with its certificate ([`agent-api.md`](agent-api.md)).

## Network and client addresses

The container reaches the sources (HTTPS), the mail server, the hosts it reads over SSH and opennetmon from Docker's bridge network; nothing
needs to be opened besides port 8444. If opennetmon runs as a container on the same host, give opensecmon the host's address and port 8443 of
opennetmon.

The sign-in throttling, the audit log and `agent_networks` use the address of the client. **Docker** and **Podman with `pasta`** (the default
since Podman 5) keep it. **Rootless Podman with `slirp4netns`** (the default before Podman 5) hands every connection to the container from the
container's own address: then all clients look like one, failed sign-ins of one lock out all, and `agent_networks` cannot tell computers apart.
opensecmon notices this and warns once in the log ("the port forwarding hides the clients"). With `pasta`, requests that the host itself
sends to its own address appear with the address of the gateway; those of other devices keep theirs. Remedies, one of them:

- `podman run --network pasta …` (with `podman-compose`: `network_mode: pasta` in `compose.yaml`);
- `network_mode: host` (without `ports:`): the server listens on port 8444 of the host;
- a reverse proxy in front with `OPENSECMON_CLIENT_IP_HEADER` (see above).

## Computers with opensecagent

Computers report their software to opensecmon with opensecagent or the scripts ([`agent-api.md`](agent-api.md)); this works with the container
as with the `.deb`. The enrollment code carries the address you opened opensecmon under and the fingerprint of its certificate.

- **Packages:** an image built from a release contains the signed opensecagent packages of the release named in
  [`dist/agent/release.txt`](../dist/agent/release.txt) (checked against their SHA-256 and the publisher key when the image is built). The
  pages of the computers then offer them for download, and updates of enrolled computers work by button. Without packages they offer only the
  scripts.
- **Newer packages than the image's:** put them with their `.sig` files into a folder, mount it and point `OPENSECMON_AGENT_PACKAGES_DIR` to it.
  opensecmon reads the folder at start and takes only files with the expected names and a signature; the agent checks the signature before
  it installs anything.

  ```yaml
      volumes:
        - ./agent:/agent:ro
      environment:
        OPENSECMON_AGENT_PACKAGES_DIR: /agent
  ```

- **`agent_networks`:** by default computers may report from private and local addresses. Narrow it with `OPENSECMON_AGENT_NETWORKS`
  (e.g. `192.168.1.0/24`) or switch the agent API off with `none`. With hidden client addresses (see above) it cannot work.

opensecagent itself does not belong into a container: it reads the software of the computer it runs on.

## Backups

The server writes a consistent copy of the database every day at 03:30 (local time, `TZ`) to `backups/` in the data volume and keeps three
([`configuration.md`](configuration.md#the-backup-made-by-the-server)); a backup missed while the container was down follows five minutes after
the start. Change it with `OPENSECMON_BACKUP_TIME` and `OPENSECMON_BACKUP_KEEP` (each copy is about as large as the database).

The backups stay in the same volume as the database, so **copy them off the host** as well, and the config volume with the key **separately**:
without `secret.key`, the stored SMTP password, the SSH key for the hosts and the tokens of every backup are unreadable. For example (the
volume names start with the folder name of `compose.yaml`; `docker volume ls` shows them):

```bash
docker run --rm -v opensecmon_data:/data:ro -v "$PWD":/out alpine \
  sh -c 'cp "$(ls -1 /data/backups/opensecmon-*.db | tail -n 1)" /out/'
docker run --rm -v opensecmon_config:/config:ro -v "$PWD":/out alpine \
  cp /config/secret.key /out/opensecmon-secret.key
```

A backup by hand at any time: `docker compose exec opensecmon opensecmon backup /var/lib/opensecmon/backups/before-update.db`
(never overwrites an existing file; files with other names than `opensecmon-<date>-<time>.db` are not deleted by the daily backup).

**Restore:** stop the container (`docker compose stop`), replace `opensecmon.db` in the data volume with the backup and delete
`opensecmon.db-wal` and `opensecmon.db-shm` next to it, keep the key that belongs to it in the config volume, then `docker compose up -d`.

## Updates

```bash
docker compose exec opensecmon opensecmon backup /var/lib/opensecmon/backups/before-<new version>.db
docker compose pull
docker compose up -d
```

New database migrations run on the first start of the new image. With `image: ghcr.io/tomcslk/opensecmon:latest` the pull fetches the newest
release; with a pinned tag (`:0.4`), change the tag first. The release notes on GitHub announce new versions; opensecmon does not check
for them itself.

**Going back** to an older image works only as long as the newer one brought no migration; otherwise restore the backup made before the update
(release notes say whether a release changes the database).

## Health check

The image runs `opensecmon healthcheck` every 30 seconds; `docker compose ps` and `docker inspect` show `healthy` or `unhealthy`. The command
asks `/healthz` of the server itself and checks the fingerprint of its certificate ([`configuration.md`](configuration.md#health-check)). Other
monitoring (opennetmon, for instance) can call `https://<host>:8444/healthz` directly; it answers under any host name.

## Security

`compose.yaml` starts the container read-only (`read_only`, writable are only the two volumes and a `tmpfs` at `/tmp`), without any
capability (`cap_drop: ALL`) and with `no-new-privileges`; the process runs as UID 10001. The image contains no shell, so a compromised
process finds no tools. As with the `.deb`, put the server into your own network only and reach it from outside through a VPN.

The image is AGPL-3.0-or-later like the source; the sign-in page and the user menu link the source code.

## Podman

Everything above works with Podman: `podman compose` (with `podman-compose` or `docker-compose` installed) or the `podman run` line with the
same options. Mind the client addresses with `slirp4netns` ([above](#network-and-client-addresses)). Ports below 1024 are not allowed rootless;
8444 is fine. The health check needs an image in Docker format, which the published image is (Podman's own builds need `--format docker`, as
`dev/container.sh` does).

## Synology

**Not tested on a Synology yet.** The image uses only standard Docker options, so it should run there as well; reports are welcome. Mind the
space ([above](#space-and-the-first-start)).

- **Models:** you need *Container Manager* (DSM 7.2 and later) or the older *Docker* package, offered for Synology's Intel and AMD models
  (most "+" models) and some ARM models; the image covers both (`amd64`, `arm64`).
- **Project:** in Container Manager, create a project (Project → Create), choose a folder such as `/volume1/docker/opensecmon` and paste
  [`compose.yaml`](../compose.yaml). Prefer `:X.Y` over `:latest` to get fixes but no jump to a new minor version without your decision.
- **Folders instead of volumes:** the folders must belong to UID 10001, otherwise the server cannot write and does not start:

  ```yaml
      volumes:
        - /volume1/docker/opensecmon/config:/etc/opensecmon
        - /volume1/docker/opensecmon/data:/var/lib/opensecmon
  ```

  ```bash
  sudo mkdir -p /volume1/docker/opensecmon/config /volume1/docker/opensecmon/data
  sudo chown -R 10001:10001 /volume1/docker/opensecmon/config /volume1/docker/opensecmon/data
  sudo chmod 700 /volume1/docker/opensecmon/config /volume1/docker/opensecmon/data
  ```

- **First user:** the image has no shell, so the terminal of Container Manager cannot open one. Enable SSH (Control Panel → Terminal & SNMP),
  sign in and run `sudo docker ps` to see the container's name (in a project usually `<project>-opensecmon-1`), then
  `sudo docker exec -it <name> opensecmon user add admin`.
- **Port:** if port 8444 is taken on the NAS, change the left side of the mapping, e.g. `"8445:8444"`, and include that port in
  `OPENSECMON_ALLOWED_HOSTS`.

## Building the image yourself

```bash
dev/agent-release.sh        # optional: the signed opensecagent packages named in dist/agent/release.txt into dist/agent/
dev/container.sh            # static binary for this machine's architecture, then the image opensecmon:<version>
dev/container.sh --test     # plus the smoke test: start read-only, health check, certificate names, create a user, sign in,
                            # package downloads, restart
```

It uses Podman if present, else Docker, and builds from a prepared context in `target/container/` without `RUN` steps.
