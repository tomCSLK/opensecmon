# opensecmon

Security advisory monitoring for your own hardware and software. opensecmon fetches public sources several times a day
(the CVE list and NVD, CISA KEV, FIRST EPSS, BSI CERT-Bund, vendor CSAF feeds, Debian and Ubuntu) and shows, as a triage
inbox, only the advisories that affect what you run. New matches above a threshold are mailed at once, everything else
goes into a daily report.

It is a single, statically linked binary (Rust) with an SQLite database. It runs as a service on a Debian or Ubuntu
server, serves its web interface over HTTPS itself and is used in the browser. It is meant for a home or small office
network with one or a few administrators.

> **Status:** all planned features are implemented and the program is in daily use. The first release is
> [v0.3.5](https://github.com/tomCSLK/opensecmon/releases/tag/v0.3.5). The agent
> [opensecagent](https://github.com/tomCSLK/opensecagent) works on Debian and Ubuntu; its Windows version is in
> progress (until then Windows computers report with a PowerShell script). The user interface is available in German
> and English.

## Features

- **Triage inbox:** matches sorted by a transparent priority (CVSS, EPSS, known exploitation, confidence of the match,
  the rating of Debian or Ubuntu), with done / ignore / snooze, bulk actions and keyboard shortcuts.
- **Assets** from several places:
  - by hand, with suggestions for vendor, product and version from the CVE and CSAF data, and a preview of the matches;
  - read from Debian and Ubuntu hosts over SSH (`dpkg`, with a forced command: read-only, no shell; a wizard shows the
    script and the `authorized_keys` line);
  - desktop computers (Debian, Ubuntu and derivatives, Windows 10/11) report their packages, snaps, Flatpaks and
    programs themselves over HTTPS, with the agent [opensecagent](https://github.com/tomCSLK/opensecagent) or a small
    script; nothing listens on the computers ([`docs/agent-api.md`](docs/agent-api.md));
  - imported from CSV or from [opennetmon](https://github.com/tomCSLK/opennetmon);
  - plus a keyword watchlist.
- **Matching** with three confidence levels: distribution package state or version ranges from CPE and CNA data (high),
  CSAF product trees (medium), keywords (low). The running kernel, a pending reboot and Ubuntu Pro are taken into
  account; the kernel of Raspberry Pi OS has no data source and is shown as such.
- **Mail:** an instant mail for new matches with KEV, a high priority, CVSS or EPSS above your thresholds (bundled, no
  flood when switched on), and a daily report at a set time.
- **Overview:** a situation page (open critical and KEV matches, the last 30 days, most affected hosts, state of the
  sources), searchable lists of all CVEs and advisories with details, CSV export.
- **Sources** are fetched incrementally (conditional requests, change lists, checksums), each with its own interval,
  state and error backoff. Only the public TLP:WHITE feeds of the BSI are used.
- **Operations:** Debian package with a hardened systemd service, built-in HTTPS with a self-signed certificate
  (your own certificate or a reverse proxy are optional), daily database backups, light and dark theme.

## Requirements

- A server with Debian 12/13 or Ubuntu 22.04 or later (`amd64`, systemd).
- About 2 GB of disk space for the database plus room for downloads and backups; about 200 MB of memory during the
  first import, much less afterwards.
- Outgoing HTTPS to the sources, and an SMTP server for the mails.

## Installation

Download `opensecmon_<version>-1_amd64.deb` and `SHA256SUMS` from the
[releases](https://github.com/tomCSLK/opensecmon/releases), then:

```sh
sha256sum -c SHA256SUMS
sudo apt install ./opensecmon_<version>-1_amd64.deb
sudo -u opensecmon opensecmon --config /etc/opensecmon/config.toml user add anna
sudo systemctl start opensecmon
```

Then open `https://<server>:8444`. The installation prints the fingerprint of the self-signed certificate; compare it
with the one your browser shows before you accept it. Enter your mail server under *Settings*, then add assets.

The first start imports all sources on its own: about 1.9 GB of downloads and some 25 minutes. Afterwards the database
holds some 420,000 CVEs in about 1.5 GB, and only changes are fetched. The full guide (configuration, certificates,
reverse proxy, users, backups, updates, uninstalling) is [`docs/operations.md`](docs/operations.md).

## Building

Requirements: a current stable Rust toolchain. For the package also `cargo-deb` and the target
`x86_64-unknown-linux-musl`.

```sh
dev/deb.sh                       # builds target/debian/opensecmon_<version>-1_amd64.deb
```

To try it without installing, create a configuration of your own (see
[`deploy/config.example.toml`](deploy/config.example.toml): set `database_path`, `secret_key_file`,
`cookie_secure = false` and `allowed_hosts = ["127.0.0.1:8090"]`, leave out `listen` and the `tls_` lines) and run:

```sh
cargo build
target/debug/opensecmon --config my.toml key generate
target/debug/opensecmon --config my.toml user add anna
target/debug/opensecmon --config my.toml serve        # http://127.0.0.1:8090
```

With `fetch_sources = false` nothing is fetched until you press "Fetch now" on the sources page. Contributions are
welcome, see [`CONTRIBUTING.md`](CONTRIBUTING.md); security issues please report as described in
[`SECURITY.md`](SECURITY.md).

The planning documents (`PLAN.md`, `CLAUDE.md`) and the clickable UI drafts in [`docs/entwurf/`](docs/entwurf/)
(made-up data) are written in German.

## Data sources and notices

opensecmon fetches the data at run time from the sources below; neither this repository nor the package contains any of
it. Their terms apply to the data, not to this program.

- This product uses data from the NVD but is not endorsed or certified by the NVD.
- CVE® data from the CVE Program, used under the CVE Terms of Use (© The MITRE Corporation). CVE is a registered
  trademark of The MITRE Corporation.
- Known Exploited Vulnerabilities Catalog by CISA (CC0 1.0).
- EPSS scores by FIRST.org (Exploit Prediction Scoring System).
- Security advisories of the German Federal Office for Information Security (BSI, CERT-Bund, Warn- und
  Informationsdienst), public TLP:WHITE feeds only.
- Vendor CSAF documents are subject to each vendor's own terms; only TLP:WHITE/CLEAR documents are loaded, and the
  details link to the original.
- Ubuntu Security Notices and CVE data © Canonical Ltd., CC BY-SA 4.0, and Debian security data, both obtained
  through [OSV.dev](https://osv.dev); open issues from the Debian Security Tracker.

The sources page of the program shows the same notices.

## License

Copyright (C) 2026 Thomas Cieslik

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public
License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
See [`LICENSE`](LICENSE).

The fonts in `static/fonts/` and `docs/entwurf/fonts/` (Fira Sans, Fira Code) are licensed under the SIL Open Font
License 1.1; the icons follow Lucide (ISC). All third-party licenses are listed in
[`THIRD-PARTY-LICENSES.txt`](THIRD-PARTY-LICENSES.txt).
