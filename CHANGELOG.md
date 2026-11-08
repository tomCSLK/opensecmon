# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Security policy (`SECURITY.md`) and contribution guide (`CONTRIBUTING.md`); the README describes the program as it is.
- The NVD notice reads "uses data from the NVD" (opensecmon reads the NVD feeds, not the API).
- Project plan, clickable UI drafts (`docs/entwurf/`), license (AGPL-3.0-or-later).
- Skeleton based on opennetmon: sign-in with Argon2 and sessions, CSRF tokens, encrypted secrets, mail server settings
  with test mail and send log, audit log, German and English, light and dark theme, empty pages of the main navigation.
- Host and origin checks (`allowed_hosts`) in front of every handler; hourly housekeeping (audit retention, sessions).
- Command line: `serve`, `user add|passwd|delete|list`, `key generate`, `backup`.
- Debian package with a hardened systemd service and a daily backup timer; CI with fmt, clippy, tests, license list,
  `cargo deny` and DCO check.
- HTTP client for the data sources (HTTPS only, size and time limits, conditional requests) and a scheduler inside
  `serve` that runs the due sources one after another, with per-source state, intervals and error backoff.
- Sources: the CVE list (cvelistV5: full archive once, then hourly deltas), NVD JSON 2.0 feeds (yearly feeds once, then
  the modified feed, checked against its SHA-256), CISA KEV and FIRST EPSS.
- "All CVEs": search (full text or CVE id), filters (period, severity band, KEV, EPSS, vendor, rejected records), four
  sort orders, pages, detail beside the list or as a sheet, and a page of its own per CVE at `/cves/{id}`.
- "Sources": state, last and next run, duration, counts, interval and on/off per source, fetch one or all now
  (recorded in the audit log); the top bar shows the state of the sources.
- A CSAF 2.0 reader: provider metadata, ROLIE feeds and `changes.csv` directories, SHA-512/SHA-256 checksums, only
  TLP:WHITE/CLEAR documents; changed documents are found by the feed's `updated` time, refused ones are remembered.
- Sources: BSI CERT-Bund (the TLP:WHITE CSAF feed) and vendor CSAF providers, added from the BSI's list of providers
  or by URL, each with a start date and a choice of distributions (VEX directories start switched off).
- "Advisories" as a second view beside "All CVEs": search (full text, advisory or CVE id), filters (period, severity,
  source, vendor), detail with products and their status, CVEs, notes and references, and a page per advisory at
  `/advisories/{seq}`. The CVE detail lists the advisories that name the CVE.
- HTTP client: a session keeps one connection open for many requests to the same host (used for CSAF documents),
  resolved addresses are reused for a minute, and stalled CSAF requests are given up after 15 s and tried once more.
- "Vendor CSAF" page (`/sources/vendors`) to add, configure and remove providers (recorded in the audit log); a source
  run that skipped documents shows a warning on the sources page.
- Sources: Debian (DSA, DLA, DTSA and DEBIAN-CVE records) and Ubuntu (USN, LSN and UBUNTU-CVE records) from OSV:
  `all.zip` once, then only the records named as changed in `modified_id.csv`; and the Debian Security Tracker, of
  which the open and undetermined issues and those without a planned DSA are kept.
- The CVE detail shows, per Debian and Ubuntu release and source package, whether the CVE is fixed (and in which
  version), open or undetermined, with urgency or priority, no-DSA notes and links to the DSA/USN.
- Assets entered by hand (Debian/Ubuntu packages, software, hardware/firmware), grouped by host, with suggestions from
  the CVE, NVD and CSAF data while typing and a preview of what the asset would match; a keyword watchlist. Changes are
  recorded in the audit log.
- Matching: packages against the Debian and Ubuntu OSV ranges (dpkg version comparison), products against the NVD CPE
  configurations, the CNA's version ranges and CSAF product trees, keywords by full-text search; three confidence
  levels that lower the priority of a match. Runs after an asset changes and after every source run that changed data.
- Inbox: views, filters with counts, matches grouped by vulnerability and ordered by priority, the detail beside the
  list, triage (done, snooze for 1/7/30 days, ignore with a reason and note, reopen) for one or many, keyboard
  shortcuts; the navigation shows the number of open matches.
- CVE and advisory details show the own affected assets with installed and fixed version and the triage actions;
  "Only mine" filter in "All CVEs".
- Hosts read over SSH: a wizard gives the inventory script and the `authorized_keys` line with a forced command
  (read-only, no shell), shows the host key's fingerprint to confirm, then reads `/etc/os-release` and the `dpkg`
  package list; one asset per source package. Hosts are read again every 6 hours, a changed host key stops the
  reading until it is confirmed. The SSH client (russh) runs inside the service with its own ed25519 key.
- Import from opennetmon (`GET /api/v1/inventory` with a token; the endpoint is not part of an opennetmon release
  yet): product suggestions from `sysDescr` and `sysObjectID`, taken over, changed or skipped per device; taken
  devices are followed.
- CSV import with a preview per row (new, changed, unchanged, error); column names in English or German.
- The asset list shows where an asset came from, filters by host and folds the packages of a host without open
  matches.
- Instant mail for new open matches that are in CISA KEV or reach a priority, CVSS or EPSS threshold (each
  switchable) with a minimum confidence; bundled over 10 minutes, one mail per vulnerability, retried with backoff
  after a failed delivery. Switching it on or changing the conditions does not mail the existing backlog.
- Daily report at a local time (`time_zone`): new matches since the last report, open critical and KEV matches,
  postponed matches due again, failed sources; optionally skipped when empty, with a preview and "send now".
- Settings pages "Instant mail" and "Daily report"; the address of the interface for links in the mails.
- "Situation" page: tiles for open critical and KEV matches (with passed KEV deadlines), the last 24 hours and the
  sources; open vulnerabilities of the last 30 days by priority band; most affected hosts; matches open longest. The
  charts are SVG drawn on the server; the hourly housekeeping keeps the counts per day for 400 days.
- CSV export of "All CVEs" and the inbox (the filtered list, at most 10,000 lines; German with `;` and a decimal comma,
  English with `,`; cells that would start a formula are prefixed with `'`).
- The affected assets in the detail show when a match was found and when the instant mail about it went out.
- Settings page "Priority": the weights of CVSS and EPSS, the KEV floor and the deductions for a medium or low
  confidence, with examples; saving recomputes every priority in the background.
- Settings page "Retention": how long the audit log and done or ignored matches that no longer apply are kept, the
  size of the database per area, and "compact the database" (VACUUM in the background).
- A minimum priority per asset: matches below it are kept but leave the inbox views, counts, CSV export, situation
  page and mails unless the inbox is filtered by that asset. Kernel source packages read over SSH start at 65.
- Operations guide (`docs/operations.md`): installation from the package, configuration, Traefik example, users,
  backup and restore, update and rollback, checklist.
- Fuzz tests for every reader of the sources and imports.
- Built-in HTTPS: `opensecmon tls generate` creates a self-signed certificate, the package does so on installation
  and serves the interface on `https://<server>:8444`; plain HTTP on that port is redirected. Your own certificate
  works as well, and a reverse proxy stays optional.
- The opennetmon import accepts a self-signed certificate by its SHA-256 fingerprint, so opennetmon on the same server
  can be read at `https://127.0.0.1:8443` without DNS or a proxy. Only that certificate is accepted; an untrusted or
  changed certificate is reported with its fingerprint to compare. Changing the fingerprint asks for the token again.
- Computers (agent), the first part of the agent API (`docs/agent-api.md`): computers are added under *Assets >
  Computers (agent)* and enroll with a one-time code (8 characters, valid 15 minutes, usable once) at
  `POST /api/v1/agent/enroll`; each gets a token of its own (only its SHA-256 hash is stored) and can check it at
  `GET /api/v1/agent/status`. The page shows the code, the address, the certificate's fingerprint with a download
  of the certificate, and curl commands; a computer can be renamed, get a new code, be revoked or removed. Requests
  are only taken from `agent_networks` (default: private and local addresses), wrong codes count like failed
  sign-ins. Names are unique across SSH hosts and computers.
- Reports of computers at `POST /api/v1/agent/report`: Debian, Ubuntu and systems based on them send the output of
  the inventory script as plain text or as JSON, optionally gzip-compressed (at most 8 MB); the packages become the
  computer's assets as for a host read over SSH and are matched in the background. An unchanged report, or the short
  form with its hash, is only noted. At most one full report every 5 minutes per computer. A refused report is
  shown on the computer's page.
- `contrib/opensecmon-agent.sh`, also offered on the computer's page: enrolls a Debian or Ubuntu computer and
  installs a systemd timer that reports every 6 hours without root.
- Inbox filter "Fix announced": only matches for which a newer version fixes the vulnerability (apt may not offer it
  yet).
- Setting "Ubuntu Pro" per SSH host and per computer (detect automatically, yes, no). The packages of the host follow
  it at once and readings no longer reset it; the form of such a package points to the setting.
- The rating of the distribution lowers the priority of a package match: Debian "unimportant" and Ubuntu "negligible"
  take off 30 points, Debian "low" or no security update planned (no-dsa, postponed, ignored) and Ubuntu "low" 10
  (page "Priority"; KEV vulnerabilities keep their floor). The detail shows the rating and what it takes off.
- Kernel and firmware source packages of Raspberry Pi OS (`+rpt` in the version) are no longer matched against Debian,
  whose data does not fit them; the asset list shows them as "no data source (Raspberry Pi kernel)" instead of folding
  them away. Other `+rpt` packages are rebuilds of Debian and are still matched.
- The inventory script of the SSH import and the agent script report the running kernel, a pending reboot and
  whether the sources of Ubuntu Pro are set up (lines `OPENSECMON_*` before `---`, JSON fields `os.kernel`,
  `os.reboot_required`, `os.ubuntu_pro`); hosts and computers show "Kernel X" or "Reboot needed, running kernel X,
  installed Y", and Ubuntu Pro is detected before the first ESM package is installed. Older scripts keep working.
- Reports from Windows computers (JSON): Windows becomes one asset named as Microsoft names it in the CVE list
  ("Windows 11 Version 24H2", "Windows Server 2022 (Server Core installation)") with the version
  `10.0.<build>.<UBR>`, matched against Microsoft's version ranges; the next report after a patch day updates it.
  Windows before 10 and unknown server builds are refused with `unsupported_system`. Programs are not taken yet.
- A PowerShell script for Windows (`contrib/opensecmon-agent.ps1`, offered on the computer's page): `enroll`,
  `report`, `status`, `update`, `uninstall`; the token in `C:\ProgramData\opensecmon-agent` (SYSTEM and
  administrators only), a scheduled task as SYSTEM at start-up and every 6 hours, reports as gzipped JSON with
  `curl.exe` including the installed programs and store apps.
- Programs, store apps, snaps and Flatpaks reported by computers are stored and become software assets by rules:
  built-in rules for common programs (store apps of Windows ignored), and the user's own rules from the new page
  "Unassigned" under "Assets" (assign to a vendor and product with suggestions and a preview of the matches, or
  ignore), which apply to all computers at once. Computers and their group in the asset list show how many entries
  are still unassigned.
- The inventory script of the SSH import and the agent script for Debian and Ubuntu (version 4) also print the
  installed snaps and Flatpak apps, as sections after the packages (`--- snap`, `--- flatpak`); `flatpak` gets a
  temporary cache directory, since the agent's service has no home to write to. They go through the
  same rules, for hosts read over SSH too (`lxd` becomes Canonical LXD); base, runtime and theme snaps of Ubuntu are
  ignored by a built-in rule. Hosts show their unassigned entries like computers. Older scripts keep working.
- The page of an enrolled computer keeps the link to the agent script, with the command to update it (before, the
  link was only shown while a one-time code was open).
- The head of a host in the asset list, the hosts page and the computers page count different vulnerabilities
  ("12 vulnerabilities in 5 packages"): two packages of a host often share a CVE (`qemu` and `qemu-hwe`).
- Preparations for the agent program opensecagent (`docs/agent-api.md`): when its packages come with opensecmon
  (`agent_packages_dir`, filled by `dev/agent-packages.sh` after checking their signatures), the computer's page
  offers them for download and shows one enrollment code to copy (`osa1_…`: address, certificate fingerprint and
  one-time code with a checksum); the scripts stay available, folded below. opensecagent is asked to report every
  15 minutes (the scripts keep 6 hours). Updates only on request: the page and the list show the agent's version
  and "Update available", *Update* and *Update all* ask for it, the next answer to the agent carries the package's
  size, SHA-256 and signature, `GET /api/v1/agent/packages/{file}` delivers it, and the agent's next report ends the
  request or shows why it failed. New migration `0021`.

### Changed

- The largest JSON columns (NVD configurations, CVE references and affected products) are stored deflated; older rows
  are converted in the background after the update. The full test database shrank from 2.2 GB to 1.5 GB.
- Pages no longer fail while the database is locked by a long write: noting session activity and marking matches as
  seen are skipped instead.
- Microsoft Edge and Notepad++ are also matched under the name their CNA uses ("Microsoft Edge (Chromium-based)",
  "notepad-plus-plus") beside the NVD's; the newest Notepad++ CVEs are only listed under the CNA's name.
- Web apps installed from Chrome (Windows programs with the publisher `Google\Chrome`) are ignored by a built-in
  rule instead of being listed as unassigned.
- At start-up the rules are applied again to the programs computers and hosts reported, so that built-in rules of a
  new version reach computers whose reports have not changed.
- Devices are also matched under the firmware name the NVD uses ("er605_firmware") and, for TP-Link, with and without
  "omada"/"tl" in front of the model.
- The opennetmon import recognises Omada access points and routers ("Linux EAP653 …") and Omada switches by their
  sysObjectID; Linux hosts with Net-SNMP are pointed to the SSH import instead.
- A redirect of the opennetmon request (for example to the sign-in of Cloudflare Access) is reported as such, with
  its target, instead of as "more than 5 redirects".

### Fixed

- Python on Windows got the version its installer reports (`3.12.10150.0` for 3.12.10, the release level folded
  into the third number), which lies above every fixed version, so only CSAF matches were found; a Windows program
  now takes the version from its display name in such a case.
- The hosts page counted matches below the minimum priority of their asset, the asset list did not.
- Ubuntu Pro set by hand on a package of a host was reset by the next reading. It is only detected once a package
  from Ubuntu Pro (ESM) is installed, which a new release often has not yet; the setting per host covers that.
- CSAF version bounds written as two products (">=5.4" and "<7.1p2") are paired into one range instead of matching
  every later version.
- Long version strings in the "Affected" section of the CVE detail no longer widen the page on phones.
- The SSH wizard creates the user on the host with a home directory (`/var/lib/<user>`), where sshd finds the key;
  plain `adduser --system` gives `/nonexistent`. It suggests the user `opensecmon-inv` (on the server that runs
  opensecmon, `opensecmon` is the service user), gives ready commands for the script and the key and mentions
  `AllowGroups` (the group `_ssh` on openmediavault).
- An instance with `fetch_sources = false` no longer starts every source on a new database; only "fetch now" runs a
  source there.

### Security

- CSAF documents, ROLIE feeds and the KEV catalog count list elements while they are read, so a small file cannot
  make the service allocate a lot of memory; ZIP archives with overlapping entries are refused.
- A slow or broken vendor CSAF provider is given up after 30 minutes or 20 failed documents in a row per run.
- The sources cannot reach addresses of the own network (loopback, private, link-local); only the opennetmon import
  may.
- CSAF directories named GREEN, AMBER or RED are skipped.
- A stored SMTP password is only used for the server, port, security and user it was entered for, the opennetmon
  token only for its URL; changing them asks for the secret again. SMTP sign-in without TLS is refused except on
  loopback.
- `backup` only accepts a new or empty regular file as target and never removes a file it did not create.
- The example configuration sets `client_ip_header`, and the service warns when it seems to run behind a proxy
  without it; the audit log is kept at least 90 days; the backup unit is hardened like the service.
