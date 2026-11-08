# Agent API (draft, version 1)

**Status of this opensecmon:** enrollment, status and reports from Debian, Ubuntu and systems based on them are
implemented, together with a shell script for them ([`contrib/opensecmon-agent.sh`](../contrib/opensecmon-agent.sh),
also offered on each computer's page), and reports from Windows, which become the asset of Windows itself, together
with a PowerShell script for them ([`contrib/opensecmon-agent.ps1`](../contrib/opensecmon-agent.ps1), also offered
there). The `items` (Windows programs, store apps, snaps, Flatpaks) are stored and become assets by rules (built-in
or set on the page *Unassigned*); the shell script sends snaps and Flatpaks as sections after the packages. It describes how a desktop computer (Windows,
Debian, Ubuntu and systems based on them such as Linux Mint or Zorin OS) reports its installed software to
opensecmon, so that its assets stay current without anybody entering them. The reporting program is called the
*agent* here. It can be a small program or, at first, a shell or PowerShell script that runs on a schedule.

## Principles

- **The agent reports, opensecmon never asks.** Only the agent opens connections. Laptops are often off or in
  another network, desktop firewalls refuse incoming connections, and no port has to be open on the computer. If the
  agent cannot reach opensecmon (no connection, wrong certificate), it tries again later. It needs no other way to
  tell whether it is at home.
- **Local network only.** opensecmon accepts agent requests only from the networks in `agent_networks` (below).
  This backs up, but does not replace, the real boundary: opensecmon is not reachable from the internet.
- **HTTPS on the existing web server.** No extra port and no protocol of its own; everything can be tried with
  `curl`.
- **One token per computer.** Each computer is enrolled once with a one-time code and gets its own token. Every
  token can be revoked on its own.
- **Reports are data.** What a computer reports is checked against limits, stored and escaped, never executed or
  followed. A computer that lies can only falsify its own assets.

## Transport

- **Base URL:** the address the web interface is opened under, e.g. `https://<server>:8444` (built-in HTTPS) or
  `https://secmon.example.org` (behind a reverse proxy). The host name must be one of `allowed_hosts`, as for the
  browser; other names get `421`.
- **Certificate:**
  - Behind a reverse proxy with a certificate from a public CA: normal verification, nothing to configure.
  - Built-in HTTPS with the self-signed certificate: the agent accepts exactly this certificate and nothing else.
    The computer's page shows its SHA-256 fingerprint (`AB:CD:…`, as `journalctl -u opensecmon` prints it on every
    start) and offers the certificate itself (`opensecmon.pem`, public part only) for download. A program compares the
    fingerprint of the certificate it is offered (the same check as the opennetmon import in opensecmon); a script
    passes the file as its only trust anchor (`curl --cacert opensecmon.pem`).
  - A certificate that does not match means: another machine, or the certificate was generated again. The agent
    sends nothing and logs the fingerprint it was offered.
- **HTTP versions:** HTTP/1.1; HTTP/2 where the server offers it.
- **Compression:** request bodies may be sent with `Content-Encoding: gzip`. Responses are small JSON documents.
- **No cookies, no CSRF token.** The API only reads the `Authorization` header. A token never opens a page of the web
  interface, and a session cookie never authorizes an API request. Requests from the API carry no `Origin` header, so
  the origin check of the web interface lets them through.
- **Never in the URL:** tokens and codes are only sent in the body or in headers, so they do not end up in proxy or
  access logs.

## Allowed networks

New setting in `config.toml`:

| Key | Default | Meaning |
|---|---|---|
| `agent_networks` | not set: private and local addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `fc00::/7`, `fe80::/10`, `::1`) | Networks (CIDR) that may enroll and report. A list replaces the default, e.g. `["192.168.1.0/24"]`; `[]` switches the API off. |

The address checked is the peer address of the connection, or behind a reverse proxy the one taken from
`client_ip_header`. Requests from other addresses get `403 network_not_allowed` before the token is looked at.

## Enrollment

1. In the web interface, *Assets > Computers (agent) > Add computer*: the user gives the computer a name (the name of the
   host in the assets and the inbox, same rules as for SSH hosts).
2. The computer's page shows a **one-time code**, the base URL, the fingerprint and the certificate, plus ready
   commands; the code stays visible there until it is used or expired (it is stored encrypted for that).
   The code has 8 characters from Crockford's Base32 (no `I`, `L`, `O`, `U`), shown as `K7FQ-29XM`, upper or lower
   case and with or without the dash accepted. It is valid for **15 minutes** and **once**. Creating a new code for the
   same computer invalidates the previous one.
3. The agent sends the code and receives its token. Only the SHA-256 hash of the token is stored; the token is shown
   nowhere and cannot be read back. A lost token means enrolling again (a new code for the same computer keeps its
   assets).

Wrong codes count like failed sign-ins (same throttle per client address): after too many, `429` with
`Retry-After`.

### Enrollment code (for opensecagent)

The scripts take the base URL, the code and the certificate one by one. The agent program
[opensecagent](https://github.com/tomCSLK/opensecagent) takes a single **enrollment code** instead, which carries
all three, so that the user only copies one thing (button *Copy code* on the computer's page; the installer and the
enrollment dialog take a code from the clipboard by themselves). The page shows it while the one-time code is valid
and opensecagent packages are installed with opensecmon (see *Updates of opensecagent*).

Form: `osa1_` followed by the payload in Crockford's Base32 (`0123456789abcdefghjkmnpqrstvwxyz`, lower case, no
padding; read in any case, spaces, line breaks and `-` are ignored, `o` reads as `0`, `i` and `l` as `1`). The
underscore keeps the code one word, so a double click selects all of it. Payload, in this order:

| Bytes | Content |
|---|---|
| 1 | Flags: bit 0 set = a certificate fingerprint follows; the other bits are 0 (a reader refuses others). |
| 32 | Only with bit 0: the SHA-256 fingerprint of the certificate of the built-in HTTPS. |
| 5 | The one-time code: its 8 characters are 40 bits of Crockford's Base32, here as 5 bytes (first character in the highest bits). |
| 1 to 255 | The address: host name or IP address with an optional port, as the browser used it (`192.0.2.10:8444`, `[fd00::2]:8444`, `secmon.example.org`); always HTTPS. |
| 4 | The first 4 bytes of the SHA-256 of all bytes before, against copying errors. |

A code with a fingerprint and an address of 15 characters is 97 characters long. A reader checks the prefix,
the alphabet, the length, the flags and the checksum and says "incomplete or damaged code" otherwise; whether the
one-time code itself is still valid only opensecmon knows (`invalid_code`).

**Certificate:** the agent accepts the certificate offered under this address if its SHA-256 fingerprint is the
one in the code, **or** if it is valid for the address by the normal verification of the system (a reverse proxy
with a certificate from a public CA). Either way an attacker without the private key of one of them is refused. A
code without a fingerprint (no built-in HTTPS) needs the normal verification.

Example: address `192.0.2.10:8444`, code `K7FQ-29XM`, fingerprint `00:01:02:…:1F` gives

```
osa1_040020g30g2gc1r81450p30d1r7h048j2ca1a5gq30chm6rw3mf1z6eze4kv8c9s68q30bhj5rrk0ehr6gt38epxvbd0
```

(the reference values are in the tests of opensecmon, `src/agent.rs`).

### `POST /api/v1/agent/enroll`

Request (`Content-Type: application/json`):

```json
{
  "schema": 1,
  "code": "K7FQ-29XM",
  "hostname": "laptop",
  "agent": { "name": "opensecmon-agent", "version": "0.1.0" }
}
```

| Field | Required | Meaning |
|---|---|---|
| `schema` | yes | Version of this document's formats, `1`. |
| `code` | yes | The one-time code. |
| `hostname` | no | Host name as the computer knows itself (shown next to the name the user gave, at most 253 characters). |
| `agent.name`, `agent.version` | no | Who reports (shown on the page, at most 64 characters each), e.g. `curl-script`, `1`. |

Response `201 Created`:

```json
{
  "device": "laptop",
  "token": "osm1_3q2-7wSxB0hLk8f_u7Yc1NJdQe9vX4aZpR6mT2cKgWo",
  "report_interval_s": 21600
}
```

- `token`: `osm1_` followed by 43 characters of Base64url (32 random bytes). The prefix makes it easy to recognize,
  e.g. for secret scanners. The agent keeps it readable only by itself (Linux: `root`, mode `600`; Windows: `SYSTEM`
  and administrators).
- `report_interval_s`: when to report: 6 hours (like the SSH import) for the scripts, **15 minutes** for
  opensecagent (`agent.name` `opensecagent`), which then sends the short form unless something changed, so that a
  requested update reaches it soon.

## Reporting

### `POST /api/v1/agent/report`

Header `Authorization: Bearer <token>`. A report always contains **the complete inventory**, never differences, so
the two sides cannot drift apart. opensecmon computes the SHA-256 of the body (after decompression); if it equals the
last stored report, it only notes the time (`unchanged`) and does not compare again.

Two forms:

**a) Plain text (Debian and Ubuntu, for scripts):** `Content-Type: text/plain; charset=utf-8`. The body is exactly
the output of the inventory script of the SSH import (`/usr/local/bin/opensecmon-inventory`): the content of
`/etc/os-release`, a line `---`, then one line per package from `dpkg-query` with status, package, version, source
package and source version, separated by tabs. It is read by the same code as the SSH import.

Before the line `---` the script may add lines of its own (optional, since opensecmon 0.3.1; older outputs stay
valid):

| Line | Meaning |
|---|---|
| `OPENSECMON_KERNEL=<release>` | The running kernel as `uname -r` prints it (letters, digits and `.+-_~`, at most 100 characters; anything else is ignored). |
| `OPENSECMON_REBOOT=1` | `/var/run/reboot-required` exists: the system waits for a reboot (only taken together with the kernel). |
| `OPENSECMON_PRO=1` | Ubuntu: `/etc/apt/sources.list.d/ubuntu-esm-infra.*` or `ubuntu-esm-apps.*` exists, the machine gets Ubuntu Pro. |

After the package lines sections may follow (optional, since opensecmon 0.3.2), each after a line `--- <name>`; their
lines become entries like `items` in the JSON form. Older opensecmon count them as skipped package lines (a warning,
the packages are taken), lines of an unknown section are ignored:

| Section | Lines |
|---|---|
| `--- snap` | The output of `LC_ALL=C snap list --unicode=never --color=never`: a header line, then per snap name, version, revision, tracking, publisher (`*` or `**` at the end marks a verified one, `-` none) and notes, separated by spaces. |
| `--- flatpak` | The output of `flatpak list --app --columns=application,name,version,installation`: application ID, name, version, installation (`system`, `user` or the name of another one), separated by tabs. Runtimes are not listed. |

Lines with an invalid snap name or Flatpak ID are skipped and counted in the warning `lines_skipped`. The scripts
print a section only if `snap` or `flatpak` is installed; under the agent's systemd service (`ProtectHome`) Flatpaks
installed for a single user are not visible, over SSH only those of the user the key belongs to.

**b) JSON (every system):** `Content-Type: application/json`.

```json
{
  "schema": 1,
  "agent": { "name": "opensecmon-agent", "version": "0.1.0" },
  "hostname": "laptop",
  "os": { "family": "linux", "os_release": "NAME=\"Zorin OS\"\nID=zorin\nID_LIKE=\"ubuntu debian\"\n…", "arch": "x86_64" },
  "dpkg": "ii \tbash\t5.2.21-2ubuntu4\tbash\t5.2.21-2ubuntu4\n…",
  "items": [
    { "type": "snap", "id": "firefox", "name": "firefox", "version": "144.0.2-1", "publisher": "mozilla" },
    { "type": "flatpak", "id": "org.mozilla.firefox", "name": "Firefox", "version": "144.0.2", "publisher": "Mozilla" }
  ]
}
```

Windows:

```json
{
  "schema": 1,
  "agent": { "name": "opensecmon-agent", "version": "0.1.0" },
  "hostname": "PC-WOHNZIMMER",
  "os": {
    "family": "windows",
    "product_name": "Windows 10 Pro",
    "display_version": "24H2",
    "build": 26100,
    "ubr": 4652,
    "installation_type": "Client",
    "arch": "x64"
  },
  "items": [
    { "type": "win", "id": "{1F1C2DFC-2D24-3E06-BCB8-725134ADF989}", "name": "Mozilla Firefox (x64 de)",
      "version": "144.0.2", "publisher": "Mozilla", "winget_id": "Mozilla.Firefox", "scope": "machine" },
    { "type": "appx", "id": "Microsoft.WindowsTerminal_8wekyb3d8bbwe", "name": "Windows Terminal",
      "version": "1.23.12811.0", "publisher": "Microsoft Corporation", "scope": "user" }
  ]
}
```

| Field | Meaning |
|---|---|
| `schema` | `1`. |
| `agent`, `hostname` | As for the enrollment. |
| `agent.updates` | Optional, `true`: the agent can install updates offered by opensecmon (opensecagent built and signed by its publisher). Only then does the page offer *Update*. Default `false`. |
| `agent.update_error` | Optional: the agent could not install the update offered last (at most 200 characters, e.g. `signature does not match`). The page shows it and stops offering the update until the user asks again. |
| `os.family` | `linux` or `windows`. |
| `os.os_release` | Linux: the content of `/etc/os-release` (at most 16 KB). Debian, Ubuntu and systems that name them in `ID_LIKE` are recognized as in the SSH import. |
| `os.product_name`, `os.display_version`, `os.build`, `os.ubr` | Windows: the values `ProductName`, `DisplayVersion`, `CurrentBuild` and `UBR` under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`. opensecmon decides Windows 10 or 11 by the build (from 22000 on Windows 11), because `ProductName` still says "Windows 10" on Windows 11. `build` and `ubr` are required. |
| `os.installation_type` | Windows, optional: `InstallationType` from the same key (`Client`, `Server`, `Server Core`); a server with `Server Core` becomes the product "… (Server Core installation)". |
| `os.kernel`, `os.reboot_required`, `os.ubuntu_pro` | Linux, optional: the running kernel (`uname -r`; a value that is no kernel release is refused with `bad_request`), a pending reboot and Ubuntu Pro (booleans), as the lines `OPENSECMON_*` of form a). |
| `os.arch` | Machine architecture as the system names it (`x86_64`, `aarch64`, `x64`, `arm64`). Stored since opensecmon 0.3.4; it chooses the package of an update. |
| `dpkg` | Linux with dpkg: the package lines exactly as in form a), without `os-release`. |
| `items` | Software outside dpkg (at most 50,000 entries together with `dpkg`). |
| `items[].type` | `snap`, `flatpak`, `win` (an entry under `…\CurrentVersion\Uninstall`, 32 and 64 bit, machine and user), `appx` (Store apps). Unknown types are skipped and counted in the warnings. |
| `items[].id` | Stable identifier: the snap name, the Flatpak application ID, the registry key name of the Uninstall entry, the package family name of an appx. |
| `items[].name`, `version`, `publisher` | As the system shows them (at most 200, 100 and 200 characters). |
| `items[].winget_id` | Windows, where known: the winget package identifier (a better key than the display name). |
| `items[].scope` | `machine` or `user` (installed for one user only). The user is never named. |

Nothing else is sent: no user names, no paths, no serial numbers, no network details.

**Short form when nothing changed:** an agent that remembers the SHA-256 of its last body may send only

```json
{ "schema": 1, "unchanged": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" }
```

opensecmon answers `unchanged` if the hash is that of the last stored report, otherwise `409 full_report_required`.
Scripts can simply always send the full report; the result is the same.

Response `200 OK`:

```json
{
  "status": "stored",
  "next_report_s": 21600,
  "warnings": [ { "code": "items_skipped", "count": 3 } ]
}
```

- `status`: `stored` (new inventory, compared in the background, the response does not wait for it) or
  `unchanged`.
- `next_report_s`: when to report next (as `report_interval_s` of the enrollment, by the reported or last known
  `agent.name`). The agent adds up to 10 % at random, so that computers started together do not report together.
- `update`: only when the user asked for an update of this computer (see *Updates of opensecagent*), also in the
  answer to the short form and in `status`.
- `warnings`: lines or entries that were skipped (`lines_skipped`; `items_skipped` for entries of an unknown type or
  without `id`), each with a count.

### `GET /api/v1/agent/status`

Header `Authorization: Bearer <token>`. For checking the token and the connection without sending anything (e.g.
right after the enrollment):

```json
{ "device": "laptop", "last_report": "2026-11-07T14:02:11Z", "next_report_s": 21600 }
```

## Updates of opensecagent

opensecagent is updated only when the user asks for it: never automatically, never from the internet.

1. The packages come **with opensecmon**: its package installs them into `/usr/share/opensecmon/agent/` (setting
   `agent_packages_dir`). opensecmon reads the folder at start and takes files named
   - `opensecagent_<version>[-<revision>]_<amd64|arm64>.deb` (Debian, Ubuntu and systems based on them) and
   - `opensecagent-<version>-<x64|arm64>-setup.exe` (Windows),

   `<version>` being two to four numbers with dots. Each file needs its signature beside it (`<file>.sig`, an SSH
   signature as `ssh-keygen -Y sign -n opensecagent` writes it, at most 4 KB); files without one, other names and
   files over 256 MB are skipped with a warning in the log. Per system and architecture the highest version counts.
2. The page of a computer shows the agent's version and *Update available* when there is a higher one for its
   system and architecture and the agent reported `"updates": true`. The button *Update* (or *Update all* in the
   list) asks for it; *Cancel* takes it back while it has not been installed.
3. The next answer to the agent (`report`, short form included, or `status`) carries

   ```json
   "update": {
     "version": "0.2.0",
     "file": "opensecagent_0.2.0-1_amd64.deb",
     "size": 4194304,
     "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
     "signature": "-----BEGIN SSH SIGNATURE-----\n…\n-----END SSH SIGNATURE-----\n"
   }
   ```

   until the agent reports this version or an `update_error`.
4. The agent downloads the file with `GET /api/v1/agent/packages/<file>` (header `Authorization: Bearer <token>`,
   same networks; only files offered in the catalogue, `404 not_found` otherwise), checks size, SHA-256 and the
   signature against the publisher key built into it, and only then installs it (Debian: `dpkg -i` by a separate
   helper; Windows: the setup with `/VERYSILENT`). opensecmon does not check the signature itself: even an
   opensecmon in other hands cannot make the computers install something the publisher did not sign.
5. Right after the installation the agent reports with its new version, which ends the request. If it fails, it
   reports `agent.update_error`.

## Errors

Every error is a JSON document `{"error": "<code>", "message": "<English text>"}` with the HTTP status below.

| Status | `error` | Meaning | What the agent does |
|---|---|---|---|
| 400 | `bad_request` | Body is not valid JSON or the form above, a field is too long, a required field is missing. | Logs it, tries again at the next interval. |
| 400 | `unsupported_schema` | `schema` is newer than this opensecmon knows; `message` names the supported versions. | Falls back to an older schema if it can, otherwise as above. |
| 401 | `invalid_code` | Enrollment: the code is unknown, used or expired. | Asks for a new code. |
| 401 | `invalid_token` | Token unknown, revoked, or the computer was deleted. | **Stops reporting** and asks to enroll again. |
| 404 | `not_found` | Package download: no such file in the catalogue. | Logs it, reports `update_error`. |
| 403 | `network_not_allowed` | The address is not in `agent_networks`. | Tries again at the next interval. |
| 409 | `full_report_required` | Short form with an unknown hash. | Sends the full report at once. |
| 413 | `too_large` | Body over 8 MB, compressed or after decompression. | Logs it, tries again at the next interval. |
| 415 | `unsupported_media_type` | Neither `text/plain` nor `application/json`, or an encoding other than `gzip`. | Logs it. |
| 422 | `unsupported_system` | Neither Debian/Ubuntu (or based on them) nor Windows 10, Windows 11 or Windows Server 2016 and later (a server build opensecmon does not know is refused too). | Logs it, tries again at the next interval. |
| 429 | `too_many_requests` | Reported too often or too many wrong codes; `Retry-After` says how long to wait. | Waits as told. |
| 503 | `busy` | The database is busy (e.g. while it is made smaller); `Retry-After` says how long to wait. | Waits as told. |

After network errors the agent waits 5, 15 and 60 minutes, then its normal interval.

## Limits

- Body at most **8 MB**, compressed and after decompression (decompression stops at the limit).
- At most **50,000** packages and items together, as for the SSH import.
- At most one **full report every 5 minutes** and one short form per minute per computer; more get `429`. Only
  accepted reports count; the times are kept in memory, so a restart of opensecmon allows the next report at once.
- Field lengths as in the tables above; `os_release` at most 16 KB.

## What opensecmon does with a report

- **Debian and Ubuntu packages** become package assets as in the SSH import: one asset per source package, with the
  same minimum priority for kernel packages.
- **Windows itself** becomes one asset: vendor Microsoft, product `Windows 11 Version 24H2` (or `Windows 10 Version
  22H2`), version `10.0.<build>.<ubr>`. This is how Microsoft names its products in the CVE records, so the version
  is compared and the match is certain. The release comes from the build (a table from Windows 10 1507 to Windows 11
  25H2, so Windows 10 LTSC 2021 counts as 21H2 as Microsoft has it), for newer builds from `display_version`.
  Servers by build: 14393 Windows Server 2016, 17763 2019, 20348 2022, 25398 2022 23H2 Edition (Server Core only),
  26100 2025. The next report with a new UBR updates the same asset, so matches fixed on patch day close by
  themselves.
- **Snap, Flatpak and Windows programs** are stored per computer and resolved by rules: first the user's own, set
  once on the page *Unassigned* (assign to a vendor and product, or ignore; they apply to every computer at once),
  then rules built into opensecmon for common programs (browsers, Office and PDF, packers, remote access, editors,
  runtimes, Canonical's snapd, LXD, MicroK8s, Multipass and Juju; store apps published by Microsoft, web apps of
  Chrome (Windows programs with the publisher `Google\Chrome`) and the base,
  runtime and theme snaps of Ubuntu such as `core24`, `gnome-*`, `mesa-*` are ignored). Snaps and Flatpaks of hosts
  read over SSH are resolved by the same rules. An entry is identified by its type and a key: the snap
  name, the Flatpak ID, the name of a store app, and for a Windows program its display name in lower case without
  anything in brackets, versions, architecture and language ("7-Zip 24.08 (x64)" → `7-zip`), because the registry
  key often changes with the version. An assigned entry becomes a software asset with the first version-like piece of
  its version (`144.0.2-1` → `144.0.2`); a Windows program takes the version from its display name when the
  installer encodes it otherwise (same major and minor version, three or more numbers in the name, the reported
  version not just longer: "Python 3.12.10 (64-bit)" with `3.12.10150.0` → `3.12.10`); two versions of the same program stay two assets. Entries without a rule do
  not become assets: they are listed on the page *Unassigned*, and the computer and its group in the asset list say
  how many there are, so they never look like "no findings".
- Each full report **replaces** the computer's assets from the agent: what is no longer reported is removed.
  Assets entered by hand stay untouched.
- A computer that stops reporting **keeps its assets** (a laptop on holiday). The page shows the time of the last
  report and warns after a number of days.
- **Revoking** a computer makes its token invalid at once; its assets stay until the computer is deleted.
- The audit log records enrollments, new codes, revocations and deletions, not single reports.

## Versioning

- The path carries the major version (`/api/v1/`). Within it, new optional fields may appear in requests and
  responses; both sides ignore fields they do not know.
- `schema` counts the formats of the bodies. A new required field or a changed meaning raises it; opensecmon keeps
  accepting older schemas for at least one release.

## Examples

Enrollment with `curl` (built-in HTTPS, certificate downloaded from the computer's page):

```sh
curl --fail-with-body --cacert opensecmon.pem \
  -H 'Content-Type: application/json' \
  -d '{"schema":1,"code":"K7FQ-29XM","hostname":"laptop","agent":{"name":"curl-script","version":"1"}}' \
  https://192.0.2.10:8444/api/v1/agent/enroll
```

Report from a Debian or Ubuntu computer with the inventory script of the SSH import. The token is read from a
header file (`Authorization: Bearer osm1_…`, mode `600`), so it does not appear in the process list:

```sh
/usr/local/bin/opensecmon-inventory | gzip -c | curl --fail-with-body --cacert /etc/opensecmon-agent/opensecmon.pem \
  -H @/etc/opensecmon-agent/auth-header \
  -H 'Content-Type: text/plain; charset=utf-8' -H 'Content-Encoding: gzip' \
  --data-binary @- https://192.0.2.10:8444/api/v1/agent/report
```

With the script for Debian and Ubuntu, which does both and installs a systemd timer (the reports then run without
root, the token comes in as a systemd credential):

```sh
sudo sh opensecmon-agent.sh enroll https://192.0.2.10:8444 K7FQ-29XM opensecmon.pem
opensecmon-agent status                # as root
sudo opensecmon-agent uninstall
```

With the PowerShell script for Windows (in a PowerShell window as administrator; it keeps the token in
`C:\ProgramData\opensecmon-agent`, readable by SYSTEM and administrators only, and adds the scheduled task
`opensecmon-agent`, which runs as SYSTEM at start-up and every 6 hours and sends the JSON with `curl.exe`):

```powershell
powershell -ExecutionPolicy Bypass -File .\opensecmon-agent.ps1 enroll https://192.0.2.10:8444 K7FQ-29XM opensecmon.pem
powershell -ExecutionPolicy Bypass -File C:\ProgramData\opensecmon-agent\opensecmon-agent.ps1 status
powershell -ExecutionPolicy Bypass -File .\opensecmon-agent.ps1 update      # a newer script in place of the old one
powershell -ExecutionPolicy Bypass -File C:\ProgramData\opensecmon-agent\opensecmon-agent.ps1 uninstall
```

It needs `curl.exe` (Windows 10 1803, Windows Server 2019 and later). With the self-signed certificate it calls curl
with `--cacert` and `--ssl-no-revoke`, because Schannel cannot ask such a certificate for its revocation.

## Not part of version 1

- Commands from opensecmon to the computer beyond `next_report_s` and the offer of a signed update the user asked
  for (no remote execution of any kind).
- Other package managers (rpm, pacman, Homebrew), macOS.
- Hardware details, running services, open ports, update status of the system.
- Removing a computer from the agent side: the user deletes it in the web interface.
