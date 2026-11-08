# Import of assets: hosts over SSH, opennetmon, CSV (phase 6).

assets-tab-hosts = Hosts (SSH)
assets-tab-opennetmon = Import from opennetmon
assets-tab-csv = CSV import
assets-hidden = { $count ->
    [one] 1 more package without open findings
   *[other] { $count } more packages without open findings
}
assets-show-all = show all
assets-all-hosts = Show all hosts
asset-origin-ssh = SSH
asset-origin-opennetmon = opennetmon
asset-origin-csv = CSV
asset-origin-ssh-note = This package comes from reading the host over SSH. The next reading overwrites changes and adds deleted packages again.
asset-origin-onm-note = This asset follows a device in opennetmon. If the rule recognises the firmware for sure, the next reading takes over the device's version.
asset-origin-onm-new = The asset will be linked to the device “{ $device }” in opennetmon.

hosts-title = Hosts (SSH)
hosts-add = Add host
hosts-none-title = No hosts yet
hosts-none-text = A host reports its installed packages over SSH. There, the key may only run a script that prints the system details and the lists of packages, snaps and Flatpaks.
hosts-col-name = Name
hosts-col-address = Address
hosts-col-system = System
hosts-col-packages = Packages
hosts-col-last = Last reading
hosts-col-state = State
hosts-affected = { $vulns ->
    [one] 1 vulnerability
   *[other] { $vulns } vulnerabilities
} in { $count ->
    [one] 1 package
   *[other] { $count } packages
}
hosts-next = next
hosts-continue = Continue setup
hosts-run = Read now
hosts-footer = Read every 6 h with a key of its own. A package here is a source package with the highest installed version; the asset list shows only packages with open findings.
hosts-own-key = Public key of opensecmon
hosts-own-key-text = Used for all hosts. The private key is stored encrypted in the database and never leaves opensecmon.
hosts-state-off = off
hosts-state-setup = setup open
hosts-state-key = confirm host key
hosts-state-key-changed = host key changed
hosts-state-error = error
hosts-state-ok = ok
hosts-state-waiting = not read yet
hosts-step-connection = Connection
hosts-step-key = Install the key
hosts-step-confirm = Confirm host key
hosts-step-test = Test
hosts-name = Name
hosts-name-help = The host's name in the assets and the inbox.
hosts-address = Address
hosts-port = Port
hosts-user = User on the host
hosts-user-help = A user of its own without privileges is enough.
hosts-moved-help = A new address or port requires confirming the host key again.
hosts-next-step = Next
hosts-manage = Manage
hosts-show-setup = Show the setup instructions
hosts-show-packages = { $count ->
    [one] Show 1 package
   *[other] Show { $count } packages
}
hosts-disable = Switch reading off
hosts-disable-help = The packages stay but are no longer updated.
hosts-enable = Switch reading on
hosts-delete = Remove host
hosts-delete-help = Removes the host with all its packages and their findings.
hosts-setup-title = Set up host
hosts-setup-user = 1. Create the user on the host:
hosts-setup-script = 2. Save this script as
hosts-setup-home = home directory
hosts-setup-groups = If the SSH server lets only some groups in (AllowGroups; on openmediavault the group _ssh), add the user to it. Otherwise skip this.
hosts-setup-key = 3. Add the key (one line) to
hosts-setup-key-help = restrict forbids a terminal and forwarding, command= allows only the script. So the key can only read the system details and the lists of packages, snaps and Flatpaks.
hosts-back = Back
hosts-connect = Connect
hosts-key-changed = The host presents a different key than before. This can be a reinstallation, or another machine at this address. Confirmed so far:
hosts-key-shown = When connecting, the host presents this host key:
hosts-key-compare = Compare it on the host. It is stored only after you confirm it. If it changes later, reading stops and you get a message here.
hosts-key-ok = The fingerprint matches the one on the host
hosts-confirm = Confirm and test
hosts-result = Connection ok. { $system }, { $count ->
    [one] 1 package read.
   *[other] { $count } packages read.
}
hosts-result-open = { $count ->
    [one] 1 package has open findings; they are in the inbox.
   *[other] { $count } packages have open findings; they are in the inbox.
}
hosts-result-none = The host key is confirmed. The packages are read with the next reading.
hosts-done = View packages

ssh-error-name = The name may only contain letters, digits, dot, hyphen and underscore (at most 100 characters).
ssh-error-name-taken = A host or computer with this name exists already.
ssh-error-address = Please enter an IP address or a host name.
ssh-error-port = The port must be between 1 and 65535.
ssh-error-username = The user name does not fit (lowercase letters, digits, _ and -, at most 32 characters).
ssh-error-connect = No connection to the host.
ssh-error-timeout = The host did not answer in time.
ssh-error-key-unknown = The host key is not confirmed yet.
ssh-error-key-changed = The host presents a different host key. Reading is stopped until you confirm the new key.
ssh-error-auth = The host refuses the key. Is the line in authorized_keys of the right user?
ssh-error-command = The script on the host failed.
ssh-error-too-large = The output of the host is too large.
ssh-error-output = The output of the host does not have the expected format. Is the script unchanged?
ssh-error-system = The host's system is not supported (only Debian and Ubuntu).
ssh-error-no-packages = The host reported no installed packages.

onm-title = Import from opennetmon
onm-last-error = Last reading failed:
onm-connection = Connection to opennetmon
onm-last = last read
onm-connection-text = opensecmon reads the devices, read-only, from an endpoint of opennetmon with a token of its own. A coming version of opennetmon brings the endpoint:
onm-url = Address of opennetmon
onm-url-help = HTTPS; HTTP only on this machine (localhost), so that the token does not cross the network in clear.
onm-token = Token
onm-token-kept = stored, leave empty to keep it
onm-token-help = Stored encrypted and not shown again.
onm-cert = Certificate fingerprint (SHA-256, optional)
onm-cert-help = Only for a self-signed certificate, for example when opennetmon runs on the same server at https://127.0.0.1:8443. opensecmon then accepts exactly this certificate and no other. Leave empty when the certificate comes from a known authority (such as Let's Encrypt).
onm-remove = Remove connection
onm-devices = Devices from opennetmon
onm-counts = { $count } devices, { $taken } taken over
onm-none-title = No devices yet
onm-none-text = Once connected, the devices from opennetmon appear here with a suggested vendor, product and version.
onm-col-device = Device in opennetmon
onm-col-suggestion = Suggestion
onm-col-rule = Recognised by
onm-gone = no longer in opennetmon
onm-via-ssh = read over SSH
onm-taken = taken over
onm-skipped = skipped
onm-unskip = Take back
onm-take = Take over
onm-change = Change
onm-skip = Skip
onm-footer = Read every 6 h. Devices taken over become assets; if the rule recognises the firmware for sure, the version follows the device.
onm-sure-yes = sure
onm-sure-check = please check
onm-sure-none = not recognised
onm-version-unknown = version unknown
onm-rule-avm = rule “AVM FRITZ!Box”
onm-rule-cisco = rule “Cisco IOS”
onm-rule-mikrotik = rule “MikroTik RouterOS”
onm-rule-tp-link = rule “TP-Link”
onm-rule-huawei = rule “Huawei”
onm-rule-enterprise = vendor from sysObjectID
onm-rule-linux = Linux host: better read its packages over SSH
onm-rule-none = no rule
onm-error-url = The address is not a valid http(s) address without credentials, query and fragment.
onm-error-http = HTTP is only allowed on this machine; on the network please use HTTPS.
onm-error-no-token = Please enter a token.
onm-error-token-again = The address or the fingerprint changed: please enter the token again.
onm-error-token-format = The token is too long or contains control characters.
onm-error-token = opennetmon refuses the token.
onm-error-missing = opennetmon does not know the endpoint (version too old?).
onm-error-fetch = opennetmon cannot be reached.
onm-error-format = The answer of opennetmon does not have the expected format.
onm-error-redirect = opennetmon redirects the request, and with a token opensecmon follows no redirect. Is there a proxy with a sign-in in front of it (such as Cloudflare Access), or does the name point elsewhere on this server? Target of the redirect
onm-error-cert = opensecmon does not trust the certificate of opennetmon (for example because it is self-signed). If this SHA-256 fingerprint matches the one of opennetmon, enter it above
onm-error-pin-mismatch = The certificate of opennetmon is not the one with the stored fingerprint (a new certificate or another server?). Fingerprint of the presented certificate
onm-error-pin = The fingerprint is not a SHA-256 value (64 hex digits, colons allowed).
onm-error-pin-http = A fingerprint only applies to an HTTPS address.

csv-title = CSV import
csv-drop = Drop a CSV file here or choose one
csv-rules = UTF-8, separator comma or semicolon, at most { $count } rows, 1 MiB
csv-text = Content of the CSV file
csv-text-help = Paste it, or choose a file above. The first line names the columns.
csv-import = { $count ->
    [one] Take over 1 row
   *[other] Take over { $count } rows
}
csv-col-line = Line
csv-col-state = Result
csv-columns = Columns
csv-columns-help = kind (package, software, hardware), vendor, product, version, host, cpe; for packages distro (debian, ubuntu) and release; note optional. German names work as well. Rows with the same kind, vendor, product and host change an existing asset; assets from SSH and opennetmon are left alone.
csv-state-new = new
csv-state-update = changes an asset
csv-state-same = unchanged
csv-state-error = error
csv-summary = { $new } new, { $update } changed, { $same } unchanged, { $errors } with errors
csv-more = and { $count } more rows
csv-error-empty = The file contains no rows.
csv-error-header = The first line must name the columns, at least “product”.
csv-error-rows = The file has too many rows.
csv-error-size = The file is too large.
csv-error-twice = The same row appears further up already.

flash-host-saved = Host saved.
flash-host-read = Host read and matched.
flash-host-deleted = Host removed with its packages.
flash-onm-saved = Connection to opennetmon saved.
flash-onm-read = Devices read from opennetmon.
flash-device-taken = Device taken over and matched.
flash-csv-imported = CSV file taken over and matched.

## Computers of the agent API (they report their software themselves)
assets-tab-computers = Computers (agent)
computers-title = Computers (agent)
computers-add = Add computer
computers-add-intro = A computer reports its installed software to opensecmon itself, only from the local network. Give it a name; the page then shows the one-time code it enrolls with.
computers-create = Add and show the code
computers-none-title = No computers yet
computers-none-text = Computers such as laptops and desktops report their software themselves while they are in the local network. Add a computer and enroll it with the code shown.
computers-col-agent = Program
computers-col-seen = Last seen
computers-footer = The API only takes requests from the allowed networks (agent_networks in the configuration; without it private and local addresses). Every computer has a token of its own.
computers-state-waiting = waiting for enrollment
computers-state-expired = code expired
computers-state-enrolled = enrolled
computers-state-revoked = revoked
computers-enroll-title = Enroll
computers-enroll-intro = The program on the computer needs these details. The code is valid for 15 minutes and once.
computers-code = One-time code
computers-code-valid = valid until
computers-url = Address
computers-fingerprint = Fingerprint of the certificate (SHA-256)
computers-cert-download = Download the certificate (opensecmon.pem)
computers-cert-none = opensecmon runs without HTTPS of its own behind a proxy: the computer checks the proxy's certificate like a browser, no fingerprint is needed.
computers-try = By hand with curl (to try it, in the folder with opensecmon.pem)
computers-try-help = The answer contains the computer's token. It is shown this one time only; keep it readable only by root.
computers-status-cmd = Check the token and the connection:
computers-details = Details of the computer
computers-hostname = Reported host name
computers-enrolled = Enrolled
computers-never = never
computers-rename = Rename
computers-new-code = Make a new code
computers-new-code-help = The old code stops working. When the computer enrolls with the new one, its previous token stops working; its assets stay.
computers-revoke = Revoke
computers-revoke-help = The token stops working at once. The assets stay until you remove the computer.
computers-delete = Remove computer
computers-delete-help = Removes the computer with all assets it reported and their findings.
computers-state-reporting = reporting
computers-state-error = report rejected
computers-last-report = Last report
computers-last-error = The last report was not taken:
computers-script-title = Debian and Ubuntu (also Mint, Zorin, Pop!_OS …)
computers-script-intro = The script enrolls the computer and installs a systemd timer that sends the lists of packages, snaps and Flatpaks every 6 hours.
computers-script-download = Download the script (opensecmon-agent.sh)
computers-update-title = Update the script
computers-update-intro = A new version of the script replaces the old one; enrollment, token and timer stay.
computers-update-help = Run it in the folder with the downloaded script. The timer sends the next report, at once with: sudo systemctl start opensecmon-agent.service
computers-script-help = Run it in the folder with the script (and opensecmon.pem, if offered above). The token is then kept in /etc/opensecmon-agent, readable by root only; the reports run without root. Remove it with: sudo opensecmon-agent uninstall
computers-windows-title = Windows 10, Windows 11 and Windows Server 2019 or later
computers-windows-intro = The PowerShell script enrolls the computer and adds a scheduled task that sends Windows and the installed programs at start-up and every 6 hours.
computers-windows-download = Download the script (opensecmon-agent.ps1)
computers-windows-help = Run it in a PowerShell window as administrator, in the folder with the script (and opensecmon.pem, if offered above). The token is then kept in C:\ProgramData\opensecmon-agent, readable by SYSTEM and administrators only; the task "opensecmon-agent" runs as SYSTEM. Remove it with: powershell -ExecutionPolicy Bypass -File C:\ProgramData\opensecmon-agent\opensecmon-agent.ps1 uninstall
computers-update-intro-windows = A new version of the script replaces the old one; enrollment, token and scheduled task stay.
computers-update-help-windows = Run it in a PowerShell window as administrator, in the folder with the downloaded script. The scheduled task sends the next report, at once with: Start-ScheduledTask opensecmon-agent
computers-error-system = The system is not supported (only Debian, Ubuntu and systems based on them).
computers-error-windows = This version of Windows is not supported (only Windows 10, Windows 11 and Windows Server 2016 and later).
computers-error-output = The report does not have the format of the inventory script.
computers-error-no-packages = The report lists no installed packages.
asset-origin-agent = Agent
asset-origin-agent-note = The computer reported this asset itself. The next report overwrites changes and adds deleted assets again.
flash-computer-saved = Computer saved.
flash-computer-code = New one-time code made.
flash-computer-revoked = Computer revoked.
flash-computer-deleted = Computer removed.

# Ubuntu Pro per host or computer
pro-mode-label = Ubuntu Pro
pro-mode-auto = detect automatically
pro-mode-yes = yes, active
pro-mode-no = no
pro-mode-help-detected = Automatic: detected, a package from Ubuntu Pro (ESM) is installed. All packages of this host follow the setting, readings do not overwrite it.
pro-mode-help-not-detected = Automatic: not detected, because Pro is only detected once a package from Ubuntu Pro (ESM) is installed. If the host is attached, choose “yes”. All packages of this host follow the setting.
pro-mode-invalid = Unknown setting for Ubuntu Pro.
asset-pro-from-host = Ubuntu Pro follows the setting of the host.
asset-pro-from-host-link = Change the setting

kernel-running = Kernel { $running }
kernel-reboot = Reboot needed, running kernel { $running }
kernel-reboot-installed = Reboot needed, running kernel { $running }, installed { $installed }
assets-tab-unassigned = Unassigned
items-type-os = System
items-type-win = Windows program
items-type-appx = Store app
items-type-snap = Snap
items-type-flatpak = Flatpak
unassigned-title = Unassigned
unassigned-text = Programs, store apps, snaps and Flatpaks that computers and hosts report and that are not assigned to a product yet. Only once assigned do they become assets and get matched against the vulnerabilities. An assignment or "Ignore" applies to all computers and hosts.
unassigned-built-in = Built-in rules assign { $assigned } entries and ignore { $ignored } (store apps of Windows, web apps of Chrome, base snaps of Ubuntu).
unassigned-none = All reported programs are assigned or ignored.
unassigned-more = and { $count } more
unassigned-col-entry = Entry
unassigned-col-versions = Versions
unassigned-col-computers = Computers and hosts
unassigned-assign = Assign
unassigned-ignore = Ignore
unassigned-user-scope = also installed for single users
unassigned-rules = Own rules
unassigned-rules-text = Assignments and ignored entries that apply to all computers and hosts; they come before the built-in rules. Removing one makes its entries "unassigned" again (or lets the built-in rule apply) and deletes their assets.
unassigned-rules-none = No own rules yet.
unassigned-rule-ignored = ignored
unassigned-rule-delete = Remove
unassigned-assign-title = Assign to a product
unassigned-assign-text = Vendor and product as the CVE list names them (the suggestions come from it). The version of each computer and host comes from its report; the preview shows the matches for the newest reported version.
unassigned-save = Assign
unassigned-back = Unassigned
unassigned-entry = Reported entry
unassigned-publisher = Publisher
flash-item-assigned = Assigned; the computers with this entry now have the asset, the matching runs in the background.
flash-item-ignored = Ignored; the entry no longer shows for any computer.
flash-rule-deleted = Rule removed.
computers-unassigned = { $count } unassigned

## opensecagent: enrollment code, downloads and updates
computers-agent-title = With opensecagent (recommended)
computers-agent-step-download = Install opensecagent on the computer:
computers-agent-step-code = Copy the enrollment code. The installer (Windows) or the enrollment dialog in the start menu (Linux) takes it by itself; otherwise paste it there.
computers-agent-code-help = The code carries the address, the certificate and the one-time code. It works once, until
computers-agent-scripts = Without opensecagent: scripts and the details one by one
computers-agent-windows = Windows
computers-agent-debian = Debian and Ubuntu
computers-agent-update-title = Update opensecagent
computers-agent-update-button = Update to { $version }
computers-agent-update-help = The computer fetches the update with its next report (within 15 minutes), checks the signature and installs it.
computers-agent-update-waiting = Update to { $version } requested, waiting for the next report of the computer
computers-agent-update-since = since
computers-agent-update-sent = Update to { $version } handed to the computer on
computers-agent-update-cancel = Cancel
computers-agent-update-failed = The last update failed:
computers-agent-update-current = opensecagent { $version } is up to date.
computers-agent-update-own = This opensecagent does not install updates (built by yourself or without the signing key); please update it by hand.
computers-update-available-short = Update available: { $version }
computers-update-requested-short = Update requested
computers-update-all = Update all ({ $count })
flash-computer-update = Update requested. The computer fetches it with its next report.
flash-computer-update-cancelled = Update cancelled.
