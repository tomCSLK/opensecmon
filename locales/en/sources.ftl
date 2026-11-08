# The sources: names, notes on licence and origin, state of the data.

source-cvelist = CVE list (cvelistV5)
source-nvd = NVD (enrichment)
source-kev = CISA KEV
source-epss = FIRST EPSS
source-bsi = BSI CERT-Bund (CSAF, TLP:WHITE)
source-vendor = Vendor CSAF
source-osv-debian = Debian (OSV: DSA, DLA, DEBIAN-CVE)
source-osv-ubuntu = Ubuntu (OSV: USN, LSN, UBUNTU-CVE)
source-debian-tracker = Debian Security Tracker

source-cvelist-notice = CVE® data of the CVE Program, used under the CVE Terms of Use (© The MITRE Corporation). CVE is a registered trademark of The MITRE Corporation.
source-nvd-notice = This product uses data from the NVD but is not endorsed or certified by the NVD. Since 15 April 2026 NIST only enriches prioritised CVEs, so many new CVEs have no CVSS and CPE from the NVD.
source-kev-notice = Known Exploited Vulnerabilities Catalog by CISA, public domain (CC0 1.0).
source-epss-notice = EPSS scores by FIRST.org (Exploit Prediction Scoring System), attribution requested.
source-bsi-notice = Security advisories of the German Federal Office for Information Security (CERT-Bund, Warn- und Informationsdienst), public feeds only (TLP:WHITE). Mind the BSI's terms of use.
source-vendor-notice = CSAF documents of the vendors you chose (TLP:WHITE/CLEAR only); terms differ by vendor, see the vendor's provider page.
source-osv-debian-notice = Security data of the Debian security team (advisories and package state per CVE), obtained through OSV.dev; the Debian data states no explicit licence.
source-osv-ubuntu-notice = Ubuntu Security Notices and CVE data by Canonical, obtained through OSV.dev; licence CC BY-SA 4.0 (© Canonical Ltd.).
source-debian-tracker-notice = Package state per release from the Debian Security Tracker (security-tracker.debian.org); only open and undetermined issues and issues without a planned DSA are stored. No explicit licence stated.

source-cvelist-state = As of { $version } · { $count } CVE records
source-nvd-state = Feed of { $version } · { $count } CVEs with NVD data
source-kev-state = Catalog { $version } · { $count } entries
source-epss-state = Model and date { $version } · { $count } scores
source-bsi-state = Newest document from { $version } · { $count } advisories
source-vendor-state = { $version } providers switched on · { $count } advisories
source-osv-debian-state = Newest record from { $version } · { $count } records
source-osv-ubuntu-state = Newest record from { $version } · { $count } records
source-debian-tracker-state = As of { $version } · { $count } open entries

sources-run-all = Fetch all now
sources-run = Fetch
sources-run-off = The source is switched off. Switch it on first, then fetch it.
sources-manual-only = Scheduled fetching is switched off in the configuration (fetch_sources = false). Sources only run when started here by hand.
sources-col-state = State
sources-col-source = Source
sources-col-last = Last run
sources-col-duration = Duration
sources-col-new = New
sources-col-changed = Changed
sources-col-next = Next run
sources-col-interval = Interval
sources-col-enabled = On
sources-col-actions = Actions
sources-details = Details
sources-enabled = Switched on
sources-save = Save
sources-notices = Notes on the data
sources-progress = { $count } processed
sources-interval-hours = { $hours } h
sources-interval-minutes = { $minutes } min
sources-interval-daily = daily
sources-interval-invalid = This interval is not offered for the source.
sources-state-running = Running
sources-state-off = Off
sources-state-waiting = Never fetched
sources-state-failed = Failed
sources-state-stale = Out of date
sources-state-ok = OK
sources-warning = Note on the last run
sources-vendors-manage = Manage providers

status-title = State of the sources
status-checked = Last check
status-running = Fetching: { $source }
status-failing = { $count ->
    [one] 1 source failed
   *[other] { $count } sources failed
}
status-never = Not fetched yet
status-ok = all sources OK
