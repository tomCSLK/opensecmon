# Die Quellen: Namen, Hinweise zu Lizenz und Herkunft, Stand der Daten.

source-cvelist = CVE-Liste (cvelistV5)
source-nvd = NVD (Anreicherung)
source-kev = CISA KEV
source-epss = FIRST EPSS
source-bsi = BSI CERT-Bund (CSAF, TLP:WHITE)
source-vendor = Hersteller-CSAF
source-osv-debian = Debian (OSV: DSA, DLA, DEBIAN-CVE)
source-osv-ubuntu = Ubuntu (OSV: USN, LSN, UBUNTU-CVE)
source-debian-tracker = Debian Security Tracker

source-cvelist-notice = CVE®-Daten des CVE Program, Nutzung nach den CVE Terms of Use (© The MITRE Corporation). CVE ist eine eingetragene Marke von The MITRE Corporation.
source-nvd-notice = This product uses data from the NVD but is not endorsed or certified by the NVD. Seit dem 15.04.2026 reichert NIST nur noch priorisierte CVEs an; CVSS und CPE fehlen daher bei vielen neuen CVEs.
source-kev-notice = Known Exploited Vulnerabilities Catalog der CISA, gemeinfrei (CC0 1.0).
source-epss-notice = EPSS-Werte von FIRST.org (Exploit Prediction Scoring System), Quellenangabe erbeten.
source-bsi-notice = Sicherheitshinweise des Bundesamts für Sicherheit in der Informationstechnik (CERT-Bund, Warn- und Informationsdienst), nur die öffentlichen Feeds (TLP:WHITE). Nutzungsbedingungen des BSI beachten.
source-vendor-notice = CSAF-Dokumente der ausgewählten Hersteller (nur TLP:WHITE/CLEAR); Bedingungen je Hersteller, siehe dessen Anbieterseite.
source-osv-debian-notice = Sicherheitsdaten des Debian-Sicherheitsteams (Advisories und Paketstatus je CVE), bezogen über OSV.dev; die Debian-Daten nennen keine ausdrückliche Lizenz.
source-osv-ubuntu-notice = Ubuntu Security Notices und CVE-Daten von Canonical, bezogen über OSV.dev; Lizenz CC BY-SA 4.0 (© Canonical Ltd.).
source-debian-tracker-notice = Paketstatus je Release aus dem Debian Security Tracker (security-tracker.debian.org); gespeichert werden nur offene und unklare Einträge sowie Einträge ohne geplantes DSA. Ohne ausdrückliche Lizenzangabe.

source-cvelist-state = Stand { $version } · { $count } CVE-Datensätze
source-nvd-state = Feed vom { $version } · { $count } CVEs mit NVD-Daten
source-kev-state = Katalog { $version } · { $count } Einträge
source-epss-state = Modell und Datum { $version } · { $count } Werte
source-bsi-state = Neuestes Dokument vom { $version } · { $count } Advisories
source-vendor-state = { $version } Anbieter eingeschaltet · { $count } Advisories
source-osv-debian-state = Neuester Datensatz vom { $version } · { $count } Datensätze
source-osv-ubuntu-state = Neuester Datensatz vom { $version } · { $count } Datensätze
source-debian-tracker-state = Stand { $version } · { $count } offene Einträge

sources-run-all = Alle jetzt abrufen
sources-run = Abrufen
sources-run-off = Die Quelle ist ausgeschaltet. Erst einschalten, dann abrufen.
sources-manual-only = Die Abrufe nach Zeitplan sind in der Konfiguration abgeschaltet (fetch_sources = false). Quellen laufen nur, wenn sie hier von Hand gestartet werden.
sources-col-state = Zustand
sources-col-source = Quelle
sources-col-last = Letzter Lauf
sources-col-duration = Dauer
sources-col-new = Neu
sources-col-changed = Geändert
sources-col-next = Nächster Lauf
sources-col-interval = Intervall
sources-col-enabled = Ein
sources-col-actions = Aktionen
sources-details = Einzelheiten
sources-enabled = Eingeschaltet
sources-save = Speichern
sources-notices = Hinweise zu den Daten
sources-progress = { $count } verarbeitet
sources-interval-hours = { $hours } h
sources-interval-minutes = { $minutes } min
sources-interval-daily = täglich
sources-interval-invalid = Dieses Intervall ist für die Quelle nicht vorgesehen.
sources-state-running = Läuft
sources-state-off = Aus
sources-state-waiting = Noch nie abgerufen
sources-state-failed = Fehler
sources-state-stale = Veraltet
sources-state-ok = In Ordnung
sources-warning = Hinweis zum letzten Lauf
sources-vendors-manage = Anbieter verwalten

status-title = Zustand der Quellen
status-checked = Letzte Prüfung
status-running = Abruf läuft: { $source }
status-failing = { $count ->
    [one] 1 Quelle mit Fehler
   *[other] { $count } Quellen mit Fehler
}
status-never = Noch kein Abruf
status-ok = alle Quellen in Ordnung
