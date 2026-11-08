# Plan: Security-Advisory-Dashboard für Debian/Ubuntu-Server (Arbeitstitel `opensecmon`)

## Status

Kurzfassung je Phase und Vorhaben. Einzelheiten, Messwerte und Abweichungen in den Abschnitten unten. Betriebsdaten
der eigenen Installation (Rechner, Versionen, Pakete auf dem Server) stehen nicht in diesem Repo.

| Datum | Stand |
|---|---|
| 2026-11-04 | Plan freigegeben, HTML-Entwürfe in `docs/entwurf/` (alle Seiten, hell/dunkel, drei Breiten, erfundene Daten) abgenommen, „go“ für die Umsetzung. **Phase 0 erledigt:** Name `opensecmon` (crates.io, Debian, GitHub frei; DPMA nicht geprüft), Repo, LICENSE (AGPL-3.0-or-later), README, CHANGELOG. |
| 2026-11-05 | **Phase 1 erledigt (Grundgerüst):** aus opennetmon übernommen und zurückgeschnitten (Anmeldung, Sitzungen, CSRF, Argon2, verschlüsselte Geheimnisse, Mail mit Testmail, Änderungsprotokoll, Fluent DE/EN, SQLite), neu: Host-/Origin-Prüfung (`allowed_hosts`), stündliche Wartung; Oberfläche nach den Entwürfen; `.deb` mit gehärteten Units und Sicherungs-Timer. 146 Tests. |
| 2026-11-05 | **Phase 2 erledigt (CVE-Basis):** eigener HTTP-Client, Ablaufplaner, Quellen cvelistV5, NVD-Feeds, CISA KEV, FIRST EPSS; Seiten „Alle CVEs“ und „Quellen“. Erstimport gemessen (unten). 198 Tests. |
| 2026-11-06 | **Phase 3 erledigt (CSAF):** eigener CSAF-2.0-Leser, Quellen „BSI CERT-Bund“ (nur TLP:WHITE) und „Hersteller-CSAF“, Ansicht „Advisories“, Seite „Hersteller-CSAF“. 219 Tests. |
| 2026-11-06 | **Phase 4 erledigt (Distributionen):** OSV Debian/Ubuntu, Debian Security Tracker, Abschnitt „Distributionen“ im CVE-Detail. 237 Tests. |
| 2026-11-06 | **Phase 5 erledigt (Assets und Abgleich):** Assets von Hand mit Vorschlägen und Vorschau, Watchlist, Abgleich-Engine mit drei Vertrauensstufen, Eingang mit Triage, „Nur meine“. 267 Tests. |
| 2026-11-06 | **Phase 6 erledigt (Import):** Hosts per SSH/`dpkg` mit Zwangsbefehl und Assistent, CSV-Import, Import aus opennetmon (nur die Seite in opensecmon; der Endpunkt in opennetmon folgt dort). 293 Tests. |
| 2026-11-06 | **Phase 7 erledigt (Meldungen):** Sofort-Mail (KEV, Priorität, CVSS, EPSS, Bündeln, kein Rückstau beim Einschalten) und Tagesbericht mit eigenen Einstellungsseiten. 316 Tests. |
| 2026-11-06 | **Phase 8 erledigt (Feinschliff):** Seite „Lage“, CSV-Export, Einstellungen „Priorität“ und „Aufbewahrung“, komprimierte JSON-Spalten (Test-DB 2,21 → 1,54 GB), Mindestpriorität je Asset. 340 Tests. |
| 2026-11-07 | **Phase 9 Punkte 1 und 2 erledigt:** Sicherheitstest (Code-Review, 536 Angriffe auf eine Wegwerf-Instanz ohne Befund, Fuzztests `src/fuzz.rs`; Behebungen im Abschnitt „Sicherheitstest“), Betriebsanleitung `docs/operations.md`. 353 Tests. |
| 2026-11-07 | **Eingebautes HTTPS** (Release wird öffentlich, nicht jeder hat einen Reverse Proxy): `src/tls.rs`, `tls generate`, Paket mit selbstsigniertem Zertifikat auf Port 8444, Proxy optional. Test-Paket im eigenen Betrieb, Erstimport dort 25 min ohne Fehler, DB 1,6 GB. 359 Tests. |
| 2026-11-07 | **opennetmon-Import mit Fingerabdruck:** Feld „Fingerabdruck des Zertifikats (SHA-256)“ für selbstsignierte Zertifikate (Migration `0015`), abgelehnte Zertifikate und Weiterleitungen werden mit Fingerabdruck bzw. Ziel gemeldet. 365 Tests, Version 0.2.0. |
| 2026-11-07 | **Desktop-Agent Schritte 1–3:** Schnittstelle `docs/agent-api.md`, Reiter „Rechner (Agent)“ mit Einmalcode und Token je Rechner (Migration `0016`), Meldungen von Debian/Ubuntu-Rechnern mit `contrib/opensecmon-agent.sh`. 390 Tests, Version 0.3.0. |
| 2026-11-07 | **Vorhaben „Rauschen im Betrieb“ abgeschlossen** (fünf Schritte, Migrationen `0017`–`0019`): Filter „Korrektur angekündigt“, Ubuntu Pro je Host, Abzug für die Einstufung der Distribution, Raspberry-Pi-Kernel ohne Datenquelle, verschiedene Schwachstellen zählen, laufender Kernel und Neustart. 406 Tests, Version 0.3.1. |
| 2026-11-07 | **Desktop-Agent Schritte 4 und 5:** Windows als Asset gegen die CNA-Bereiche von Microsoft, PowerShell-Skript `contrib/opensecmon-agent.ps1`, Seite „Nicht zugeordnet“ mit eingebauten und eigenen Regeln (Migration `0020`), Snaps und Flatpaks in beiden Linux-Skripten. Befunde aus dem Betrieb behoben (Flatpak-Cache unter dem Dienst, Python-Version aus dem Namen, Zweitschlüssel für Edge/Notepad++, Web-Apps von Chrome ignoriert, Regeln beim Start neu angewandt). 423 Tests, Versionen 0.3.2 und 0.3.3. |
| 2026-11-07 | **Agent-Programm opensecagent** als eigenes Repo (AGPL-3.0-or-later), Plan dort. **Schritt 7 erledigt (Vorbereitung):** Anmeldecode `osa1_…`, Paketkatalog `agent_packages_dir`, 15-Minuten-Takt, Updates nur auf Knopfdruck, `dev/agent-packages.sh` prüft die Signaturen (Migration `0021`). 439 Tests. |
| 2026-11-08 | **Version 0.3.4** mit dem signierten opensecagent 0.1.1, **Version 0.3.5**: Abstände und Höhen der Knöpfe auf allen Seiten gemessen und korrigiert, opensecagent 0.1.2. Beide als Update im Container geprüft. |
| 2026-11-08 | **Prüfung vor dem Öffentlich-Schalten:** keine Geheimnisse in Stand und Historie; Bedingungen der Quellen geprüft (kein Hindernis für ein Programm, das zur Laufzeit abruft; Hinweise im Abschnitt „Offene Punkte“); Betriebsdaten aus dem Plan genommen, Beispieldaten der Entwürfe neutral, README neu, `SECURITY.md` und `CONTRIBUTING.md`. Lizenz AGPL-3.0-or-later bestätigt. Die Historie beginnt mit einem Anfangs-Commit neu; Commit-Nummern in diesem Plan beziehen sich auf die frühere, private Historie. |

## Context

Ziel ist eine eigene Serveranwendung, die mehrmals täglich öffentliche Quellen nach neuen Sicherheitslücken
und Advisories abfragt und sie in einer Weboberfläche zeigt. Ein Filter soll nur die Meldungen zeigen, die die
eigene Soft- und Hardware betreffen. Vorbild ist das „Security Advisory Dashboard Pro“ von isw-adtools. Das ist ein
Windows-Tool für 499 €. Es verbindet BSI CERT-Bund, CISA KEV und EPSS zu einem Prioritätswert und hat Watchlist,
Asset-Profil, Mail-Berichte und Export.

Entscheidungen des Nutzers (2026-11-04):
- **Technik wie opennetmon:** Rust, axum, askama, sqlx/SQLite, statisches musl-Binary, `.deb`, systemd-Dienst.
- **Einsatz:** Heimnetz oder kleines Netz, ein Administrator, Betrieb auf einem eigenen Debian/Ubuntu-Server, direkt
  per HTTPS oder hinter einem Reverse Proxy.
- **Quellen im ersten Release:** BSI CERT-Bund (CSAF), CISA KEV, FIRST EPSS, CVE/NVD, CSAF-Feeds der Hersteller,
  Ubuntu und Debian (dazu OSV).
- **Filter auf die eigenen Produkte:** eine Asset-Liste, die man von Hand pflegt, plus automatischer Import:
  - die installierten Pakete per SSH (`dpkg`), nur lesend;
  - die Geräte aus opennetmon.
- **Meldungen:** eine Mail sofort bei einem Treffer über einer Schwelle und eine tägliche Zusammenfassung.
- **Repo:** zunächst privat (`tomCSLK/<name>`). Öffentlich wird es erst nach einer Prüfung der Lizenzen und
  Nutzungsbedingungen der Quellen.

## Ansatz

Eine eigenständige Anwendung (einzelnes Crate wie opennetmon). Das Grundgerüst wird aus opennetmon kopiert und
angepasst, nicht neu erfunden.

### Aus opennetmon übernehmen

| Bereich | Quelle | Anpassung |
|---|---|---|
| Anmeldung, Argon2, Tokens | `src/auth/mod.rs`, `src/auth/throttle.rs` | unverändert |
| Sessions, CSRF, Login | `src/web/auth.rs`, `migrations/0002`, `0018` | Rollen auf Admin reduzieren; dazu eine Host/Origin-Prüfung (gibt es in opennetmon nicht) |
| Sicherheits-Header, Passwortprüfung | `src/web/mod.rs` (CSP `default-src 'self'`) | unverändert |
| Verschlüsselte Geheimnisse | `src/crypto.rs` (XChaCha20, `secret.key` 0600) | auch für SMTP-Passwort, NVD-API-Key und SSH-Schlüssel |
| HTTP-Client | `src/http_client.rs` (hyper + rustls, Größenlimit, Deadline) | ETag/If-Modified-Since und gzip ergänzen; die Größengrenze je Quelle wählbar (große Downloads) |
| Hintergrundjobs | Muster `Poller::spawn` in `src/poller.rs` (`tokio::select!` + `watch` zum Beenden) | ein Job je Quelle |
| Mail | `src/mail.rs`, `src/mail/testsmtp.rs`, `src/web/mail_settings.rs`, `src/alerting.rs` (Mail-Warteschlange) | Mailtypen „Treffer“ und „Tagesbericht“ |
| i18n DE/EN | `src/i18n.rs`, `locales/{de,en}/*.ftl` (Fluent) | unverändert |
| Datenbank | `src/storage/mod.rs` (WAL, STRICT, `backup_to`), `sqlx::migrate!` | eigene Migrationen |
| Änderungsprotokoll | `src/audit.rs`, `src/storage/audit.rs`, `templates/audit.html` | unverändert |
| Update-Hinweis | `src/update_check.rs` | Repo-Name anpassen, erst nach dem Öffentlich-Schalten |
| Oberfläche (nur Technik) | `src/web/assets.rs` (eingebettete Dateien mit ETag), Umschaltung hell/dunkel aus `static/theme.js`, Zeitablauf der Sitzung aus `session.js` | **keine** Übernahme von Layout und CSS: Die Oberfläche wird für die Triage neu entworfen (siehe unten) |
| Paketbau | `dev/release.sh`, `dev/deb.sh` (cargo-deb), `deploy/deb/postinst`/`postrm`, `deploy/opennetmon.service` (gehärtet) | Name und Pfade: `/etc/<name>/`, `/var/lib/<name>/` |
| CI und Lizenzen | `.github/workflows/ci.yml`, `dev/third-party-licenses.py` | `cargo deny` mit `deny.toml` wie bei openpacketmon statt `cargo audit` |

### Quellen (Recherche vom 2026-11-04; mit [?] markierte Angaben sind noch nicht bestätigt)

| Quelle | Endpunkt / Format | Aktualisierung | Produkt-Kennung | Lizenz / Hinweis |
|---|---|---|---|---|
| CVE-Basis | `github.com/CVEProject/cvelistV5`: Release-Asset `YYYY-MM-DD_all_CVEs_at_midnight.zip` einmal, danach stündliche Delta-Zips (CVE JSON 5) | stündlich bis alle 2 h | CNA-Angaben `affected[]` (Hersteller/Produkt/Versionen, teils CPE) | CVE Terms of Use |
| NVD (Anreicherung) | JSON-2.0-Feeds `nvdcve-2.0-modified.json.gz` + `.meta` (SHA-256), Jahresfeeds für den Erstimport; kein API-Key nötig | alle 2 h (nicht öfter) | CVSS, CPE-Konfigurationen mit Versionsbereichen | Hinweis „uses NVD data but is not endorsed…“ Pflicht. **Seit 15.04.2026 reichert NIST nur noch priorisierte CVEs an**, CPE fehlt oft. Deshalb ist NVD Ergänzung, nicht Grundlage |
| CISA KEV | `cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | alle 6 h, bedingtes GET | `vendorProject`/`product` als Freitext | CC0 |
| EPSS | täglich `epss.empiricalsecurity.com/epss_scores-current.csv.gz` (Weiterleitung folgen), Tabelle komplett ersetzen | täglich | nur CVE-ID | Quellenangabe erbeten |
| BSI CERT-Bund | CSAF-Provider `wid.cert-bund.de/.well-known/csaf/provider-metadata.json`; **nur die TLP:WHITE-ROLIE-Feeds** (`bsi-wid-white`, `bsi-white`, `bsi-cvd-white`). Die GREEN-Feeds nicht laden. ROLIE-Feed > 10 MB, Einträge nach `updated` vergleichen, nur geänderte Dokumente holen, SHA-256 prüfen | alle 2 h | CSAF `product_tree` (Hersteller → Produkt → Version, teils CPE) | Bedingungen [?]; deckt auch Hersteller ohne eigenen CSAF-Feed ab (AVM, TP-Link, Fortinet, Synology …) |
| Hersteller-CSAF | Auswahl aus dem BSI-Lister `wid.cert-bund.de/.well-known/csaf-aggregator/aggregator.json` + eigene URL (`/.well-known/csaf/provider-metadata.json`). Geprüft: Cisco, Microsoft, Red Hat, SUSE, Siemens, Huawei. Bei Directory-Providern inkrementell über `changes.csv` | alle 6 h | CSAF `product_tree` | je Hersteller; große VEX-Bestände (Red Hat, Microsoft) nur gefiltert nach Herstellern/Produkten der eigenen Assets laden |
| Debian | OSV-Bulk `osv-vulnerabilities.storage.googleapis.com/Debian/all.zip`, inkrementell über `modified_id.csv`; dazu Security Tracker `security-tracker.debian.org/tracker/data/json` (> 10 MB, bedingtes GET) für Status/Dringlichkeit je Release | alle 6 h | Paketname + Release + behobene Version (PURL) | Tracker ohne Lizenzangabe [?] |
| Ubuntu | OSV-Bulk `…/Ubuntu/all.zip` + `modified_id.csv`; USN-Titel über `ubuntu.com/security/notices.json?limit=&offset=` | alle 6 h | Paket + Codename + Version | CC BY-SA 4.0 (Namensnennung) |

Rust-Crates: `csaf-models` (serde-Typen CSAF 2.0) für die Dokumente. Den ROLIE-Leser schreiben wir selbst (in
`csaf-walker` noch nicht umgesetzt). Den CPE-Abgleich mit Versionsbereichen schreiben wir ebenfalls selbst; `cpe` hilft
höchstens beim Parsen. Vor der Aufnahme jedes Crate prüfen (Pflege, Lizenz, `cargo deny`). Die GitHub Advisory
Database (nur Sprach-Ökosysteme) bleibt vorerst weg.

### Neue Teile

1. **Abrufer je Quelle** (`src/sources/<quelle>.rs`, gemeinsames Trait `Source`):
   - Jede Quelle hat ein eigenes Intervall (Standard 2–6 h, im Webinterface einstellbar), Zufallsversatz,
     Backoff bei Fehlern und einen Zustand je Quelle in `source_state` (ETag, Last-Modified, Cursor, letzter Lauf,
     Fehler).
   - Nur Änderungen laden, wo die Quelle es kann (siehe Tabelle der Quellen). Erstimport einmalig.
   - Antworten der Quellen gelten als nicht vertrauenswürdige Daten: Größenlimits, strenges Parsen, keine
     Ausführung, HTML in Beschreibungen escapen.
2. **Datenmodell** (Migrationen):
   - `cves`: id, Beschreibung, CVSS-Wert und Vektor, Veröffentlicht/Geändert, KEV-Flag mit Datum,
     EPSS mit Perzentil;
   - `advisories`: Quelle, Kennung, Titel, Zusammenfassung, Schweregrad, URL, Veröffentlicht/Aktualisiert,
     Status neu/Update;
   - `advisory_cves`;
   - `affected`: betroffene Produkte mit Hersteller, Produkt, Versionsbereich, CPE, PURL, Distribution/Release,
     behobene Version;
   - `assets`: Typ Software/Hardware, Hersteller, Produkt, Version, CPE/PURL, Herkunft manuell/SSH/opennetmon,
     Host;
   - `ssh_hosts`;
   - `matches`: Asset × Advisory/CVE, Vertrauen hoch/mittel/niedrig, zuerst gesehen, Status
     neu/gesehen/ignoriert/behoben;
   - `notifications` und `source_state`.
   - Volltextsuche mit SQLite FTS5.
3. **Abgleich** (`src/matching.rs`), nach Vertrauen gestaffelt:
   - **hoch:** CPE-Abgleich mit Versionsbereich (NVD-Konfigurationen) oder der Paketstatus der Distribution
     (Paket + Release + behobene Version gegen die installierte `dpkg`-Version; Debian-Versionsvergleich nach dem
     dpkg-Algorithmus, eigene Funktion mit Tests);
   - **mittel:** Hersteller und Produkt aus dem CSAF-Produktbaum;
   - **niedrig:** Stichwort-Watchlist.

   Der Abgleich läuft nach jedem Abruf und nach jeder Änderung an den Assets nur über die neuen oder geänderten
   Einträge.
4. **Priorität:**
   - Sie setzt sich zusammen aus CVSS, KEV (schlägt alles), EPSS und dem Vertrauen des Treffers.
   - Die Formel wird auf der Detailseite offengelegt. Das Beispiel nutzt CVSS × EPSS.
5. **Asset-Import:**
   - **Per SSH:**
     - Die App erzeugt einen eigenen ed25519-Schlüssel.
     - Der Host-Schlüssel wird beim ersten Kontakt angezeigt und erst nach Bestätigung gespeichert.
     - Auf dem Zielhost steht in `authorized_keys` ein Eintrag `restrict,command="dpkg-query -W -f=…"`
       (nur dieser eine Befehl). Dazu kommt `/etc/os-release` über denselben Weg (kleines Wrapper-Skript, das die
       App zum Kopieren anbietet).
     - Rust-Crate `russh` (reines Rust), Zeitlimits.
     - Ziele zuerst ein Ubuntu-Server, ein Raspberry Pi und ein NAS (Debian 13).
   - **Aus opennetmon:** opennetmon speichert heute weder Hersteller noch Modell oder Firmware und hat keine API.
     Nötig ist deshalb eine kleine Erweiterung in opennetmon:
     - `sysDescr`/`sysObjectID` je Gerät beim Abfragen speichern (neue Migration);
     - einen lesenden Endpunkt `/api/v1/inventory` mit Bearer-Token.
     - Das ist eigene Arbeit im opennetmon-Projekt, nur nach Freigabe dort.
     - Bis dahin gibt es einen CSV-Import.
   - Die Zuordnung „sysDescr → Hersteller/Produkt/Firmware“ läuft über Regeln (Router, Switches, Access Points,
     NAS, Raspberry Pi …). Was nicht erkannt wird, bestätigt oder korrigiert der Nutzer von Hand.
6. **Meldungen:**
   - Sofort-Mail bei einem neuen Treffer über einer Schwelle (CVSS ≥ x, KEV immer, EPSS ≥ y, Vertrauen ≥ z), nur
     neue Treffer.
   - Tagesbericht zu einer festen Uhrzeit.
   - „Jetzt senden“ und eine Testmail.
7. **Oberfläche:** neu entworfen, siehe den folgenden Abschnitt.

## UI/UX-Konzept (neu, nicht von opennetmon übernommen)

Entscheidungen des Nutzers (2026-11-04): Triage-Posteingang als Hauptansicht, ruhige Optik hell/dunkel,
Server-HTML mit htmx, klickbare HTML-Entwürfe vor dem „go“.

**Leitidee:** Die Anwendung ist ein Arbeitswerkzeug zum Abarbeiten, keine Seite mit Kennzahlen. Die Startseite
ist der **Eingang**. Er zeigt nur Treffer, die eigene Assets betreffen, und ist leer, wenn nichts zu tun ist
(„Alles erledigt, letzte Prüfung vor 12 min“).

**Navigation:** eine schmale Kopfleiste mit Eingang · Lage · Assets · Alle CVEs · Quellen, dazu die globale Suche
(CVE-ID, Advisory-ID, Produkt; Taste `/`). Die Einstellungen und das Protokoll liegen im Benutzermenü.

**Seiten:**
1. **Eingang (drei Spalten):**
   - **Links:** Filter mit Anzahl (Status neu/gesehen/später, Typ Software/Hardware, Hersteller, Host, Quelle,
     KEV, Schwere) und gespeicherte Ansichten (z. B. „★ Kritisch + KEV“).
   - **Mitte:** Trefferliste nach Priorität. Jede Zeile zeigt:
     - ein Prioritätssymbol mit Wert (Form + Farbe + Text, nie nur Farbe) und ein KEV-Abzeichen;
     - die Kennung und einen kurzen Titel;
     - das betroffene Asset mit Host.
     Mehrere Advisories zur selben CVE werden zu einer Zeile zusammengefasst.
   - **Rechts:** Details. Das sind:
     - Schwere, CVSS-Vektor lesbar aufgeschlüsselt, EPSS als Balken mit Perzentil, KEV-Datum und Frist;
     - „Betrifft“ (installierte Version, behobene Version, Host);
     - die Quellen mit Links;
     - die Aktionen.
   - **Aktionen:** Erledigt, Ignorieren (mit Grund, gilt optional für ein Asset), Später (1/7/30 Tage) und
     „Gesehen“, das automatisch gesetzt wird. Mehrfachauswahl für Sammelaktionen.
   - **Tastatur:** `j`/`k` wählen, `e` erledigt, `i` ignorieren, `s` später, `o` öffnet die Quelle, `?` zeigt die
     Hilfe.
   - Die URL enthält Filter und Auswahl, damit Links aus der Mail direkt auf den Treffer führen.
2. **Lage:** wenige Kacheln (offen kritisch, KEV, neu seit gestern, Quellen ok), dazu:
   - der Verlauf der offenen Treffer über 30 Tage;
   - die am stärksten betroffenen Hosts und Geräte;
   - die Liste „ältester offener Treffer“.
3. **Assets:**
   - Eine Liste nach Host bzw. Gerät gruppiert, je Gruppe mit der Zahl offener Treffer. Paketlisten aus SSH
     erscheinen zusammengefasst (z. B. „server01 · 1 243 Pakete · 5 offen“) und lassen sich aufklappen.
   - Assets von Hand anlegen mit Vorschlägen beim Tippen (Hersteller → Produkt → Version aus CPE- und
     CSAF-Daten) und einer Vorschau „würde aktuell N Meldungen treffen“.
   - Watchlist-Stichwörter.
   - Hosts (SSH), mit einem Assistenten:
     - Schlüssel anzeigen, die `authorized_keys`-Zeile zum Kopieren ausgeben;
     - den Host-Schlüssel bestätigen und testen.
   - Import aus opennetmon mit Zuordnung „Gerät → Produkt“ zum Bestätigen.
4. **Alle CVEs:** die Recherche-Ansicht über den ganzen Datenbestand, auch ohne eigene Treffer. Sie hat:
   - Filterchips (Zeitraum, Quelle, Schwere, KEV, EPSS ≥, Hersteller, Volltext);
   - die Spalten Prio/ID/Titel/CVSS/EPSS/KEV/Veröffentlicht;
   - Seiten und CSV-Export.
   - Die Detailansicht ist dieselbe Komponente wie im Eingang.
5. **Quellen:** je Quelle Zustand, letzter Lauf, Dauer, Anzahl neu/geändert, nächster Lauf, Fehler, „Jetzt
   abrufen“, Schalter ein/aus, Intervall und Quellenhinweis (Lizenz/Attribution).
6. **Einstellungen:** Mail und Schwellen für Sofort-Mails, Uhrzeit des Tagesberichts mit Vorschau, Formel der
   Priorität, Aufbewahrung, Konto.
   **Protokoll:** Änderungsprotokoll wie in opennetmon.

**Optik:**
- Ruhiges neutrales Grau mit einem Akzent (Petrol/Blau, endgültig im Entwurf).
- Farbe nur für die Schweregrade (kritisch/hoch/mittel/niedrig) und KEV, immer zusammen mit Symbol und Text.
- Hell und dunkel gleichwertig, nach Systemeinstellung, umschaltbar.
- Kontrast mindestens 4,5 : 1, sichtbarer Fokus, `prefers-reduced-motion`.
- Dichte Tabellenzeilen (32–36 px), Grundschrift 14–15 px.
- Schriften Fira Sans (Text) und Fira Code (Kennungen, Versionen, Vektoren): **lokal eingebettet, kein Google-Fonts-
  Import**; SIL OFL, kommt in die Lizenzliste.
- SVG-Symbole (Lucide, ISC-Lizenz), keine Emojis.
- Herkunft der Gestaltungsdaten: ui-ux-pro-max. Übernommen sind nur der Stil „Minimalism & Swiss“ mit hoher Dichte
  und das Schriftpaar. Das gleichzeitig getroffene Werbeseiten-Profil „Trust & Authority + Conversion“ passt
  nicht und wird verworfen.

**Breiten:**
- ab 1280 px drei Spalten;
- 900–1279 px zwei Spalten, die Details als Seitenblatt;
- unter 900 px eine Spalte (Liste → Detail), damit Links aus der Mail auch am Handy funktionieren.

**Technik:**
- askama-Vorlagen und htmx 2 (eingebettet, kein CDN, kein Build-Schritt). Liste und Details werden als Teilstücke
  nachgeladen; jede Seite funktioniert auch ohne JavaScript.
- CSP `default-src 'self'`: keine Inline-Skripte, kein `hx-on`.
- Eigene CSS-Datei mit Tokens (Farben, Abstände, Schriftgrößen) als CSS-Variablen.
- Die Diagramme der Seite Lage zeichnet der Server als SVG; uPlot nur bei Bedarf.

**Entwürfe vor dem „go“:**
- Statische, klickbare HTML-Mock-ups mit Beispieldaten in `docs/entwurf/`: Eingang, Detail, Lage, Assets mit
  Host-Assistent, Alle CVEs, Quellen, Einstellungen; je hell und dunkel; Breiten 1440, 1024 und 390 px.
- Sie dienen nur zur Abnahme der Gestaltung. Sie sind kein Anwendungscode und werden später nicht übernommen,
  höchstens die Tokens.
- Prüfung mit dem Pre-Delivery-Check von ui-ux-pro-max: Kontrast, Fokus, keine Information nur über Farbe.

## Vor Phase 0: Doku und Entwürfe

Anweisung des Nutzers (2026-11-04): **Es wird kein Anwendungscode erzeugt, bis der Nutzer „go“ gibt.** Den Plan
hat er am 2026-11-04 mit „go“ freigegeben. Die Reihenfolge davor bleibt:

1. `PLAN.md` (diese Datei) und `CLAUDE.md` angelegt (2026-11-04).
2. HTML-Entwürfe in `docs/entwurf/` (siehe UI/UX-Konzept), vom Nutzer im Browser abnehmen lassen und die
   Rückmeldungen hier einarbeiten.
3. Erst danach Phase 0 (`git init`, Repo) und die weiteren Phasen, jeweils nach Freigabe.

## Phasen (jede Phase nach „go“ des Nutzers, Doku nach jedem Schritt)

0. **Projekt anlegen:** ✓ erledigt 2026-11-04
   - `git init`, privates Repo `tomCSLK/<name>`, `CLAUDE.md`, `PLAN.md` (dieser Plan, ausführlich), README
     (Englisch), CHANGELOG.
   - Lizenz vorläufig AGPL-3.0 wie opennetmon (vor dem Öffentlich-Schalten bestätigen).
   - Den endgültigen Namen prüfen (GitHub, crates.io, Debian).
1. **Grundgerüst aus opennetmon:** ✓ erledigt 2026-11-05 (Abweichungen im Abschnitt unten)
   - Der Dienst startet und zeigt nach dem Login eine leere Übersicht.
   - Enthalten: Benutzer per `user add`, DE/EN, hell/dunkel, Mail-Einstellungen mit Testmail, Protokoll,
     `.deb`, CI grün.
2. **Quellen Stufe 1, CVE-Basis:** ✓ erledigt 2026-11-05 (Messung und Abweichungen in den Abschnitten unten)
   - cvelistV5 (Erstimport per Tages-Zip, danach Deltas), NVD-Feeds zur Anreicherung, CISA KEV, EPSS.
   - Dazu die CVE-Liste mit Filtern und Detailseite.
   - Erstimport messen (Laufzeit, DB-Größe; erwartet: einige hunderttausend CVEs).
3. **Quellen Stufe 2, CSAF:** ✓ erledigt 2026-11-06 (Messung und Abweichungen in den Abschnitten unten)
   - Ein gemeinsamer CSAF-2.0-Leser (Provider-Metadaten, eigener ROLIE-Leser, `changes.csv`, SHA-256;
     OpenPGP-Signatur als spätere Option).
   - BSI CERT-Bund (nur WHITE), danach die Hersteller-Feeds aus dem BSI-Lister und eigenen URLs.
   - Die Advisory-Liste.
4. **Quellen Stufe 3, Distributionen:** ✓ erledigt 2026-11-06 (Messung und Abweichungen in den Abschnitten unten)
   - OSV-Bulk für Debian und Ubuntu (inkrementell), Debian Security Tracker, Ubuntu-USN-Titel.
5. **Assets und Abgleich:** ✓ erledigt 2026-11-06 (Messung und Abweichungen in den Abschnitten unten) Assets von Hand, Vorschläge, Abgleich-Engine, Trefferstatus, Filter „nur meine
   Assets“, Priorität.
6. **Import:** ✓ erledigt 2026-11-06 (Messung und Abweichungen in den Abschnitten unten; die opennetmon-Seite fehlt noch)
   - 6a: SSH/dpkg mit Host-Schlüssel-Bestätigung.
   - 6b: CSV-Import.
   - 6c: opennetmon-Endpunkt (Arbeit im opennetmon-Projekt, mit dessen nächstem Release) und Import hier.
7. **Meldungen:** ✓ erledigt 2026-11-06 (Messung und Abweichungen in den Abschnitten unten) Sofort-Mail und Tagesbericht.
8. **Feinschliff:** ✓ erledigt 2026-11-06 (Messung und Abweichungen in den Abschnitten unten) Übersicht, CSV-Export,
   Aufbewahrung, Datenbankgröße, Handy-Ansicht.
9. **Betrieb:**
   - Sicherheitstest (Code-Review, Angriffe auf eine Testinstanz, Fuzztests für die Parser). ✓ erledigt 2026-11-07
     (Abschnitt „Sicherheitstest“ unten)
   - Betriebsanleitung `docs/operations.md` (Installation, Konfiguration, Benutzer, Sicherung, Update, Traefik).
     ✓ erledigt 2026-11-07
   - Eingebautes HTTPS (Nutzerwunsch 2026-11-07, Abschnitt „Abweichungen“). ✓ erledigt 2026-11-07
   - Test-Paket im eigenen Betrieb. ✓ erledigt 2026-11-07 (0.1.0-2, `https://<server>:8444`; Erstimport auf dem
     Server 25 min: cvelist 9,5 min, NVD 7 min, BSI 5 min, OSV Ubuntu 2,5 min, Rest < 1 min; DB 1,6 GB, danach ~25 MB RAM)
   - Reverse Proxy mit eigener Subdomain; seit dem eingebauten HTTPS optional. ✓ erledigt 2026-11-07
   - Erstes Release.

## Vorhaben: Desktop-Agent („go“ 2026-11-07, Schritt für Schritt)

Idee des Nutzers (2026-11-07): ein kleines Programm für Desktop-Rechner (Windows, Linux wie Zorin oder Mint), das
die installierte Software an opensecmon meldet und die Assets dort aktuell hält, nur im lokalen Netz. Dieses
Vorhaben bereitet **opensecmon** darauf vor; der Agent selbst ist ein späteres, eigenes Projekt. **„go“ am
2026-11-07** (Token je Rechner, mit Schritt 1 anfangen); die Schnittstelle ist in `docs/agent-api.md` festgelegt und
geht den Einzelheiten unten vor. Bis dahin für Windows: Windows und Programme von Hand oder per CSV (Version nach jedem Patchday nachziehen).

### Grundsatz: der Agent meldet sich, opensecmon fragt nicht ab

Anders als beim SSH-Import baut nur der Agent Verbindungen auf: Laptops sind oft aus oder in einem anderen Netz,
die Windows-Firewall sperrt eingehende Verbindungen, und auf dem Rechner muss kein Port offen sein. Der Agent
meldet beim Start, alle paar Stunden und nach Updates; erreicht er opensecmon nicht (Zertifikat passt nicht, keine
Verbindung), versucht er es später wieder. Mehr Erkennung des Netzes braucht er nicht.

### Kommunikation

- **HTTPS** über den vorhandenen Webserver (Port 8444 oder über Traefik), kein eigenes Protokoll, mit `curl` testbar.
  Bei direktem Zugang nimmt der Agent nur das Zertifikat mit dem eingetragenen Fingerabdruck an (wie der
  opennetmon-Import, `OwnVerifier`), über Traefik reicht die normale Prüfung. Keine Suche im Netz (mDNS): die
  Adresse kommt aus der Anmeldung, ein fremdes Gerät kann sich nicht als opensecmon ausgeben.
- **Anmeldung, einmal je Rechner:** In der Oberfläche „Rechner hinzufügen“ zeigt Adresse, Fingerabdruck und einen
  Einmalcode (15 min gültig). `POST /api/v1/agent/enroll` mit `{ code, hostname, os }` liefert
  `{ device_id, token }`; das Token gibt es nur dieses eine Mal. opensecmon speichert nur den Hash (SHA-256 eines
  zufälligen 256-Bit-Tokens reicht), der Agent das Token nur für root bzw. SYSTEM lesbar. Jeder Rechner einzeln
  sperrbar; Anmelden und Sperren im Protokoll, einzelne Meldungen nicht.
- **Meldung:** `POST /api/v1/agent/report` mit `Authorization: Bearer <token>`, JSON (gzip erlaubt) mit
  Schemaversion, Agent-Version, Betriebssystem (Familie, Name, Version, Build, Codename, `ID_LIKE`) und der
  vollständigen Liste der Einträge (Art `deb`/`snap`/`flatpak`/`win`/`appx` …, Name, Version, Quellpaket und
  -version, Hersteller, bei Windows wenn vorhanden die winget-ID). Immer vollständig statt Unterschieden (kann nicht
  auseinanderlaufen); unverändert nur der Hash, opensecmon vermerkt dann nur „zuletzt gemeldet“. Die Antwort nennt
  den Abstand bis zur nächsten Meldung (zentral einstellbar) und kann „bitte jetzt vollständig melden“ enthalten;
  eine Verbindung zum Rechner gibt es nie.
- **Antworten:** 200 `stored`/`unchanged`; 401 Token gesperrt oder Rechner gelöscht (Agent hört auf, verlangt neue
  Anmeldung); 403 Adresse nicht erlaubt; 413 zu groß; 429 zu oft (mit Wartezeit).
- **Nur lokales Netz:** neue Einstellung `agent_networks` (z. B. das eigene /24), Anfragen von anderen Adressen
  ergeben 403 (hinter dem Proxy über `client_ip_header`). Zusätzliche Sicherung, keine echte Grenze; die Grenze
  bleibt, dass opensecmon von außen nicht erreichbar ist.
- Die Schnittstelle nimmt nur das Token, nie die Sitzung der Oberfläche (kein Cookie, daher kein CSRF); ein Token
  öffnet keine Seite der Oberfläche. `allowed_hosts` gilt weiter.

### Grenzen und Sicherheit

- Höchstens 8 MB (auch entpackt, Schutz gegen gepackte Riesendateien), 50 000 Einträge wie beim SSH-Import, eine
  volle Meldung höchstens alle paar Minuten je Token.
- Gemeldete Daten sind nur Daten: escapen, Grenzen prüfen, nichts ausführen. Ein manipulierter Rechner kann nur
  seine eigenen Assets verfälschen. Fuzztest für das Einlesen in `src/fuzz.rs`.

### Datenmodell

- Hosts allgemeiner: „Geräte“ mit Herkunft SSH oder Agent (heute `ssh_hosts`), dazu Token-Hash, Agent-Version,
  zuletzt gemeldet, Betriebssystem.
- Assets mit Herkunft `agent` werden bei jeder Meldung überschrieben, nicht mehr gemeldete Einträge entfernt
  (wie beim SSH-Import). Ein Rechner, der sich nicht meldet, verliert nie automatisch seine Assets (Laptop im
  Urlaub); die Oberfläche zeigt „zuletzt gemeldet“ und warnt nach X Tagen.

### Erkennen der Software (der eigentliche Aufwand)

- **Debian/Ubuntu und Abkömmlinge (Zorin, Mint):** `listing.rs` erkennt sie schon über `ID_LIKE` und
  `UBUNTU_CODENAME`. Für `.deb`-Pakete kann der Agent die Ausgabe des SSH-Skripts schicken: gleiches Einlesen,
  gleicher Abgleich, Endpunkt ohne Agent testbar.
- **Snap und Flatpak:** keine Daten von Debian/Ubuntu (Firefox unter Ubuntu ist ein Snap, unter Zorin oft ein
  Flatpak); brauchen eine Zuordnung auf Produkte (z. B. Mozilla/Firefox).
- **Windows selbst:** aus Build und `DisplayVersion` direkt „Windows 11 Version 24H2“ mit Version
  `10.0.<Build>.<UBR>` (so führt die CNA von Microsoft die Produkte; Abgleich mit Version, Vertrauen hoch).
  Aktualisiert sich damit nach jedem Patchday von selbst.
- **Windows-Programme:** Anzeigenamen wie „Mozilla Firefox (x64 de)“ passen nicht zu den Produktnamen der Quellen.
  Zuordnung in opensecmon, nicht im Agent (wird besser ohne neue Agents): eingebaute Regeln für häufige
  Programme, winget-IDs als stabiler Schlüssel, Seite „Nicht zugeordnet“, auf der der Nutzer jedes unbekannte
  Programm einmal zuordnet oder ignoriert; die Regel gilt dann für alle Rechner. Nicht zugeordnete Programme
  dürfen nicht wie „ohne Treffer“ aussehen.

### Schritte in opensecmon

1. Beschreibung der Schnittstelle `docs/agent-api.md` (Englisch, Entwurf Version 1). ✓ erledigt 2026-11-07:
   Anmeldung (`/enroll`, Code 8 Zeichen Crockford-Base32, 15 min, einmal; Token `osm1_` + 32 Zufallsbytes, nur der
   Hash gespeichert), Meldung (`/report` als `text/plain` = Ausgabe des SSH-Skripts oder JSON mit `os`, `dpkg`,
   `items`; Kurzform `unchanged` mit Hash), `/status`, Fehlercodes, Grenzen, `agent_networks` (Standard: private
   und lokale Adressen, `[]` schaltet ab), Versionierung, Beispiele. Geprüft: `curl --cacert` mit dem
   selbstsignierten Zertifikat aus `tls generate` klappt (ohne `--cacert` Fehler 60).
2. Rechner anlegen, Anmeldung mit Einmalcode und Token, Sperren, `agent_networks`. ✓ erledigt 2026-11-07:
   Migration `0016_agent_devices`, `src/agent.rs` (Netze, Code, Token), `storage/agents.rs`, Endpunkte
   `POST /api/v1/agent/enroll` und `GET /api/v1/agent/status` (`web/agent_api.rs`, nur JSON, auch die Fehler),
   Reiter „Rechner (Agent)“ unter „Assets“ (`web/computers.rs`: Liste, Hinzufügen, Seite mit Code, Adresse,
   Fingerabdruck, Download `opensecmon.pem` (nur der Zertifikatsteil) und `curl`-Befehlen; Umbenennen, neuer Code,
   Sperren, Entfernen mit den Assets), Konfiguration `agent_networks`, Protokoll-Art „Rechner“. Abweichungen:
   - Eigene Tabelle `agent_devices` statt die SSH-Hosts zu verallgemeinern (die Spalten haben kaum etwas gemeinsam);
     Namen sind über beide Tabellen eindeutig (`agents::name_taken`), die Assets hängen wie bei SSH am Namen
     (`assets.host`) und an der Herkunft `agent:<id>`.
   - Der Code wird außer als Hash auch verschlüsselt gespeichert (Kontext `agent.code`), damit die Seite ihn zeigen
     kann, solange er gilt; nach der Anmeldung oder beim Sperren wird er gelöscht.
   - Ein neuer Code für einen angemeldeten Rechner lässt das alte Token gelten, bis die neue Anmeldung es ersetzt.
   - Im Protokoll steht die Anmeldung unter dem Benutzer `agent:<Name>`, Token und Code nur als „gesetzt“.
   - Falsche Codes zählen in der Anmelde-Drossel unter dem Namen `#agent-enroll` (je Adresse und insgesamt).
   - Ist die Datenbank belegt, antwortet die API mit `503 busy` und `Retry-After: 60`.
   Geprüft: 383 Tests (18 neu, u. a. Ablauf Ende zu Ende, Netze inkl. `::ffff:`-Adressen, Drossel, kaputte Anfragen,
   CSRF), Wegwerf-Instanz mit eingebautem HTTPS und `curl --cacert` (Anmelden, Status, Code nur einmal, falsches
   Token 401), Seiten hell/dunkel bei 1440 und 390 px ohne Überlauf.
3. Endpunkt für Debian/Ubuntu-Rechner mit dem vorhandenen Einlesen, Grenzen, Tests mit `curl`; danach den Laptop
   (Zorin) per systemd-Timer und `curl` anbinden und eine Weile beobachten. ✓ Endpunkt erledigt 2026-11-07:
   `POST /api/v1/agent/report` (Text = Ausgabe des Inventar-Skripts oder JSON mit `os_release`/`dpkg`, beides
   optional gzip, höchstens 8 MB nach dem Entpacken), Pakete als Assets mit Herkunft `agent` über dasselbe
   `sync_packages` wie SSH, Abgleich im Hintergrund nach der Antwort; gleicher Inhalt oder Kurzform mit Hash nur
   vermerkt (`unchanged`), unbekannter Hash 409; Takt höchstens eine volle Meldung je 5 min und eine Kurzform je
   Minute (429 mit `Retry-After`, nur im Speicher); abgelehnte Meldungen auf der Seite des Rechners („Meldung
   abgelehnt“). Skript `contrib/opensecmon-agent.sh` (auch auf der Seite des Rechners zum Herunterladen, mit fertigem
   Befehl): `enroll` mit Code und Zertifikat, legt Token und Einstellungen in `/etc/opensecmon-agent` (nur root),
   installiert sich als `/usr/local/sbin/opensecmon-agent` mit Timer alle 6 h (zufällig bis 30 min später); der
   Dienst läuft mit `DynamicUser` ohne root und bekommt Token, Adresse und Zertifikat als Credentials
   (`systemd-analyze security`: 3.0 OK); dazu `report`, `status`, `uninstall`. Abweichungen und Grenzen:
   - Windows-Meldungen bekommen bis Schritt 4 `422 unsupported_system`, `items` (Snap, Flatpak) werden bis Schritt
     5 übersprungen und als `items_skipped` gezählt.
   - Die Asset-Liste fasst die Pakete eines Rechners wie die eines SSH-Hosts zusammen (Zeile „System · Agent“).
   - Version 0.3.0 (neue Schnittstelle und Migration `0016`).
   Geprüft: 390 Tests (u. a. Ablauf Text → JSON mit gzip → Kurzform → Sperren, Abgleich im Hintergrund, alle
   Fehlerfälle, Taktgrenze), Fuzztest der Meldungen (Text, JSON, gzip; 20 000 Runden ohne Befund); Wegwerf-Instanz
   mit eingebautem HTTPS: dieser Laptop (Zorin OS 18.1) mit dem Skript ohne root angemeldet, 1208 Quellpakete in
   149 ms gespeichert, Status, Taktgrenze und Dienst-Weg über `CREDENTIALS_DIRECTORY` geprüft; gegen die Test-DB
   dieselbe Liste: 126 ms, Abgleich 3,1 s mit 4739 Treffern bei 191 Paketen (wie beim SSH-Weg), Testrechner danach
   entfernt; Paket im Debian-13-Container installiert und entfernt; Seiten hell/dunkel bei 1440 und 390 px.
   Im eigenen Betrieb mit einem Laptop angemeldet, die erste Meldung kam an (2026-11-07).
4. ✓ Regel für die Windows-Version (erst nach dem Vorhaben „Rauschen im Betrieb“). Erledigt 2026-11-07:
   Vorab an der Test-DB geprüft: Microsoft führt als CNA Produkte wie „Windows 11 Version 24H2“ mit Bereichen
   `10.0.26100.0` bis unter `10.0.26100.9711`; ein Software-Asset Microsoft/„Windows 11 Version 24H2“ mit Version
   `10.0.26100.<UBR>` trifft damit schon über den vorhandenen CNA-Abgleich (hohes Vertrauen): UBR 4652 bis zur
   Grenze 2000 Treffer in 0,6 s, UBR 9999 keiner; Windows Server 2025 dazu über NVD und CSAF. Umgesetzt:
   `src/inventory/windows.rs` (Release aus dem Build per Tabelle 1507 bis 25H2, sonst `DisplayVersion`; Windows 11
   ab Build 22000, „Windows 10“ in `ProductName` wird ersetzt; Server nach Build 2016/2019/2022/2022 23H2/2025, mit
   `installation_type` „Server Core“ als „… (Server Core installation)“; vor Windows 10 und unbekannte Server-Builds
   `None`), JSON-Meldung mit `family = windows` (`product_name`, `display_version`, `build`, `ubr` Pflicht bzw.
   optional, neu optional `installation_type`), `agents::store_windows` und `inventory::sync_one` (genau ein Asset
   je Windows-Rechner, Art Software, Herkunft `agent`; dasselbe Produkt behält Asset und Treffer und bekommt die neue
   Version, alles andere des Rechners wird entfernt), Rechner zeigt „Windows 11 Pro 24H2“, Release „24H2“, Pakete 1.
   Nicht unterstützte Versionen: `422 unsupported_system` mit Hinweis auf der Seite des Rechners. `items` (Programme,
   Store-Apps) weiter übersprungen (`items_skipped`) bis Schritt 5. Keine Migration. Test Ende zu Ende (Meldung →
   Asset → Treffer → Patchday mit neuem UBR → Treffer erledigt sich), Fuzztest mit Windows-Beispiel; 409 Tests.
   Einen Windows-Agenten oder ein Skript gibt es noch nicht (Schritt 6 bzw. Zwischenschritt PowerShell, offen).
5. Zuordnung der Programmnamen mit der Seite „Nicht zugeordnet“, auch für Snap und Flatpak (größter Teil).
   Entschieden (Nutzer, 2026-11-07): Snap und Flatpak gleich mit; zuerst mit Skripten arbeiten (kein eigenes
   Agent-Programm); Lizenz und Repo des Agents später. Plan (nur Plan, Umsetzung je Teil nach „go“):
   - **5a PowerShell-Skript für Windows** (`contrib/opensecmon-agent.ps1`, wie `opensecmon-agent.sh`): `enroll`
     mit Einmalcode und Zertifikat, Token unter `C:\ProgramData\opensecmon-agent` nur für SYSTEM und
     Administratoren, geplante Aufgabe als SYSTEM beim Start und alle 6 h, `report`, `status`, `uninstall`. Meldet
     `os` (Registry `CurrentVersion`) und schon die `items`: Uninstall-Einträge aus HKLM (64 und 32 Bit; Programme
     nur eines Benutzers sieht SYSTEM nicht, `scope = user` später) und Store-Apps (`Get-AppxPackage -AllUsers`).
     Versand mit `curl.exe` (in Windows 10/11 enthalten); vorher prüfen: `--cacert` mit Schannel und ob Smart App
     Control ein unsigniertes Skript zulässt (sonst Aufruf per `powershell -ExecutionPolicy Bypass -File`, oder
     Signatur). Sofort nützlich: Windows selbst als Asset (Schritt 4), die Programme liegen schon bereit für 5b.
   - **5b Programme speichern und zuordnen** in opensecmon: Tabelle der gemeldeten Einträge je Rechner (Art, Kennung,
     Name, Version, Hersteller, winget-ID), Regeln (Art + Kennung, winget-ID oder Name → Hersteller/Produkt oder
     „ignorieren“), eingebaute Regeln für häufige Programme (Browser, Office, PDF, Packer, Laufzeitumgebungen,
     Fernwartung, Editoren), Seite „Nicht zugeordnet“ unter „Assets“ (jeder unbekannte Eintrag einmal, mit Zahl der
     Rechner; Zuordnen mit den Vorschlägen und der Vorschau des Asset-Formulars, oder Ignorieren; gilt für alle
     Rechner). Zugeordnete Einträge werden Software-Assets mit Herkunft `agent` (gleiches Produkt nur einmal je
     Rechner), Abgleich wie bei Software von Hand (CNA/NVD mit Version: hoch). Auf der Seite des Rechners und in
     der Asset-Liste „N nicht zugeordnet“, damit nichts wie „ohne Treffer“ aussieht. Versionen: erstes
     versionsartiges Stück, Regeln dürfen es anpassen (z. B. Snap `144.0.2-1` → `144.0.2`). Migration, Fuzztest.
   - **5c Snap und Flatpak im Linux-Skript:** `snap list` und `flatpak list --app` (systemweit; Flatpaks im
     Benutzerordner sieht der Dienst wegen `ProtectHome` nicht) als zusätzlicher Abschnitt nach den dpkg-Zeilen
     (eigene Trennzeile, ältere opensecmon zählen ihn nur als übersprungene Zeilen) bzw. als `items` im JSON;
     dieselbe Zuordnung wie 5b. Für das SSH-Skript genauso (Snaps wie `lxd` auf Ubuntu-Servern).
   Reihenfolge-Vorschlag: 5a → 5b → 5c (alle drei erledigt). Keine Mail, wenn sich ein Rechner länger nicht meldet (Nutzer, 2026-11-07).
   **Stand 5a (2026-11-07): umgesetzt, unter Windows noch nicht ausprobiert.** `contrib/opensecmon-agent.ps1`
   (Windows PowerShell 5.1, nur ASCII, per Test geprüft) mit `enroll`, `report`, `status`, `update` (neue Fassung
   an die Stelle der alten), `uninstall`, `version`. Ordner `C:\ProgramData\opensecmon-agent` wird mit seinen
   Rechten angelegt (nur SYSTEM und Administratoren, Besitzer Administratoren); ein schon vorhandener Ordner muss
   SYSTEM oder den Administratoren gehören, sonst Abbruch (Benutzer dürfen in ProgramData Ordner anlegen, die
   Aufgabe läuft als SYSTEM). Die Aufgabe startet die Kopie im geschützten Ordner, nie die heruntergeladene Datei.
   Versand mit `curl.exe` (Token nur in einer Kopfzeilen-Datei), bei eigenem Zertifikat `--cacert` und
   `--ssl-no-revoke`. `items`: Uninstall-Einträge aus HKLM (64/32 Bit) und aus den geladenen Hives angemeldeter
   Benutzer (`scope = user`, ohne Namen), Store-Apps aller Benutzer ohne Frameworks; winget-ID fehlt (winget läuft
   nicht als SYSTEM). Seite des Rechners: Abschnitt Windows mit Download und Befehl, nach einer Windows-Meldung
   der Befehl `update` statt `sudo install`. Abweichung: Windows Server 2016 hat kein `curl.exe`, das Skript
   verlangt Windows 10 ab 1803 bzw. Server ab 2019 (die API nimmt 2016 weiter an). Abhängigkeit: `pwsh` fehlt hier,
   das Skript ist nicht maschinell auf Syntax geprüft. Offen, vom Nutzer unter Windows zu prüfen: Anmeldung mit
   `--cacert` (Schannel), Smart App Control (setzt nicht signierte Skripte womöglich in den Constrained Language
   Mode, dann scheitern die .NET-Aufrufe), geplante Aufgabe läuft, Meldung kommt an. 411 Tests.
   **Stand 5b (2026-11-07): umgesetzt.** Migration `0020` (Tabellen `agent_items` je Rechner, bei jeder vollen
   Meldung ersetzt, und `item_rules`; `report_hash` aller Rechner geleert, damit die nächste Meldung voll gespeichert
   wird). `src/inventory/items.rs`: Schlüssel je Eintrag (Windows-Programm: Anzeigename klein, ohne Klammern,
   Versionen, Architektur und Sprache, „7-Zip 24.08 (x64)“ → `7-zip`, weil die Registry-Kennung bei MSI je Version
   wechselt; Store-App: Name; Snap/Flatpak: Kennung), Version = erstes versionsartiges Stück, eingebaute Regeln für
   rund 30 Windows-Programme und je 8–9 Snaps/Flatpaks (gegen die Test-DB geprüft: alle Hersteller/Produkt-Schlüssel
   kommen in NVD oder CNA vor), Store-Apps von Microsoft eingebaut ignoriert. Windows selbst ist ein Eintrag der Art
   `os` und immer zugeordnet. `src/storage/items.rs`: Abgleich der Software-Assets je Rechner (gleiches Produkt behält
   sein Asset und seine Treffer, neue Version wird übernommen). Seite „Nicht zugeordnet“ (`src/web/unassigned.rs`,
   Reiter mit Zahl): je Eintrag einmal mit Versionen und Rechnern, „Zuordnen“ mit Vorschlägen und Vorschau wie im
   Asset-Formular (Vorschlag: Herausgeber und Name ohne Version), „Ignorieren“, Liste „Eigene Regeln“ mit Entfernen;
   Regeln wirken sofort auf alle Rechner (Abgleich im Hintergrund), im Protokoll als „Regel für gemeldete
   Programme“. Rechnerliste, Rechnerseite und Kopf in der Asset-Liste zeigen „N nicht zugeordnet“. Abweichungen vom
   Plan: ein Asset je Produkt **und Version** statt je Produkt (zwei Java-Versionen bleiben zwei Assets, sonst würde
   die ältere übersehen); keine Regeln nach winget-ID (das Skript schickt keine, winget läuft nicht als SYSTEM);
   Regeln passen die Version nicht an (das erste versionsartige Stück reicht für Snap `144.0.2-1`). Fuzztest mit
   Programmen in der Windows-Meldung. 418 Tests. Im Browser noch nicht angesehen.
   **Stand 5c (2026-11-07): umgesetzt.** Beide Linux-Skripte (Inventar-Skript des SSH-Imports, Agent-Skript
   `VERSION=3`, nach 0.3.2 `VERSION=4` mit temporärem Cache für `flatpak`) geben nach den dpkg-Zeilen die Abschnitte `--- snap` (`LC_ALL=C snap list --unicode=never
   --color=never`) und `--- flatpak` (`flatpak list --app --columns=application,name,version,installation`) aus, je
   nur wenn das Programm da ist; `dpkg-query` nicht mehr per `exec`, sein Fehler beendet das Skript weiter mit seinem
   Status, Fehler von `snap`/`flatpak` nicht. `listing::parse` liest die Abschnitte (Kopfzeile von `snap list`
   übersprungen, Herausgeber ohne `*`/`**`, Flatpak `user` = nur für einen Benutzer, ungültige Namen/IDs zählen als
   übersprungene Zeilen, unbekannte Abschnitte werden still übergangen); ältere opensecmon zählen die Zeilen nur als
   übersprungen. Migration `0020` geändert (damals noch nirgends eingespielt; seit 0.3.2 im Betrieb, nicht mehr ändern): `agent_items` hängt jetzt an `origin_ref`
   (`agent:<id>` oder `ssh:<id>`) statt an `device_id`, damit auch SSH-Hosts Einträge haben; beim Löschen von
   Rechner oder Host werden sie mit entfernt. Bei Rechnern zählen die Abschnitte und die JSON-`items` zusammen.
   Eingebaut: Basis-, Laufzeit- und Themen-Snaps (`core`, `core16`–`core26`, `bare`, `gnome-*`, `kf5-*`, `kf6-*`,
   `mesa-*`, `gtk-common-themes`, `snapd-desktop-integration`, `snap-store`, `firmware-updater` …) ignoriert; Snaps
   `snapd`, `lxd`, `microk8s`, `multipass`, `juju` → Canonical (Schlüssel in der Test-DB geprüft). Hostliste und Kopf
   in der Asset-Liste zeigen „N nicht zugeordnet“ auch für Hosts; Seite „Nicht zugeordnet“ nennt Rechner und Hosts.
   Nebenbei: `apply_listing` schreibt in einer `BEGIN IMMEDIATE`-Transaktion (las vorher erst, ein Abgleich
   dazwischen hätte sonst zu SQLITE_BUSY führen können). Nach dem Update: das Inventar-Skript auf den SSH-Hosts neu
   nach `/usr/local/bin/opensecmon-inventory` kopieren, auf den Rechnern das Agent-Skript neu installieren. 421 Tests.
6. Danach der Agent als eigenes Projekt (`opensecagent`, eigenes Repo, AGPL-3.0-or-later; angelegt 2026-11-07 in
   `../opensecagent/`, Plan dort; Umsetzung nur nach „go“). Entschieden (Nutzer, 2026-11-07): Dienst auf beiden
   Systemen, Programme aller Benutzer, `.deb` und Inno Setup, Neuanmeldung mit „Neuer Code“ (Eintrag bleibt),
   Updates nur auf Knopfdruck, Agent-Pakete im opensecmon-Paket, eigene Signatur des Herausgebers; Grundregel:
   Anwender brauchen weder Kommandozeile noch Schlüssel.
7. **Vorbereitung für opensecagent** (geplant 2026-11-07, nur nach „go“; Einzelheiten in
   `../opensecagent/PLAN.md`, Abschnitt „Nötige Änderungen in opensecmon“): zuerst in `docs/agent-api.md`
   festlegen, dann umsetzen:
   - Anmeldecode als eine Zeichenkette nur zum Kopieren (Form A, Nutzer 2026-11-07: `osa1-…` mit Adresse,
     Fingerabdruck, Einmalcode und Prüfsumme), Knopf „Code kopieren“; Seite „Rechner hinzufügen“ mit
     Installer-Download und Code.
   - `next_report_s` für den Agenten 15 min (Skripte bleiben bei 6 h; die Taktgrenze in `src/agent.rs` erlaubt
     das schon).
   - Agent-Version je Rechner, „Update verfügbar“, Knopf „Aktualisieren“, Auftrag in der Antwort auf die Meldung,
     Download der Pakete mit Signatur, Rückmeldung von Erfolg oder Fehler.
   - Agent-Pakete und Signaturen im opensecmon-Paket (`dev/deb.sh`).

   **Erledigt (2026-11-07, 439 Tests):**
   - Format in `docs/agent-api.md` (Abschnitte „Enrollment code (for opensecagent)“ und „Updates of
     opensecagent“, neue optionale Felder `agent.updates`, `agent.update_error`, `os.arch` gespeichert, Antwortfeld
     `update`, `GET /api/v1/agent/packages/{file}`).
   - Anmeldecode `src/agent_code.rs` (Schreiben und als Vorlage für den Agenten auch Lesen; Crockford-Base32,
     Prüfsumme aus SHA-256, Beispielwert im Dokument per Test geprüft). Abweichung vom Plan: Präfix `osa1_` statt
     `osa1-`, damit ein Doppelklick den ganzen Code markiert (wie das Token `osm1_`). Zertifikat: der Agent nimmt
     es, wenn der Fingerabdruck passt **oder** die normale Prüfung für die Adresse gelingt (Proxy mit öffentlichem
     Zertifikat).
   - Paketkatalog `src/agent_packages.rs` (Ordner `agent_packages_dir`, Standard `/usr/share/opensecmon/agent`,
     beim Start gelesen; nur erwartete Namen mit `.sig` daneben, je System und Architektur die höchste Version).
   - Seite des Rechners: „Mit opensecagent (empfohlen)“ mit Downloads und Anmeldecode zum Kopieren, die Skripte
     eingeklappt darunter; erscheint nur, wenn Pakete mitgekommen sind. Abschnitt „opensecagent aktualisieren“
     (angefordert/übergeben/fehlgeschlagen/aktuell, Zurücknehmen); Liste mit „Update verfügbar“ und „Alle
     aktualisieren“. Im Browser an einer Wegwerf-Instanz geprüft.
   - Takt: `agent::report_interval_secs` (opensecagent 15 min, Skripte 6 h) in Anmeldung, Meldung und Status.
   - Migration `0021_agent_updates` (Architektur, `can_update`, angeforderte Version, Zeiten, Fehler).
   - Paketbau: `dev/agent-packages.sh <Ordner> [allowed_signers]` prüft Namen und Signaturen (Standard
     `../opensecagent/keys/allowed_signers`, Identität und Namensraum `opensecagent`) und legt die Pakete nach
     `dist/agent/`; `dev/deb.sh` nimmt sie mit und nennt sie (mit Wegwerf-Schlüssel ausprobiert, auch eine
     veränderte Datei wird abgelehnt). Ohne Pakete bleibt nur `dist/agent/README.md` im Paket, die Seiten zeigen
     dann nur die Skripte.
   - Noch kein neues Test-Paket (nur auf Auftrag).

### Der Agent (später, nur Vorbedingungen)

- Rust, klein, ein Programm für Linux und Windows; auf beiden als Dienst (entschieden 2026-11-07, statt Timer).
- Läuft er als SYSTEM, sieht er Programme nur eines Benutzers nicht (`HKCU`, Store-Apps): Benutzerprofile
  mitlesen oder zusätzlich im Benutzerkontext laufen.
- Windows-Signatur: gleiches Problem wie bei openpacketmon (Smart App Control); das für NetzCampus geplante
  Certum-Open-Source-Zertifikat könnte es lösen.

### Offen (Entscheidungen des Nutzers)

- ~~Ein Token je Rechner oder ein gemeinsames.~~ Entschieden: ein Token je Rechner (Nutzer, 2026-11-07).
- ~~Snap und Flatpak gleich mit?~~ Entschieden: ja, in Schritt 5 (Nutzer, 2026-11-07); zuerst mit Skripten.
- ~~Mail, wenn sich ein Rechner länger nicht meldet, und nach wie vielen Tagen.~~ Entschieden: keine Mail (Nutzer,
  2026-11-07); die Seite zeigt die letzte Meldung.
- ~~Lizenz des Agents.~~ Entschieden: dieselbe wie opensecmon, **AGPL-3.0-or-later** (Nutzer, 2026-11-07). Die
  Skripte unter `contrib/` bleiben bei opensecmon.
- ~~Eigenes Repo oder Workspace mit opensecmon.~~ Entschieden: **eigenes Repo `opensecagent`** (Nutzer,
  2026-11-07). Name geprüft (2026-11-07): frei unter `tomCSLK` auf GitHub, auf crates.io und in Debian; auf GitHub
  gibt es zwei kleine fremde Repos gleichen Namens ohne Beschreibung (`DulanDias/`, `lemontreeran/`, zuletzt
  2026-03 bzw. 2025-06). DPMA nicht geprüft. Repo privat angelegt (2026-11-07, Ordner `../opensecagent/`, Commit `0664bc2`, CI grün);
  Plan und offene Fragen dort in `PLAN.md`. Das Format bleibt in
  `docs/agent-api.md` von opensecmon festgelegt; der Agent hält sich daran.

### Ideen (noch nicht beschlossen, Umsetzung nur nach „go“)

- **Python aus dem „Python install manager“** (Befund 2026-11-07, Windows-Testrechner): Laufzeiten, die `py install` anlegt,
  haben keinen Uninstall-Eintrag und fehlen deshalb in der Windows-Meldung. Möglich wäre, die PEP-514-Einträge
  (`Software\Python\<Firma>\<Tag>`, Maschine und angemeldete Benutzer) mitzulesen; im Skript oder erst im Agent.
- **CSAF hinter genaueren Daten** (Befund 2026-11-07, Windows-Testrechner, Python 3.14.10): Das BSI nennt oft nur einen groben
  Bereich („Python < 3.15.0“), NVD kennt die Grenze je Zweig und schließt die Version aus; der CSAF-Treffer (mittel)
  bleibt trotzdem offen (5 von 8 Python-Treffern). Vorschlag: den CSAF-Treffer übergehen, wenn NVD- oder
  Herstellerdaten für dasselbe Produkt und dieselbe CVE einen prüfbaren Bereich haben und die Version ausschließen.

- **Herstellervorschlag für Flatpaks** (Nutzer, 2026-11-07): `flatpak list` nennt keinen Herausgeber, deshalb schlägt
  „Zuordnen“ auf der Seite „Nicht zugeordnet“ bei Flatpaks keinen Hersteller vor, und ein Klick auf „Zuordnen“ legt
  eine Regel ohne Hersteller an (so geschehen mit zwei Flatpaks im Test; beide
  ohne Einträge in der CVE-Liste). Vorschlag: den Hersteller aus der Anwendungs-ID (umgekehrter DNS-Name) ableiten.
  Bei Hosting-Namensräumen der Teil nach dem Hoster (`com.github.<x>`, `io.github.<x>`, `io.gitlab.<x>`,
  `page.codeberg.<x>`, `net.sourceforge.<x>` → `<x>`, also `com.github.maoschanz.drawing` → `maoschanz`), sonst der
  Teil nach der Top-Level-Domain (`io.missioncenter.MissionCenter` → `missioncenter`, `org.mozilla.firefox` →
  `mozilla`, `org.gnome.*` → `gnome`, `org.kde.*` → `kde`). Nur als Vorschlag im Formular (der Nutzer kann ihn
  ändern, die Vorschläge aus der CVE-Liste bleiben), nicht für die eingebauten Regeln. Offen: ob der Vorschlag nur
  kommen soll, wenn der Hersteller in der CVE-Liste vorkommt, und ob Snaps mit `-` als Herausgeber genauso behandelt
  werden (dort gibt es keine Kennung mit Domain, also nur der Snap-Name).

## Vorhaben: Rauschen im Betrieb (geplant 2026-11-07, vor Schritt 4 des Desktop-Agents)

Anlass sind die „Befunde aus dem Betrieb“ (Abschnitt unter „Offene Punkte“): Der Eingang eines Ubuntu-Servers und eines Raspberry Pi war
mit Treffern ohne Handlungsbedarf voll. Ein Windows-Agent brächte noch mehr Treffer dazu, deshalb kommt dieses
Vorhaben vorher. Reihenfolge vom Nutzer bestätigt (2026-11-07), Umsetzung Schritt für Schritt nach „go“.

### Bewertung der Befunde (mit dem Code abgeglichen)

- **Befund 1 (Pi-Kernel):** Der Befund stimmt. Der Abgleich sucht nur nach Quellpaket und Release (`linux`,
  Debian 13), die Herkunft kennt er nicht. `+rpt` allein ist als Merkmal zu breit (nachgebaute Pakete wie glibc
  fielen mit heraus). Deshalb nur zusammen mit einer festen Liste von Kernel-Quellpaketen.
- **Befund 2 (Einstufung):** Im Kern richtig, aber `base_prio` ist nur die Notlösung, falls die CVE unbekannt ist.
  Wirksam ist die Priorität der CVE (CVSS × 7 + EPSS × 20, `MATCH_PRIO_SQL`). „Alle 904 mit `base_prio` 40“
  heißt also nicht, dass alle Priorität 40 haben. Richtig bleibt: Eine CVE mit CVSS 7,5, die Debian als
  „unimportant“ führt, landet über 50. Der Tracker wird nur im CVE-Detail angezeigt, im Abgleich gar nicht genutzt.
  Debians OSV-Datensätze haben keine Einstufung. Dass beim Ubuntu-Server kein Treffer eine Korrektur hat, ist bei
  Ubuntu normal (viele „needed“/„deferred“, 26.04 ist neu). Deshalb ist der Filter wichtiger als jede Gewichtung.
- **Befund 3 (Kernel):** Die Folgerung im Befund ist umgekehrt. Sind mehrere Kernel installiert, nimmt
  `listing.rs` je Quellpaket die *höchste* Version (7.0.0-42), laufend ist die *ältere* (7.0.0-38). Die Treffer
  unterschätzen die Lage also eher, Livepatch fängt nur einen Teil ab. Sinnvoll ist der Hinweis „Neustart nötig,
  läuft Kernel X“. Einen Abgleich gegen den laufenden Kernel braucht es vorerst nicht.
- **Befund 4 (mehrfach je Host):** Der Befund stimmt. Assets zusammenlegen wäre falsch (`qemu` und `qemu-hwe` sind
  getrennte Pakete, beide brauchen das Update). Stattdessen in den Zahlen verschiedene Schwachstellen zählen.
- **Befund 5 (Ubuntu Pro):** Der Befund stimmt, siehe dort. Pro wirkt nur, wo OSV eigene Pro-Einträge hat
  (Korrekturen über esm-infra/esm-apps, bei 26.04 bisher wenige, vor allem `universe`). Ohne Pro fehlen aber
  Korrekturen: Der Eingang sagt „keine Korrektur“, wo es eine gibt.
- **Auch beim Agenten:** Der Laptop zeigt dieselben Muster. Dazu tragen dort 73 Pakete „zorin“ in der Version, ein
  ähnliches Herkunftsproblem wie `+rpt` (ungeprüft, ob Eigenbauten oder nachgebaute Ubuntu-Pakete). Das gehört zu
  Schritt 5 des Agents (Namenszuordnung).

### Schritte

1. **Filter „Korrektur angekündigt“ im Eingang** (Spalte `fixed` gibt es schon). „Behoben in X“ heißt nicht, dass
   apt die Korrektur schon anbietet (zlib `+deb13u1`). Daher nicht „verfügbar“ nennen. Dazu den Hinweis „Kernel und
   Firmware des Pi bleiben ohne Treffer“ im Assistenten korrigieren. ✓ erledigt 2026-11-07 (mit 1b): Gruppe
   „Korrektur“ in der Filterspalte (`fix=1`), wirkt je Treffer wie das Vertrauen (eine Schwachstelle bleibt, wenn
   einer ihrer Treffer eine Korrektur hat; der Host-Filter zählt nur dessen Treffer), auch im CSV-Export. Abweichung:
   Der Hinweis zum Pi-Kernel steht nirgends im Code oder in den Dokus von opensecmon (er stammte aus einer Anleitung
   außerhalb des Projekts), also nichts zu korrigieren; richtig wird er erst mit Schritt 3. Test-DB: 167 von 2174 offenen
   Treffern haben eine angekündigte Korrektur.
   - **1b. Ubuntu Pro als Einstellung am Host bzw. Rechner:** Auf der Seite des SSH-Hosts und des Agent-Rechners
     gibt es „Ubuntu Pro“ mit den Werten *automatisch* (Standard), *ja* und *nein*. Die Paket-Assets erben den
     Wert, das Lesen überschreibt ihn nicht mehr. Bei importierten Assets entfällt das Pro-Häkchen im Formular, bei
     Assets von Hand bleibt es. Braucht eine Migration, keine Skriptänderung. ✓ erledigt 2026-11-07: Migration
     `0017_pro_mode` (`pro_mode` und `pro_detected` an `ssh_hosts` und `agent_devices`, `pro_detected` aus den
     bisherigen Versionen mit „esm“ vorbelegt), `inventory::ProMode`/`set_pro_mode`, `sync_packages` bekommt das
     wirksame Pro statt des erkannten; Formular „Ubuntu Pro“ (`templates/pro_setting.html`) in der Karte „Verwalten“
     von Host und Rechner, nur bei Ubuntu; geänderte Pakete werden sofort neu abgeglichen, die Änderung steht im
     Protokoll. Im Formular eines importierten Pakets statt des Häkchens der Hinweis mit Link zur Einstellung (der
     Wert bleibt beim Speichern erhalten). Für Debian gilt Pro nie, auch nicht mit „ja“.
2. **Einstufung der Distribution als eigener Abzug** neben dem Abzug für das Vertrauen, einstellbar auf der Seite
   „Priorität“:
   - „unimportant“/„negligible“ zieht stark ab (Vorschlag 30);
   - „no-dsa“/„postponed“/„ignored“/„low“ zieht leicht ab (Vorschlag 10);
   - KEV bleibt unberührt (Untergrenze wie bisher);
   - für Debian kommt der Wert aus dem Tracker, für Ubuntu aus der OSV-Priorität;
   - wirkt auch auf die Schwellen der Sofort-Mail;
   - sichtbar im Detail („Debian: unimportant, −30“).

   ✓ erledigt 2026-11-07: Migration `0018_distro_rating` (Spalte `rating` an den Treffern, `penalty_unimportant`
   30 und `penalty_minor` 10 in `prio_settings`), `matches::Rating` (Debian aus dem Tracker der passenden
   Codenamen-Zeile: „unimportant“, no-dsa mit Grund „ignored“/„postponed“ oder ohne Grund, Dringlichkeit „low“;
   Ubuntu aus der Priorität des UBUNTU-CVE-Datensatzes: „negligible“, „low“), Abzug in Rust (`Weights::match_prio`,
   `Row::prio`) und im SQL der Zähler (gemeinsame Teile per `concat!`), Felder auf der Seite „Priorität“
   („Unwichtig“ darf nicht weniger abziehen als „Gering“), Zeile „Debian stuft ein: … (−30 Punkte)“ im Detail.
   Abweichungen: Treffer ohne CVE (`osv:`) bekommen keine Einstufung, ihre Schwere ist schon die Grundpriorität
   (sonst doppelt); Debian „end-of-life“ zieht nichts ab (dort kommt gar keine Korrektur). Die Einstufung kommt mit
   dem nächsten Abgleich (nach dem nächsten Quellenlauf), bis dahin zieht nichts ab; sie senkt nur, die Sofort-Mail
   bekommt dadurch nichts Neues. Test-DB (Schätzung per SQL): beim Ubuntu-Kernel 398 von 2000 Treffern eingestuft
   (390 „low“, 8 „negligible“), beim Debian-openssl 1 von 48. Der Tracker-Abruf je Paket nutzt den Index
   `debian_tracker_package`.
3. ✓ **Pi-Kernel ohne Datenquelle:** Kernel-Quellpakete aus einer festen Liste (`linux`, `linux-signed-*`,
   `raspi-firmware`, ggf. `linux-firmware`) mit `+rpt` in der Version nicht gegen Debian abgleichen. Sie stehen
   sichtbar als „ohne Datenquelle (Raspberry-Pi-Kernel)“ in der Liste, nicht still versteckt. Andere `+rpt`-Pakete
   werden weiter abgeglichen. Später möglich, nicht jetzt: der Pi-Kernel als Produkt „Linux kernel“ gegen die
   Bereiche des Kernel-CNA in cvelistV5 (fachlich richtig, aber Hunderte Treffer).
   Umgesetzt (2026-11-07): `Asset::pi_kernel` (Paket, Debian, `+rpt` in der Version, Quellpaket `linux`,
   `linux-signed-*`, `raspi-firmware` oder `linux-firmware`), der Abgleich überspringt solche Assets, vorhandene
   Treffer werden beim nächsten Abgleich „von selbst erledigt“. In der Asset-Liste werden sie nicht mit den Paketen
   ohne Treffer eingeklappt, sondern stehen mit der Marke „ohne Datenquelle (Raspberry-Pi-Kernel)“ (Erklärung als
   Tooltip); Formular und Vorschau zeigen einen Hinweis. Keine Migration. 402 Tests. Die Test-DB hat keinen Pi-Kernel,
   geprüft nur mit Tests; im Betrieb verschwinden die Kernel-Treffer eines Pi beim nächsten Abgleich.
4. ✓ **Verschiedene Schwachstellen zählen** in den Zahlen je Host und auf der Seite „Lage“. Die Trefferzahl bleibt
   beim Asset.
   Umgesetzt (2026-11-07): Die Seite „Lage“ (meistbetroffene Hosts, Kacheln) und der Host-Filter des Eingangs
   zählten schon je Schwachstelle; neu ein Test, der das für zwei Pakete mit derselben CVE festhält. Doppelt gezählt
   haben die Kopfzeile je Host in der Asset-Liste (Summe der Treffer aller Assets, jetzt „N Schwachstellen offen“) und
   die Hosts-Seite („N betroffen“ = Pakete, jetzt „N Schwachstellen in M Paketen“); dieselbe Zeile neu auf der Seite
   „Rechner (Agent)“. Dabei behoben: Die Hosts-Seite und der Assistent zählten auch Treffer unter der
   Mindestpriorität des Assets mit (jetzt wie die Asset-Liste, `matches::open_per_origin`). 404 Tests.
5. **Laufender Kernel, Neustart und Pro-Erkennung im Skript:**
   - Zusätzliche Angaben: laufender Kernel (`uname -r`), Neustart nötig (`/var/run/reboot-required`) und Pro
     (`/etc/apt/sources.list.d/ubuntu-esm-infra.*` bzw. `ubuntu-esm-apps.*` vorhanden, für alle lesbar, also auch
     mit dem Zwangsbefehl ohne root).
   - Pro-Merkmal: „esm“ in einer Version bleibt als zweites Merkmal, *automatisch* aus 1b nutzt beide.
   - Anzeige: beim Host „Neustart nötig, läuft Kernel X, installiert Y“.
   - Zuerst im Agenten (optionale Felder in der JSON-Meldung, `docs/agent-api.md`; Skript
     `contrib/opensecmon-agent.sh`).
   - Beim SSH-Skript abwärtsverträglich (Zusatzzeilen vor `---`, alte Ausgaben bleiben gültig); die Hosts kopieren
     das Skript neu, wenn sie ohnehin neu eingerichtet werden.
   - ✓ Umgesetzt (2026-11-07): Beide Skripte (SSH und `contrib/opensecmon-agent.sh`, jetzt Version 2) schreiben vor
     `---` die Zeilen `OPENSECMON_KERNEL=…`, `OPENSECMON_REBOOT=1` und `OPENSECMON_PRO=1`; die JSON-Meldung hat dafür
     die optionalen Felder `os.kernel`, `os.reboot_required`, `os.ubuntu_pro` (werden in dieselben Zeilen
     übersetzt, ein Kernel mit fremden Zeichen wird abgelehnt). `listing.rs` liest sie, dazu den höchsten
     installierten Kernel aus den Quellpaketen `linux`, `linux-signed*`, `linux-hwe-*`; Migration `0019`
     (`kernel`, `kernel_installed`, `reboot_required` an `ssh_hosts` und `agent_devices`). Pro-Erkennung: Datei oder
     „esm“ in einer Version. Anzeige in den Listen „Hosts“ und „Rechner“ unter dem System und auf der Seite des Hosts
     bzw. Rechners: „Kernel X“, bei ausstehendem Neustart als Warnung „Neustart nötig, läuft Kernel X, installiert
     Y“. Abweichung: „installiert“ ist die Version des Quellpakets (`7.0.0-42.42`), nicht der Name aus `uname -r`.
     Ein Test führt das SSH-Skript auf einem System mit dpkg aus (CI, Laptop). Betriebsanleitung und
     `docs/agent-api.md` ergänzt (Skript neu kopieren). 406 Tests.

## Abweichungen vom Entwurf und Entscheidungen der Umsetzung

Stand Phase 1 (2026-11-05):

- **Adressen:** `/` Eingang, `/situation`, `/assets`, `/cves`, `/sources` (englisch wie der Code, statt `lage.html` usw.).
- **Einstellungen als eigene Seiten** (`/settings/mail`, `/settings/account`, `/settings/audit`) statt Reitern mit `#`, damit
  sie ohne JavaScript gehen. Phase 1 hat nur Mailserver, Konto und Protokoll; Schwellen, Tagesbericht, Priorität und
  Aufbewahrung kommen mit ihren Phasen.
- **Ein Benutzertyp:** jeder Benutzer ist Administrator, keine Rollen; Benutzer nur über die Kommandozeile
  (`opensecmon user …`). Der Name ist in der Oberfläche nicht änderbar.
- **HTTPS eingebaut (Nutzerentscheidung 2026-11-07, vorher „kein eingebautes HTTPS“):** Weil das Release öffentlich
  wird und nicht jeder einen Reverse Proxy betreibt, bringt opensecmon wie opennetmon eigenes HTTPS mit
  (`src/tls.rs` aus opennetmon, `opensecmon tls generate`, selbstsigniertes Zertifikat bei der Installation, HTTP auf
  dem Port wird umgeleitet). Paketstandard `0.0.0.0:8444` (8443 belegt opennetmon), ohne `client_ip_header`. Der
  Betrieb hinter Traefik bleibt möglich (`127.0.0.1:8090`, ohne `tls_`-Zeilen, mit `client_ip_header`). Bis dahin galt:
  opensecmon lauscht standardmäßig auf `127.0.0.1:8090` hinter einem TLS-Reverse-Proxy
  (Traefik). Dafür neu gegenüber opennetmon: `allowed_hosts` (fremde Hostnamen → 421, gegen DNS-Rebinding) und eine
  Origin-/`Sec-Fetch-Site`-Prüfung für alle ändernden Anfragen (zusätzlich zu CSRF-Token und `SameSite=Strict`).
- **htmx** ist noch nicht eingebunden (zu Phase 2 siehe unten).
- **Statusleiste der Quellen** in der Kopfleiste und Tastenkürzel-Hilfe fehlen noch (Statusleiste mit Phase 2 erledigt).
- **Weggelassen aus opennetmon:** HTTP-Client und Update-Hinweis (Phase 2 bzw. nach dem Öffentlich-Schalten), TLS,
  Poller, MIBs, Rollen, Zeitplan-Modul. `time_zone` steht schon in der Konfiguration, wird aber erst für den
  Tagesbericht (Phase 7) benutzt.
- **askama ohne Feature `config`**, damit das nicht mehr gepflegte `basic-toml` (RUSTSEC-2026-0374) wegfällt.
- **Betriebsdoku:** `docs/operations.md` (seit Phase 9, 2026-11-07).
- **Symbole:** Lucide (ISC) mit eigenem Zeichen; Lizenztext in `dev/licenses/lucide-ISC.txt` und in
  `THIRD-PARTY-LICENSES.txt`.

Stand Phase 2 (2026-11-05):

- **Kein htmx:** die Seiten sind serverseitig gerendert, Filter, Sortierung und Seiten sind Links bzw. GET-Formulare und
  gehen ohne JavaScript. Zwei kleine eigene Skripte ersetzen das Nachladen: `static/cves.js` holt dieselbe Seite mit
  `sel=` und tauscht nur das Detail (mit `pushState`, auf schmalen Bildschirmen als Blatt), `static/sources.js` klappt
  die Detailzeilen auf, schickt den Ein/Aus-Schalter ab und lädt die Tabelle alle 5 s neu, solange eine Quelle läuft.
  Damit keine neue Abhängigkeit; htmx nur, falls eine spätere Seite es wirklich braucht.
- **Eigene Detailseite `/cves/{id}`** zusätzlich zum Detail neben der Liste (für Links aus Suche, Mails und Treffern).
  Eine vollständige CVE-Kennung im Suchfeld springt direkt dorthin.
- **„Alle CVEs“ ohne Filter nach Quelle:** er sollte mit den CSAF-Quellen (Phase 3) kommen, steht aber noch aus.
  „Nur eigene Treffer“ gibt es seit Phase 5 als Filter-Chip „Nur meine“. CSV-Export seit Phase 8. Der Herstellerfilter nimmt den Herstellernamen (über
  `cve_products`); Vorschläge beim Tippen fehlen noch.
- **Seitengröße 50, höchstens 200 Seiten** (10 000 Zeilen); wer tiefer will, filtert.
- **Priorität vorläufig ohne Asset-Bezug:** CVSS × 7 + EPSS-Perzentil × 20, KEV mindestens 90 (Bänder ≥ 85 kritisch,
  ≥ 65 hoch, ≥ 45 mittel). Das Vertrauen des Treffers zieht seit Phase 5 etwas ab (unten); die Formel steht aufklappbar im Detail.
- **Statusleiste der Quellen** in der Kopfleiste ist jetzt da (letzte Prüfung, Zahl der fehlerhaften Quellen, laufende
  Quelle); die Tastenkürzel-Hilfe kommt mit dem Eingang.
- **Schmale Bildschirme:** die CVE-Tabelle behält eine Mindestbreite von 620 px und scrollt in ihrem Rahmen seitwärts,
  damit der Titel lesbar bleibt (im Entwurf wurde der Titel auf wenige Buchstaben gekürzt).
- **Datenbankabfragen ohne `ANALYZE`:** SQLite hat keine Statistiken; die Liste gibt dem Planer deshalb Hinweise
  (`+state` bei selektiven Filtern, `INDEXED BY` beim Sortieren über den ganzen Zeitraum). `ANALYZE` hat die Pläne im
  Test verschlechtert und bleibt aus.
- **Große Aktualisierungen in Blöcken** von 10 000 Zeilen (EPSS, Prioritäten), damit Webanfragen nie länger als das
  `busy_timeout` von 5 s auf die Schreibsperre warten; WAL auf 64 MB begrenzt, beim Beenden wird der Pool geschlossen.

Stand Phase 3 (2026-11-06):

- **Eigene CSAF-Typen** (`src/csaf/`, serde) statt der Crate `csaf-models`: nur die Felder, die Liste, Detail und
  später der Abgleich brauchen, tolerant gegenüber fehlerhaften Einzelfeldern (`lenient`), Grenzen für Einträge und
  Produkte. Keine neue Abhängigkeit.
- **Keine OpenPGP-Prüfung** (wie geplant später optional); geprüft wird die Prüfsumme, bevorzugt SHA-512, sonst
  SHA-256 (ROLIE-Link `rel=hash` bzw. `.sha512`/`.sha256` neben dem Dokument). Fehlt sie, wird das Dokument trotzdem
  gespeichert und als „ungeprüft“ markiert (`hash_checked`).
- **Nur TLP:WHITE/CLEAR:** Verteilungen und Dokumente mit anderer TLP werden nicht geladen, auch wenn ein Hersteller sie
  öffentlich anbietet.
- **BSI als eine Anbieterzeile** in `csaf_providers` (wie ein Hersteller, Quelle `bsi`), damit Leser, Speicher und
  Liste für beide gleich sind. Die Quellen „BSI CERT-Bund“ und „Hersteller-CSAF“ haben getrennte Intervalle
  (2 h bzw. 6 h) und getrennte Zustände.
- **Änderungen über die Zeit `updated` im Feed** (ROLIE) bzw. `changes.csv`: nur neue oder geänderte Dokumente werden
  geladen; ETag/Last-Modified des Feeds werden erst gespeichert, wenn kein Dokument vorübergehend gescheitert ist.
  Abgelehnte Dokumente (falsche TLP, kaputtes JSON, 404) stehen in `csaf_skipped` und werden erst wieder versucht,
  wenn sich ihr `updated` ändert. Ein Lauf mit übersprungenen Dokumenten ist erfolgreich, zeigt aber auf der Seite
  „Quellen“ eine Warnung (`source_state.last_warning`).
- **Hersteller:** eigene Seite `/sources/vendors` (statt eines Bereichs in den Einstellungen) mit der Anbieterliste des
  BSI (Aggregator, auf Knopfdruck geladen) oder eigener URL, Startdatum je Anbieter (vorgeschlagen: 1. Januar des
  Vorjahres) und Auswahl der Verteilungen; VEX-Verzeichnisse (eine Datei je CVE, z. B. Red Hat) sind beim Hinzufügen
  aus. Filtern nach den eigenen Assets: seit Phase 5 „Nur meine“.
- **Advisories als zweite Ansicht** unter „Alle CVEs“ (Umschalter CVEs/Advisories) statt eines eigenen
  Navigationspunkts; eigene Seite je Advisory `/advisories/{seq}`, das CVE-Detail nennt die Advisories zur CVE.
  Die Schwere wird aus dem Text (BSI: „kritisch“ … ) bzw. dem höchsten CVSS-Wert in fünf Bänder übersetzt.
- **HTTP-Client für viele kleine Dateien angepasst** (Befunde beim ersten echten BSI-Import):
  - DNS-Zwischenspeicher (60 s je Host): die Namensauflösung dauerte im Heimnetz zeitweise 2–5 s je Anfrage, weil der
    lokale Resolver bei mehreren Abfragen je Sekunde drosselte.
  - Etwa jede 40. Anfrage hing bis zur Grenze von 60 s: für CSAF-Dokumente gilt jetzt eine Wartegrenze von 15 s je
    Schritt (`Get::idle`) und ein sofortiger zweiter Versuch.
  - Verbindungen werden wiederverwendet (`http_client::Session`, HTTP/1.1 keep-alive, eine Verbindung je
    Download-Platz, 4 gleichzeitig): mit einer neuen TLS-Verbindung je Dokument und Prüfsumme (rund 10 je Sekunde)
    nahm der BSI-Server nach einigen tausend Dokumenten zeitweise keine neuen Verbindungen mehr an.

Stand Phase 4 (2026-11-06):

- **Keine eigene Abfrage von `ubuntu.com/security/notices.json`:** Titel, Text, CVEs und behobene Versionen der USN
  stehen schon in den OSV-Datensätzen von Ubuntu. Eine Quelle weniger.
- **OSV statt der Einzelquellen von Debian:** DSA/DLA/DTSA und der Paketstatus je CVE kommen aus OSV
  (`osv-vulnerabilities.storage.googleapis.com/{Debian,Ubuntu}/`). Erstimport aus `all.zip`, danach `modified_id.csv`
  (bedingt) und nur die geänderten Datensätze einzeln (4 Verbindungen, keep-alive). Mehr als 10 000 Änderungen laden
  `all.zip` neu; dabei werden Datensätze entfernt, die OSV nicht mehr hat (höchstens, wenn das Zip mindestens die
  Hälfte der gespeicherten enthält). Cursor ist das neueste `modified`; scheitern einzelne Datensätze, bleibt der Cursor
  davor stehen (Warnung auf der Seite „Quellen“), und sie werden mit der nächsten geänderten Liste wieder versucht.
- **Gespeichert werden Versionsbereiche** (eingeführt, behoben, zuletzt betroffen) je Release (`Debian:13`,
  `Ubuntu:26.04:LTS`, `Ubuntu:Pro:20.04:LTS` …) und Quellpaket, nicht die Listen aller betroffenen Versionen; für den
  Abgleich in Phase 5 reicht der Vergleich mit der behobenen Version (dpkg-Vergleich). Bei CVE-Datensätzen der
  Distributionen wird die Beschreibung nicht gespeichert (sie wiederholt die der CVE).
- **Debian Security Tracker nur als Ergänzung:** OSV nennt schon die behobenen Versionen. Gespeichert werden nur
  Einträge, die offen oder unklar sind, und Einträge mit „no-dsa“ (Grund „postponed“/„ignored“), rund 29 000 Zeilen;
  das 90-MB-JSON wird als Strom gelesen, Änderungen werden als Unterschied geschrieben. `sid` erscheint im CVE-Detail
  nicht (kein Server-Release).
- **Zurückgezogene Datensätze** (`withdrawn`) packt OSV nicht in `all.zip` (bei Ubuntu 146 Stück, alle in der
  Änderungsliste); kommt eine Rücknahme über die Änderungsliste, bleibt der Datensatz mit Datum gespeichert und wird im
  CVE-Detail ausgeblendet.
- **DSA/USN noch nicht in der Advisory-Liste:** sie erscheinen vorerst nur im CVE-Detail (Abschnitt „Distributionen“,
  mit Link auf die Seite der Distribution). Ob sie als dritte Quelle in die Ansicht „Advisories“ kommen, entscheidet
  sich mit dem Eingang in Phase 5.
- **Höchstens 40 Zeilen je Distribution im CVE-Detail:** Ubuntu nennt für manche Kernel-CVEs Hunderte Kernel-Pakete
  je Release; der Rest steht auf der Seite der Distribution (Link).
- **Keine Auswahl der Releases:** alle Releases werden gespeichert, auch alte (Debian 3.0 bis 11, Ubuntu 14.04,
  Pro/FIPS/Realtime-Varianten). Die Datenbank wächst dadurch um 441 MB, fast nur durch Kernel-Pakete (unten). In
  Phase 5 bzw. 8 prüfen, ob Releases ohne eigene Assets oder die Kernel-Varianten kompakter oder gar nicht gespeichert
  werden.

Stand Phase 5 (2026-11-06):

- **Abgleich und Vertrauen:** Pakete (Quellpaket, Release, installierte Version) gegen die OSV-Bereiche der
  Distribution mit dpkg-Vergleich: hoch. Produkte gegen die CPE-Konfigurationen der NVD und die Versionsbereiche der
  CNA im CVE-Datensatz: hoch, wenn die Version im Bereich liegt; gegen CSAF-Produktbäume (Versionen als Text wie
  „<10.6p2“): mittel. Ein Produkt ohne prüfbare Version trifft mittel, aber nur Meldungen, die höchstens 30 Tage
  vor dem Anlegen des Assets erschienen sind (sonst stünden alle alten CVEs eines Produkts im Eingang).
  Watchlist-Stichwörter (Phrase in Titel und Produktnamen, ebenfalls nur die letzten 30 Tage): niedrig.
- **Priorität mit Vertrauen als Abzug:** Priorität der Schwachstelle (CVSS × 7 + EPSS-Perzentil × 20, KEV mindestens
  90; Meldungen ohne CVE nach ihrer Schwere) minus 0 (hoch), 10 (mittel) oder 25 (niedrig). Ein mittlerer Treffer
  einer KEV-CVE bleibt bei 90, ein niedriger nicht.
- **BSI-Bereiche werden gepaart:** das BSI schreibt einen Bereich als zwei Produkte („>=5.4“ betroffen und „<7.1p2“
  ohne Status). Untere und obere halboffene Grenzen werden zu geschlossenen Bereichen verbunden; vorher traf „>=5.4“
  jede spätere Version (OpenSSH 9.6p1 bekam CVEs von 2016).
- **Voller Abgleich statt inkrementell:** jeder Lauf berechnet alle Treffer eines Assets neu und schreibt nur den
  Unterschied (`storage::matches::sync`). Er läuft nach dem Speichern eines Assets und nach jedem Abruf einer Quelle,
  die etwas geändert hat (alle Assets, ein Lauf zur Zeit). Fallen Treffer weg, werden sie als „von selbst erledigt“
  geschlossen (`auto = 1`) und öffnen sich wieder, wenn sie zurückkommen; von Hand Erledigtes bleibt erledigt.
- **Höchstens 2000 Treffer je Asset** (die neuesten zuerst): ein Kernel weit hinter seinem Release hätte sonst
  Tausende alter CVEs. Höchstens 500 Treffer je Stichwort und Tabelle.
- **Asset anlegen als eigene Seite** (`/assets/new`, `/assets/{id}`) statt als Dialog; die Vorschau der Treffer
  steht im Formular und aktualisiert sich beim Tippen (ohne Skript per Knopf „Vorschau“).
- **Noch keine Reiter „Hosts (SSH)“, „opennetmon“ und „CSV“** auf der Seite „Assets“: sie kommen mit Phase 6 (seit 2026-11-06 da).
- **Eingang:** Filter mit Einfachauswahl je Gruppe (Schwere, Vertrauen, Art, Host/Gerät, Asset, Watchlist), ohne
  Facetten für Hersteller und Quelle; die Liste zeigt höchstens 300 Schwachstellen („… weitere, bitte filtern“).
  „Ignorieren“ ohne die Option „künftig für dieses Asset ignorieren“; Gründe: nicht genutzt, nur im LAN,
  Fehlalarm, anderer (Notiz bis 1000 Zeichen). „Später“ für 1, 7 oder 30 Tage; danach wird der Treffer beim Öffnen
  des Eingangs wieder offen. Rückgängig über „Wieder öffnen“ statt einer Rückgängig-Leiste.
- **Triage nicht im Änderungsprotokoll:** der Zustand steht am Treffer (wann, Grund, Notiz). Anlegen, Ändern und
  Löschen von Assets und Stichwörtern werden protokolliert.
- **DSA/USN bleiben im CVE-Detail**, nicht in der Ansicht „Advisories“; USN/DSA ohne eigene CVE erscheinen im Eingang
  mit einem kurzen Detail und dem Link auf OSV.
- **Datenbankgröße nicht angefasst:** Assets und Treffer brauchen kaum Platz (6 Assets, 2168 Treffer: 0,4 MB). Ob
  NVD-Konfigurationen und alte Releases kompakter gespeichert werden, bleibt bei Phase 8 (dort komprimiert, siehe Stand Phase 8).

Stand Phase 6 (2026-11-06):

- **SSH im Prozess (russh) statt `ssh`-Programm:** eigener ed25519-Schlüssel der Anwendung (verschlüsselt mit
  `secret.key`, öffentlicher Teil auf der Seite „Hosts (SSH)“), keine eigene `known_hosts`-Datei. Nur ed25519- und
  ECDSA-Host-Schlüssel, **kein RSA** (das Crate `rsa` hat eine offene Meldung, RUSTSEC-2023-0071); Hosts mit nur
  RSA-Schlüssel lassen sich nicht einbinden (heutige Debian/Ubuntu-Server haben immer ed25519).
- **Zwangsbefehl auf dem Host:** `restrict,command="/usr/local/bin/opensecmon-inventory"` vor dem Schlüssel; das
  Skript (zum Kopieren im Assistenten) gibt `/etc/os-release`, eine Zeile `---` und `dpkg-query` aus, sonst nichts.
  Die Anwendung schickt keinen eigenen Befehl, der Host entscheidet. Grenzen: 8 MiB Ausgabe, 50 000 Pakete, 60 s.
- **Ein Asset je Quellpaket** mit der höchsten installierten Version (statt je Binärpaket): OSV und der Debian-Tracker
  führen Quellpakete; `openssh-client`, `-server`, `-sftp-server` wären sonst drei gleiche Treffer. Die Asset-Liste
  zeigt von einem Host nur die Pakete mit offenen Treffern, die übrigen eingeklappt („… ohne offene Meldungen“).
- **Assistent in vier Schritten** wie im Entwurf, aber als Seiten mit Formularen (ohne Dialog): Schritt aus dem
  Zustand des Hosts, ein Neuladen bleibt im richtigen Schritt. Fingerabdruck SHA-256 wie `ssh-keygen -lf`.
  Ein geänderter Host-Schlüssel stoppt das Lesen, bis er neu bestätigt ist (alter und neuer Fingerabdruck stehen da).
- **Abfrage alle 6 h**, im selben Hintergrundlauf wie opennetmon, ein Host zur Zeit, nur wenn `fetch_sources` an ist
  (sonst nur „Jetzt lesen“). Fehler mit Rückzug wie bei den Quellen. Nach dem Lesen werden nur neue und geänderte
  Pakete abgeglichen; weggefallene Pakete werden gelöscht (ihre Treffer schließen sich).
- **Release-Erkennung über `os-release`:** Debian und Ubuntu direkt, Abkömmlinge (Mint, Pop!_OS, Zorin, Raspberry Pi OS …)
  über `ID_LIKE` und `UBUNTU_CODENAME`/`VERSION_CODENAME`. Andere Systeme lehnt das Lesen mit einer Meldung am Host
  ab („nur Debian und Ubuntu“).
- **opennetmon:** nur die Seite in opensecmon. Der Endpunkt `GET /api/v1/inventory` ist in opennetmon **noch nicht
  gebaut**; er kommt mit einem der nächsten Releases von opennetmon (Vertrag: `GET /api/v1/inventory` mit Bearer-Token). Getestet gegen eine Attrappe (Python, im Scratchpad) und im
  Test gegen einen lokalen axum-Server. Adresse nur HTTPS oder HTTP auf Loopback; mit Token keine Weiterleitungen.
  Regeln über `sysDescr`/`sysObjectID`: AVM (auch Modell aus dem Text), Cisco IOS, MikroTik, TP-Link, Huawei, sonst
  nur der Hersteller aus der Enterprise-Nummer („bitte prüfen“). Übernommene Geräte folgen opennetmon (neue Version →
  Asset geändert und neu abgeglichen); verschwundene Geräte bleiben, solange ein Asset an ihnen hängt.
- **CSV als Text statt Datei-Upload:** ein Textfeld, in das `static/inventory.js` die gewählte oder hingezogene Datei
  liest (ohne Skript: einfügen). Kein `multipart` nötig. Höchstens 1 MiB und 5000 Zeilen, Vorschau zeigt 300 Zeilen.
  Spaltennamen deutsch oder englisch, `;` oder `,`. Die CSV ändert nur Assets von Hand oder aus CSV (gleich sind
  Art, Hersteller, Produkt, Host und bei Paketen Distribution/Release); Assets von SSH oder opennetmon bleiben bei
  ihrer Quelle. Gelöscht wird per CSV nichts.
- **Echte Server zu diesem Zeitpunkt nicht eingerichtet** (erst nach Freigabe). Geprüft wurde Ende zu Ende mit `fake_ssh_host`
  (Beispielprogramm, Feature `fake-host`) und der echten Paketliste des Laptops.
- **Rauschen bei Paketen:** Kernel-Quellpakete (`linux`, `linux-hwe-*`) und alte Bibliotheken wie `mozjs115` bringen
  hunderte bis 2000 Treffer (unten). Zusammenfassen oder Ausblenden gehört zu Phase 8 (dort per Mindestpriorität je Asset).

Stand Phase 7 (2026-11-06):

- **Einstellungen als zwei eigene Seiten** `/settings/alerts` und `/settings/report` (statt Karten mit `#`), vor
  „Mailserver“ in der Seitenleiste; `/settings` führt zur Sofort-Mail. Die Empfänger stehen nur bei „Mailserver“
  (im Entwurf auch auf der Karte „Sofort-Mail“), die Testmail ebenfalls. Priorität und Aufbewahrung bleiben für Phase 8.
- **Was „neu“ heißt:** Ein Treffer geht per Sofort-Mail hinaus, wenn er offen ist (neu oder gesehen), noch nicht
  gemeldet wurde und eine der eingeschalteten Bedingungen erfüllt (KEV; Priorität, CVSS oder EPSS über der Schwelle;
  Mindestvertrauen). Das gilt auch für einen älteren Treffer, der die Bedingung erst später erfüllt (CVE kommt in
  KEV, EPSS steigt). Beim Einschalten (Mail oder Sofort-Mail) und bei geänderten Bedingungen gelten die Treffer, die sie
  in diesem Moment erfüllen, als bekannt (`alert = 'quiet'`) und werden nicht gemailt: kein Rückstau beim Einschalten.
  Treffer, die vor der Mail erledigt oder ignoriert wurden, gehen nicht mehr hinaus.
- **Bündeln:** der erste Treffer wartet 10 min auf weitere (ein Quellenlauf oder Host-Import ergibt eine Mail). „Dieselbe
  Schwachstelle nur einmal“ nimmt Treffer einer schon gemeldeten CVE als bekannt, wenn weitere Assets dazukommen.
- **Mails als reiner Text** (kein HTML), Liste nach Schwachstelle gruppiert und nach Priorität geordnet, höchstens 25
  Einträge und je 5 Assets, darunter „… und N weitere im Eingang“. Je Eintrag Priorität mit Stufe, KEV, Titel,
  Betroffenes mit behobener Version, Grund der Meldung und Link `/?sel=…`. Texte aus Quellen ohne Steuer- und
  Richtungszeichen, gekürzt. Links nur mit eingetragener **Adresse der Oberfläche** (neues Feld auf der Seite
  Sofort-Mail); opensecmon kennt seine öffentliche Adresse hinter Traefik sonst nicht.
- **Tagesbericht:** Uhrzeit in der Zeitzone aus `time_zone` (sonst die des Systems), Teile: neue Treffer seit dem letzten
  Bericht (beim ersten: 24 h), offen mit Priorität ≥ 85 oder KEV (ohne die oben schon genannten), bis morgen wieder
  fällige zurückgestellte Treffer, Quellen mit Fehlern. Eine Uhrzeit, die beim Einschalten oder Verstellen schon
  vorbei ist, wird nicht nachgeholt; war der Dienst zur Uhrzeit aus, kommt der Bericht beim nächsten Start einmal.
  Vorschau auf der Seite in der Sprache der Mails; „Jetzt senden“ sendet auch einen leeren oder ausgeschalteten Bericht.
- **Fehler beim Versand:** neuer Versuch nach 15 min, dann 30, 60, höchstens alle 2 h; jeder Versuch steht in
  „Letzte Sendeversuche“.
- **Nur eine Instanz meldet:** die Prüfung läuft nur, wenn `fetch_sources` an ist (wie der Hintergrundlauf der Hosts),
  damit eine zweite Instanz zum Ansehen auf derselben DB keine doppelten Mails schickt.
- **Noch nicht:** Zeitleiste „Sofort-Mail gesendet“ im Detail (der Zeitpunkt steht schon in `matches.alert_ms`),
  Mail in HTML, eigene Empfänger je Mailart.

Stand Phase 8 (2026-11-06):

- **Lage ohne Diagramm-Bibliothek:** Verlauf und Balken sind SVG, das der Server mit Klassen zeichnet (CSP ohne
  `style`-Attribute, kein Skript). Die Tageszahlen schreibt die stündliche Wartung (`situation_days`, 400 Tage). Tage
  vor der ersten Aufzeichnung werden aus dem heutigen Stand der Treffer zurückgerechnet und blass gezeichnet.
- **CSV nur für „Alle CVEs“ und den Eingang**, nicht für die Ansicht „Advisories“; höchstens 10 000 Zeilen in der
  Reihenfolge der Liste. Deutsch mit `;` und Dezimalkomma, Englisch mit `,` und Punkt, UTF-8 mit BOM (Excel). Zellen,
  die mit `=`, `+`, `-`, `@`, Tab oder CR beginnen, bekommen ein `'` davor (Titel kommen aus den Quellen).
- **Priorität und Aufbewahrung als eigene Seiten** `/settings/priority` und `/settings/retention` (im Entwurf Karten
  auf einer Seite), wie die anderen Einstellungen. Die Stufen (85/65/45) bleiben fest, einstellbar sind nur die
  Gewichte. Beim Speichern rechnet der Dienst alle CVE-Prioritäten im Hintergrund neu (~15 s); solange wartet die
  Sofort-Mail, und Treffer, die erst die neuen Gewichte über eine Schwelle heben, gelten als bekannt (kein Mailschwall).
- **CVEs und Advisories werden nie gelöscht:** ein später angelegtes Asset kann von einer alten Lücke betroffen sein.
  Gelöscht werden nur erledigte und ignorierte Treffer, die der Abgleich seit N Tagen nicht mehr findet
  (`matches.gone_ms`; Standard 1 Jahr), und Protokolleinträge (Konfiguration oder 90 Tage bis 5 Jahre).
- **Datenbankgröße:** `nvd_cves.configs`, `cves.refs` und `cves.affected` stehen deflate-komprimiert in `_z`-Spalten
  (flate2 war schon da); ältere Zeilen packt der Dienst nach dem Start im Hintergrund, den Platz gibt erst
  „Datenbank verkleinern“ frei. Die OSV-Bereiche der Kernel-Pakete (rund 3,2 Mio. Zeilen, 419 MB im Bereich
  Distributionen) bleiben, weil der Abgleich sie braucht.
- **Größe je Bereich** misst die Wartung einmal am Tag und nach dem Verkleinern (`dbstat`, 15 s auf der vollen DB;
  dabei steht täglich eine Warnung „slow statement“ im Log). Die Seite zeigt Dateigröße und freien Platz sofort.
- **Während des Verkleinerns** (~1 min) warten Schreibzugriffe; Seiten laden weiter (Sitzung, „gesehen“ und Wecken
  zurückgestellter Treffer scheitern still). Eine Triage oder ein Speichern kann nach 5 s mit einer Fehlerseite
  abbrechen und muss wiederholt werden. Ein durch Neustart abgebrochener Lauf gilt als fehlgeschlagen.
- **Rauschen per Mindestpriorität je Asset** statt Zusammenfassen im Eingang: Treffer unter der Schwelle bleiben
  gespeichert und erscheinen, wenn der Eingang nach dem Asset gefiltert ist; sonst fehlen sie in Ansichten, Zahlen,
  CSV, Lage und Mails, ein Hinweis im Eingang nennt ihre Zahl. Kernel-Quellpakete aus dem SSH-Import starten bei 65
  („hoch“), andere (z. B. `mozjs115`) bei 0 und lassen sich im Asset-Formular einstellen.
- **Keine Anzeige „letzte Sicherung“:** die Sicherung läuft als eigener systemd-Timer (`opensecmon-backup.timer`), der Dienst
  kennt ihr Ergebnis nicht.
- **Handy-Ansicht:** alle Seiten bei 390 px hell/dunkel geprüft, kein waagerechter Überlauf; Navigation unten wie im
  Entwurf.

### Messung des Erstimports (2026-11-05, Laptop, Release-Bau, ein Lauf)

| Quelle | Laufzeit | Datensätze |
|---|---|---|
| cvelistV5 (Mitternachts-Zip, ~650 MB) | 343 s | 419 967 |
| NVD (Jahres-Feeds 2002–2026) | 517 s | 419 946 |
| CISA KEV | 12 s | 1 768 |
| FIRST EPSS | 36 s | 400 564 |

- Gesamt 16:43 min, höchstens 187 MB Arbeitsspeicher.
- **Datenbank 1,78 GB** (erwartet waren ~1 GB): `cves` 731 MB, `nvd_cves` 501 MB (vor allem die CPE-Konfigurationen),
  `cve_products` 132 MB plus 85 MB Index, Volltextindex 115 MB. In Phase 5 prüfen, ob die NVD-Konfigurationen
  kompakter gespeichert werden können (nur, was der Abgleich braucht); Aufräumen in Phase 8.
- Abfragen auf der vollen Datenbank (Debug-Bau, ganze Seite): Liste der letzten 30 Tage ~0,1 s, ganzer Zeitraum je
  Sortierung 0,1–0,2 s (auch Seite 200), Volltext 0,06–0,3 s, KEV 0,1 s, Hersteller mit vielen CVEs (Microsoft,
  29 000) ~0,8 s, Detail 0,02 s.
- Die Datenbankdatei entsteht mit den Rechten des Prozesses; der Dienst läuft mit `UMask=0077` und
  `StateDirectoryMode=0750`, im Paket also 0600. Downloads liegen in `downloads/` neben der Datenbank (0700).

### Messung des BSI-Imports (2026-11-06, Laptop, Release-Bau, Test-DB aus Phase 2)

- Feed `bsi-white.json`: 14 525 Dokumente (TLP:WHITE), alle mit passender SHA-512-Prüfsumme, keines abgelehnt.
- Mit wiederverwendeten Verbindungen (4 gleichzeitig) rund 50 Dokumente je Sekunde: die letzten 9 433 Dokumente in
  186 s, der ganze Erstimport also etwa 5 min; höchstens 94 MB Arbeitsspeicher. Vorher (neue Verbindung je Anfrage)
  4–6 Dokumente je Sekunde und zeitweise keine Antwort des Servers (siehe Abweichungen).
- Zweiter Lauf direkt danach: 1 s, nichts Neues (Feed unverändert).
- Datenbank +92 MB (1,79 → 1,88 GB): `advisories` 58 MB (vor allem Notizen und Referenzen), `advisory_products`
  16 MB plus 4 MB Index (114 798 Zeilen, im Mittel 8 Produkte, höchstens 1 391), `advisory_cves` 4 MB
  (103 195 Zuordnungen), Volltextindex 2 MB.
- Abfragen (Release-Bau, ganze Seite): Advisory-Liste ganzer Zeitraum, Volltext und CVE-Kennung 2–5 ms, Filter nach
  Schwere ~25 ms, Detail 2 ms.
- Hersteller-CSAF Ende zu Ende: Anbieterliste des BSI geladen (14 Anbieter), Intevation ab 01.01.2025 hinzugefügt,
  danach 5 Dokumente in 2 s.
- Schwere der BSI-Hinweise: 358 kritisch, 5 159 hoch, 8 110 mittel, 899 niedrig. Hersteller nach Produkten:
  „Open Source“ 5 667, SUSE 4 063, Red Hat 3 885, Oracle 3 094, Ubuntu 3 076, Debian 3 032.

### Messung der Distributionen (2026-11-06, Laptop, Release-Bau, Test-DB aus Phase 3)

| Quelle | Laufzeit | Datensätze |
|---|---|---|
| Debian (OSV, `all.zip` ~80 MB) | 14 s | 73 549 (11 154 DSA/DLA/DTSA, 62 395 CVE-Datensätze) |
| Ubuntu (OSV, `all.zip` ~800 MB) | 137 s | 73 346 (8 369 USN/LSN, 64 977 CVE-Datensätze) |
| Debian Security Tracker (JSON ~90 MB) | 1 s | 28 775 offene bzw. „no-dsa“-Einträge |

- Zweiter Lauf direkt danach: alle drei unter 0,5 s, nichts Neues (Änderungslisten bzw. Tracker unverändert, 304).
- Arbeitsspeicher nach dem Ubuntu-Import 246 MB (vorher höchstens 187 MB beim CVE-Erstimport).
- **Datenbank +441 MB (1,88 → 2,33 GB):** `osv_affected` 207 MB plus 154 MB Indizes (3,57 Mio. Zeilen, davon
  3,18 Mio. für Kernel-Pakete `linux*`; am meisten Ubuntu 22.04 mit 0,92 Mio., 26.04 nur 0,10 Mio.),
  `osv_records` 27 MB, `osv_cves` 17 MB (363 483 Zuordnungen), `debian_tracker` 3 MB.
- CVE-Detail mit Distributionen (Release-Bau, ganze Seite): 1,5–3 ms, schlimmster Fall CVE-2026-43493 (Kernel,
  463 Zeilen, 40 gezeigt) 15 ms.

### Messung des Abgleichs (2026-11-06, Laptop, Release-Bau, Test-DB aus Phase 4, je Asset ein Lauf)

| Asset | Version | Laufzeit | Treffer |
|---|---|---|---|
| Paket `openssh`, Ubuntu 24.04 | 1:9.6p1-3ubuntu13.4 | 24 ms | 32 |
| Paket `linux`, Ubuntu 24.04 | 6.8.0-40.40 | 1,33 s | 2000 (Grenze) |
| Paket `openssl`, Debian 12 | 3.0.11-1~deb12u2 | 53 ms | 49 |
| Software OpenBSD OpenSSH | 9.6p1 | 220 ms | 35 (NVD 28, CNA 6, CSAF 1) |
| Software Traefik | 3.1.2 | 86 ms | 49 |
| Hardware (Router-Firmware) | – | 9 ms | 0 |
| Watchlist (Router-Modell) | – | 3,3 s → 0,04 s | 0 |

- Die Stichwortsuche fragte den Volltextindex zuerst je Zeile ab (Join); mit einer Unterabfrage auf die `rowid`
  läuft sie einmal (11 ms statt 20 s im CLI ohne Zwischenspeicher).
- Eingang mit 2134 offenen Treffern (Release-Bau, ganze Seite): ~80 ms; Vorschläge beim Tippen 1–200 ms; Vorschau
  eines Assets ~200 ms.
- Stichproben plausibel: Traefik 3.1.2 trifft z. B. CVE-2024-45410 („≥ 3.0.0, < 3.1.3“, behoben in 3.1.3),
  OpenSSH 9.6p1 u. a. CVE-2024-6387 (regreSSHion); die Router-Firmware ohne Treffer.

### Messung des Imports (2026-11-06, Laptop, Release-Bau, Test-DB aus Phase 5)

- **SSH, Ende zu Ende im Browser:** Assistent Schritte 1–4 mit `fake_ssh_host` und der echten Ausgabe des Laptops
  (Zorin OS 18.1, als Ubuntu 24.04 erkannt): 2212 Zeilen `dpkg-query`, **1207 Quellpakete** als Assets. Fingerabdruck
  gleich der Ausgabe von `ssh-keygen -lf`. Lesen und Abgleich zusammen **3,0 s** (davon Abgleich 2,9 s), Ergebnis
  4739 Treffer bei 191 Paketen.
- **Rauschen:** `linux` erreicht die Grenze von 2000 Treffern, `linux-hwe-7.0` hat 640, `mozjs115` 1020; die langsamste
  OSV-Abfrage (Kernel) dauert 1,18 s. In Phase 8 per Mindestpriorität je Asset gelöst (unten).
- **opennetmon-Attrappe** mit fünf Geräten: ein Router „sicher“ (übernommen, als Asset mit Firmware-Version), ein
  zweiter Router und ein Switch „bitte prüfen“, ein Gateway „nicht erkannt“, ein Laptop „wird per SSH erfasst“.
- **CSV** im Browser: Vorschau „3 neu, 0 geändert, 0 unverändert, 1 mit Fehler“.
- Seiten hell/dunkel, 1440 und 390 px geprüft; bei 390 px liefen „Hosts (SSH)“ (484 px) und „opennetmon“ (411 px)
  über, behoben (Raster mit `minmax(0, 1fr)`).
- Danach Test-DB zurückgesetzt (wieder 6 Assets und ein Stichwort; Host, Gerät und opennetmon-Adresse gelöscht).

### Messung der Meldungen (2026-11-06, Laptop, Release-Bau, Test-DB aus Phase 6)

- Testinstanz mit `fetch_sources = true`, alle Quellen in der DB abgeschaltet (keine Abrufe), Mail an `dev/smtp_sink.py`.
- Start: von 2168 offenen Treffern erfüllte 1 die Standardbedingungen (KEV oder Priorität ≥ 85) und galt als bekannt,
  keine Mail.
- Kernel-Paket `linux` 6.1.38-1 (Debian 12) als Asset: 2000 neue Treffer, höchste Priorität 80, keiner in KEV: keine
  Mail (richtig). Paket `exim4` 4.69-1: 66 Treffer, Sofort-Mail in der nächsten Minute mit **16 Schwachstellen** (5 in
  KEV zuerst), Gründe und Links stimmen.
- Abfrage der noch nicht gemeldeten offenen Treffer je Minute: **7 ms** bei 4213 Treffern. Seiten „Sofort-Mail“ 0,11 s,
  „Tagesbericht“ mit Vorschau 0,24 s.
- Tagesbericht auf „jetzt + 2 min“ gestellt: um 18:17:06 gesendet, „Neu seit …: 2519“, kritisch offene ohne Doppelung.
- Seiten hell/dunkel, 1440 und 390 px: kein Überlauf; lange Kästchen-Texte brachen bei 390 px unter das Kästchen,
  behoben.
- Danach Test-DB aus der Sicherung zurückgespielt (wieder 6 Assets, Quellen an, Mail aus; Migration 0009 läuft beim
  nächsten Start).

### Messung des Feinschliffs (2026-11-06, Laptop, Release-Bau, Test-DB aus Phase 7)

- **Priorität neu berechnen:** 16 s bzw. 14 s für 395 498 geänderte CVEs (zwei Läufe mit verschiedenen Gewichten).
- **Erster Start mit Phase 8:** Migrationen `0012`/`0013` einmalig ~26 s, danach Packen im Hintergrund: 725 477 Zeilen
  in 53 s. Verhältnis auf Stichproben: `configs` 4,1×, `affected` 2,8×, `refs` 1,9×.
- **Größe:** `dbstat` 15 s, VACUUM 43 s auf 2,3 GB. Datei 2,21 GB → **1,54 GB** (665 MB frei geworden); Bereiche:
  CVE-Liste 1,8 → 1,0 GB, Advisories 95 MB, Distributionen 419 MB, eigene Daten 606 KB.
- **Nach dem Packen gleich:** CVE-Details und Vorschauen des Abgleichs wie vorher; OpenSSH 14 ms, Linux-Kernel
  0,77 s, Windows 10 0,3 s, CVE-Detail 4 ms.
- **Während des Verkleinerns:** Seiten zuerst 5 s (Sperre beim Schreiben der Sitzung), nach der Korrektur < 0,1 s.
- **Mindestpriorität:** Kernel-Asset (Ubuntu 24.04, 2000 Treffer, davon 3 mit behobener Version) auf 65: Eingang
  **262 statt 2164** offene Treffer, Hinweis „1 872 Schwachstellen ausgeblendet“; Eingang 0,06 s, Lage 0,08 s.
- Seiten hell/dunkel, 1440 und 390 px geprüft (Lage, Eingang, Einstellungen Priorität und Aufbewahrung, Assets und
  Asset-Formular), kein Überlauf.
- Die Test-DB bleibt im neuen Stand (gepackt, verkleinert, Kernel-Asset auf 65); die Sicherung von vorher liegt in
  `dev/data/import-before-phase8c.db` (gitignored).

### Sicherheitstest (Phase 9, 2026-11-06/07)

Vorgehen: Code-Review (Leser der Quellen, HTTP-Client, Importe, Web-Handler, Anmeldung, Geheimnisse, Sicherung,
Units), Fuzztests in `src/fuzz.rs` (eigener Zufallsgenerator, Mutationen der Beispieldateien, `FUZZ_ITERATIONS`/
`FUZZ_SEED`; je Leser 60 000 Runden ohne Absturz, langsamste Eingabe < 1 ms) und ein Angriffsskript gegen eine
Wegwerf-Instanz (Port 8093, eigene DB im Scratchpad).

**Angriffe (536 Prüfungen, 0 Befunde):** alle Seiten ohne Anmeldung (Umleitung), alle 36 POST-Routen ohne/mit falschem
CSRF-Token, fremder `Origin`/`null`/`Sec-Fetch-Site`/`Host`, Sicherheitsköpfe, XSS über Assets, Watchlist, Hostnamen
und eine feindliche CVE (Skript, `img onerror`, `svg onload`, `javascript:`-Link, Formel in der CSV), unsinnige
Parameter und Pfad-Traversal, 20-MB-Formular (413), Referer auf Fehlerseiten, SSRF über Hersteller-URLs (Loopback,
Heimnetz, Link-Local, `file:`), Drossel bei 14 Fehlversuchen und 60 gleichzeitigen Anmeldungen (alle 401/429 in 0,1 s,
andere Adresse meldet sich weiter an), Abmelden, Cookie-Flags. Speicher der Instanz 15 → 122 MB.

**Behoben** (Commits `3158dd6`, `91db83f` und der Ablaufplaner-Fix):
- CSAF-Dokumente, ROLIE-Feeds und KEV: Listen zählen beim Lesen gegen ein Budget (keine Speicher-Verstärkung durch
  viele leere Objekte).
- ZIP-Archive (cvelist, OSV): Archive mit überlappenden Einträgen werden abgelehnt, Lesen bricht beim Abbruch ab.
- Ein langsamer oder kaputter CSAF-Anbieter hält den Lauf nicht mehr auf: höchstens 30 min je Lauf und 20 Fehler in
  Folge, der Rest folgt im nächsten Lauf.
- CVE-Datensätze: höchstens 20 CWEs (vorher quadratische Prüfung), Produkte begrenzt.
- HTTP-Client: Abrufe der Quellen erreichen keine Adressen des eigenen Netzes (Loopback, privat, Link-Local, CGNAT,
  ULA); nur der opennetmon-Import darf ins LAN. `Authorization` erscheint nicht im Debug-Log.
- CSAF: Verzeichnisse mit GREEN/AMBER/RED im Namen werden übersprungen und als eingeschränkt gezählt.
- Debian Security Tracker: Größengrenze 384 MB.
- Gespeichertes SMTP-Passwort gilt nur für denselben Server, Port, dieselbe Verschlüsselung und denselben Benutzer;
  der opennetmon-Token nur für dieselbe URL (sonst neu eingeben).
- SMTP-Anmeldung ohne Verschlüsselung nur noch zu Loopback.
- Aufbewahrung des Protokolls mindestens 90 Tage.
- `backup` löscht bei einem Fehler nur eine selbst angelegte Datei; ein vorhandenes Ziel muss eine leere normale
  Datei sein (nicht Symlink, nicht `/dev/null`).
- Drossel hinter dem Proxy: `client_ip_header = "x-forwarded-for"` steht aktiv in der Beispielkonfiguration, Warnung
  beim Start, wenn er hinter einem Proxy fehlt.
- Sicherungs-Unit gehärtet wie der Dienst (ohne `PrivateNetwork`, wegen Containern).
- **Ablaufplaner:** Eine Instanz mit `fetch_sources = false` startete auf einer neuen DB alle Quellen, weil neue Zeilen
  `next_run_ms = 0` haben und 0 zugleich „Jetzt abrufen“ hieß. Beim Angriffstest lief so ungewollt ein echter
  cvelist-Erstimport an (abgebrochen, Daten gelöscht). Jetzt markiert „Jetzt abrufen“ mit `-1`
  (`storage::sources::REQUESTED`), Test `without_the_scheduler_only_requested_sources_run`.

**Geprüft, ohne Befund:** jede ändernde Route braucht Sitzung und CSRF-Token; Cookies `HttpOnly`, `SameSite=Strict`,
`Secure`; askama escapt überall, Links nur `http(s)`; SQL immer gebunden, FTS-Begriffe gequotet; XChaCha20-Poly1305 für
Geheimnisse; CSV mit Formelschutz; Dienst-Unit gehärtet; CSP `default-src 'self'` ohne Inline-Skripte.

**Bewusst nicht geändert:**
- NVD-Feeds ohne Grenze je Eintrag (fester Host über TLS, Gesamtgrößen begrenzt).
- Advisory-URL als Schlüssel: ein Hersteller-Feed könnte theoretisch eine BSI-Zeile mit derselben URL überschreiben
  (nur bei einem bösartigen, vom Admin eingetragenen Anbieter).
- `allowed_hosts` ist im Paket leer und muss bei der Einrichtung gesetzt werden (postinst und `docs/operations.md`
  sagen es).
- SQLite 3.46 (gebündelt über sqlx) hat bekannte CVEs, die eigenes SQL eines Angreifers brauchen; Update mit sqlx 0.9.
- Fehlertext von VACUUM wird dem Admin angezeigt.
- Zu lange Formularangaben ergeben Status 200 mit Fehlermeldung statt 422.

## Offene Punkte (vor der jeweiligen Phase klären)

- ~~Endgültiger Name (Vorschläge `opensecmon`, `openvulnmon`) und Subdomain.~~ Erledigt: Name `opensecmon`
  (2026-11-04).
- ~~Lizenz und Nutzungsbedingungen der Quellen~~ Geprüft 2026-11-08: Alle Quellen erlauben den Abruf zur Laufzeit
  durch ein selbst betriebenes Programm, keine Klausel widerspricht der AGPL. Hinweispflichten gelten für Kopien der
  Daten (im Repo und im Paket liegen keine, Testdaten sind erfunden). Die Seite „Quellen“ und das README nennen CVE
  (MITRE), NVD (Satz für Feeds angepasst), CISA KEV (CC0), FIRST EPSS, BSI CERT-Bund, Ubuntu (CC BY-SA 4.0) und Debian;
  Hersteller-CSAF verlinken auf ihr Original (Bedingungen je Anbieter, z. B. Red Hat CC BY 4.0). Für Debian (OSV) und den
  Debian Security Tracker nennt Debian keine Lizenz.
- NVD-API-Key ist nicht nötig, weil die JSON-Feeds reichen. Ein Key wäre nur für gezielte Einzelabfragen
  sinnvoll (optional in den Einstellungen).
- Hersteller ohne CSAF (viele Heimrouter, Switches und NAS-Systeme): Abdeckung über BSI CERT-Bund prüfen,
  sobald Stufe 2 läuft. Eigene Abrufer für RSS- oder HTML-Seiten nur bei echten Lücken und erst nach dem ersten
  Release.

### Befunde aus dem Betrieb (2026-11-07, Test-Paket 0.2.0-1, SSH-Import eines Ubuntu-26.04-Servers und eines Raspberry Pi mit Debian 13)

Aus der DB der Betriebsinstanz gelesen (nur lesend):

1. **Kernel des Raspberry Pi wird gegen Debians Kernel geprüft.** Raspberry Pi OS liefert den Kernel aus
   `archive.raspberrypi.com`, Quellpaket ebenfalls `linux`, Version mit `+rpt`. Der Abgleich nahm dafür die
   OSV-Bereiche und den Tracker von Debians `linux` (anderer Kernel-Zweig) → mehrere hundert Treffer ohne Aussage.
   Andere `+rpt`-Pakete (z. B. `glibc`, `bluez`) sind nachgebaute Debian-Pakete und dürfen weiter abgeglichen
   werden. `dpkg-query` liefert die Herkunft nicht, also bleibt die Versionsendung das Merkmal.
2. **Debians und Ubuntus Einstufung floss nicht in die Priorität ein.** Viele Treffer führt der Tracker als
   „unimportant“ oder „no-dsa“, nur wenige haben eine Korrektur; bei Ubuntu fast alle „medium“ oder „low“.
3. **Kernel: installiert statt laufend.** Bei mehreren installierten Kerneln zählt die höchste Version, laufen kann
   eine ältere (Neustart steht aus, ggf. Livepatch).
4. **Dieselbe Lücke mehrfach je Host:** `qemu` und `qemu-hwe`, `grub2-signed`/`grub2-unsigned`, viele
   `linux-firmware-*`-Assets. Im Eingang stört es wenig, in den Zahlen je Host und auf der Lage-Seite schon.
5. **Ubuntu Pro wurde nicht erkannt**, solange noch kein ESM-Paket installiert war; von Hand nachtragen half nicht,
   weil das Lesen den Wert zurücksetzte.

Bewertung und Umsetzung im Abschnitt „Vorhaben: Rauschen im Betrieb“.

## Verifikation

- Unit-Tests je Parser mit gespeicherten Beispieldateien der Quellen (keine Netzzugriffe in den Tests).
- Debian-Versionsvergleich mit den Testfällen von dpkg.
- Abgleich-Tests: Asset + Advisory ergibt den erwarteten Treffer und das erwartete Vertrauen.
- Fake-SMTP für die Mails.
- Handler-Tests mit `axum`/`tower` wie in opennetmon.
- Ende zu Ende auf dem Laptop:
  - Testinstanz starten, Erstimport aller Quellen, Laufzeit und DB-Größe messen.
  - Ein Asset anlegen (z. B. `openssh-server` mit alter Version) und prüfen, dass ein Treffer und eine Mail kommen
    (2026-11-06 mit `exim4` 4.69-1 und `dev/smtp_sink.py`).
  - Den SSH-Import mit Zwangsbefehl testen (2026-11-06 mit `fake_ssh_host` und der Paketliste des Laptops; echte
    Hosts erst nach OK).
  - Im Browser prüfen.
- Vor jedem Commit fmt, clippy `-D warnings`, Tests, `cargo deny`; CI grün.
