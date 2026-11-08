# Import der Assets: Hosts per SSH, opennetmon, CSV (Phase 6).

assets-tab-hosts = Hosts (SSH)
assets-tab-opennetmon = Import aus opennetmon
assets-tab-csv = CSV-Import
assets-hidden = { $count ->
    [one] 1 weiteres Paket ohne offene Meldungen
   *[other] { $count } weitere Pakete ohne offene Meldungen
}
assets-show-all = alle zeigen
assets-all-hosts = Alle Hosts zeigen
asset-origin-ssh = SSH
asset-origin-opennetmon = opennetmon
asset-origin-csv = CSV
asset-origin-ssh-note = Dieses Paket kommt aus der Abfrage des Hosts per SSH. Die nächste Abfrage überschreibt Änderungen und legt gelöschte Pakete wieder an.
asset-origin-onm-note = Dieses Asset folgt einem Gerät aus opennetmon. Erkennt die Regel die Firmware sicher, übernimmt die nächste Abfrage die Version des Geräts.
asset-origin-onm-new = Das Asset wird mit dem Gerät „{ $device }“ aus opennetmon verknüpft.

hosts-title = Hosts (SSH)
hosts-add = Host hinzufügen
hosts-none-title = Noch keine Hosts
hosts-none-text = Ein Host liefert über SSH seine installierten Pakete. Der Schlüssel darf dort nur ein Skript ausführen, das Systemangaben und die Listen der Pakete, Snaps und Flatpaks ausgibt.
hosts-col-name = Name
hosts-col-address = Adresse
hosts-col-system = System
hosts-col-packages = Pakete
hosts-col-last = Letzte Abfrage
hosts-col-state = Zustand
hosts-affected = { $vulns ->
    [one] 1 Schwachstelle
   *[other] { $vulns } Schwachstellen
} in { $count ->
    [one] 1 Paket
   *[other] { $count } Paketen
}
hosts-next = nächste
hosts-continue = Weiter einrichten
hosts-run = Jetzt abfragen
hosts-footer = Abfrage alle 6 h über einen eigenen Schlüssel. Ein Paket ist hier ein Quellpaket mit der höchsten installierten Version; die Liste der Assets zeigt nur Pakete mit offenen Meldungen.
hosts-own-key = Öffentlicher Schlüssel von opensecmon
hosts-own-key-text = Gehört zu allen Hosts. Der private Schlüssel liegt verschlüsselt in der Datenbank und verlässt opensecmon nicht.
hosts-state-off = aus
hosts-state-setup = Einrichtung offen
hosts-state-key = Host-Schlüssel bestätigen
hosts-state-key-changed = Host-Schlüssel geändert
hosts-state-error = Fehler
hosts-state-ok = ok
hosts-state-waiting = noch nicht abgefragt
hosts-step-connection = Verbindung
hosts-step-key = Schlüssel hinterlegen
hosts-step-confirm = Host-Schlüssel bestätigen
hosts-step-test = Testen
hosts-name = Name
hosts-name-help = So heißt der Host in den Assets und im Eingang.
hosts-address = Adresse
hosts-port = Port
hosts-user = Benutzer auf dem Host
hosts-user-help = Ein eigener Benutzer ohne Rechte reicht.
hosts-moved-help = Eine neue Adresse oder ein neuer Port verlangt, den Host-Schlüssel erneut zu bestätigen.
hosts-next-step = Weiter
hosts-manage = Verwalten
hosts-show-setup = Anleitung zur Einrichtung zeigen
hosts-show-packages = { $count ->
    [one] 1 Paket zeigen
   *[other] { $count } Pakete zeigen
}
hosts-disable = Abfrage ausschalten
hosts-disable-help = Die Pakete bleiben, werden aber nicht mehr aktualisiert.
hosts-enable = Abfrage einschalten
hosts-delete = Host entfernen
hosts-delete-help = Entfernt den Host mit allen seinen Paketen und deren Treffern.
hosts-setup-title = Host einrichten
hosts-setup-user = 1. Lege auf dem Host den Benutzer an:
hosts-setup-script = 2. Speichere dieses Skript als
hosts-setup-home = Home-Verzeichnis
hosts-setup-groups = Lässt der SSH-Server nur bestimmte Gruppen herein (AllowGroups, bei openmediavault die Gruppe _ssh), nimm den Benutzer dort auf. Sonst überspringen.
hosts-setup-key = 3. Hinterlege den Schlüssel (eine Zeile) in
hosts-setup-key-help = restrict verbietet Terminal und Weiterleitungen, command= erlaubt nur das Skript. Der Schlüssel kann also nur Systemangaben und die Listen der Pakete, Snaps und Flatpaks lesen.
hosts-back = Zurück
hosts-connect = Verbinden
hosts-key-changed = Der Host meldet einen anderen Schlüssel als bisher. Das kann eine Neuinstallation sein oder ein fremder Rechner unter dieser Adresse. Bisher bestätigt:
hosts-key-shown = Beim Verbinden meldet der Host diesen Host-Schlüssel:
hosts-key-compare = Vergleiche ihn auf dem Host. Erst nach deiner Bestätigung wird er gespeichert. Ändert er sich später, bricht die Abfrage ab und du bekommst hier eine Meldung.
hosts-key-ok = Der Fingerabdruck stimmt mit dem auf dem Host überein
hosts-confirm = Bestätigen und testen
hosts-result = Verbindung ok. { $system }, { $count ->
    [one] 1 Paket gelesen.
   *[other] { $count } Pakete gelesen.
}
hosts-result-open = { $count ->
    [one] 1 Paket hat offene Meldungen, sie stehen im Eingang.
   *[other] { $count } Pakete haben offene Meldungen, sie stehen im Eingang.
}
hosts-result-none = Der Host-Schlüssel ist bestätigt. Die Pakete werden bei der nächsten Abfrage gelesen.
hosts-done = Pakete ansehen

ssh-error-name = Der Name darf nur Buchstaben, Ziffern, Punkt, Binde- und Unterstrich enthalten (höchstens 100 Zeichen).
ssh-error-name-taken = Ein Host oder Rechner mit diesem Namen ist schon angelegt.
ssh-error-address = Bitte eine IP-Adresse oder einen Hostnamen angeben.
ssh-error-port = Der Port muss zwischen 1 und 65535 liegen.
ssh-error-username = Der Benutzername passt nicht (Kleinbuchstaben, Ziffern, _ und -, höchstens 32 Zeichen).
ssh-error-connect = Keine Verbindung zum Host.
ssh-error-timeout = Der Host hat nicht rechtzeitig geantwortet.
ssh-error-key-unknown = Der Host-Schlüssel ist noch nicht bestätigt.
ssh-error-key-changed = Der Host meldet einen anderen Host-Schlüssel. Die Abfrage ist gestoppt, bis du den neuen Schlüssel bestätigst.
ssh-error-auth = Der Host lehnt den Schlüssel ab. Steht die Zeile in authorized_keys des richtigen Benutzers?
ssh-error-command = Das Skript auf dem Host ist fehlgeschlagen.
ssh-error-too-large = Die Ausgabe des Hosts ist zu groß.
ssh-error-output = Die Ausgabe des Hosts hat nicht das erwartete Format. Ist das Skript unverändert?
ssh-error-system = Das System des Hosts wird nicht unterstützt (nur Debian und Ubuntu).
ssh-error-no-packages = Der Host hat keine installierten Pakete gemeldet.

onm-title = Import aus opennetmon
onm-last-error = Letzte Abfrage fehlgeschlagen:
onm-connection = Verbindung zu opennetmon
onm-last = zuletzt abgefragt
onm-connection-text = opensecmon liest die Geräte lesend über einen Endpunkt von opennetmon mit eigenem Token. Den Endpunkt bringt eine kommende Version von opennetmon mit:
onm-url = Adresse von opennetmon
onm-url-help = HTTPS; HTTP nur auf diesem Rechner (localhost), damit das Token nicht unverschlüsselt durchs Netz geht.
onm-token = Token
onm-token-kept = gespeichert, leer lassen zum Behalten
onm-token-help = Wird verschlüsselt gespeichert und nicht wieder angezeigt.
onm-cert = Fingerabdruck des Zertifikats (SHA-256, optional)
onm-cert-help = Nur für ein selbstsigniertes Zertifikat, etwa wenn opennetmon auf demselben Server unter https://127.0.0.1:8443 läuft. Dann nimmt opensecmon genau dieses Zertifikat an und sonst keines. Leer lassen, wenn das Zertifikat von einer bekannten Stelle stammt (z. B. Let's Encrypt).
onm-remove = Verbindung entfernen
onm-devices = Geräte aus opennetmon
onm-counts = { $count } Geräte, { $taken } übernommen
onm-none-title = Noch keine Geräte
onm-none-text = Sobald die Verbindung steht, erscheinen hier die Geräte aus opennetmon mit einem Vorschlag für Hersteller, Produkt und Version.
onm-col-device = Gerät in opennetmon
onm-col-suggestion = Vorschlag
onm-col-rule = Erkannt durch
onm-gone = nicht mehr in opennetmon
onm-via-ssh = wird per SSH erfasst
onm-taken = übernommen
onm-skipped = übersprungen
onm-unskip = Wieder aufnehmen
onm-take = Übernehmen
onm-change = Ändern
onm-skip = Überspringen
onm-footer = Abfrage alle 6 h. Übernommene Geräte werden zu Assets; erkennt die Regel die Firmware sicher, folgt die Version dem Gerät.
onm-sure-yes = sicher
onm-sure-check = bitte prüfen
onm-sure-none = nicht erkannt
onm-version-unknown = Version unbekannt
onm-rule-avm = Regel „AVM FRITZ!Box“
onm-rule-cisco = Regel „Cisco IOS“
onm-rule-mikrotik = Regel „MikroTik RouterOS“
onm-rule-tp-link = Regel „TP-Link“
onm-rule-huawei = Regel „Huawei“
onm-rule-enterprise = Hersteller aus sysObjectID
onm-rule-linux = Linux-Host: Pakete besser per SSH lesen
onm-rule-none = keine Regel
onm-error-url = Die Adresse ist keine gültige http(s)-Adresse ohne Anmeldedaten, Abfrage und Anker.
onm-error-http = HTTP ist nur auf diesem Rechner erlaubt; im Netz bitte HTTPS.
onm-error-no-token = Bitte ein Token angeben.
onm-error-token-again = Adresse oder Fingerabdruck haben sich geändert: Bitte das Token erneut eingeben.
onm-error-token-format = Das Token ist zu lang oder enthält Steuerzeichen.
onm-error-token = opennetmon lehnt das Token ab.
onm-error-missing = opennetmon kennt den Endpunkt nicht (zu alte Version?).
onm-error-fetch = opennetmon ist nicht erreichbar.
onm-error-format = Die Antwort von opennetmon hat nicht das erwartete Format.
onm-error-redirect = opennetmon leitet die Anfrage um, und mit Token folgt opensecmon keiner Weiterleitung. Steht ein Proxy mit Anmeldung davor (z. B. Cloudflare Access), oder zeigt der Name auf diesem Server woandershin? Ziel der Weiterleitung
onm-error-cert = opensecmon vertraut dem Zertifikat von opennetmon nicht (etwa weil es selbstsigniert ist). Stimmt dieser SHA-256-Fingerabdruck mit dem von opennetmon überein, ihn oben eintragen
onm-error-pin-mismatch = Das Zertifikat von opennetmon ist nicht das mit dem eingetragenen Fingerabdruck (neues Zertifikat oder ein anderer Server?). Fingerabdruck des vorgelegten Zertifikats
onm-error-pin = Der Fingerabdruck ist kein SHA-256-Wert (64 Hexadezimalzeichen, Doppelpunkte erlaubt).
onm-error-pin-http = Ein Fingerabdruck gilt nur für eine HTTPS-Adresse.

csv-title = CSV-Import
csv-drop = CSV-Datei hierher ziehen oder auswählen
csv-rules = UTF-8, Trennzeichen Komma oder Semikolon, höchstens { $count } Zeilen, 1 MiB
csv-text = Inhalt der CSV-Datei
csv-text-help = Einfügen oder oben eine Datei wählen. Die erste Zeile nennt die Spalten.
csv-import = { $count ->
    [one] 1 Zeile übernehmen
   *[other] { $count } Zeilen übernehmen
}
csv-col-line = Zeile
csv-col-state = Ergebnis
csv-columns = Spalten
csv-columns-help = typ (paket, software, hardware), hersteller, produkt, version, host, cpe; für Pakete distro (debian, ubuntu) und release; notiz optional. Englische Namen gehen auch. Zeilen mit gleicher Art, gleichem Hersteller, Produkt und Host ändern ein vorhandenes Asset; Assets aus SSH und opennetmon bleiben unberührt.
csv-state-new = neu
csv-state-update = ändert ein Asset
csv-state-same = unverändert
csv-state-error = Fehler
csv-summary = { $new } neu, { $update } geändert, { $same } unverändert, { $errors } mit Fehler
csv-more = und { $count } weitere Zeilen
csv-error-empty = Die Datei enthält keine Zeilen.
csv-error-header = Die erste Zeile muss die Spalten nennen, mindestens „produkt“.
csv-error-rows = Die Datei hat zu viele Zeilen.
csv-error-size = Die Datei ist zu groß.
csv-error-twice = Dieselbe Zeile steht weiter oben schon.

flash-host-saved = Host gespeichert.
flash-host-read = Host abgefragt und abgeglichen.
flash-host-deleted = Host mit seinen Paketen entfernt.
flash-onm-saved = Verbindung zu opennetmon gespeichert.
flash-onm-read = Geräte aus opennetmon gelesen.
flash-device-taken = Gerät übernommen und abgeglichen.
flash-csv-imported = CSV-Datei übernommen und abgeglichen.

## Computers of the agent API (they report their software themselves)
assets-tab-computers = Rechner (Agent)
computers-title = Rechner (Agent)
computers-add = Rechner hinzufügen
computers-add-intro = Ein Rechner meldet seine installierte Software selbst an opensecmon, nur aus dem lokalen Netz. Gib ihm einen Namen; danach zeigt die Seite den Einmalcode, mit dem er sich anmeldet.
computers-create = Anlegen und Code zeigen
computers-none-title = Noch keine Rechner
computers-none-text = Rechner wie Laptops und Desktop-PCs melden ihre Software selbst, wenn sie im lokalen Netz sind. Lege einen Rechner an und melde ihn mit dem angezeigten Code an.
computers-col-agent = Programm
computers-col-seen = Zuletzt gesehen
computers-footer = Die Schnittstelle nimmt nur Anfragen aus den erlaubten Netzen an (agent_networks in der Konfiguration, ohne Eintrag private und lokale Adressen). Jeder Rechner hat ein eigenes Token.
computers-state-waiting = wartet auf Anmeldung
computers-state-expired = Code abgelaufen
computers-state-enrolled = angemeldet
computers-state-revoked = gesperrt
computers-enroll-title = Anmelden
computers-enroll-intro = Diese Angaben braucht das Programm auf dem Rechner. Der Code gilt 15 Minuten und nur einmal.
computers-code = Einmalcode
computers-code-valid = gültig bis
computers-url = Adresse
computers-fingerprint = Fingerabdruck des Zertifikats (SHA-256)
computers-cert-download = Zertifikat herunterladen (opensecmon.pem)
computers-cert-none = opensecmon läuft ohne eigenes HTTPS hinter einem Proxy: der Rechner prüft dessen Zertifikat wie ein Browser, ein Fingerabdruck ist nicht nötig.
computers-try = Von Hand mit curl (zum Ausprobieren, im Ordner mit opensecmon.pem)
computers-try-help = Die Antwort enthält das Token des Rechners. Es wird nur dieses eine Mal angezeigt; bewahre es nur für root lesbar auf.
computers-status-cmd = Token und Verbindung prüfen:
computers-details = Angaben des Rechners
computers-hostname = Gemeldeter Hostname
computers-enrolled = Angemeldet
computers-never = noch nie
computers-rename = Umbenennen
computers-new-code = Neuen Code erzeugen
computers-new-code-help = Der alte Code gilt dann nicht mehr. Meldet sich der Rechner mit dem neuen an, gilt sein bisheriges Token nicht mehr; seine Assets bleiben.
computers-revoke = Sperren
computers-revoke-help = Das Token gilt sofort nicht mehr. Die Assets bleiben, bis du den Rechner entfernst.
computers-delete = Rechner entfernen
computers-delete-help = Entfernt den Rechner mit allen Assets, die er gemeldet hat, und deren Treffern.
computers-state-reporting = meldet
computers-state-error = Meldung abgelehnt
computers-last-report = Letzte Meldung
computers-last-error = Die letzte Meldung wurde nicht übernommen:
computers-script-title = Debian und Ubuntu (auch Mint, Zorin, Pop!_OS …)
computers-script-intro = Das Skript meldet den Rechner an und richtet einen systemd-Timer ein, der alle 6 Stunden die Listen der Pakete, Snaps und Flatpaks schickt.
computers-script-download = Skript herunterladen (opensecmon-agent.sh)
computers-update-title = Skript aktualisieren
computers-update-intro = Eine neue Fassung des Skripts ersetzt die alte; Anmeldung, Token und Timer bleiben.
computers-update-help = Im Ordner mit dem heruntergeladenen Skript ausführen. Die nächste Meldung schickt der Timer, sofort mit: sudo systemctl start opensecmon-agent.service
computers-script-help = Im Ordner mit dem Skript (und opensecmon.pem, falls oben angeboten) ausführen. Das Token liegt danach nur für root lesbar in /etc/opensecmon-agent; die Meldungen laufen ohne root-Rechte. Entfernen mit: sudo opensecmon-agent uninstall
computers-windows-title = Windows 10, Windows 11 und Windows Server ab 2019
computers-windows-intro = Das PowerShell-Skript meldet den Rechner an und richtet eine geplante Aufgabe ein, die beim Start und alle 6 Stunden Windows und die installierten Programme schickt.
computers-windows-download = Skript herunterladen (opensecmon-agent.ps1)
computers-windows-help = In einer PowerShell als Administrator im Ordner mit dem Skript (und opensecmon.pem, falls oben angeboten) ausführen. Das Token liegt danach nur für SYSTEM und Administratoren lesbar in C:\ProgramData\opensecmon-agent, die Aufgabe „opensecmon-agent“ läuft als SYSTEM. Entfernen mit: powershell -ExecutionPolicy Bypass -File C:\ProgramData\opensecmon-agent\opensecmon-agent.ps1 uninstall
computers-update-intro-windows = Eine neue Fassung des Skripts ersetzt die alte; Anmeldung, Token und geplante Aufgabe bleiben.
computers-update-help-windows = In einer PowerShell als Administrator im Ordner mit dem heruntergeladenen Skript ausführen. Die nächste Meldung schickt die geplante Aufgabe, sofort mit: Start-ScheduledTask opensecmon-agent
computers-error-system = Das System wird nicht unterstützt (nur Debian, Ubuntu und darauf aufbauende Systeme).
computers-error-windows = Diese Windows-Version wird nicht unterstützt (nur Windows 10, Windows 11 und Windows Server ab 2016).
computers-error-output = Die Meldung hat nicht das Format des Inventar-Skripts.
computers-error-no-packages = Die Meldung enthält keine installierten Pakete.
asset-origin-agent = Agent
asset-origin-agent-note = Dieses Asset hat der Rechner selbst gemeldet. Die nächste Meldung überschreibt Änderungen und legt gelöschte Assets wieder an.
flash-computer-saved = Rechner gespeichert.
flash-computer-code = Neuer Einmalcode erzeugt.
flash-computer-revoked = Rechner gesperrt.
flash-computer-deleted = Rechner entfernt.

# Ubuntu Pro je Host oder Rechner
pro-mode-label = Ubuntu Pro
pro-mode-auto = automatisch erkennen
pro-mode-yes = ja, aktiv
pro-mode-no = nein
pro-mode-help-detected = Automatisch: erkannt, ein Paket aus Ubuntu Pro (ESM) ist installiert. Alle Pakete dieses Hosts folgen der Einstellung, das Lesen überschreibt sie nicht.
pro-mode-help-not-detected = Automatisch: nicht erkannt, denn erkannt wird Pro erst, wenn ein Paket aus Ubuntu Pro (ESM) installiert ist. Ist der Host angemeldet, „ja“ wählen. Alle Pakete dieses Hosts folgen der Einstellung.
pro-mode-invalid = Unbekannte Einstellung für Ubuntu Pro.
asset-pro-from-host = Ubuntu Pro folgt der Einstellung des Hosts.
asset-pro-from-host-link = Einstellung ändern

kernel-running = Kernel { $running }
kernel-reboot = Neustart nötig, läuft Kernel { $running }
kernel-reboot-installed = Neustart nötig, läuft Kernel { $running }, installiert { $installed }
assets-tab-unassigned = Nicht zugeordnet
items-type-os = System
items-type-win = Windows-Programm
items-type-appx = Store-App
items-type-snap = Snap
items-type-flatpak = Flatpak
unassigned-title = Nicht zugeordnet
unassigned-text = Programme, Store-Apps, Snaps und Flatpaks, die Rechner und Hosts melden und die noch keinem Produkt zugeordnet sind. Erst zugeordnet werden sie zu Assets und gegen die Schwachstellen abgeglichen. Eine Zuordnung oder „Ignorieren“ gilt für alle Rechner und Hosts.
unassigned-built-in = Eingebaute Regeln ordnen { $assigned } Einträge zu und ignorieren { $ignored } (Store-Apps von Windows, Web-Apps von Chrome, Basis-Snaps von Ubuntu).
unassigned-none = Alle gemeldeten Programme sind zugeordnet oder ignoriert.
unassigned-more = und { $count } weitere
unassigned-col-entry = Eintrag
unassigned-col-versions = Versionen
unassigned-col-computers = Rechner und Hosts
unassigned-assign = Zuordnen
unassigned-ignore = Ignorieren
unassigned-user-scope = auch für einzelne Benutzer installiert
unassigned-rules = Eigene Regeln
unassigned-rules-text = Zuordnungen und ignorierte Einträge, die für alle Rechner und Hosts gelten; sie gehen den eingebauten Regeln vor. Entfernen macht die Einträge wieder „nicht zugeordnet“ (oder lässt die eingebaute Regel gelten) und löscht ihre Assets.
unassigned-rules-none = Noch keine eigenen Regeln.
unassigned-rule-ignored = ignoriert
unassigned-rule-delete = Entfernen
unassigned-assign-title = Einem Produkt zuordnen
unassigned-assign-text = Hersteller und Produkt so, wie die CVE-Liste sie nennt (die Vorschläge kommen aus ihr). Die Version kommt bei jedem Rechner und Host aus seiner Meldung; die Vorschau zeigt die Treffer für die neueste gemeldete Version.
unassigned-save = Zuordnen
unassigned-back = Nicht zugeordnet
unassigned-entry = Gemeldeter Eintrag
unassigned-publisher = Herausgeber
flash-item-assigned = Zugeordnet; die Rechner mit diesem Eintrag haben jetzt das Asset, der Abgleich läuft im Hintergrund.
flash-item-ignored = Ignoriert; der Eintrag erscheint bei keinem Rechner mehr.
flash-rule-deleted = Regel entfernt.
computers-unassigned = { $count } nicht zugeordnet

## opensecagent: enrollment code, downloads and updates
computers-agent-title = Mit opensecagent (empfohlen)
computers-agent-step-download = opensecagent auf dem Rechner installieren:
computers-agent-step-code = Den Anmeldecode kopieren. Der Installer (Windows) bzw. der Anmeldedialog im Startmenü (Linux) übernimmt ihn von selbst; sonst dort einfügen.
computers-agent-code-help = Der Code enthält Adresse, Zertifikat und Einmalcode. Er gilt nur einmal, bis
computers-agent-scripts = Ohne opensecagent: Skripte und Angaben einzeln
computers-agent-windows = Windows
computers-agent-debian = Debian und Ubuntu
computers-agent-update-title = opensecagent aktualisieren
computers-agent-update-button = Auf { $version } aktualisieren
computers-agent-update-help = Der Rechner holt das Update bei seiner nächsten Meldung (spätestens nach 15 Minuten), prüft die Signatur und installiert es.
computers-agent-update-waiting = Update auf { $version } angefordert, wartet auf die nächste Meldung des Rechners
computers-agent-update-since = seit
computers-agent-update-sent = Update auf { $version } an den Rechner übergeben am
computers-agent-update-cancel = Zurücknehmen
computers-agent-update-failed = Das letzte Update ist fehlgeschlagen:
computers-agent-update-current = opensecagent { $version } ist aktuell.
computers-agent-update-own = Dieses opensecagent installiert keine Updates (selbst gebaut oder ohne Signaturschlüssel); bitte von Hand aktualisieren.
computers-update-available-short = Update verfügbar: { $version }
computers-update-requested-short = Update angefordert
computers-update-all = Alle aktualisieren ({ $count })
flash-computer-update = Update angefordert. Der Rechner holt es bei seiner nächsten Meldung.
flash-computer-update-cancelled = Update zurückgenommen.
