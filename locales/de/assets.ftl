## Assets (Seite „Assets“, Formular, Watchlist)

assets-areas = Bereiche der Assets
assets-tab-assets = Assets
assets-tab-watchlist = Watchlist
assets-search = Assets durchsuchen
assets-search-placeholder = Asset, Paket, Version, Host suchen
assets-kind-any = Alle Arten
assets-open-only = nur mit offenen Treffern
assets-filter = Filtern
assets-add = Asset anlegen
assets-add-here = Asset hier anlegen
assets-none-title = Noch keine Assets
assets-none-text = Lege deine Software, Pakete und Geräte an. Nur Meldungen, die dazu passen, landen im Eingang.
assets-none-filtered = Kein Asset passt zum Filter.
assets-col-asset = Asset
assets-col-version = Version
assets-col-kind = Art
assets-col-detail = Kennung / Notiz
assets-col-open = Offene Treffer
assets-toggle = Auf- oder zuklappen
assets-no-host = Ohne Host
assets-group-count = { $count ->
    [one] 1 Asset
   *[other] { $count } Assets
}
assets-open-count = { $count } offen
assets-open-none = keine
assets-group-open = { $count ->
    [one] 1 Schwachstelle offen
   *[other] { $count } Schwachstellen offen
}
assets-shown = { $shown } von { $total } Assets

asset-kind-package = Paket (Debian/Ubuntu)
asset-kind-software = Software
asset-kind-hardware = Hardware / Firmware
asset-new-title = Asset anlegen
asset-back = Assets
asset-matched = Zuletzt abgeglichen
asset-kind = Art
asset-kind-package-help = Pakete werden mit den Daten von Debian und Ubuntu abgeglichen, Software und Geräte mit CVE, NVD und CSAF.
asset-fields-package = Paket
asset-fields-product = Produkt
asset-distro = Distribution
asset-release = Release
asset-release-help = Debian: Hauptversion (12, 13), Ubuntu: Jahr und Monat (24.04)
asset-pro = Ubuntu Pro (ESM) ist aktiv
asset-pro-help = Dann zählen die Korrekturen aus Ubuntu Pro, sofern es welche gibt.
asset-package = Paketname
asset-package-help = Binär- oder Quellpaket wie bei dpkg, z. B. openssh-server
asset-vendor = Hersteller
asset-vendor-help = Vorschläge aus CVE-, NVD- und CSAF-Angaben
asset-product = Produkt
asset-cpe = Kennung (CPE 2.3, optional)
asset-cpe-help = Füllt Hersteller, Produkt und Version, wenn sie leer sind. Nur angeben, wenn du sie kennst.
asset-version = Version
asset-version-help = Bei Paketen die Version wie bei dpkg (mit Epoche und Revision), sonst wie beim Hersteller
asset-host = Host / Gerät
asset-host-help = Gruppiert die Assets und erscheint im Eingang
asset-note = Notiz
asset-preview-title = Vorschau der Treffer
asset-preview-hint = Gib Produkt oder Paket und Version an, dann siehst du hier, welche Meldungen zurzeit passen.
asset-no-source-pi = ohne Datenquelle (Raspberry-Pi-Kernel)
asset-no-source-pi-note = Kernel und Firmware von Raspberry Pi OS baut Raspberry Pi selbst. Die Daten von Debian passen nicht dazu, deshalb gleicht opensecmon dieses Paket nicht ab. Updates dafür kommen über apt von Raspberry Pi.
asset-preview-none = Zurzeit keine bekannte Meldung für diese Angaben.
asset-preview-count = { $count ->
    [one] Würde zurzeit 1 Meldung treffen.
   *[other] Würde zurzeit { $count } Meldungen treffen.
}
asset-preview-more = und { $count } weitere
asset-save = Speichern
asset-preview = Vorschau
asset-cancel = Abbrechen
asset-delete = Asset löschen
asset-delete-help = Löscht das Asset mit allen seinen Treffern und deren Bearbeitungsstand.

asset-error-kind = Unbekannte Art.
asset-error-too-long = Eine Angabe ist zu lang.
asset-error-control = Eine Angabe enthält Steuerzeichen.
asset-error-distro = Wähle Debian oder Ubuntu.
asset-error-release = Das Release passt nicht: bei Debian eine Zahl (13), bei Ubuntu Jahr.Monat (24.04).
asset-error-package = Der Paketname passt nicht (Kleinbuchstaben, Ziffern, + - . wie bei dpkg).
asset-error-package-version = Die Paketversion muss mit einer Ziffer beginnen (z. B. 1:9.6p1-3ubuntu13.4).
asset-error-cpe = Die Kennung ist keine gültige CPE 2.3 (cpe:2.3:a:hersteller:produkt:…).
asset-error-product = Gib ein Produkt an (oder eine CPE).

watch-title = Watchlist
watch-text = Stichwörter für Geräte und Programme ohne saubere Kennung. Gesucht wird in Titel und Produktangaben der Advisories. Treffer daraus haben das Vertrauen
watch-none = Noch keine Stichwörter.
watch-open = { $count } offen
watch-since = seit
watch-delete = Stichwort entfernen
watch-keyword = Stichwort hinzufügen
watch-add = Hinzufügen
watch-add-help = Ganze Wörter, ohne Groß-/Kleinschreibung. Neue Stichwörter schauen 30 Tage zurück.
watch-error-short = Das Stichwort braucht mindestens drei Zeichen aus Buchstaben oder Ziffern.
watch-error-exists = Dieses Stichwort ist schon auf der Watchlist.

## Treffer

match-confidence-high = hoch
match-confidence-medium = mittel
match-confidence-low = niedrig
match-method-distro = Distribution (Paketversion)
match-method-nvd = NVD (CPE und Version)
match-method-cna = CVE-Datensatz (Produkt und Version)
match-method-csaf = Advisory (Produktbaum)
match-method-watch = Stichwort der Watchlist

flash-asset-added = Asset angelegt und abgeglichen.
flash-asset-saved = Asset gespeichert und neu abgeglichen.
flash-asset-deleted = Asset gelöscht.
flash-watch-added = Stichwort hinzugefügt und abgeglichen.
flash-watch-deleted = Stichwort entfernt.
asset-min-prio = Im Eingang erst ab Priorität
asset-min-prio-help = Leer oder 0: alle Treffer. Treffer darunter bleiben gespeichert und erscheinen nur mit dem Filter auf dieses Asset, nicht in Zählern, Lage und Mails. Für Kernel-Pakete aus dem SSH-Import ist 65 voreingestellt.
asset-error-min-prio = Die Mindestpriorität muss eine ganze Zahl von 0 bis 100 sein.
assets-min-prio-title = Treffer unter Priorität { $prio } sind gedämpft
