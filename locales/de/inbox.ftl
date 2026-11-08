## Eingang und Triage

inbox-filters = Filter
inbox-close-filters = Filter schließen
inbox-views = Ansichten
inbox-view-open = Offen
inbox-view-critical = Kritisch + KEV
inbox-view-new = Neu seit gestern
inbox-view-later = Später
inbox-view-done = Erledigt
inbox-view-ignored = Ignoriert
inbox-group-sev = Schwere
inbox-group-kev = Ausnutzung
inbox-kev-only = Nur KEV
inbox-group-fix = Korrektur
inbox-fix-only = Korrektur angekündigt
inbox-group-conf = Vertrauen
inbox-group-kind = Art
inbox-kind-watch = Watchlist
inbox-group-host = Host / Gerät
inbox-asset = Asset
inbox-reset = zurücksetzen
inbox-reset-all = Alle Filter entfernen
inbox-remove = Filter entfernen
inbox-list = Treffer
inbox-count = { $count ->
    [one] 1 Meldung
   *[other] { $count } Meldungen
}
inbox-more = { $count } weitere, bitte filtern
inbox-select-all = Alle auswählen
inbox-select = Auswählen
inbox-selected = ausgewählt
inbox-bulk-clear = Auswahl aufheben
inbox-sort = Sortierung
inbox-sort-prio = Priorität
inbox-sort-new = Neueste zuerst
inbox-sort-host = Nach Host
inbox-apply = Anwenden
inbox-new = neu
inbox-until = bis { $date }
inbox-assets = { $count } Treffer
inbox-keyword = Stichwort „{ $keyword }“
inbox-age-today = heute
inbox-age-days = { $count ->
    [one] 1 Tag
   *[other] { $count } Tage
}
inbox-age-weeks = { $count } Wo.
inbox-keys = j k wählen · e erledigt · s später · i ignorieren · o Quelle · x markieren
inbox-detail = Details
inbox-detail-empty = Keine Meldung ausgewählt.
inbox-done-title = Alles erledigt
inbox-done-text = Keine offenen Treffer für deine Assets.
inbox-checked = Letzte Prüfung der Quellen:
inbox-to-situation = Zur Lage
inbox-nothing-title = Nichts gefunden
inbox-nothing-text = Keine Meldung passt zu diesen Filtern.
inbox-setup-title = Noch keine Assets
inbox-setup-text = Der Eingang zeigt nur Meldungen, die deine Software, Pakete und Geräte betreffen. Lege sie an oder setze Stichwörter auf die Watchlist.
inbox-setup-assets = Asset anlegen
inbox-setup-watch = Watchlist
inbox-error-action = Unbekannte Aktion.

match-state-new = neu
match-state-seen = offen
match-state-later = zurückgestellt bis { $date }
match-state-done = erledigt
match-state-resolved = erledigt (nicht mehr betroffen)
match-state-ignored = ignoriert

own-installed = installiert
own-fixed = behoben in
own-rating = { $distro } stuft ein: { $rating } (−{ $points } Punkte)
rating-unimportant = unwichtig („unimportant“)
rating-negligible = unbedeutend („negligible“)
rating-low = gering („low“)
rating-no-dsa = kein Sicherheitsupdate geplant („no-dsa“)
rating-postponed = zurückgestellt („postponed“)
rating-ignored = wird nicht behoben („ignored“)
own-method = Abgleich über
own-evidence = Belege
own-found = gefunden
own-mailed = Sofort-Mail
own-open-inbox = Im Eingang bearbeiten

triage-done = Erledigt
triage-later = Später
triage-later-1 = Morgen
triage-later-7 = In 7 Tagen
triage-later-30 = In 30 Tagen
triage-ignore = Ignorieren
triage-ignore-ok = Ignorieren
triage-reason = Grund
triage-reason-unused = Funktion nicht genutzt
triage-reason-lan = Nur im LAN erreichbar, Risiko akzeptiert
triage-reason-false = Fehlalarm: Version oder Produkt passt nicht
triage-reason-other = Anderer Grund
triage-note = Notiz (optional)
triage-for = Gilt für
triage-ignore-help = Ignorierte Treffer bleiben unter „Ignoriert“ sichtbar und lassen sich wieder öffnen.
triage-reopen = Wieder öffnen
triage-open-source = Quelle öffnen

flash-triage-done = Als erledigt markiert.
flash-triage-later = Zurückgestellt.
flash-triage-ignored = Ignoriert.
flash-triage-reopened = Wieder geöffnet.
inbox-muted = { $count ->
    [one] 1 Schwachstelle
   *[other] { $shown } Schwachstellen
} unter der Mindestpriorität { $assets ->
    [one] ihres Assets
   *[other] ihrer Assets ({ $assets })
} ausgeblendet
inbox-muted-shown = Mit dem Asset-Filter erscheinen auch Treffer unter seiner Mindestpriorität { $prio }. Mindestpriorität ändern
