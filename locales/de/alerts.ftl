# Sofort-Mail und Tagesbericht (Texte der Mails in der Sprache der Mails)
alert-prio = Priorität
alert-reason-kev = steht in CISA KEV
alert-reason-prio = Priorität { $prio } ≥ { $min }
alert-reason-cvss = CVSS { $score } ≥ { $min }
alert-reason-epss = EPSS { $epss } % ≥ { $min } %
alert-because = Gemeldet, weil: { $reasons }
alert-affected-host = { $asset } auf { $host }
alert-affected-keyword = Stichwort „{ $keyword }“
alert-fixed = behoben in { $version }
alert-more-affected = und { $count } weitere
alert-more-items = … und { $count } weitere im Eingang
alert-inbox-link = Eingang: { $url }
alert-footer = Diese Mail kommt von opensecmon.
alert-footer-link = Diese Mail kommt von opensecmon. Einstellungen: { $url }
alert-subject-one = Neuer Treffer: { $id }
alert-subject-many = { $count } neue Treffer, höchste Priorität { $prio }: { $ids }
alert-intro = { $count ->
    [one] opensecmon hat einen neuen Treffer für eigene Assets gefunden.
   *[other] opensecmon hat { $count } neue Treffer für eigene Assets gefunden.
}
report-subject = Tagesbericht { $date }: { $new ->
    [one] 1 neuer Treffer
   *[other] { $new } neue Treffer
}, { $open } kritisch offen
report-intro = Tagesbericht von opensecmon für den { $date }
report-open-total = { $count ->
    [one] Im Eingang ist 1 Meldung offen.
   *[other] Im Eingang sind { $count } Meldungen offen.
}
report-nothing = Nichts zu melden: keine neuen Treffer, nichts kritisch offen, alle Quellen in Ordnung.
report-new = Neu seit { $since }: { $count }
report-open = Offen mit Priorität ≥ 85 oder in KEV: { $count }
report-open-above = { $count ->
    [one] (1 davon steht oben bei den neuen Treffern)
   *[other] ({ $count } davon stehen oben bei den neuen Treffern)
}
report-due = Zurückgestellt, bis morgen wieder fällig: { $count }
report-sources = Quellen mit Fehlern: { $count }
report-source-since = letzter Erfolg { $time }
report-source-never = noch nie erfolgreich

# Einstellungsseiten
settings-alerts = Sofort-Mail
settings-report = Tagesbericht
alerts-title = Sofort-Mail bei neuen Treffern
alerts-subtitle = Eine Mail an die Empfänger aus „E-Mail“, sobald ein neuer offener Treffer eine der Bedingungen erfüllt. Die Prüfung läuft einmal pro Minute.
alerts-enabled = Sofort-Mail an
alerts-conditions = Melden, wenn ein neuer Treffer eine dieser Bedingungen erfüllt
alerts-on-kev = Er steht in CISA KEV (wird aktiv ausgenutzt)
alerts-prio = Priorität mindestens
alerts-cvss = CVSS mindestens
alerts-epss = EPSS mindestens (in %)
alerts-confidence = Mindestens nötiges Vertrauen
alerts-confidence-hint = Stichwort-Treffer (niedrig) kommen sonst nur in den Tagesbericht.
alerts-grouping = Zusammenfassen
alerts-bundle = Treffer innerhalb von 10 Minuten in einer Mail bündeln
alerts-once = Dieselbe Schwachstelle nur einmal melden, auch wenn weitere Assets dazukommen
alerts-known-hint = Beim Einschalten und bei geänderten Bedingungen gelten die Treffer, die sie schon erfüllen, als bekannt: sie stehen im Eingang, eine Mail kommt nur für neue.
alerts-public-url = Adresse der Oberfläche (für Links in den Mails)
alerts-public-url-hint = Zum Beispiel { $example }. Leer: die Mails enthalten keine Links.
alerts-status = Stand
alerts-mail-off = Die E-Mail-Benachrichtigung ist ausgeschaltet; es geht keine Mail hinaus.
alerts-mail-settings = Zu den E-Mail-Einstellungen
alerts-last = Letzte Sofort-Mail: { $time }
alerts-last-never = Noch keine Sofort-Mail gesendet.
alerts-waiting = { $count ->
    [one] 1 Treffer wartet auf die nächste Mail.
   *[other] { $count } Treffer warten auf die nächste Mail.
}
alerts-retry = Der letzte Versand ist fehlgeschlagen; nächster Versuch { $time }.
alerts-saved = Einstellungen der Sofort-Mail gespeichert.
alerts-error-prio = Die Priorität muss eine ganze Zahl von 0 bis 100 sein.
alerts-error-cvss = Der CVSS-Wert muss zwischen 0 und 10 liegen.
alerts-error-epss = Der EPSS-Wert muss zwischen 0 und 100 % liegen.
alerts-error-url = Die Adresse muss mit http:// oder https:// beginnen und darf nur Rechner, Port und Pfad enthalten.
report-title = Tagesbericht
report-subtitle = Einmal am Tag eine Übersicht an die Empfänger aus „E-Mail“.
report-enabled = Tagesbericht an
report-time = Uhrzeit
report-time-hint = Zeitzone: { $zone }.
report-content = Inhalt
report-part-new = Neue Treffer seit dem letzten Bericht
report-part-open = Alle offenen Treffer mit Priorität ≥ 85 oder in KEV
report-part-sources = Quellen mit Fehlern
report-part-due = Zurückgestellte Treffer, die bis morgen wieder fällig werden
report-skip-empty = Nicht senden, wenn es nichts zu melden gibt
report-saved = Einstellungen des Tagesberichts gespeichert.
report-error-time = Bitte eine Uhrzeit im Format HH:MM angeben.
report-preview = Vorschau
report-preview-hint = So sähe der Bericht jetzt aus (Sprache der Mails).
report-preview-to = An { $recipients }
report-preview-no-recipients = Noch keine Empfänger eingetragen.
report-next = Nächster Bericht: { $time }
report-last = Letzter Bericht: { $time }
report-send-now = Jetzt senden
report-send-hint = Sendet den Bericht sofort, auch wenn er leer ist; der nächste zählt neue Treffer ab dann.
report-sent = Tagesbericht an { $recipients } gesendet.
report-preview-empty = (Wird nicht gesendet: nichts zu melden.)
alert-av-n = Netzwerk
alert-av-a = Nachbarnetz
alert-av-l = lokal
alert-av-p = physischer Zugriff
alert-pr-n = ohne Anmeldung
alert-pr-l = mit Anmeldung
alert-pr-h = mit Administratorrechten
alert-ui-n = keine Interaktion
alert-ui-r = mit Interaktion
alert-days-ago = { $days ->
    [0] heute
    [one] gestern
   *[other] vor { $days } Tagen
}
alert-epss-percentile = höher als bei { $percent } % aller CVEs
alert-epss-label = EPSS (Wahrscheinlichkeit der Ausnutzung)
alert-bsi = Kurzfassung des BSI · { $id }
alert-cvss = CVSS { $version }
alert-kev-since = seit { $date }
alert-kev-due = Frist der CISA: { $date }
alert-kev-exploited = KEV · wird ausgenutzt
alert-published = Veröffentlicht
alert-on = auf
alert-fixed-in = behoben in
alert-affected = Betroffen ({ $count })
alert-col-asset = Asset
alert-col-host = Host
alert-col-versions = Installiert → behoben
alert-col-confidence = Abgleich
alert-no-fix = noch keine Korrektur
alert-reasons = Gemeldet, weil
alert-chip-prio = { $band } · Priorität { $prio }
alert-open-inbox = Im Eingang öffnen
alert-open-cve = CVE-Detail
alert-open-all = Alle im Eingang öffnen
alert-settings-link = Sofort-Mails einstellen
alert-many-chip = { $count } neue Treffer
alert-many-title = { $count } neue Treffer für eigene Assets
alert-many-top = Höchste Priorität { $prio }
alert-many-kev = { $count } in CISA KEV
alert-many-hosts = { $count ->
    [one] 1 Host betroffen
   *[other] { $count } Hosts betroffen
}
alert-tile-kev = in KEV
alert-tile-hosts = Hosts
alert-worst-first = Schlimmste zuerst
report-heading = Lage am { $date }
report-change-up = { $count } mehr als gestern
report-change-down = { $count } weniger als gestern
report-change-same = so viele wie gestern
report-hosts = Meistbetroffene Hosts
report-hosts-line = Meistbetroffene Hosts: { $hosts }
report-host = { $host } { $count }
report-host-critical = { $host } { $count } ({ $critical } kritisch)
report-host-open = { $count } offen
report-host-crit = { $count } kritisch
report-trend = Offene Schwachstellen, 14 Tage
report-today = heute
report-tile-new = neu seit { $since }
report-tile-open = kritisch offen (≥ 85 oder KEV)
report-tile-due = wieder fällig
report-tile-sources = Quellen mit Fehlern
report-nothing-chip = Nichts zu melden
report-nothing-title = Ruhiger Tag
report-pre-open = { $count } offen
report-pre-new = { $count } neu
report-pre-critical = { $count } kritisch offen
report-pre-sources = { $count ->
    [one] 1 Quelle mit Fehlern
   *[other] { $count } Quellen mit Fehlern
}
report-open-inbox = Eingang öffnen
report-open-situation = Lage
report-open-sources = Quellen
report-settings-link = Tagesbericht einstellen
