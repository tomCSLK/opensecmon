situation-subtitle-now = { $count ->
    [one] 1 offene Schwachstelle
   *[other] { $shown } offene Schwachstellen
} auf { $hosts ->
    [one] 1 Host
   *[other] { $hosts } Hosts
}
situation-to-inbox = Zum Eingang
situation-tile-critical = Offen kritisch
situation-tile-critical-new = davon { $count } neu
situation-tile-kev = Aktiv ausgenutzt (KEV)
situation-tile-kev-overdue = { $count ->
    [one] 1 Frist abgelaufen
   *[other] { $count } Fristen abgelaufen
}
situation-tile-kev-none-overdue = keine Frist abgelaufen
situation-tile-new = Neu in 24 Stunden
situation-tile-new-sub = zuerst gefunden seit gestern um diese Zeit
situation-tile-sources = Quellen in Ordnung
situation-tile-sources-value = { $ok } von { $count }
situation-tile-sources-fine = alle eingeschalteten laufen
situation-tile-sources-sub = { $failed } mit Fehler, { $stale } veraltet
situation-chart-title = Offene Schwachstellen, letzte 30 Tage
situation-chart-by = nach Stufe der Priorität
situation-chart-label = Offene Schwachstellen je Tag, gestapelt nach Stufe. Heute { $count }.
situation-bar-title = { $date }: { $count } offen ({ $bands })
situation-derived = aus den Treffern zurückgerechnet
situation-derived-note = Blasse Balken: aus den heutigen Treffern zurückgerechnet (vor der ersten Aufzeichnung)
situation-hosts-title = Am stärksten betroffen
situation-watchlist = Watchlist
situation-no-host = Ohne Host
situation-none-open = Keine offenen Treffer.
situation-oldest-title = Am längsten offen
situation-col-prio = Prio
situation-col-id = Kennung
situation-col-asset = Asset
situation-col-open = Offen seit
situation-days-open = { $count ->
    [0] heute
    [one] 1 Tag
   *[other] { $count } Tage
}
situation-sources-details = Details
situation-no-sources = Keine Quelle eingeschaltet.
