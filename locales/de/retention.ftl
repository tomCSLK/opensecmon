# Einstellungsseite „Aufbewahrung“
settings-retention = Aufbewahrung
retention-title = Aufbewahrung
retention-audit = Protokoll behalten
retention-audit-config = wie Konfiguration ({ $period })
retention-audit-hint = Ältere Einträge des Änderungsprotokolls löscht die stündliche Wartung. In der Konfiguration stehen { $period }.
retention-closed = Erledigte und ignorierte Treffer, die nicht mehr zutreffen
retention-closed-hint = Gelöscht wird erst, wenn der Abgleich den Treffer so lange nicht mehr findet (z. B. nach einem Update oder einem gelöschten Asset). Treffer, die noch zutreffen, bleiben mit ihrem Zustand erhalten, sonst kämen sie als neu zurück.
retention-cves-hint = CVEs und Advisories bleiben immer erhalten, auch ohne eigenen Treffer: Ein später angelegtes Asset kann von einer alten Lücke betroffen sein.
retention-keep = immer behalten
retention-days = { $count ->
    [one] 1 Tag
   *[other] { $count } Tage
}
retention-years = { $count ->
    [one] 1 Jahr
   *[other] { $count } Jahre
}
retention-saved = Aufbewahrung gespeichert.
retention-error = Bitte eine der angebotenen Fristen wählen.
retention-db = Datenbank
retention-db-total = Größe der Datenbank: { $size }.
retention-db-free = Davon frei nach dem Löschen: { $size }.
retention-area-cves = CVE-Liste (CVE, NVD, KEV, EPSS)
retention-area-advisories = Advisories (CSAF)
retention-area-distros = Distributionen (OSV, Debian Security Tracker)
retention-area-own = Eigene Daten (Assets, Treffer, Protokoll, Einstellungen)
retention-measured = Aufgeteilt nach Bereichen, gemessen
retention-not-measured = Die Aufteilung nach Bereichen misst die Wartung einmal am Tag; noch keine Messung.
retention-vacuum = Datenbank verkleinern
retention-vacuum-hint = Verkleinern schreibt die Datenbank ohne freien Platz neu (VACUUM). Das dauert bei allen Quellen etwa eine Minute und braucht vorübergehend freien Plattenplatz etwa in doppelter Größe der Datenbank. Solange warten Abrufe und Änderungen; was dabei scheitert, holt der nächste Lauf nach.
retention-vacuum-started = Verkleinern gestartet; es läuft im Hintergrund.
retention-vacuum-running = Die Datenbank wird verkleinert, seit
retention-vacuum-last = Zuletzt verkleinert
retention-vacuum-freed = { $size } frei geworden
retention-vacuum-failed = Verkleinern ist fehlgeschlagen:
retention-vacuum-interrupted = Der Dienst wurde dabei beendet. Die Datenbank ist unverändert.
