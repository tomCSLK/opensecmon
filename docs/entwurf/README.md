# Entwürfe der Oberfläche (opensecmon)

Klickbare HTML-Entwürfe zur Abnahme der Gestaltung (`PLAN.md`, Abschnitt „UI/UX-Konzept“).
**Kein Anwendungscode.** Die echte Oberfläche rendert der Server (askama + htmx). Übernommen werden höchstens die Tokens aus
`assets/tokens.css`.

- Start: `index.html` im Browser öffnen (geht direkt als Datei, kein Server nötig).
- Seiten: Eingang, Detail, Lage, Assets, Alle CVEs, Quellen, Einstellungen, Breiten (1440/1024/390 px nebeneinander).
- Die Entwurfsleiste oben wechselt die Seiten und das Thema (System/Hell/Dunkel). Im Eingang zeigt „Leerer Eingang“ den Zustand ohne Treffer.
- **Alle Daten sind erfunden** (CVE-, WID-, USN- und DSA-Nummern, Versionen, Werte). Die Links zu den Quellen sind Platzhalter.

## Dateien

| Datei | Inhalt |
|---|---|
| `assets/tokens.css` | Farben hell/dunkel, Schriften, Abstände |
| `assets/app.css` | Komponenten und Breiten |
| `assets/icons.js` | Symbole nach Lucide (ISC), dazu eigene Formen für die Schwere |
| `assets/data.js` | Beispieldaten und Prioritätsformel |
| `assets/app.js` | Rahmen, Thema, Detail-Komponente, Dialoge |
| `assets/eingang.js`, `assets/pages.js` | Logik der Seiten |
| `fonts/` | Fira Sans 400/500/600, Fira Code 400/500 (latin, woff2) von Fontsource 5.3.0, SIL OFL 1.1 (`OFL-*.txt`) |

## Vor dem Öffentlich-Schalten des Repos

Hostnamen und Geräte in den Beispieldaten sind allgemein gehalten, ähneln aber dem eigenen Netz. Bei Bedarf weiter neutralisieren
oder den Ordner nicht veröffentlichen.
