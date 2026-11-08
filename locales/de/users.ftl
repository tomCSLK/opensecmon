# Anmeldung, „Mein Konto“ und Prüfung der Zugangsdaten.

## Anmeldung

login-title = Anmelden
login-tagline = Sicherheitsmeldungen für die eigenen Systeme
login-submit = Anmelden
login-free-software = opensecmon ist freie Software unter der AGPL-3.0
login-failed = Benutzername oder Passwort ist falsch.
login-busy = Gerade laufen zu viele Anmeldungen gleichzeitig. Bitte in ein paar Sekunden erneut versuchen.
login-throttled = Zu viele fehlgeschlagene Anmeldeversuche. Bitte in { $wait } erneut versuchen.
login-signed-out-idle =
    { $minutes ->
        [one] Du wurdest nach { $minutes } Minute ohne Aktivität abgemeldet.
       *[other] Du wurdest nach { $minutes } Minuten ohne Aktivität abgemeldet.
    }
login-wait-seconds =
    { $seconds ->
        [one] { $seconds } Sekunde
       *[other] { $seconds } Sekunden
    }
login-wait-minutes =
    { $minutes ->
        [one] { $minutes } Minute
       *[other] { $minutes } Minuten
    }

## Prüfung von Benutzername und Passwort

username-length = Der Benutzername muss 3 bis 32 Zeichen lang sein.
username-chars = Erlaubt sind Buchstaben, Ziffern sowie . _ -
username-taken = Der Benutzername ist bereits vergeben.
password-too-short = Das Passwort muss mindestens 10 Zeichen lang sein.
password-too-long = Das Passwort darf höchstens 128 Zeichen lang sein.
password-mismatch = Die beiden Passwörter stimmen nicht überein.

## Mein Konto

account-language-hint = „Wie im Browser“ folgt der Spracheinstellung des Browsers; ohne passende Sprache gilt Deutsch.
account-password-title = Passwort ändern
account-current-password = Bisheriges Passwort
account-password-hint = 10 bis 128 Zeichen. Deine anderen Sitzungen (z. B. auf dem Handy) werden abgemeldet, diese bleibt angemeldet.
account-too-many-attempts = Zu viele falsche Passwörter. Bitte später erneut versuchen.
account-current-wrong = Das bisherige Passwort ist falsch.
account-password-unchanged = Das neue Passwort muss sich vom bisherigen unterscheiden.
account-name-hint = Den Namen ändert nur die Kommandozeile (opensecmon user).
