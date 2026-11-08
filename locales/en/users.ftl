# Sign-in, "My account" and checks of the credentials.

## Sign-in

login-title = Sign in
login-tagline = Security advisories for your own systems
login-submit = Sign in
login-free-software = opensecmon is free software under the AGPL-3.0
login-failed = Wrong user name or password.
login-busy = Too many sign-ins are being checked right now. Please try again in a few seconds.
login-throttled = Too many failed sign-in attempts. Please try again in { $wait }.
login-signed-out-idle =
    { $minutes ->
        [one] You were signed out after { $minutes } minute without activity.
       *[other] You were signed out after { $minutes } minutes without activity.
    }
login-wait-seconds =
    { $seconds ->
        [one] { $seconds } second
       *[other] { $seconds } seconds
    }
login-wait-minutes =
    { $minutes ->
        [one] { $minutes } minute
       *[other] { $minutes } minutes
    }

## Checks of user name and password

username-length = The user name must be 3 to 32 characters long.
username-chars = Allowed are letters, digits and . _ -
username-taken = This user name is already taken.
password-too-short = The password must be at least 10 characters long.
password-too-long = The password must not be longer than 128 characters.
password-mismatch = The two passwords do not match.

## My account

account-language-hint = “Same as the browser” follows the browser's language setting; without a matching language, German is used.
account-password-title = Change password
account-current-password = Current password
account-password-hint = 10 to 128 characters. Your other sessions (e.g. on your phone) are signed out; this one stays signed in.
account-too-many-attempts = Too many wrong passwords. Please try again later.
account-current-wrong = The current password is wrong.
account-password-unchanged = The new password must differ from the current one.
account-name-hint = Only the command line changes the name (opensecmon user).
