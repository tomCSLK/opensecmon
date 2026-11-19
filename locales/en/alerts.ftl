# Instant mail and daily report (texts of the mails in the language of the mails)
alert-prio = Priority
alert-reason-kev = listed in CISA KEV
alert-reason-prio = priority { $prio } ≥ { $min }
alert-reason-cvss = CVSS { $score } ≥ { $min }
alert-reason-epss = EPSS { $epss } % ≥ { $min } %
alert-because = Reported because: { $reasons }
alert-affected-host = { $asset } on { $host }
alert-affected-keyword = keyword “{ $keyword }”
alert-fixed = fixed in { $version }
alert-more-affected = and { $count } more
alert-more-items = … and { $count } more in the inbox
alert-inbox-link = Inbox: { $url }
alert-footer = This mail comes from opensecmon.
alert-footer-link = This mail comes from opensecmon. Settings: { $url }
alert-subject-one = New match: { $id }
alert-subject-many = { $count } new matches, highest priority { $prio }: { $ids }
alert-intro = { $count ->
    [one] opensecmon found a new match for your assets.
   *[other] opensecmon found { $count } new matches for your assets.
}
report-subject = Daily report { $date }: { $new ->
    [one] 1 new match
   *[other] { $new } new matches
}, { $open } critical open
report-intro = Daily report of opensecmon for { $date }
report-open-total = { $count ->
    [one] 1 advisory is open in the inbox.
   *[other] { $count } advisories are open in the inbox.
}
report-nothing = Nothing to report: no new matches, nothing critical open, all sources fine.
report-new = New since { $since }: { $count }
report-open = Open with priority ≥ 85 or in KEV: { $count }
report-open-above = { $count ->
    [one] (1 of them is listed above with the new matches)
   *[other] ({ $count } of them are listed above with the new matches)
}
report-due = Postponed, due again by tomorrow: { $count }
report-sources = Sources with errors: { $count }
report-source-since = last success { $time }
report-source-never = never successful

# Settings pages
settings-alerts = Instant mail
settings-report = Daily report
alerts-title = Instant mail for new matches
alerts-subtitle = A mail to the recipients from “E-mail” as soon as a new open match meets one of the conditions. The check runs once a minute.
alerts-enabled = Instant mail on
alerts-conditions = Report when a new match meets one of these conditions
alerts-on-kev = It is listed in CISA KEV (actively exploited)
alerts-prio = Priority at least
alerts-cvss = CVSS at least
alerts-epss = EPSS at least (in %)
alerts-confidence = Minimum confidence
alerts-confidence-hint = Keyword matches (low) otherwise only appear in the daily report.
alerts-grouping = Grouping
alerts-bundle = Bundle matches within 10 minutes into one mail
alerts-once = Report the same vulnerability only once, even when more assets turn out to be affected
alerts-known-hint = When switched on and when the conditions change, the matches that already meet them count as known: they are in the inbox, a mail only comes for new ones.
alerts-public-url = Address of the interface (for links in the mails)
alerts-public-url-hint = For example { $example }. Empty: the mails contain no links.
alerts-status = Status
alerts-mail-off = E-mail notification is switched off; no mail goes out.
alerts-mail-settings = Go to the e-mail settings
alerts-last = Last instant mail: { $time }
alerts-last-never = No instant mail sent yet.
alerts-waiting = { $count ->
    [one] 1 match is waiting for the next mail.
   *[other] { $count } matches are waiting for the next mail.
}
alerts-retry = The last delivery failed; next attempt { $time }.
alerts-saved = Instant mail settings saved.
alerts-error-prio = The priority must be a whole number from 0 to 100.
alerts-error-cvss = The CVSS score must be between 0 and 10.
alerts-error-epss = The EPSS value must be between 0 and 100 %.
alerts-error-url = The address must start with http:// or https:// and may only contain host, port and path.
report-title = Daily report
report-subtitle = Once a day an overview to the recipients from “E-mail”.
report-enabled = Daily report on
report-time = Time
report-time-hint = Time zone: { $zone }.
report-content = Content
report-part-new = New matches since the last report
report-part-open = All open matches with priority ≥ 85 or in KEV
report-part-sources = Sources with errors
report-part-due = Postponed matches that are due again by tomorrow
report-skip-empty = Do not send when there is nothing to report
report-saved = Daily report settings saved.
report-error-time = Please enter a time as HH:MM.
report-preview = Preview
report-preview-hint = What the report would look like now (language of the mails).
report-preview-to = To { $recipients }
report-preview-no-recipients = No recipients entered yet.
report-next = Next report: { $time }
report-last = Last report: { $time }
report-send-now = Send now
report-send-hint = Sends the report at once, even when it is empty; the next one counts new matches from then on.
report-sent = Daily report sent to { $recipients }.
report-preview-empty = (Would not be sent: nothing to report.)
alert-av-n = network
alert-av-a = adjacent network
alert-av-l = local
alert-av-p = physical access
alert-pr-n = no login
alert-pr-l = with login
alert-pr-h = with admin rights
alert-ui-n = no user interaction
alert-ui-r = user interaction
alert-days-ago = { $days ->
    [0] today
    [one] yesterday
   *[other] { $days } days ago
}
alert-epss-percentile = higher than for { $percent } % of all CVEs
alert-epss-label = EPSS (probability of exploitation)
alert-bsi = Summary by the BSI · { $id }
alert-cvss = CVSS { $version }
alert-kev-since = since { $date }
alert-kev-due = CISA due date: { $date }
alert-kev-exploited = KEV · exploited
alert-published = Published
alert-on = on
alert-fixed-in = fixed in
alert-affected = Affected ({ $count })
alert-col-asset = Asset
alert-col-host = Host
alert-col-versions = Installed → fixed
alert-col-confidence = Match
alert-no-fix = no fix yet
alert-reasons = Reported because
alert-chip-prio = { $band } · priority { $prio }
alert-open-inbox = Open in the inbox
alert-open-cve = CVE detail
alert-open-all = Open all in the inbox
alert-settings-link = Instant mail settings
alert-many-chip = { $count } new matches
alert-many-title = { $count } new matches for own assets
alert-many-top = Highest priority { $prio }
alert-many-kev = { $count } in CISA KEV
alert-many-hosts = { $count ->
    [one] 1 host affected
   *[other] { $count } hosts affected
}
alert-tile-kev = in KEV
alert-tile-hosts = Hosts
alert-worst-first = Worst first
report-heading = Situation on { $date }
report-change-up = { $count } more than yesterday
report-change-down = { $count } fewer than yesterday
report-change-same = as many as yesterday
report-hosts = Most affected hosts
report-hosts-line = Most affected hosts: { $hosts }
report-host = { $host } { $count }
report-host-critical = { $host } { $count } ({ $critical } critical)
report-host-open = { $count } open
report-host-crit = { $count } critical
report-trend = Open vulnerabilities, 14 days
report-today = today
report-tile-new = new since { $since }
report-tile-open = critical open (≥ 85 or KEV)
report-tile-due = due again
report-tile-sources = sources with errors
report-nothing-chip = Nothing to report
report-nothing-title = A quiet day
report-pre-open = { $count } open
report-pre-new = { $count } new
report-pre-critical = { $count } critical open
report-pre-sources = { $count ->
    [one] 1 source with errors
   *[other] { $count } sources with errors
}
report-open-inbox = Open the inbox
report-open-situation = Situation
report-open-sources = Sources
report-settings-link = Daily report settings
