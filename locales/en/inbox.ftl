## Inbox and triage

inbox-filters = Filters
inbox-close-filters = Close filters
inbox-views = Views
inbox-view-open = Open
inbox-view-critical = Critical + KEV
inbox-view-new = New since yesterday
inbox-view-later = Later
inbox-view-done = Done
inbox-view-ignored = Ignored
inbox-group-sev = Severity
inbox-group-kev = Exploitation
inbox-kev-only = KEV only
inbox-group-fix = Fix
inbox-fix-only = Fix announced
inbox-group-conf = Confidence
inbox-group-kind = Kind
inbox-kind-watch = Watchlist
inbox-group-host = Host / device
inbox-asset = Asset
inbox-reset = reset
inbox-reset-all = Remove all filters
inbox-remove = Remove filter
inbox-list = Matches
inbox-count = { $count ->
    [one] 1 advisory
   *[other] { $count } advisories
}
inbox-more = { $count } more, please filter
inbox-select-all = Select all
inbox-select = Select
inbox-selected = selected
inbox-bulk-clear = Clear selection
inbox-sort = Sort order
inbox-sort-prio = Priority
inbox-sort-new = Newest first
inbox-sort-host = By host
inbox-apply = Apply
inbox-new = new
inbox-until = until { $date }
inbox-assets = { $count } matches
inbox-keyword = Keyword “{ $keyword }”
inbox-age-today = today
inbox-age-days = { $count ->
    [one] 1 day
   *[other] { $count } days
}
inbox-age-weeks = { $count } wk.
inbox-keys = j k select · e done · s later · i ignore · o source · x mark
inbox-detail = Details
inbox-detail-empty = No advisory selected.
inbox-done-title = All done
inbox-done-text = No open matches for your assets.
inbox-checked = Sources last checked:
inbox-to-situation = To the situation
inbox-nothing-title = Nothing found
inbox-nothing-text = No advisory fits these filters.
inbox-setup-title = No assets yet
inbox-setup-text = The inbox shows only advisories that affect your software, packages and devices. Add them or put keywords on the watchlist.
inbox-setup-assets = Add asset
inbox-setup-watch = Watchlist
inbox-error-action = Unknown action.

match-state-new = new
match-state-seen = open
match-state-later = deferred until { $date }
match-state-done = done
match-state-resolved = done (no longer affected)
match-state-ignored = ignored

own-installed = installed
own-fixed = fixed in
own-rating = { $distro } rates it: { $rating } (−{ $points } points)
rating-unimportant = unimportant
rating-negligible = negligible
rating-low = low
rating-no-dsa = no security update planned (“no-dsa”)
rating-postponed = postponed
rating-ignored = will not be fixed (“ignored”)
own-method = Matched by
own-evidence = Evidence
own-found = found
own-mailed = instant mail
own-open-inbox = Handle in the inbox

triage-done = Done
triage-later = Later
triage-later-1 = Tomorrow
triage-later-7 = In 7 days
triage-later-30 = In 30 days
triage-ignore = Ignore
triage-ignore-ok = Ignore
triage-reason = Reason
triage-reason-unused = Feature not used
triage-reason-lan = Only reachable in the LAN, risk accepted
triage-reason-false = False positive: version or product does not fit
triage-reason-other = Other reason
triage-note = Note (optional)
triage-for = Applies to
triage-ignore-help = Ignored matches stay visible under “Ignored” and can be reopened.
triage-reopen = Reopen
triage-open-source = Open source

flash-triage-done = Marked as done.
flash-triage-later = Deferred.
flash-triage-ignored = Ignored.
flash-triage-reopened = Reopened.
inbox-muted = { $count ->
    [one] 1 vulnerability
   *[other] { $shown } vulnerabilities
} below the minimum priority of { $assets ->
    [one] its asset
   *[other] their assets ({ $assets })
} hidden
inbox-muted-shown = With the asset filter, matches below its minimum priority { $prio } show as well. Change the minimum priority
