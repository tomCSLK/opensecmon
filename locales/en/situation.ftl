situation-subtitle-now = { $count ->
    [one] 1 open vulnerability
   *[other] { $shown } open vulnerabilities
} on { $hosts ->
    [one] 1 host
   *[other] { $hosts } hosts
}
situation-to-inbox = To the inbox
situation-tile-critical = Open critical
situation-tile-critical-new = { $count } of them new
situation-tile-kev = Actively exploited (KEV)
situation-tile-kev-overdue = { $count ->
    [one] 1 deadline passed
   *[other] { $count } deadlines passed
}
situation-tile-kev-none-overdue = no deadline passed
situation-tile-new = New in 24 hours
situation-tile-new-sub = first found since this time yesterday
situation-tile-sources = Sources fine
situation-tile-sources-value = { $ok } of { $count }
situation-tile-sources-fine = all switched-on sources run
situation-tile-sources-sub = { $failed } failed, { $stale } stale
situation-chart-title = Open vulnerabilities, last 30 days
situation-chart-by = by priority band
situation-chart-label = Open vulnerabilities per day, stacked by band. Today { $count }.
situation-bar-title = { $date }: { $count } open ({ $bands })
situation-derived = worked out from the matches
situation-derived-note = Pale bars: worked out from today's matches (before the first record)
situation-hosts-title = Most affected
situation-watchlist = Watchlist
situation-no-host = Without host
situation-none-open = No open matches.
situation-oldest-title = Open longest
situation-col-prio = Prio
situation-col-id = Id
situation-col-asset = Asset
situation-col-open = Open for
situation-days-open = { $count ->
    [0] today
    [one] 1 day
   *[other] { $count } days
}
situation-sources-details = Details
situation-no-sources = No source switched on.
