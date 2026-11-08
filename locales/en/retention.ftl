# Settings page "Retention"
settings-retention = Retention
retention-title = Retention
retention-audit = Keep the audit log
retention-audit-config = as configured ({ $period })
retention-audit-hint = The hourly housekeeping removes older entries of the audit log. The configuration says { $period }.
retention-closed = Done and ignored matches that no longer apply
retention-closed-hint = Removed only once the matching has not found the match for that long (e.g. after an update or a deleted asset). Matches that still apply keep their state, or they would come back as new.
retention-cves-hint = CVEs and advisories are always kept, also without an own match: an asset added later may be affected by an old vulnerability.
retention-keep = keep forever
retention-days = { $count ->
    [one] 1 day
   *[other] { $count } days
}
retention-years = { $count ->
    [one] 1 year
   *[other] { $count } years
}
retention-saved = Retention saved.
retention-error = Please choose one of the offered periods.
retention-db = Database
retention-db-total = Size of the database: { $size }.
retention-db-free = Free after deleting: { $size }.
retention-area-cves = CVE list (CVE, NVD, KEV, EPSS)
retention-area-advisories = Advisories (CSAF)
retention-area-distros = Distributions (OSV, Debian Security Tracker)
retention-area-own = Own data (assets, matches, audit log, settings)
retention-measured = By area, measured
retention-not-measured = The housekeeping measures the areas once a day; not measured yet.
retention-vacuum = Compact the database
retention-vacuum-hint = Compacting rewrites the database without its free space (VACUUM). With all sources this takes about a minute and temporarily needs free disk space of about twice the database. Meanwhile fetches and changes wait; what fails is caught up by the next run.
retention-vacuum-started = Compacting started; it runs in the background.
retention-vacuum-running = The database is being compacted, since
retention-vacuum-last = Last compacted
retention-vacuum-freed = { $size } freed
retention-vacuum-failed = Compacting failed:
retention-vacuum-interrupted = The service stopped meanwhile. The database is unchanged.
