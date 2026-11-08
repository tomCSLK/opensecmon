-- Phase 8: the page "Situation" keeps the open vulnerabilities of every day for its 30-day trend.
-- `day` is the local date (configured time zone) as `YYYY-MM-DD`; the housekeeping writes the current day every
-- hour, so a day keeps the counts of its last hour. Days before the first entry are worked out from the matches.
CREATE TABLE situation_days (
    day  TEXT PRIMARY KEY NOT NULL,
    crit INTEGER NOT NULL,
    high INTEGER NOT NULL,
    med  INTEGER NOT NULL,
    low  INTEGER NOT NULL,
    kev  INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
