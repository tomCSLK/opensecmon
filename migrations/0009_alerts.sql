-- Phase 7: instant mails for new matches and the daily report.

-- The settings (one row) and what the notifier remembers between its rounds.
-- Instant mail: a match is reported when it is open, has at least `min_confidence` and meets one of the switched
-- on conditions (KEV, priority, CVSS, EPSS in percent). `bundle`: wait 10 minutes after the first match so that
-- one mail carries the whole run of a source. `once_per_vuln`: a vulnerability that was mailed once is not mailed
-- again when further assets turn out to be affected.
-- `public_url` is the address of the interface for the links in the mails (empty: no links).
-- Daily report at `report_minute` (minutes after midnight in the configured time zone) with the parts switched on.
-- `alert_key`/`report_key` describe the settings the last round worked with; when they change (switched on,
-- other thresholds), the matches that meet the conditions at that moment are taken as known instead of being
-- mailed, and a report time that has already passed today is not caught up.
CREATE TABLE alert_settings (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    instant           INTEGER NOT NULL DEFAULT 1 CHECK (instant IN (0, 1)),
    on_kev            INTEGER NOT NULL DEFAULT 1 CHECK (on_kev IN (0, 1)),
    prio_on           INTEGER NOT NULL DEFAULT 1 CHECK (prio_on IN (0, 1)),
    prio_min          INTEGER NOT NULL DEFAULT 85 CHECK (prio_min BETWEEN 0 AND 100),
    cvss_on           INTEGER NOT NULL DEFAULT 0 CHECK (cvss_on IN (0, 1)),
    cvss_min          REAL NOT NULL DEFAULT 9.0 CHECK (cvss_min BETWEEN 0 AND 10),
    epss_on           INTEGER NOT NULL DEFAULT 0 CHECK (epss_on IN (0, 1)),
    epss_min          REAL NOT NULL DEFAULT 10.0 CHECK (epss_min BETWEEN 0 AND 100),
    min_confidence    TEXT NOT NULL DEFAULT 'medium' CHECK (min_confidence IN ('high', 'medium', 'low')),
    bundle            INTEGER NOT NULL DEFAULT 1 CHECK (bundle IN (0, 1)),
    once_per_vuln     INTEGER NOT NULL DEFAULT 1 CHECK (once_per_vuln IN (0, 1)),
    public_url        TEXT NOT NULL DEFAULT '',
    report            INTEGER NOT NULL DEFAULT 1 CHECK (report IN (0, 1)),
    report_minute     INTEGER NOT NULL DEFAULT 420 CHECK (report_minute BETWEEN 0 AND 1439),
    report_new        INTEGER NOT NULL DEFAULT 1 CHECK (report_new IN (0, 1)),
    report_open       INTEGER NOT NULL DEFAULT 1 CHECK (report_open IN (0, 1)),
    report_sources    INTEGER NOT NULL DEFAULT 1 CHECK (report_sources IN (0, 1)),
    report_due        INTEGER NOT NULL DEFAULT 0 CHECK (report_due IN (0, 1)),
    report_skip_empty INTEGER NOT NULL DEFAULT 1 CHECK (report_skip_empty IN (0, 1)),
    -- State of the notifier.
    alert_key         TEXT NOT NULL DEFAULT '',
    pending_since_ms  INTEGER,
    alert_failures    INTEGER NOT NULL DEFAULT 0,
    alert_retry_ms    INTEGER NOT NULL DEFAULT 0,
    last_alert_ms     INTEGER,
    report_key        TEXT NOT NULL DEFAULT '',
    report_slot_ms    INTEGER NOT NULL DEFAULT 0,
    report_failures   INTEGER NOT NULL DEFAULT 0,
    report_retry_ms   INTEGER NOT NULL DEFAULT 0,
    last_report_ms    INTEGER,
    updated_ms        INTEGER NOT NULL DEFAULT 0
) STRICT;

INSERT INTO alert_settings (id) VALUES (1);

-- Whether a match went out by instant mail: '' not yet, 'sent' in a mail at `alert_ms`, 'quiet' taken as known
-- without a mail (it met the conditions when they were switched on, or its vulnerability was mailed before).
ALTER TABLE matches ADD COLUMN alert TEXT NOT NULL DEFAULT '' CHECK (alert IN ('', 'sent', 'quiet'));
ALTER TABLE matches ADD COLUMN alert_ms INTEGER;

CREATE INDEX matches_alert ON matches (alert, state);
