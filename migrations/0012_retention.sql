-- Phase 8: retention (page "Database").
-- `audit_days` overrides `retention_audit_days` of the configuration when set. `closed_days` removes done and
-- ignored matches that have not been found for that many days (0 keeps them); a match that is still found stays,
-- or it would come back as new. `gone_ms` of a match is when the matching stopped finding it.
-- `vacuum_*` describe the last "compact the database" (VACUUM) run from the page; `size_*` are the bytes of the
-- areas as the housekeeping last measured them (once a day, `dbstat` reads the whole file).
CREATE TABLE retention_settings (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    audit_days  INTEGER CHECK (audit_days IS NULL OR audit_days BETWEEN 1 AND 36500),
    closed_days INTEGER NOT NULL DEFAULT 365 CHECK (closed_days BETWEEN 0 AND 36500),
    vacuum_started_ms INTEGER,
    vacuum_done_ms    INTEGER,
    vacuum_error      TEXT NOT NULL DEFAULT '',
    vacuum_freed      INTEGER NOT NULL DEFAULT 0,
    size_cves       INTEGER NOT NULL DEFAULT 0,
    size_advisories INTEGER NOT NULL DEFAULT 0,
    size_distros    INTEGER NOT NULL DEFAULT 0,
    size_own        INTEGER NOT NULL DEFAULT 0,
    sizes_ms        INTEGER
) STRICT;

INSERT INTO retention_settings (id) VALUES (1);

ALTER TABLE matches ADD COLUMN gone_ms INTEGER;

-- Done by themselves: gone since then. Other closed matches get their time with the next matching.
UPDATE matches SET gone_ms = state_ms WHERE state = 'done' AND auto = 1;

CREATE INDEX matches_gone ON matches (gone_ms) WHERE gone_ms IS NOT NULL;
