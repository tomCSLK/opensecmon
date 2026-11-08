-- How the distribution rates a match of a package (the Debian Security Tracker, Ubuntu's priority in OSV):
-- 'unimportant' (Debian) or 'negligible' (Ubuntu) take off penalty_unimportant, 'low', 'no-dsa', 'postponed' and
-- 'ignored' (Debian: no security update planned) take off penalty_minor; '' takes off nothing. Written by the
-- matching. A match of medium or high confidence of a KEV CVE still stays at kev_floor.
ALTER TABLE matches ADD COLUMN rating TEXT NOT NULL DEFAULT ''
    CHECK (rating IN ('', 'unimportant', 'negligible', 'low', 'no-dsa', 'postponed', 'ignored'));
ALTER TABLE prio_settings ADD COLUMN penalty_unimportant INTEGER NOT NULL DEFAULT 30
    CHECK (penalty_unimportant BETWEEN 0 AND 100);
ALTER TABLE prio_settings ADD COLUMN penalty_minor INTEGER NOT NULL DEFAULT 10
    CHECK (penalty_minor BETWEEN 0 AND 100);
