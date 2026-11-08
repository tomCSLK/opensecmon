-- Phase 4: the distributions. OSV records of Debian and Ubuntu (DSA, DLA, DTSA, DEBIAN-CVE; USN, LSN,
-- UBUNTU-CVE) and the open issues of the Debian Security Tracker. Their texts are data, shown escaped.

-- One row per OSV record. `kind` is 'advisory' (DSA, DLA, DTSA, USN, LSN) or 'cve' (the distribution's view
-- of one CVE: DEBIAN-CVE-…, UBUNTU-CVE-…, Debian's older CVE-… records). `modified` is the record's own
-- timestamp as published (a record whose `modified` did not change is not written again). `details` is only
-- kept for advisories (for CVE records it repeats the CVE description). `priority` is Ubuntu's priority
-- (severity type "Ubuntu"), `url` the advisory page.
CREATE TABLE osv_records (
    seq          INTEGER PRIMARY KEY,
    id           TEXT NOT NULL UNIQUE,
    source       TEXT NOT NULL CHECK (source IN ('debian', 'ubuntu')),
    kind         TEXT NOT NULL CHECK (kind IN ('advisory', 'cve')),
    summary      TEXT NOT NULL DEFAULT '',
    details      TEXT NOT NULL DEFAULT '',
    priority     TEXT NOT NULL DEFAULT '',
    url          TEXT NOT NULL DEFAULT '',
    published_ms INTEGER,
    modified     TEXT NOT NULL,
    modified_ms  INTEGER NOT NULL,
    withdrawn_ms INTEGER,
    fetched_ms   INTEGER NOT NULL
) STRICT;

CREATE INDEX osv_records_source ON osv_records (source, modified_ms);

-- The CVEs a record is about (from `upstream`, `aliases` and the id itself).
CREATE TABLE osv_cves (
    cve_id     TEXT NOT NULL,
    record_seq INTEGER NOT NULL REFERENCES osv_records (seq) ON DELETE CASCADE,
    PRIMARY KEY (cve_id, record_seq)
) STRICT, WITHOUT ROWID;

CREATE INDEX osv_cves_record ON osv_cves (record_seq);

-- The affected source packages, one row per range: `ecosystem` as published ("Debian:13",
-- "Ubuntu:26.04:LTS", "Ubuntu:Pro:20.04:LTS"), `release` its version number ("13", "26.04"). A range without
-- `fixed` and `last_affected` is open. The lists of affected versions are not kept (the ranges say the same
-- for the comparison with installed versions). `urgency` is Debian's urgency of the release.
CREATE TABLE osv_affected (
    record_seq    INTEGER NOT NULL REFERENCES osv_records (seq) ON DELETE CASCADE,
    ecosystem     TEXT NOT NULL,
    release       TEXT NOT NULL,
    package       TEXT NOT NULL,
    introduced    TEXT NOT NULL DEFAULT '',
    fixed         TEXT NOT NULL DEFAULT '',
    last_affected TEXT NOT NULL DEFAULT '',
    urgency       TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX osv_affected_record ON osv_affected (record_seq);
CREATE INDEX osv_affected_package ON osv_affected (package, release);

-- The Debian Security Tracker, only what OSV does not say: issues that are open or undetermined in a
-- release, and issues the security team will not fix with a DSA ("no-dsa", with the reason "postponed" or
-- "ignored"). `release` is the codename (bookworm, trixie, forky, sid). Replaced by every run.
CREATE TABLE debian_tracker (
    cve_id        TEXT NOT NULL,
    package       TEXT NOT NULL,
    release       TEXT NOT NULL,
    status        TEXT NOT NULL,
    urgency       TEXT NOT NULL DEFAULT '',
    nodsa         TEXT NOT NULL DEFAULT '',
    nodsa_reason  TEXT NOT NULL DEFAULT '',
    fixed_version TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (cve_id, package, release)
) STRICT, WITHOUT ROWID;

CREATE INDEX debian_tracker_package ON debian_tracker (package, release);

INSERT INTO source_state (source, interval_secs) VALUES
    ('osv_debian', 21600),
    ('osv_ubuntu', 21600),
    ('debian_tracker', 21600);
