-- Phase 2: the sources of the CVE basis (cvelistV5, NVD, CISA KEV, EPSS) and what they deliver.
-- Every source owns its own tables and keeps them up to date without the others; the copies in `cves`
-- (main CVSS score, EPSS, KEV date, priority) are derived from them after each run.

-- State of every source: settings, the validators of the last download (ETag/Last-Modified, a cursor such as
-- the last cvelistV5 release) and the outcome of the last run. Times are Unix milliseconds (UTC).
CREATE TABLE source_state (
    source           TEXT PRIMARY KEY NOT NULL,
    enabled          INTEGER NOT NULL DEFAULT 1,
    interval_secs    INTEGER NOT NULL,
    etag             TEXT,
    last_modified    TEXT,
    cursor           TEXT,
    -- What the data says about itself (catalog version, model and date …) and how many entries it has.
    version          TEXT,
    item_count       INTEGER,
    last_started_ms  INTEGER,
    last_finished_ms INTEGER,
    last_success_ms  INTEGER,
    last_duration_ms INTEGER,
    last_new         INTEGER,
    last_changed     INTEGER,
    last_error       TEXT,
    failures         INTEGER NOT NULL DEFAULT 0,
    next_run_ms      INTEGER NOT NULL DEFAULT 0
) STRICT;

INSERT INTO source_state (source, interval_secs) VALUES
    ('cvelist', 3600),
    ('nvd', 7200),
    ('kev', 21600),
    ('epss', 86400);

-- One row per CVE record of cvelistV5. `seq` is a stable row id for the full-text index (an implicit rowid
-- could change with VACUUM). `title` is the CNA's title or the start of the description. `refs` and `affected`
-- are compact JSON for the detail page (affected: the CNA's product entries as published).
-- Derived columns: the main CVSS score (see storage::cves::MAIN_METRIC), EPSS, the KEV date and `prio`.
CREATE TABLE cves (
    seq             INTEGER PRIMARY KEY,
    id              TEXT NOT NULL UNIQUE,
    state           TEXT NOT NULL CHECK (state IN ('published', 'rejected')),
    assigner        TEXT NOT NULL DEFAULT '',
    title           TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    products        TEXT NOT NULL DEFAULT '',
    published_ms    INTEGER,
    updated_ms      INTEGER,
    record_updated  TEXT NOT NULL DEFAULT '',
    cwes            TEXT NOT NULL DEFAULT '',
    refs            TEXT NOT NULL DEFAULT '[]',
    affected        TEXT NOT NULL DEFAULT '[]',
    cvss_score      REAL,
    cvss_version    TEXT,
    cvss_vector     TEXT,
    cvss_source     TEXT,
    epss            REAL,
    epss_percentile REAL,
    kev_added       TEXT,
    prio            INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX cves_published ON cves (published_ms);
CREATE INDEX cves_prio ON cves (prio);
CREATE INDEX cves_cvss ON cves (cvss_score);
CREATE INDEX cves_epss ON cves (epss);
CREATE INDEX cves_kev ON cves (kev_added) WHERE kev_added IS NOT NULL;

-- Full-text search over title, description and product names (external content: the text lives in `cves`).
CREATE VIRTUAL TABLE cves_fts USING fts5 (
    title, description, products,
    content = 'cves', content_rowid = 'seq',
    tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TRIGGER cves_fts_insert AFTER INSERT ON cves BEGIN
    INSERT INTO cves_fts (rowid, title, description, products)
    VALUES (new.seq, new.title, new.description, new.products);
END;
CREATE TRIGGER cves_fts_delete AFTER DELETE ON cves BEGIN
    INSERT INTO cves_fts (cves_fts, rowid, title, description, products)
    VALUES ('delete', old.seq, old.title, old.description, old.products);
END;
CREATE TRIGGER cves_fts_update AFTER UPDATE OF title, description, products ON cves BEGIN
    INSERT INTO cves_fts (cves_fts, rowid, title, description, products)
    VALUES ('delete', old.seq, old.title, old.description, old.products);
    INSERT INTO cves_fts (rowid, title, description, products)
    VALUES (new.seq, new.title, new.description, new.products);
END;

-- CVSS scores of every provider: `cna` and `adp` from cvelistV5, `nvd` (NIST's own, type Primary) from the NVD.
-- `source` names the organisation (CNA/ADP short name, NVD source identifier).
CREATE TABLE cve_metrics (
    cve_id   TEXT NOT NULL,
    provider TEXT NOT NULL CHECK (provider IN ('cna', 'adp', 'nvd')),
    source   TEXT NOT NULL,
    version  TEXT NOT NULL,
    score    REAL NOT NULL,
    vector   TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (cve_id, provider, source, version)
) STRICT, WITHOUT ROWID;

-- Vendors and products a CVE names: from the CNA's `affected` list (`cna`) and the NVD's CPE configurations
-- (`nvd`). `vendor`/`product` are normalised keys (lower case letters and digits only), the names as given.
CREATE TABLE cve_products (
    cve_id       TEXT NOT NULL,
    origin       TEXT NOT NULL CHECK (origin IN ('cna', 'nvd')),
    vendor       TEXT NOT NULL,
    product      TEXT NOT NULL,
    vendor_name  TEXT NOT NULL,
    product_name TEXT NOT NULL,
    PRIMARY KEY (cve_id, origin, vendor, product)
) STRICT, WITHOUT ROWID;

CREATE INDEX cve_products_vendor ON cve_products (vendor, product);

-- What the NVD adds per CVE: its status and the CPE configurations (compact JSON, used for matching later).
CREATE TABLE nvd_cves (
    cve_id        TEXT PRIMARY KEY NOT NULL,
    status        TEXT NOT NULL DEFAULT '',
    last_modified TEXT NOT NULL DEFAULT '',
    configs       TEXT NOT NULL DEFAULT '[]'
) STRICT, WITHOUT ROWID;

-- CISA's catalog of known exploited vulnerabilities, replaced as a whole on every change.
CREATE TABLE kev (
    cve_id          TEXT PRIMARY KEY NOT NULL,
    vendor          TEXT NOT NULL DEFAULT '',
    product         TEXT NOT NULL DEFAULT '',
    name            TEXT NOT NULL DEFAULT '',
    description     TEXT NOT NULL DEFAULT '',
    date_added      TEXT NOT NULL,
    due_date        TEXT NOT NULL DEFAULT '',
    ransomware      TEXT NOT NULL DEFAULT '',
    required_action TEXT NOT NULL DEFAULT '',
    notes           TEXT NOT NULL DEFAULT ''
) STRICT, WITHOUT ROWID;

-- FIRST EPSS: probability of exploitation in the next 30 days and its percentile, replaced daily.
CREATE TABLE epss (
    cve_id     TEXT PRIMARY KEY NOT NULL,
    score      REAL NOT NULL,
    percentile REAL NOT NULL
) STRICT, WITHOUT ROWID;
