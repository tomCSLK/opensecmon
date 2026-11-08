-- Phase 3: CSAF advisories from BSI CERT-Bund and from vendors (CSAF 2.0 trusted providers).
-- Only documents labelled TLP:WHITE or TLP:CLEAR are loaded; their texts are data, shown escaped.

-- The CSAF providers: BSI CERT-Bund (one row, source 'bsi') and the vendors chosen on the page
-- "Vendor CSAF" (source 'vendor'). `url` is the provider-metadata.json; `distributions` caches what it said
-- at the last run ([{"kind": "rolie" | "directory", "url": …, "tlp": …}]), `skip` lists distribution URLs not
-- to load (Red Hat's VEX directory, for example), `since` (YYYY-MM-DD) leaves older documents out.
CREATE TABLE csaf_providers (
    id            INTEGER PRIMARY KEY,
    source        TEXT NOT NULL CHECK (source IN ('bsi', 'vendor')),
    url           TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL DEFAULT '',
    enabled       INTEGER NOT NULL DEFAULT 1,
    since         TEXT NOT NULL DEFAULT '',
    skip          TEXT NOT NULL DEFAULT '[]',
    distributions TEXT NOT NULL DEFAULT '[]',
    added_ms      INTEGER NOT NULL,
    checked_ms    INTEGER,
    last_error    TEXT,
    documents     INTEGER NOT NULL DEFAULT 0
) STRICT;

INSERT INTO csaf_providers (source, url, name, added_ms)
VALUES ('bsi', 'https://wid.cert-bund.de/.well-known/csaf/provider-metadata.json', 'BSI CERT-Bund', 0);

-- Validators of every ROLIE feed and `changes.csv` (a feed that did not change is not read again). They are
-- only saved after a run in which every document of the feed was handled, so failed downloads are retried.
CREATE TABLE csaf_feeds (
    url           TEXT PRIMARY KEY NOT NULL,
    provider_id   INTEGER NOT NULL REFERENCES csaf_providers (id) ON DELETE CASCADE,
    etag          TEXT,
    last_modified TEXT,
    checked_ms    INTEGER NOT NULL
) STRICT;

-- Documents that were fetched but not stored (wrong checksum, not TLP:WHITE, not CSAF …), with the `updated`
-- of the feed entry: they are tried again only when the provider publishes a new version.
CREATE TABLE csaf_skipped (
    url         TEXT PRIMARY KEY NOT NULL,
    provider_id INTEGER NOT NULL REFERENCES csaf_providers (id) ON DELETE CASCADE,
    updated     TEXT NOT NULL,
    reason      TEXT NOT NULL,
    checked_ms  INTEGER NOT NULL
) STRICT;

-- One row per CSAF document. `display_id` is the id people know (BSI: WID-SEC-2026-4365 of the portal, the
-- tracking id is WID-SEC-W-2026-4365), `feed_updated` the time the feed gave for this version (unchanged →
-- not fetched again). `severity` is the band (from the publisher's aggregate severity, else from the highest
-- CVSS score), `severity_text` the publisher's own word. `notes` and `refs` are compact JSON for the detail.
CREATE TABLE advisories (
    seq           INTEGER PRIMARY KEY,
    provider_id   INTEGER NOT NULL REFERENCES csaf_providers (id) ON DELETE CASCADE,
    source        TEXT NOT NULL CHECK (source IN ('bsi', 'vendor')),
    url           TEXT NOT NULL UNIQUE,
    feed_updated  TEXT NOT NULL DEFAULT '',
    tracking_id   TEXT NOT NULL,
    display_id    TEXT NOT NULL,
    publisher     TEXT NOT NULL DEFAULT '',
    title         TEXT NOT NULL DEFAULT '',
    summary       TEXT NOT NULL DEFAULT '',
    products      TEXT NOT NULL DEFAULT '',
    lang          TEXT NOT NULL DEFAULT '',
    tlp           TEXT NOT NULL DEFAULT '',
    severity      TEXT NOT NULL DEFAULT '' CHECK (severity IN ('critical', 'high', 'medium', 'low', '')),
    severity_text TEXT NOT NULL DEFAULT '',
    cvss_score    REAL,
    status        TEXT NOT NULL DEFAULT '',
    version       TEXT NOT NULL DEFAULT '',
    published_ms  INTEGER,
    updated_ms    INTEGER,
    web_url       TEXT NOT NULL DEFAULT '',
    hash_checked  INTEGER NOT NULL DEFAULT 0,
    cve_count     INTEGER NOT NULL DEFAULT 0,
    product_count INTEGER NOT NULL DEFAULT 0,
    notes         TEXT NOT NULL DEFAULT '[]',
    refs          TEXT NOT NULL DEFAULT '[]',
    fetched_ms    INTEGER NOT NULL
) STRICT;

CREATE INDEX advisories_updated ON advisories (updated_ms, seq);
CREATE INDEX advisories_provider ON advisories (provider_id, updated_ms);
CREATE INDEX advisories_tracking ON advisories (tracking_id);
CREATE INDEX advisories_display ON advisories (display_id);

CREATE VIRTUAL TABLE advisories_fts USING fts5 (
    display_id, title, summary, products,
    content = 'advisories', content_rowid = 'seq',
    tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TRIGGER advisories_fts_insert AFTER INSERT ON advisories BEGIN
    INSERT INTO advisories_fts (rowid, display_id, title, summary, products)
    VALUES (new.seq, new.display_id, new.title, new.summary, new.products);
END;
CREATE TRIGGER advisories_fts_delete AFTER DELETE ON advisories BEGIN
    INSERT INTO advisories_fts (advisories_fts, rowid, display_id, title, summary, products)
    VALUES ('delete', old.seq, old.display_id, old.title, old.summary, old.products);
END;
CREATE TRIGGER advisories_fts_update AFTER UPDATE OF display_id, title, summary, products ON advisories BEGIN
    INSERT INTO advisories_fts (advisories_fts, rowid, display_id, title, summary, products)
    VALUES ('delete', old.seq, old.display_id, old.title, old.summary, old.products);
    INSERT INTO advisories_fts (rowid, display_id, title, summary, products)
    VALUES (new.seq, new.display_id, new.title, new.summary, new.products);
END;

-- The CVEs an advisory names.
CREATE TABLE advisory_cves (
    advisory_seq INTEGER NOT NULL REFERENCES advisories (seq) ON DELETE CASCADE,
    cve_id       TEXT NOT NULL,
    PRIMARY KEY (advisory_seq, cve_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX advisory_cves_cve ON advisory_cves (cve_id);

-- The products of the CSAF product tree: vendor and product as normalised keys (as in `cve_products`) and as
-- given, the version (`version_range` = 1: a range such as "<10.6p2"), CPE/PURL and the status the
-- vulnerabilities give the product: affected, fixed, not_affected, investigating, recommended or '' (named
-- in the tree only, as BSI does with the fixed versions). Matching against the assets comes with phase 5.
CREATE TABLE advisory_products (
    advisory_seq  INTEGER NOT NULL REFERENCES advisories (seq) ON DELETE CASCADE,
    product_id    TEXT NOT NULL,
    vendor        TEXT NOT NULL,
    product       TEXT NOT NULL,
    vendor_name   TEXT NOT NULL,
    product_name  TEXT NOT NULL,
    name          TEXT NOT NULL,
    version       TEXT NOT NULL DEFAULT '',
    version_range INTEGER NOT NULL DEFAULT 0,
    cpe           TEXT NOT NULL DEFAULT '',
    purl          TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT ''
        CHECK (status IN ('affected', 'fixed', 'not_affected', 'investigating', 'recommended', '')),
    PRIMARY KEY (advisory_seq, product_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX advisory_products_vendor ON advisory_products (vendor, product);

-- The providers of the BSI's list (aggregator.json), kept for the page "Vendor CSAF" until it is loaded again.
CREATE TABLE csaf_lister (
    url       TEXT PRIMARY KEY NOT NULL,
    name      TEXT NOT NULL,
    role      TEXT NOT NULL DEFAULT '',
    loaded_ms INTEGER NOT NULL
) STRICT;

INSERT INTO source_state (source, interval_secs) VALUES ('bsi', 7200), ('vendor', 21600);

-- A run can succeed with warnings (documents skipped): shown on the sources page, cleared by the next run.
ALTER TABLE source_state ADD COLUMN last_warning TEXT;
