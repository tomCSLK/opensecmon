-- Phase 5: the own assets, the watchlist and the matches between them and the vulnerabilities.

-- One piece of own software or hardware. `kind`:
--   'package'  a Debian/Ubuntu source package on a host (`distro`, `release` such as "13" or "24.04",
--              `pro` = the host gets Ubuntu Pro/ESM updates); matched against the OSV ranges of the distro.
--   'software' / 'hardware'  a product: matched through vendor/product keys (as in `cve_products`,
--              `advisory_products`) or the vendor/product of `cpe` (CPE 2.3) against the NVD's CPE
--              configurations, the CNA's version ranges and the CSAF product trees.
-- `vendor`/`product` are the normalised keys (lower case letters and digits), the names as entered.
-- `origin` says where the asset came from ('manual' now; SSH, CSV and opennetmon follow in phase 6).
CREATE TABLE assets (
    id           INTEGER PRIMARY KEY,
    kind         TEXT NOT NULL CHECK (kind IN ('package', 'software', 'hardware')),
    vendor       TEXT NOT NULL DEFAULT '',
    product      TEXT NOT NULL,
    vendor_name  TEXT NOT NULL DEFAULT '',
    product_name TEXT NOT NULL,
    version      TEXT NOT NULL DEFAULT '',
    host         TEXT NOT NULL DEFAULT '',
    cpe          TEXT NOT NULL DEFAULT '',
    distro       TEXT NOT NULL DEFAULT '' CHECK (distro IN ('', 'debian', 'ubuntu')),
    release      TEXT NOT NULL DEFAULT '',
    pro          INTEGER NOT NULL DEFAULT 0,
    origin       TEXT NOT NULL DEFAULT 'manual',
    note         TEXT NOT NULL DEFAULT '',
    created_ms   INTEGER NOT NULL,
    updated_ms   INTEGER NOT NULL,
    matched_ms   INTEGER
) STRICT;

CREATE INDEX assets_host ON assets (host, product);

-- Keywords for products without a usable identifier, searched in the titles and product names of CVEs and
-- advisories published since `since_ms` (30 days before the keyword was added).
CREATE TABLE watchlist (
    id         INTEGER PRIMARY KEY,
    keyword    TEXT NOT NULL UNIQUE,
    created_ms INTEGER NOT NULL,
    since_ms   INTEGER NOT NULL,
    matched_ms INTEGER
) STRICT;

-- A match: an asset (or a watchlist keyword) is affected by a vulnerability. `vuln` is the CVE id, or for
-- reports without a CVE "adv:<advisory seq>" (CSAF) or "osv:<record id>" (DSA/USN). `subject` is
-- "a:<asset id>" or "w:<keyword id>", unique together with `vuln`.
-- `confidence`: high (version checked against a range of the distribution, the NVD or the CNA), medium
-- (CSAF product tree, or the product matches and the version could not be checked), low (watchlist).
-- `method`: distro, nvd, cna, csaf, watch. `fixed` is the version that fixes it (if known), `evidence` the
-- ids of the records that matched (USN-…, DSA-…, WID-SEC-…), comma separated. `base_prio` is the priority
-- of a report without a CVE (CVE matches use `cves.prio`).
-- `state`: new, seen, later (until `until_ms`), done, ignored. `auto` = 1: set to done by the matching
-- because the asset is no longer affected (a newer version); it opens again if the match comes back.
CREATE TABLE matches (
    id            INTEGER PRIMARY KEY,
    subject       TEXT NOT NULL,
    asset_id      INTEGER REFERENCES assets (id) ON DELETE CASCADE,
    watch_id      INTEGER REFERENCES watchlist (id) ON DELETE CASCADE,
    vuln          TEXT NOT NULL,
    title         TEXT NOT NULL DEFAULT '',
    confidence    TEXT NOT NULL CHECK (confidence IN ('high', 'medium', 'low')),
    method        TEXT NOT NULL CHECK (method IN ('distro', 'nvd', 'cna', 'csaf', 'watch')),
    fixed         TEXT NOT NULL DEFAULT '',
    evidence      TEXT NOT NULL DEFAULT '',
    base_prio     INTEGER NOT NULL DEFAULT 0,
    state         TEXT NOT NULL DEFAULT 'new'
        CHECK (state IN ('new', 'seen', 'later', 'done', 'ignored')),
    until_ms      INTEGER,
    reason        TEXT NOT NULL DEFAULT '',
    note          TEXT NOT NULL DEFAULT '',
    auto          INTEGER NOT NULL DEFAULT 0,
    first_seen_ms INTEGER NOT NULL,
    updated_ms    INTEGER NOT NULL,
    state_ms      INTEGER NOT NULL,
    CHECK ((asset_id IS NULL) != (watch_id IS NULL)),
    UNIQUE (subject, vuln)
) STRICT;

CREATE INDEX matches_vuln ON matches (vuln);
CREATE INDEX matches_state ON matches (state, vuln);
CREATE INDEX matches_asset ON matches (asset_id);
CREATE INDEX matches_watch ON matches (watch_id);

-- The matching looks up CSAF products by product key alone (BSI names many vendors "Open Source").
CREATE INDEX advisory_products_product ON advisory_products (product);
