-- Phase 8: the weights of the priority are settings (page "Priority").
-- Priority of a CVE: CVSS × cvss_weight + EPSS percentile (0–1) × epss_weight, at most 100; a CVE in CISA KEV at
-- least kev_floor. A match takes off what its confidence costs (high 0, medium penalty_medium, low penalty_low);
-- a match of medium or high confidence of a KEV CVE stays at kev_floor. The defaults are the formula of phases 2–7.
-- `recompute` is 1 from saving new weights until every CVE priority follows them; meanwhile the instant mail waits,
-- so that priorities half old, half new do not count as escalations.
CREATE TABLE prio_settings (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    cvss_weight    REAL NOT NULL DEFAULT 7 CHECK (cvss_weight BETWEEN 0 AND 10),
    epss_weight    REAL NOT NULL DEFAULT 20 CHECK (epss_weight BETWEEN 0 AND 100),
    kev_floor      INTEGER NOT NULL DEFAULT 90 CHECK (kev_floor BETWEEN 0 AND 100),
    penalty_medium INTEGER NOT NULL DEFAULT 10 CHECK (penalty_medium BETWEEN 0 AND 100),
    penalty_low    INTEGER NOT NULL DEFAULT 25 CHECK (penalty_low BETWEEN 0 AND 100),
    updated_ms     INTEGER NOT NULL DEFAULT 0,
    recompute      INTEGER NOT NULL DEFAULT 0 CHECK (recompute IN (0, 1))
) STRICT;

INSERT INTO prio_settings (id) VALUES (1);
