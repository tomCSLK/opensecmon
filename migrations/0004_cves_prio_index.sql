-- "All CVEs" sorted by priority over the whole period: without this index SQLite sorts every published CVE
-- (1.4 s for page 1, 2.5 s for page 200 on a full database); walking it reads only the rows of the page.
-- It replaces the index on prio alone, which the list never used (every query filters on the state).
DROP INDEX cves_prio;
CREATE INDEX cves_state_prio ON cves (state, prio, published_ms, seq);
