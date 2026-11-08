-- The list of all CVEs filters on the state and sorts by the publication date; counting all published
-- CVEs without this index read the whole table (six seconds for 400,000 records).
DROP INDEX cves_published;
CREATE INDEX cves_state_published ON cves (state, published_ms);
