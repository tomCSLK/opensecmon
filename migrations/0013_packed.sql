-- Phase 8: the largest JSON columns are stored deflated (`storage::packed`): the text column holds '' and the
-- `_z` column the deflated text. Rows written before keep their text until the background conversion on start
-- packs them; '[]' stays text. The space they free returns to the file with "compact the database" (VACUUM).
ALTER TABLE nvd_cves ADD COLUMN configs_z BLOB;
ALTER TABLE cves ADD COLUMN refs_z BLOB;
ALTER TABLE cves ADD COLUMN affected_z BLOB;
