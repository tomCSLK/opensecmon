-- Software that computers and hosts report beside their packages (agent API `items`, the sections of the
-- inventory script): programs and store apps of Windows, snaps and Flatpaks, and Windows itself (type 'os').
-- `origin_ref` is the computer ('agent:<id>') or SSH host ('ssh:<id>') as on its assets; removed with it.
-- Replaced with every full report. `item_key` groups the same program across computers and versions (see
-- `inventory::items::key`).
CREATE TABLE agent_items (
    origin_ref TEXT NOT NULL,
    type      TEXT NOT NULL CHECK (type IN ('os', 'win', 'appx', 'snap', 'flatpak')),
    item_id   TEXT NOT NULL,
    item_key  TEXT NOT NULL,
    name      TEXT NOT NULL,
    version   TEXT NOT NULL,
    publisher TEXT NOT NULL,
    winget_id TEXT NOT NULL DEFAULT '',
    scope     TEXT NOT NULL DEFAULT 'machine' CHECK (scope IN ('machine', 'user')),
    PRIMARY KEY (origin_ref, type, item_id)
) STRICT;
CREATE INDEX agent_items_key ON agent_items (type, item_key);

-- How a reported program becomes an asset, for all computers: by its type and key, to a product (vendor and
-- product as in the asset form) or ignored. Before the rules built into opensecmon.
CREATE TABLE item_rules (
    id           INTEGER PRIMARY KEY,
    type         TEXT NOT NULL,
    item_key     TEXT NOT NULL,
    action       TEXT NOT NULL CHECK (action IN ('asset', 'ignore')),
    vendor_name  TEXT NOT NULL DEFAULT '',
    product_name TEXT NOT NULL DEFAULT '',
    created_ms   INTEGER NOT NULL,
    UNIQUE (type, item_key)
) STRICT;

-- The next report of every computer is stored in full, even if it equals the last one, so its items are kept.
UPDATE agent_devices SET report_hash = '';
