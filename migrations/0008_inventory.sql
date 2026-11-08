-- Phase 6: assets from other places: hosts read over SSH, CSV files and the devices of opennetmon.

-- Where an asset came from: `origin` is 'manual', 'csv', 'ssh' or 'opennetmon'; `origin_ref` names the
-- object it belongs to ("ssh:<host id>", "onm:<device id>"), empty for manual and CSV assets. Assets with a
-- reference are kept up to date by their source (a package that is gone from the host is removed).
ALTER TABLE assets ADD COLUMN origin_ref TEXT NOT NULL DEFAULT '';
CREATE INDEX assets_origin_ref ON assets (origin_ref) WHERE origin_ref != '';

-- A host whose packages are read over SSH. The command is forced on the host (`authorized_keys`), the app
-- only reads its output: /etc/os-release, a line "---", then one line per installed package.
-- `host_key` is the confirmed host key (OpenSSH format); empty until the user confirmed `seen_key`, the
-- key the host presented at the last contact. A key that differs from the confirmed one stops the reading.
-- `distro`/`release` come from /etc/os-release ('' if it is neither Debian nor Ubuntu nor based on them).
CREATE TABLE ssh_hosts (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    address     TEXT NOT NULL,
    port        INTEGER NOT NULL DEFAULT 22 CHECK (port BETWEEN 1 AND 65535),
    username    TEXT NOT NULL,
    host_key    TEXT NOT NULL DEFAULT '',
    seen_key    TEXT NOT NULL DEFAULT '',
    os_name     TEXT NOT NULL DEFAULT '',
    distro      TEXT NOT NULL DEFAULT '',
    release     TEXT NOT NULL DEFAULT '',
    packages    INTEGER NOT NULL DEFAULT 0,
    enabled     INTEGER NOT NULL DEFAULT 1,
    last_ms     INTEGER,
    last_ok_ms  INTEGER,
    last_error  TEXT NOT NULL DEFAULT '',
    failures    INTEGER NOT NULL DEFAULT 0,
    created_ms  INTEGER NOT NULL
) STRICT;

-- One row: the app's own SSH key (encrypted with secret.key) and the link to opennetmon (token encrypted).
CREATE TABLE inventory_settings (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    ssh_key      BLOB,
    ssh_public   TEXT NOT NULL DEFAULT '',
    onm_url      TEXT NOT NULL DEFAULT '',
    onm_token    BLOB,
    onm_last_ms  INTEGER,
    onm_error    TEXT NOT NULL DEFAULT ''
) STRICT;
INSERT INTO inventory_settings (id) VALUES (1);

-- The devices opennetmon reported at the last reading, with the product the rules suggest.
-- `state`: 'new' (to be decided), 'taken' (an asset `asset_id` follows the device), 'skipped'.
CREATE TABLE onm_devices (
    id            INTEGER PRIMARY KEY,
    name          TEXT NOT NULL,
    address       TEXT NOT NULL DEFAULT '',
    sys_descr     TEXT NOT NULL DEFAULT '',
    sys_object_id TEXT NOT NULL DEFAULT '',
    vendor_name   TEXT NOT NULL DEFAULT '',
    product_name  TEXT NOT NULL DEFAULT '',
    version       TEXT NOT NULL DEFAULT '',
    kind          TEXT NOT NULL DEFAULT 'hardware',
    rule          TEXT NOT NULL DEFAULT '',
    sure          INTEGER NOT NULL DEFAULT 0,
    state         TEXT NOT NULL DEFAULT 'new' CHECK (state IN ('new', 'taken', 'skipped')),
    asset_id      INTEGER REFERENCES assets (id) ON DELETE SET NULL,
    seen_ms       INTEGER NOT NULL
) STRICT;
