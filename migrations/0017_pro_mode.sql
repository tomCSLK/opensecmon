-- Ubuntu Pro per SSH host and per computer of the agent API: `pro_mode` 'auto' (as the reading finds it), 'yes'
-- or 'no'; `pro_detected` what the last reading found. The package assets of the host follow the effective value,
-- a reading no longer resets it.
ALTER TABLE ssh_hosts ADD COLUMN pro_mode TEXT NOT NULL DEFAULT 'auto'
    CHECK (pro_mode IN ('auto', 'yes', 'no'));
ALTER TABLE ssh_hosts ADD COLUMN pro_detected INTEGER NOT NULL DEFAULT 0 CHECK (pro_detected IN (0, 1));
ALTER TABLE agent_devices ADD COLUMN pro_mode TEXT NOT NULL DEFAULT 'auto'
    CHECK (pro_mode IN ('auto', 'yes', 'no'));
ALTER TABLE agent_devices ADD COLUMN pro_detected INTEGER NOT NULL DEFAULT 0 CHECK (pro_detected IN (0, 1));

-- What the readings so far found: a source version with "esm" (as `inventory::listing` detects it).
UPDATE ssh_hosts SET pro_detected = EXISTS (
    SELECT 1 FROM assets
     WHERE origin_ref = 'ssh:' || ssh_hosts.id AND distro = 'ubuntu' AND instr(version, 'esm') > 0);
UPDATE agent_devices SET pro_detected = EXISTS (
    SELECT 1 FROM assets
     WHERE origin_ref = 'agent:' || agent_devices.id AND distro = 'ubuntu' AND instr(version, 'esm') > 0);
