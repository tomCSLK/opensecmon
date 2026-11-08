-- What the inventory script says beside the packages (from the lines `OPENSECMON_*` before `---`): the running
-- kernel (`uname -r`, '' if the script does not say), the highest installed kernel source version and whether
-- the system waits for a reboot (`/var/run/reboot-required`).
ALTER TABLE ssh_hosts ADD COLUMN kernel TEXT NOT NULL DEFAULT '';
ALTER TABLE ssh_hosts ADD COLUMN kernel_installed TEXT NOT NULL DEFAULT '';
ALTER TABLE ssh_hosts ADD COLUMN reboot_required INTEGER NOT NULL DEFAULT 0 CHECK (reboot_required IN (0, 1));
ALTER TABLE agent_devices ADD COLUMN kernel TEXT NOT NULL DEFAULT '';
ALTER TABLE agent_devices ADD COLUMN kernel_installed TEXT NOT NULL DEFAULT '';
ALTER TABLE agent_devices ADD COLUMN reboot_required INTEGER NOT NULL DEFAULT 0 CHECK (reboot_required IN (0, 1));
