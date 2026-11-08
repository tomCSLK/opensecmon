-- Updates of opensecagent on request (docs/agent-api.md, "Updates of opensecagent"): the architecture the
-- computer reports (`os.arch`, chooses the package), whether its agent can install updates (`agent.updates`), the
-- version the user asked for ('' none), when they asked and when it was first offered to the agent, and why the
-- agent could not install it ('' none).
ALTER TABLE agent_devices ADD COLUMN arch TEXT NOT NULL DEFAULT '';
ALTER TABLE agent_devices ADD COLUMN can_update INTEGER NOT NULL DEFAULT 0 CHECK (can_update IN (0, 1));
ALTER TABLE agent_devices ADD COLUMN update_version TEXT NOT NULL DEFAULT '';
ALTER TABLE agent_devices ADD COLUMN update_requested_ms INTEGER;
ALTER TABLE agent_devices ADD COLUMN update_sent_ms INTEGER;
ALTER TABLE agent_devices ADD COLUMN update_error TEXT NOT NULL DEFAULT '';
