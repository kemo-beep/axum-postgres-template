-- Soft delete for audit trail and recovery (users, orgs, workspaces)
ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_by UUID;

ALTER TABLE orgs ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE orgs ADD COLUMN IF NOT EXISTS deleted_by UUID;

ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS deleted_by UUID;
