-- Add orgs:manage and workspaces:manage permissions for RBAC integration

INSERT INTO permissions (id, name) VALUES (gen_random_uuid(), 'orgs:manage'), (gen_random_uuid(), 'workspaces:manage')
ON CONFLICT (name) DO NOTHING;

-- Admin gets org and workspace manage
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'admin' AND p.name IN ('orgs:manage', 'workspaces:manage')
ON CONFLICT (role_id, permission_id) DO NOTHING;
