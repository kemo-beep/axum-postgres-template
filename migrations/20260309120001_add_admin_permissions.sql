-- Add admin:access and admin:impersonate permissions
INSERT INTO permissions (id, name) VALUES
  (gen_random_uuid(), 'admin:access'),
  (gen_random_uuid(), 'admin:impersonate')
ON CONFLICT (name) DO NOTHING;

-- Grant both to admin role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'admin' AND p.name IN ('admin:access', 'admin:impersonate')
ON CONFLICT (role_id, permission_id) DO NOTHING;
