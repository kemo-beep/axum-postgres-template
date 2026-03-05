-- Add files:read and files:write permissions
INSERT INTO permissions (id, name) VALUES (gen_random_uuid(), 'files:read'), (gen_random_uuid(), 'files:write')
ON CONFLICT (name) DO NOTHING;

-- Add guest role if not present (migration uses viewer which exists)
INSERT INTO roles (id, name) VALUES (gen_random_uuid(), 'guest') ON CONFLICT (name) DO NOTHING;

-- viewer -> files:read
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'viewer' AND p.name = 'files:read'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- member -> users:read, files:read, files:write (extend member; users:read may already exist)
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'member' AND p.name IN ('users:read', 'files:read', 'files:write')
ON CONFLICT (role_id, permission_id) DO NOTHING;
