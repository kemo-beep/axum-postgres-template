-- Roles
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Permissions (e.g. users:read, users:write, billing:manage)
CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Role-Permission junction
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- User-Role assignment
CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);

-- Seed default roles and permissions
INSERT INTO roles (id, name) VALUES (gen_random_uuid(), 'admin'), (gen_random_uuid(), 'member'), (gen_random_uuid(), 'viewer')
ON CONFLICT (name) DO NOTHING;

INSERT INTO permissions (id, name) VALUES (gen_random_uuid(), 'users:read'), (gen_random_uuid(), 'users:write'), (gen_random_uuid(), 'billing:manage')
ON CONFLICT (name) DO NOTHING;

-- Admin gets all permissions; member gets users:read
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE (r.name = 'admin') OR (r.name = 'member' AND p.name = 'users:read')
ON CONFLICT (role_id, permission_id) DO NOTHING;
