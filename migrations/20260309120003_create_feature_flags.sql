CREATE TABLE feature_flags (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    org_id UUID REFERENCES orgs(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Global flags: one per name (org_id IS NULL)
CREATE UNIQUE INDEX idx_feature_flags_global ON feature_flags(name) WHERE org_id IS NULL;

-- Per-org flags: unique (name, org_id)
CREATE UNIQUE INDEX idx_feature_flags_org ON feature_flags(name, org_id) WHERE org_id IS NOT NULL;
