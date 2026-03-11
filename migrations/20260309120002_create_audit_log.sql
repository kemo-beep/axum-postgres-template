CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_id UUID NOT NULL REFERENCES users(id),
    action TEXT NOT NULL,
    target_user_id UUID REFERENCES users(id),
    target_org_id UUID REFERENCES orgs(id),
    metadata JSONB,
    ip TEXT,
    path TEXT
);

CREATE INDEX idx_audit_log_actor_id ON audit_log(actor_id);
CREATE INDEX idx_audit_log_target_user_id ON audit_log(target_user_id);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);
