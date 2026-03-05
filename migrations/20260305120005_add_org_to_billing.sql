-- Add org_id to billing tables and create org_credits.

-- Add org_id to subscriptions (nullable for backfill)
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES orgs(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_subscriptions_org_id ON subscriptions (org_id);

-- Add org_id to credit_transactions
ALTER TABLE credit_transactions ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES orgs(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_credit_transactions_org_id ON credit_transactions (org_id);

-- Add org_id to subscription_transactions
ALTER TABLE subscription_transactions ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES orgs(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_subscription_transactions_org_id ON subscription_transactions (org_id);

-- org_credits: per-org credit balance (replaces user_credits for org-scoped billing)
CREATE TABLE IF NOT EXISTS org_credits (
    org_id UUID PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    balance BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Backfill: create personal org for each user with billing data, set org_id
DO $$
DECLARE
    r RECORD;
    new_org_id UUID;
    new_slug TEXT;
BEGIN
    FOR r IN
        SELECT DISTINCT u.id AS user_id
        FROM users u
        WHERE EXISTS (SELECT 1 FROM subscriptions s WHERE s.user_id = u.id)
           OR EXISTS (SELECT 1 FROM user_credits uc WHERE uc.user_id = u.id)
    LOOP
        new_org_id := gen_random_uuid();
        new_slug := 'personal-' || replace(r.user_id::text, '-', '');
        INSERT INTO orgs (id, name, slug, created_at, updated_at)
        VALUES (new_org_id, 'Personal', new_slug, now(), now());
        INSERT INTO org_members (org_id, user_id, role)
        VALUES (new_org_id, r.user_id, 'owner')
        ON CONFLICT (org_id, user_id) DO NOTHING;
        UPDATE subscriptions SET org_id = new_org_id WHERE user_id = r.user_id AND org_id IS NULL;
        UPDATE credit_transactions SET org_id = new_org_id WHERE user_id = r.user_id AND org_id IS NULL;
        UPDATE subscription_transactions st SET org_id = (
            SELECT org_id FROM subscriptions s WHERE s.id = st.subscription_id LIMIT 1
        ) WHERE org_id IS NULL;
        INSERT INTO org_credits (org_id, balance, updated_at)
        SELECT new_org_id, uc.balance, now()
        FROM user_credits uc WHERE uc.user_id = r.user_id
        ON CONFLICT (org_id) DO UPDATE SET balance = org_credits.balance + EXCLUDED.balance, updated_at = now();
    END LOOP;
END $$;

-- Make org_id NOT NULL where we have data (optional: run after backfill)
-- ALTER TABLE subscriptions ALTER COLUMN org_id SET NOT NULL;
-- ALTER TABLE credit_transactions ALTER COLUMN org_id SET NOT NULL;
