-- Initial auth, RBAC, password reset, logout blacklist, and Stripe billing tables.

-- Users
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT,
    google_sub TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS users_google_sub_key
    ON users (google_sub)
    WHERE google_sub IS NOT NULL;

-- Email login codes for passwordless login
CREATE TABLE IF NOT EXISTS email_login_codes (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL,
    code TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_email_login_codes_email_expires_at
    ON email_login_codes (email, expires_at);

-- Roles & permissions (RBAC)
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- Seed default roles
INSERT INTO roles (id, name)
VALUES
    (gen_random_uuid(), 'admin'),
    (gen_random_uuid(), 'member')
ON CONFLICT (name) DO NOTHING;

-- Password reset tokens
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id_expires_at
    ON password_reset_tokens (user_id, expires_at);

-- Logout token blacklist (JWT jti)
CREATE TABLE IF NOT EXISTS token_blacklist (
    jti UUID PRIMARY KEY,
    exp TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_token_blacklist_exp
    ON token_blacklist (exp);

-- Stripe subscription plans (synced from Stripe)
CREATE TABLE IF NOT EXISTS subscription_plans (
    id UUID PRIMARY KEY,
    stripe_product_id TEXT NOT NULL,
    stripe_price_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    interval TEXT NOT NULL,
    amount_cents BIGINT NOT NULL,
    currency TEXT NOT NULL DEFAULT 'usd',
    features JSONB NOT NULL DEFAULT '[]'::jsonb,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- User subscriptions
CREATE TABLE IF NOT EXISTS subscriptions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    stripe_customer_id TEXT NOT NULL,
    stripe_subscription_id TEXT NOT NULL UNIQUE,
    plan_id UUID REFERENCES subscription_plans(id),
    status TEXT NOT NULL, -- pending, active, cancelled, etc.
    current_period_start TIMESTAMPTZ,
    current_period_end TIMESTAMPTZ,
    cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id
    ON subscriptions (user_id);

-- Subscription transactions (history of events)
CREATE TABLE IF NOT EXISTS subscription_transactions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subscription_id UUID NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL, -- created, renewed, cancelled, payment_succeeded, payment_failed, etc.
    stripe_invoice_id TEXT,
    amount_cents BIGINT,
    currency TEXT,
    receipt_url TEXT,
    occurred_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_subscription_transactions_user_id
    ON subscription_transactions (user_id);

-- Token packages (one-time products; synced from Stripe)
CREATE TABLE IF NOT EXISTS token_packages (
    id UUID PRIMARY KEY,
    stripe_product_id TEXT NOT NULL,
    stripe_price_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    tokens BIGINT NOT NULL,
    amount_cents BIGINT NOT NULL,
    currency TEXT NOT NULL DEFAULT 'usd',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- User credits (current token balance)
CREATE TABLE IF NOT EXISTS user_credits (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    balance BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Credit transactions (purchases, usage, refunds)
CREATE TABLE IF NOT EXISTS credit_transactions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    package_id UUID REFERENCES token_packages(id),
    amount_tokens BIGINT NOT NULL DEFAULT 0,
    amount_cents BIGINT NOT NULL DEFAULT 0,
    currency TEXT NOT NULL DEFAULT 'usd',
    kind TEXT NOT NULL, -- purchase, usage, refund
    stripe_payment_intent_id TEXT,
    stripe_charge_id TEXT,
    receipt_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_credit_transactions_user_id
    ON credit_transactions (user_id);

