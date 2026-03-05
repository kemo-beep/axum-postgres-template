-- Add stripe_customer_id to users for Stripe Customer Portal
ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS users_stripe_customer_id_key ON users (stripe_customer_id) WHERE stripe_customer_id IS NOT NULL;
