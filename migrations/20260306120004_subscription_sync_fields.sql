-- Add last_payment_at and paused_at to subscriptions for full sync from Stripe.
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS last_payment_at TIMESTAMPTZ;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS paused_at TIMESTAMPTZ;
