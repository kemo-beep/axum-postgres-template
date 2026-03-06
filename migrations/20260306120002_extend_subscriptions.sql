-- Add trial and cancellation fields to subscriptions for production-grade billing flows.
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS trial_start TIMESTAMPTZ;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS trial_end TIMESTAMPTZ;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS canceled_at TIMESTAMPTZ;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS latest_invoice_id TEXT;
