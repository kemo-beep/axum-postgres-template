-- Add billing_email to subscription_transactions (email used at checkout/payment, may differ from users.email).
ALTER TABLE subscription_transactions ADD COLUMN IF NOT EXISTS billing_email TEXT;
