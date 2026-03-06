-- Add hosted_invoice_url, invoice_pdf_url, status to subscription_transactions
-- for transaction details and frontend actions (view/download invoice).

ALTER TABLE subscription_transactions ADD COLUMN IF NOT EXISTS hosted_invoice_url TEXT;
ALTER TABLE subscription_transactions ADD COLUMN IF NOT EXISTS invoice_pdf_url TEXT;
ALTER TABLE subscription_transactions ADD COLUMN IF NOT EXISTS status VARCHAR(50);

-- Backfill: use existing receipt_url as hosted_invoice_url, event_type as status
UPDATE subscription_transactions
SET hosted_invoice_url = receipt_url, status = event_type
WHERE hosted_invoice_url IS NULL AND receipt_url IS NOT NULL;
UPDATE subscription_transactions
SET status = event_type
WHERE status IS NULL;
