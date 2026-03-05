-- Email login codes for passwordless auth (6-digit code, 15min expiry)
CREATE TABLE IF NOT EXISTS email_login_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL,
    code TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_email_login_codes_email ON email_login_codes(email);
CREATE INDEX IF NOT EXISTS idx_email_login_codes_expires_at ON email_login_codes(expires_at);
