# PII Handling

This document inventories personally identifiable information (PII) stored by the application and how it is handled.

## PII Inventory

| Table | Column | Purpose |
|-------|--------|---------|
| `users` | `email` | Primary identifier, login |
| `users` | `password_hash` | Authentication (hashed) |
| `users` | `google_sub` | OAuth identifier |
| `users` | `stripe_customer_id` | Link to Stripe billing |
| `email_login_codes` | `email` | Magic link / code delivery |
| `org_invites` | `email` | Invite delivery |
| `subscription_transactions` | `billing_email` | Checkout/payment email |
| `api_key_usage_log` | `ip` | Audit (may be PII in some jurisdictions) |

## Minimization

- We store only PII necessary for core functionality (auth, billing, org membership).
- `password_hash`: Argon2 hashed; never stored in plain text.
- API keys: Only key hashes stored, never raw keys.
- Application logs: Avoid logging emails, tokens, or other PII.

## Encryption

- **At-rest**: Recommend database-level encryption (provider-managed, e.g. PostgreSQL transparent data encryption or cloud storage encryption).
- **In transit**: Use TLS for all connections (DB, HTTP, Stripe).
- **Application-level**: Column-level encryption is not implemented. Use database or filesystem encryption for sensitive data at rest.

## Access

- PII is accessible to: application handlers (for auth, billing, org flows), admins with DB access, support (if applicable).
- Future: Audit logging for sensitive actions (login, role changes, billing) to track access.
