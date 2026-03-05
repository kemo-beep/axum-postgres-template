# SaaS Backend Checklist

Production-ready backend checklist for an Axum + PostgreSQL SaaS stack.

---

## Code Quality & Architecture

*Neat, clean, and well-thought-out structure for scalability and maintainability.*

### Project structure

- [x] Clear module boundaries: `routes/`, `auth/`, `services/`, `repositories/` (in auth)
- [x] Feature-based or domain-based layout (e.g. `auth/`, `billing/`, `storage/`)
- [ ] Shared types and errors in a central place; avoid circular deps

### Layering

- [x] Handlers: thin, extract input → call service → return response
- [x] Services: business logic, orchestration, no HTTP/axum details
- [x] Repositories: DB access only, return domain types or raw data
- [ ] Keep dependencies one-way (handlers → services → repositories)

### Domain & types

- [x] Domain types separate from DB/API DTOs; map at boundaries
- [x] Enums for bounded states (subscription status, role, etc.)
- [x] Newtype wrappers for IDs to avoid mixing `UserId` and `TenantId`

### Errors

- [ ] Use `thiserror` / `anyhow`; convert to `ApiError` at handler boundary
- [ ] Avoid `unwrap()` in production paths; use `?` and propagate
- [ ] Don’t leak internal errors to clients; log and return generic messages

### Consistency

- [ ] Naming: consistent conventions (snake_case, plural routes, etc.)
- [ ] `rustfmt` and `clippy` in CI; address warnings
- [ ] Doc comments for public APIs and non-obvious logic

### Scalability mindset

- [ ] Stateless handlers (session/tenant in extractors or state)
- [ ] Avoid N+1 queries; batch or join where needed
- [ ] External calls (email, Stripe, R2) non-blocking and with timeouts

---

## Core Infrastructure

### PostgreSQL & SQLx
- [ ] Migrations run at startup (`sqlx::migrate!`)
- [ ] Connection pooling configured (`DATABASE_POOL_MAX_SIZE` vs Postgres `max_connections`)
- [ ] Prepared statement caching (SQLx default)
- [ ] Migrations folder at `./migrations/`
- [ ] `DATABASE_URL` in `.env` / env vars

### Configuration
- [ ] `APP_ENVIRONMENT` (development/production)
- [ ] `PORT` / `listen_address`
- [ ] Sensitive config via env vars, never hardcoded

---

## Email (SMTP)

- [x] Add SMTP crate: `lettre` (tokio1)
- [x] Env vars: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `MAIL_FROM`
- [ ] TLS/STARTTLS for production
- [ ] Transactional emails (signup, password reset, etc.)
- [ ] Async sending (background task or queue)
- [ ] Email templates (e.g. `maud`, `askama`, or simple string templates)
- [ ] Rate limiting for email-sending endpoints

---

## Object Storage (Cloudflare R2)

- [x] R2 S3-compatible API (stub; requires `aws-sdk-s3`, Rust 1.91+ for full support)
- [x] Env vars: `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `R2_BUCKET_NAME`, `R2_ENDPOINT`
- [ ] Presigned URLs for private file access
- [ ] Public bucket policy for static assets (optional)
- [ ] File size limits and validation on upload
- [ ] Content-Type / MIME type handling
- [ ] Cleanup on record deletion (or soft delete + lifecycle rules)

---

## Authentication

*Who is the user?*

Three login methods: **email code**, **Google**, and **email + password**.

### User model

- [x] `users` table: id, email, password_hash (nullable), google_sub (nullable), created_at, etc.
- [ ] One user per email; link Google OAuth to existing account by email if present

### Login method 1: Email code (passwordless)

- [x] Step 1: User enters email → API sends a short-lived code (e.g. 6 digits) via SMTP
- [x] Store code in DB with expiry (15 min); rate limit per IP (`tower_governor`)
- [x] Step 2: User submits email + code → validate code, create JWT, log in
- [x] Invalidate code after successful use (one-time)
- [x] If no user exists for email, create user on first successful code login (passwordless signup)

### Login method 2: Google

- [x] OAuth 2.0 flow: redirect to Google → callback with auth code → exchange for tokens
- [x] Get email from Google profile; match by email or create user
- [x] Store `google_sub` on user for future logins
- [x] Env: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `BASE_URL` for redirect URI

### Login method 3: Email + password

- [x] Registration: email + password, validation, duplicate-email check; hash password (`argon2`)
- [x] Login: validate credentials → create JWT
- [ ] Password reset: send reset link or code via email, one-time use, expiry (structure in place)
- [ ] Account lockout after N failed attempts (optional)

### Common auth

- [ ] Logout: invalidate token (stateless JWT; blacklist optional)
- [x] JWT (same for all three methods)
  - JWT: stateless, `Authorization: Bearer`
  - Sessions: `axum-extra::CookieSession` or Redis-backed
- [ ] Token refresh flow (if JWT)
- [ ] Secure, httpOnly, SameSite cookies if cookie-based
- [ ] Rate limiting on login and “send code” endpoints

---

## Authorization & RBAC

*What can the user do?*

### Role-Based Access Control (RBAC)

- [x] `roles` table (e.g. `admin`, `member`, `viewer`, `guest`)
- [x] `permissions` table (e.g. `users:read`, `users:write`, `billing:manage`)
- [x] `role_permissions` junction (many-to-many: role ↔ permission)
- [x] `user_roles` (user ↔ role; support multiple roles per user)
- [ ] Permission naming convention (e.g. `resource:action`)

### Enforcement

- [x] Auth extractor: `RequireAuth` (checks Bearer token, returns user)
- [x] Helpers: `check_permission`, `check_role` (via RbacRepository)
- [ ] Apply per-route or per-router via `.route_layer()`
- [ ] 401 Unauthorized when not authenticated
- [ ] 403 Forbidden when authenticated but lacking permission

### Resource-Level Authorization

- [ ] Ownership checks: user can only access their own resources
- [ ] Multi-tenancy: org/workspace/tenant scoping (e.g. `tenant_id` on resources)
- [ ] Row-level checks in queries (filter by `user_id` / `tenant_id`)

### API Keys & Service Accounts

- [ ] API keys for machine-to-machine (e.g. `X-API-Key` header)
- [ ] Scoped keys (per-tenant, read-only, etc.)
- [ ] Key rotation and expiry
- [ ] Audit log for key usage

---

## Security (General)

- [x] Rate limiting (`tower-governor`) on auth endpoints (send-code, login, register)
- [x] CORS configured for known frontend origins
- [x] Request IDs / correlation IDs (tower-http)
- [ ] HTTPS in production (reverse proxy)
- [x] Security headers (X-Content-Type-Options, X-Frame-Options, HSTS in prod)
- [ ] Audit logging for sensitive actions (login, role changes, billing)

---

## Payments: Stripe / Polar.sh

*Subscriptions and one-time purchases (token packages, products).*

### Provider choice

- **Stripe** — mature, broad adoption, full control over UX
- **Polar.sh** — developer-focused, open source, simpler setup, built-in billing dashboard

### Configuration

- [ ] Env vars: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PUBLISHABLE_KEY` (or `POLAR_ACCESS_TOKEN`, `POLAR_WEBHOOK_SECRET`, etc.)
- [ ] Webhook signing secret for idempotent, secure event handling

### Subscriptions

- [ ] Plan models: `subscription_plans` (id, name, price_id, interval, amount, features)
- [ ] `subscriptions` table (user_id, plan_id, external_id, status, current_period_end)
- [ ] Create Checkout Session / Payment Link for subscription signup
- [ ] Webhook handlers: `checkout.session.completed`, `customer.subscription.created`, `customer.subscription.updated`, `customer.subscription.deleted`
- [ ] Sync subscription status to DB on webhook events
- [ ] Grace period / dunning for failed renewals
- [ ] Cancel / downgrade / upgrade flows

### Token packages / one-time products

- [ ] `token_packages` or `products` (id, name, external_price_id, tokens, price)
- [ ] Create Checkout Session for one-time purchase
- [ ] Webhook: `checkout.session.completed` (payment_intent or one-time)
- [ ] Credit tokens to user/account on successful payment
- [ ] `user_tokens` or `credits` balance table with audit trail (transactions log)

### Webhooks

- [x] Dedicated webhook route: `POST /webhooks/stripe` (signature verification structure)
- [ ] Verify signature (Stripe: `Stripe-Signature`, Polar: signing secret)
- [ ] Idempotency: use `id` or `request_id` to avoid double-processing
- [ ] Return 200 quickly, process async (background task / queue) if needed
- [ ] Log failures for debugging; retry policy per provider docs

### Checkout & customer portal

- [ ] Redirect to Stripe Checkout / Polar checkout with `success_url`, `cancel_url`, `customer_email` / `metadata` (user_id, tenant_id)
- [ ] Customer portal link for managing subscription, payment methods, invoices
- [ ] Store `customer_id` (Stripe) or equivalent on user for portal / future payments

### Edge cases

- [ ] Handle `invoice.payment_failed` (notify user, retry logic)
- [ ] Proration on plan changes
- [ ] Refunds and their impact on token balance (if applicable)

---

## API & Errors

- [ ] Consistent error types (`thiserror`, `ApiError`)
- [ ] HTTP status codes mapped to errors
- [ ] Validation (e.g. `validator`, `axum-valid`)
- [ ] OpenAPI / Swagger (optional, e.g. `utoipa`)

---

## Observability

- [ ] Structured logging (`tracing`, `tracing-subscriber`)
- [ ] `RUST_LOG` for log levels
- [ ] Health check endpoint (readiness + liveness)
- [ ] Metrics (optional: `metrics` + Prometheus exporter)
- [ ] Tracing propagation (e.g. OpenTelemetry) for distributed requests
- [ ] Error tracking (e.g. Sentry) in production

---

## Background Jobs & Async Work

*Reliable processing for emails, webhooks, token crediting, scheduled tasks.*

- [x] Job queue trait (`services::JobQueue`); template uses `tokio::spawn`. Document Redis/`background-jobs` as production upgrade.
- [x] Async email sending via `EmailSender` trait (spawn or queue)
- [ ] Webhook handling: return 200 fast, process in background
- [ ] Scheduled jobs: subscription checks, cleanup, reminder emails
- [ ] Retries with backoff and dead-letter handling
- [ ] Job observability (enqueue/fail counts, latency)

---

## Graceful Shutdown

- [x] Handle SIGTERM / SIGINT (`tokio::signal::ctrl_c`)
- [x] Stop accepting new connections
- [x] Drain in-flight requests (axum graceful shutdown)
- [ ] Close DB pool and other resources
- [ ] Exit cleanly

---

## API Design & Versioning

- [x] API versioning (`/v1/` for auth, files, etc.)
- [ ] Idempotency keys for mutable endpoints (`Idempotency-Key` header)
- [ ] Request/response size limits
- [ ] Pagination for list endpoints (cursor or offset)
- [ ] Deprecation headers / sunset policy

---

## Data & Compliance

- [ ] Soft delete for audit trail and recovery
- [ ] Account deletion flow (GDPR right to erasure)
- [ ] Data export (GDPR right to portability)
- [ ] Data retention policy (logs, audit, backups)
- [ ] PII handling: minimize storage, encrypt if needed

---

## Resilience

- [x] DB connection retry with backoff on startup
- [ ] Timeouts on external calls (Stripe, SMTP, R2)
- [ ] Circuit breaker for external services (optional)
- [ ] Request timeout (already in tower-http)
- [ ] DB backup strategy and restore procedure

---

## Testing

- [x] Integration tests (health, auth: register, login, /me 401)
- [x] Test database per run (random DB); migrations
- [x] CI pipeline (build, test, lint, JWT_SECRET stub)
- [ ] E2E tests for critical flows (auth, checkout)
- [ ] Load testing for key endpoints

---

## Admin & Operations

- [ ] Admin API or internal routes (auth-protected)
- [ ] Impersonation for support (audit-logged)
- [ ] Feature flags (per-tenant or global)
- [ ] Runbook / ops documentation

---

## Deployment

- [ ] Dockerfile / container image
- [ ] Migrations in startup (or separate init job)
- [ ] Health checks in container orchestration
- [ ] Secrets from env / secret manager (e.g. Doppler, Vault)
- [ ] Multi-replica: stateless app, connection pool sizing
- [ ] Zero-downtime deploys (rolling, blue-green)

---

## Dependencies to Add

| Feature     | Crate Suggestion   |
|------------|--------------------|
| SMTP       | `lettre`, `lettre-async` |
| R2/S3      | `aws-sdk-s3` with custom endpoint |
| Password   | `argon2` (preferred), `bcrypt` |
| JWT        | `jsonwebtoken`, `jwt-simple` |
| Sessions   | `axum-extra` (cookies), `tower-sessions` (Redis-backed) |
| OAuth/OIDC | `openidconnect`, `oauth2` |
| MFA/TOTP   | `totp-rs` |
| Rate limit | `tower-governor` |
| Validation | `validator`, `axum-valid` |
| Stripe     | `stripe-rust` (official Rust SDK) |
| Polar.sh   | `reqwest` + REST API (no official Rust SDK) |
| Background jobs | `background-jobs`, `sidekiq-rs` (Redis) |
| Error tracking | `sentry` (Sentry SDK) |
