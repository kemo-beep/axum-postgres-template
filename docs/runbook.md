# Operations Runbook

Operational procedures and incident response for the Axum + PostgreSQL backend.

## Deployment

- **Migrations**: Run automatically on startup via `sqlx::migrate!` in `main`. No manual migration step.
- **Environment**: Required variables from `.env.sample`. Ensure `APP_ENVIRONMENT`, `PORT`, `DATABASE_URL`, `JWT_SECRET` are set.
- **Build**: `cargo build --release` for production; run the resulting binary.
- **Docker**: No Dockerfile included by default; add one for containerized deploys. Ensure migrations run on startup and the DB is reachable.

## Health Checks

| Endpoint | Purpose |
|----------|---------|
| `GET /health` | Liveness and readiness probe |

Configure your container orchestrator (Kubernetes, ECS, etc.) to use `/health` for both liveness and readiness. A 200 response means the app is up and responsive.

## Scaling

- **Stateless**: The app is stateless. Run multiple replicas behind a load balancer.
- **Database pool**: Set `DATABASE_POOL_MAX_SIZE` per instance. Typical values: 10–20 per replica. Total connections ≈ replicas × pool size; stay under Postgres `max_connections`.
- **Recommended**: 2+ replicas for redundancy; scale horizontally as traffic grows.

## Common Incidents

### DB connection failures

- **Symptoms**: 500 errors, logs showing "connection refused" or pool exhaustion.
- **Checks**: Verify `DATABASE_URL`, Postgres is running, firewall allows connections.
- **Actions**: Restart app; if pool exhaustion, reduce `DATABASE_POOL_MAX_SIZE` or increase Postgres `max_connections`.

### Stripe webhook delays or failures

- **Symptoms**: Subscriptions not syncing; webhook retries in Stripe dashboard.
- **Checks**: `POST /webhooks/stripe` returns 200; `STRIPE_WEBHOOK_SECRET` matches Stripe.
- **Actions**: Check logs for webhook errors; reconcile manually via billing service if needed.

### High error rate

- **Symptoms**: Elevated 5xx or 4xx in monitoring.
- **Checks**: `RUST_LOG=server=debug` for details; check DB, Stripe, SMTP, and R2 connectivity.
- **Actions**: Scale up; fix underlying service; consider circuit breakers for external calls.

## Logs & Observability

- **RUST_LOG**: Set per-module levels (e.g. `server=debug,tower_http=info,sqlx=info`).
- **Output**: Logs go to stdout/stderr; capture with a log aggregator (CloudWatch, Datadog, etc.).
- **Sentry**: Add Sentry for error tracking and instrumentation if desired.

## Data Retention

See [retention.md](retention.md) for detailed retention of logs, audit data, ephemeral data, and backups.

- **audit_log**: 1 year; daily cleanup.
- **api_key_usage_log**: 90 days; daily cleanup.

## Backup & Restore

- **Strategy**: Use PostgreSQL backups (pg_dump, point-in-time recovery) via your hosting provider.
- **Retention**: Typically 7–30 days; adjust for compliance.
- **Restore**: Follow provider documentation.

## Admin Tools

### Internal routes (auth-protected)

All `/internal/*` routes require `admin:access` (JWT with admin role). Use `Authorization: Bearer <token>`.

| Endpoint | Description |
|----------|-------------|
| `GET /internal/job-stats` | Job queue stats (enqueue, success, fail, dead-letter, latency) |
| `POST /internal/impersonate` | Create impersonation token (requires `admin:impersonate`) |
| `GET /internal/feature-flags` | List all feature flags |
| `PUT /internal/feature-flags/:name` | Set global flag (body: `{ "enabled": true }`) |
| `PUT /internal/feature-flags/:name?org_id=...` | Set per-org flag override |

### Impersonation

Support can impersonate users for debugging:

1. `POST /internal/impersonate` with `{ "user_id": "<target-uuid>" }` and admin Bearer token.
2. Response: `{ "token": "...", "expires_in_secs": 900 }`.
3. Use that token for subsequent requests; all actions are logged to `audit_log` (actor, target, action, path).

### Feature flags

- **Global**: `PUT /internal/feature-flags/:name` with `{ "enabled": true|false }`.
- **Per-org**: `PUT /internal/feature-flags/:name?org_id=<uuid>` with `{ "enabled": true|false }`.
- **Effective flags for org**: `GET /v1/orgs/:org_id/feature-flags` (org member).

## Secrets

- **JWT_SECRET**: Required for auth; min 32 characters.
- **STRIPE_SECRET_KEY**, **STRIPE_WEBHOOK_SECRET**: For billing.
- **SMTP_***, **MAIL_FROM**: For transactional email.
- **R2_***: For storage.

Store in env or a secret manager (Doppler, Vault, etc.). Never commit secrets.
