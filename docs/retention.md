# Data Retention Policy

This document describes data retention periods and cleanup practices.

## Application Logs (Tracing)

- **Storage**: Logs are written to stdout/stderr; in production, captured by a log aggregator (e.g. CloudWatch, Datadog).
- **Retention**: Configure at the aggregator level. Recommend **30–90 days** depending on compliance needs.
- **Note**: Avoid logging PII in application logs.

## Audit Data

### `api_key_usage_log`

- **Purpose**: Audit trail for API key usage (method, path, status, IP).
- **Retention**: **90 days**. Rows older than 90 days are deleted by the daily cleanup job.
- **Config**: Retention period is hardcoded in `src/jobs/scheduler.rs`. Adjust `ChronoDuration::days(90)` if needed.

### `audit_log`

- **Purpose**: Audit trail for sensitive actions (impersonation start, impersonated requests).
- **Retention**: **1 year**. Rows older than 365 days are deleted by the daily cleanup job.
- **Config**: Retention period is hardcoded in `src/jobs/scheduler.rs`. Adjust `ChronoDuration::days(365)` if needed.

## Ephemeral Data (Daily Cleanup)

The following are deleted when expired:

| Table | Retention | Criteria |
|-------|-----------|----------|
| `email_login_codes` | Until expiry | `expires_at < now` |
| `password_reset_tokens` | Until expiry | `expires_at < now` |
| `token_blacklist` | Until expiry | `exp < now` |
| `org_invites` | Until expiry | `expires_at < now` |

## Soft-Deleted Data

- **Tables**: `users`, `orgs`, `workspaces` (columns: `deleted_at`, `deleted_by`).
- **Retention**: Soft-deleted users can be restored within **30 days** via `POST /v1/auth/restore`.
- **Permanent erasure**: After the retention window, or immediately via `POST /v1/auth/me/delete-permanent`, data is permanently deleted (GDPR erasure flow).

## Backups

- **Recommendation**: Use PostgreSQL backups (pg_dump, point-in-time recovery) managed by your hosting provider.
- **Retention**: Typically **7–30 days** for operational backups; adjust per compliance requirements.
- **Restore**: Follow provider documentation for restore procedures.
- **Full details**: See [backup.md](backup.md) for backup strategy, retention, and restore procedures.
