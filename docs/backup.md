# Database Backup & Restore

This document describes backup strategy and restore procedures for the PostgreSQL database.

## Backup Strategy

### Managed PostgreSQL

Use your hosting provider’s automated backups when available:

- **Neon**: Automatic branching and point-in-time restore. See [Neon Backup Docs](https://neon.tech/docs/guides/backup).
- **Supabase**: Daily automated backups; PITR on Pro plan. See [Supabase Backup Docs](https://supabase.com/docs/guides/platform/backups).
- **AWS RDS**: Automated snapshots and PITR. See [RDS Backup Docs](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html).

### Manual Exports (`pg_dump`)

For ad-hoc exports or disaster recovery outside provider tools:

```bash
# Full backup (custom format, compressed)
pg_dump -Fc "$DATABASE_URL" -f backup.dump

# Schema only
pg_dump -Fc -s "$DATABASE_URL" -f schema.dump

# Specific tables (adjust as needed)
pg_dump -Fc -t users -t orgs -t workspaces "$DATABASE_URL" -f subset.dump
```

### Point-in-Time Recovery (PITR)

When your provider supports PITR (Neon, Supabase Pro, RDS), use it to restore to a specific timestamp. Follow provider-specific docs for procedures.

## Retention

- **Operational backups**: Typically **7–30 days**; adjust per compliance and risk tolerance.
- **Compliance / long-term**: Some regulations require longer retention; use archive storage (e.g. S3 Glacier) for `pg_dump` exports if needed.

## Restore Procedure

### From provider UI/CLI

- **Neon**: Restore from branch or create a new branch from a point in time.
- **Supabase**: Use dashboard or CLI to restore from backup.
- **RDS**: Restore from automated snapshot or PITR via AWS Console/CLI.

### From `pg_dump` file

```bash
# Restore full dump
pg_restore -d "$DATABASE_URL" --no-owner --no-privileges backup.dump

# Schema only (e.g. before data restore)
pg_restore -d "$DATABASE_URL" -s --no-owner --no-privileges schema.dump

# Interactive (review objects before applying)
pg_restore -d "$DATABASE_URL" -i backup.dump
```

Adjust flags as needed (e.g. `--clean` to drop objects before recreate; use with caution in production).

### After restore

1. **Migrations**: If the schema changed after the backup, run migrations: `sqlx migrate run` (or your migration runner).
2. **Application**: Restart the application and verify health endpoints.

## References

- [Neon Backup & Restore](https://neon.tech/docs/guides/backup)
- [Supabase Backups](https://supabase.com/docs/guides/platform/backups)
- [AWS RDS Backup](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html)
- [PostgreSQL pg_dump](https://www.postgresql.org/docs/current/app-pgdump.html)
- [PostgreSQL pg_restore](https://www.postgresql.org/docs/current/app-pgrestore.html)
