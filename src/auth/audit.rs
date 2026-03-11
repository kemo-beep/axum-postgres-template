//! Audit logging for sensitive actions (impersonation, etc.).

use sqlx::PgPool;

use crate::common::{OrgId, UserId};

/// Audit log repository: insert entries for sensitive actions.
#[derive(Clone)]
pub struct AuditRepository {
    pool: PgPool,
}

impl AuditRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Insert an audit log entry. Call via tokio::spawn for non-blocking writes.
    pub async fn log(
        &self,
        actor_id: UserId,
        action: &str,
        target_user_id: Option<UserId>,
        target_org_id: Option<OrgId>,
        metadata: Option<serde_json::Value>,
        ip: Option<&str>,
        path: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO audit_log (actor_id, action, target_user_id, target_org_id, metadata, ip, path)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(actor_id.0)
        .bind(action)
        .bind(target_user_id.map(|u| u.0))
        .bind(target_org_id.map(|o| o.0))
        .bind(metadata)
        .bind(ip)
        .bind(path)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Delete audit_log rows older than the given timestamp. Returns number of rows deleted.
    pub async fn delete_older_than(&self, before: chrono::DateTime<chrono::Utc>) -> Result<u64, sqlx::Error> {
        let result = sqlx::query("DELETE FROM audit_log WHERE created_at < $1")
            .bind(before)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

/// Spawn a non-blocking audit log for impersonation start.
pub fn log_impersonation_start_async(
    pool: PgPool,
    actor_id: UserId,
    target_user_id: UserId,
    ip: Option<String>,
) {
    tokio::spawn(async move {
        let repo = AuditRepository::new(pool);
        if let Err(e) = repo
            .log(
                actor_id,
                "impersonation_start",
                Some(target_user_id),
                None,
                None,
                ip.as_deref(),
                None,
            )
            .await
        {
            tracing::warn!("Audit log failed: {}", e);
        }
    });
}

/// Spawn a non-blocking audit log for an impersonated request.
pub fn log_impersonation_request_async(
    pool: PgPool,
    actor_id: UserId,
    target_user_id: UserId,
    method: String,
    path: String,
    ip: Option<String>,
) {
    tokio::spawn(async move {
        let repo = AuditRepository::new(pool);
        let metadata = serde_json::json!({ "method": method });
        if let Err(e) = repo
            .log(
                actor_id,
                "impersonation_request",
                Some(target_user_id),
                None,
                Some(metadata),
                ip.as_deref(),
                Some(&path),
            )
            .await
        {
            tracing::warn!("Audit log failed: {}", e);
        }
    });
}
