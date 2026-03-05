//! Repository for API keys and usage audit log.

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::common::{OrgId, UserId, WorkspaceId};

/// Stored API key (without raw key material).
#[derive(Clone, Debug)]
pub struct ApiKey {
    pub id: Uuid,
    pub user_id: UserId,
    pub name: String,
    pub org_id: Option<OrgId>,
    pub workspace_id: Option<WorkspaceId>,
    pub permissions: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Clone)]
pub struct ApiKeyRepository {
    pool: PgPool,
}

impl ApiKeyRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new API key. Returns (id, key_hash).
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        key_hash: &str,
        user_id: UserId,
        name: &str,
        org_id: Option<OrgId>,
        workspace_id: Option<WorkspaceId>,
        permissions: &[String],
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<ApiKey> {
        let id = Uuid::now_v7();
        let now = Utc::now();
        let permissions_json = serde_json::to_value(permissions)?;

        let row = sqlx::query(
            r#"
            INSERT INTO api_keys (id, key_hash, user_id, name, org_id, workspace_id, permissions, expires_at, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)
            RETURNING id, user_id, name, org_id, workspace_id, permissions, expires_at, created_at, updated_at, last_used_at
            "#,
        )
        .bind(id)
        .bind(key_hash)
        .bind(user_id.0)
        .bind(name)
        .bind(org_id.map(|o| o.0))
        .bind(workspace_id.map(|w| w.0))
        .bind(&permissions_json)
        .bind(expires_at)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        Ok(row_to_api_key(row))
    }

    /// Look up API key by key hash. Returns None if not found or expired.
    pub async fn get_by_key_hash(&self, key_hash: &str) -> Result<Option<ApiKey>> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, name, org_id, workspace_id, permissions, expires_at, created_at, updated_at, last_used_at
            FROM api_keys
            WHERE key_hash = $1
            "#,
        )
        .bind(key_hash)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(row_to_api_key))
    }

    /// List all API keys for a user (without key material).
    pub async fn list_by_user_id(&self, user_id: UserId) -> Result<Vec<ApiKey>> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, name, org_id, workspace_id, permissions, expires_at, created_at, updated_at, last_used_at
            FROM api_keys
            WHERE user_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id.0)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(row_to_api_key).collect())
    }

    /// Delete an API key. Returns true if a row was deleted.
    pub async fn delete(&self, id: Uuid, user_id: UserId) -> Result<bool> {
        let result = sqlx::query("DELETE FROM api_keys WHERE id = $1 AND user_id = $2")
            .bind(id)
            .bind(user_id.0)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Update last_used_at.
    pub async fn update_last_used_at(&self, id: Uuid) -> Result<()> {
        let now = Utc::now();
        sqlx::query("UPDATE api_keys SET last_used_at = $1, updated_at = $1 WHERE id = $2")
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Get API key by id (for rotation, ownership check).
    pub async fn get_by_id(&self, id: Uuid) -> Result<Option<ApiKey>> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, name, org_id, workspace_id, permissions, expires_at, created_at, updated_at, last_used_at
            FROM api_keys
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(row_to_api_key))
    }

    /// Insert a usage log entry. Call from service with tokio::spawn for non-blocking audit.
    pub async fn log_usage(
        &self,
        api_key_id: Uuid,
        method: &str,
        path: &str,
        status: u16,
        ip: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO api_key_usage_log (id, api_key_id, method, path, status, ip)
            VALUES (gen_random_uuid(), $1, $2, $3, $4, $5)
            "#,
        )
        .bind(api_key_id)
        .bind(method)
        .bind(path)
        .bind(status as i32)
        .bind(ip)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

fn row_to_api_key(row: sqlx::postgres::PgRow) -> ApiKey {
    let permissions: Vec<String> = row
        .get::<serde_json::Value, _>("permissions")
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    ApiKey {
        id: row.get("id"),
        user_id: UserId(row.get("user_id")),
        name: row.get("name"),
        org_id: row.get::<Option<Uuid>, _>("org_id").map(OrgId),
        workspace_id: row.get::<Option<Uuid>, _>("workspace_id").map(WorkspaceId),
        permissions,
        expires_at: row.get("expires_at"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        last_used_at: row.get("last_used_at"),
    }
}
