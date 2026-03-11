//! Repository for feature flags (global and per-org).

use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::common::OrgId;

#[derive(Clone, Debug)]
pub struct FeatureFlagRow {
    pub name: String,
    pub org_id: Option<Uuid>,
    pub enabled: bool,
}

#[derive(Clone)]
pub struct FeatureFlagRepository {
    pool: PgPool,
}

impl FeatureFlagRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn get_global(&self, name: &str) -> Result<Option<bool>, sqlx::Error> {
        let row = sqlx::query_scalar(
            "SELECT enabled FROM feature_flags WHERE name = $1 AND org_id IS NULL",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get_for_org(&self, name: &str, org_id: OrgId) -> Result<Option<bool>, sqlx::Error> {
        let row = sqlx::query_scalar(
            "SELECT enabled FROM feature_flags WHERE name = $1 AND org_id = $2",
        )
        .bind(name)
        .bind(org_id.0)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn upsert_global(&self, name: &str, enabled: bool) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO feature_flags (name, org_id, enabled, updated_at)
            VALUES ($1, NULL, $2, now())
            ON CONFLICT (name) WHERE (org_id IS NULL) DO UPDATE SET enabled = $2, updated_at = now()
            "#,
        )
        .bind(name)
        .bind(enabled)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn upsert_for_org(
        &self,
        name: &str,
        org_id: OrgId,
        enabled: bool,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO feature_flags (name, org_id, enabled, updated_at)
            VALUES ($1, $2, $3, now())
            ON CONFLICT (name, org_id) WHERE (org_id IS NOT NULL) DO UPDATE SET enabled = $3, updated_at = now()
            "#,
        )
        .bind(name)
        .bind(org_id.0)
        .bind(enabled)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_all(&self) -> Result<Vec<FeatureFlagRow>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT name, org_id, enabled FROM feature_flags ORDER BY name, org_id NULLS FIRST",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r: sqlx::postgres::PgRow| FeatureFlagRow {
                name: r.get("name"),
                org_id: r.get("org_id"),
                enabled: r.get("enabled"),
            })
            .collect())
    }

    pub async fn list_effective_for_org(&self, org_id: OrgId) -> Result<Vec<(String, bool)>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            WITH global AS (
                SELECT name, enabled FROM feature_flags WHERE org_id IS NULL
            ),
            org_flags AS (
                SELECT name, enabled FROM feature_flags WHERE org_id = $1
            )
            SELECT COALESCE(o.name, g.name) AS name, COALESCE(o.enabled, g.enabled) AS enabled
            FROM global g
            FULL OUTER JOIN org_flags o ON g.name = o.name
            ORDER BY name
            "#,
        )
        .bind(org_id.0)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r: sqlx::postgres::PgRow| {
                let name: String = r.get("name");
                let enabled: bool = r.get("enabled");
                (name, enabled)
            })
            .collect())
    }
}
