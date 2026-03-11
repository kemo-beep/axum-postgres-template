//! Org repository: orgs, workspaces, org_members, org_invites.

use anyhow::Result;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::common::{ApiError, OrgId, UserId, WorkspaceId};

/// Domain type for an organization. Maps from `orgs` table.
#[derive(Clone, Debug)]
pub struct Org {
    pub id: OrgId,
    pub name: String,
    pub slug: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Domain type for a workspace within an org. Maps from `workspaces` table.
#[derive(Clone, Debug)]
pub struct Workspace {
    pub id: WorkspaceId,
    pub org_id: OrgId,
    pub name: String,
    pub slug: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Membership of a user in an org with a role. Maps from `org_members` table.
#[derive(Clone, Debug)]
pub struct OrgMember {
    pub org_id: OrgId,
    pub user_id: UserId,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

/// Org member with user email, for responses that need to show member details.
/// Use `get_org_members_with_users` to fetch in a single JOIN query (avoids N+1).
#[derive(Clone, Debug)]
pub struct OrgMemberWithEmail {
    pub org_id: OrgId,
    pub user_id: UserId,
    pub role: String,
    pub email: String,
    pub created_at: DateTime<Utc>,
}

/// Database access for orgs, workspaces, org_members, and invites.
#[derive(Clone)]
pub struct OrgRepository {
    pool: PgPool,
}

impl OrgRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_org(&self, user_id: UserId, name: &str, slug: &str) -> Result<Org> {
        let now = Utc::now();
        let id = Uuid::now_v7();
        let row = sqlx::query(
            r#"
            INSERT INTO orgs (id, name, slug, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $4)
            RETURNING id, name, slug, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(name)
        .bind(slug)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        sqlx::query("INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, 'owner')")
            .bind(id)
            .bind(user_id.0)
            .execute(&self.pool)
            .await?;

        Ok(Org {
            id: OrgId(row.get("id")),
            name: row.get("name"),
            slug: row.get("slug"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    pub async fn get_org(&self, id: OrgId) -> Result<Option<Org>> {
        let row =
            sqlx::query("SELECT id, name, slug, created_at, updated_at FROM orgs WHERE id = $1 AND deleted_at IS NULL")
                .bind(id.0)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|r| Org {
            id: OrgId(r.get("id")),
            name: r.get("name"),
            slug: r.get("slug"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }

    pub async fn get_org_by_slug(&self, slug: &str) -> Result<Option<Org>> {
        let row =
            sqlx::query("SELECT id, name, slug, created_at, updated_at FROM orgs WHERE slug = $1 AND deleted_at IS NULL")
                .bind(slug)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|r| Org {
            id: OrgId(r.get("id")),
            name: r.get("name"),
            slug: r.get("slug"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }

    pub async fn add_member(&self, org_id: OrgId, user_id: UserId, role: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, $3) ON CONFLICT (org_id, user_id) DO UPDATE SET role = $3",
        )
        .bind(org_id.0)
        .bind(user_id.0)
        .bind(role)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn remove_member(&self, org_id: OrgId, user_id: UserId) -> Result<bool> {
        let result = sqlx::query("DELETE FROM org_members WHERE org_id = $1 AND user_id = $2")
            .bind(org_id.0)
            .bind(user_id.0)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn get_user_orgs(
        &self,
        user_id: UserId,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Org>> {
        let rows = sqlx::query(
            r#"
            SELECT o.id, o.name, o.slug, o.created_at, o.updated_at
            FROM orgs o
            JOIN org_members om ON om.org_id = o.id
            WHERE om.user_id = $1 AND o.deleted_at IS NULL
            ORDER BY o.name
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(user_id.0)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| Org {
                id: OrgId(r.get("id")),
                name: r.get("name"),
                slug: r.get("slug"),
                created_at: r.get("created_at"),
                updated_at: r.get("updated_at"),
            })
            .collect())
    }

    pub async fn get_org_members(
        &self,
        org_id: OrgId,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<OrgMember>> {
        let rows = sqlx::query(
            "SELECT org_id, user_id, role, created_at FROM org_members WHERE org_id = $1 ORDER BY created_at LIMIT $2 OFFSET $3",
        )
        .bind(org_id.0)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| OrgMember {
                org_id: OrgId(r.get("org_id")),
                user_id: UserId(r.get("user_id")),
                role: r.get("role"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    /// Returns org members with user email in a single query. Use when the API needs member details.
    pub async fn get_org_members_with_users(
        &self,
        org_id: OrgId,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<OrgMemberWithEmail>> {
        let rows = sqlx::query(
            r#"
            SELECT om.org_id, om.user_id, om.role, om.created_at, u.email
            FROM org_members om
            JOIN users u ON u.id = om.user_id AND u.deleted_at IS NULL
            WHERE om.org_id = $1
            ORDER BY om.created_at
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(org_id.0)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| OrgMemberWithEmail {
                org_id: OrgId(r.get("org_id")),
                user_id: UserId(r.get("user_id")),
                role: r.get("role"),
                email: r.get("email"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    pub async fn get_member_role(&self, org_id: OrgId, user_id: UserId) -> Result<Option<String>> {
        let row = sqlx::query_scalar::<_, String>(
            "SELECT role FROM org_members WHERE org_id = $1 AND user_id = $2",
        )
        .bind(org_id.0)
        .bind(user_id.0)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn count_members_with_role(&self, org_id: OrgId, role: &str) -> Result<i64> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM org_members WHERE org_id = $1 AND role = $2",
        )
        .bind(org_id.0)
        .bind(role)
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

    /// Ensures the user is a member of the org. Returns Ok(()) if yes, ApiError::NotFound otherwise.
    pub async fn ensure_user_in_org(&self, user_id: UserId, org_id: OrgId) -> Result<(), ApiError> {
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM org_members WHERE org_id = $1 AND user_id = $2)",
        )
        .bind(org_id.0)
        .bind(user_id.0)
        .fetch_one(&self.pool)
        .await
        .map_err(ApiError::DatabaseError)?;
        if exists {
            Ok(())
        } else {
            Err(ApiError::NotFound)
        }
    }

    pub async fn create_workspace(
        &self,
        org_id: OrgId,
        name: &str,
        slug: &str,
    ) -> Result<Workspace> {
        let now = Utc::now();
        let id = Uuid::now_v7();
        let row = sqlx::query(
            r#"
            INSERT INTO workspaces (id, org_id, name, slug, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $5)
            RETURNING id, org_id, name, slug, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(org_id.0)
        .bind(name)
        .bind(slug)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(Workspace {
            id: WorkspaceId(row.get("id")),
            org_id: OrgId(row.get("org_id")),
            name: row.get("name"),
            slug: row.get("slug"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    pub async fn get_workspace(&self, id: WorkspaceId) -> Result<Option<Workspace>> {
        let row = sqlx::query(
            "SELECT id, org_id, name, slug, created_at, updated_at FROM workspaces WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| Workspace {
            id: WorkspaceId(r.get("id")),
            org_id: OrgId(r.get("org_id")),
            name: r.get("name"),
            slug: r.get("slug"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }

    pub async fn list_workspaces(
        &self,
        org_id: OrgId,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Workspace>> {
        let rows = sqlx::query(
            "SELECT id, org_id, name, slug, created_at, updated_at FROM workspaces WHERE org_id = $1 AND deleted_at IS NULL ORDER BY name LIMIT $2 OFFSET $3",
        )
        .bind(org_id.0)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| Workspace {
                id: WorkspaceId(r.get("id")),
                org_id: OrgId(r.get("org_id")),
                name: r.get("name"),
                slug: r.get("slug"),
                created_at: r.get("created_at"),
                updated_at: r.get("updated_at"),
            })
            .collect())
    }

    /// Ensures the user can access the workspace (is org member; workspace inherits org access).
    /// Uses a single query to check workspace existence and org membership.
    pub async fn ensure_workspace_access(
        &self,
        user_id: UserId,
        workspace_id: WorkspaceId,
    ) -> Result<(), ApiError> {
        let exists = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM workspaces w
                JOIN org_members om ON om.org_id = w.org_id
                JOIN orgs o ON o.id = w.org_id AND o.deleted_at IS NULL
                WHERE w.id = $1 AND om.user_id = $2 AND w.deleted_at IS NULL
            )
            "#,
        )
        .bind(workspace_id.0)
        .bind(user_id.0)
        .fetch_one(&self.pool)
        .await
        .map_err(ApiError::DatabaseError)?;
        if exists {
            Ok(())
        } else {
            Err(ApiError::NotFound)
        }
    }

    pub fn hash_invite_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub async fn create_invite(
        &self,
        org_id: OrgId,
        email: &str,
        role: &str,
        invited_by: UserId,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<Uuid> {
        let id = Uuid::now_v7();
        let token_hash = Self::hash_invite_token(token);
        sqlx::query(
            r#"
            INSERT INTO org_invites (id, org_id, email, role, token_hash, expires_at, invited_by_user_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(id)
        .bind(org_id.0)
        .bind(email)
        .bind(role)
        .bind(token_hash)
        .bind(expires_at)
        .bind(invited_by.0)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn find_invite_by_token(&self, token: &str) -> Result<Option<InviteRow>> {
        let token_hash = Self::hash_invite_token(token);
        let row = sqlx::query(
            r#"
            SELECT id, org_id, email, role, expires_at, invited_by_user_id
            FROM org_invites
            WHERE token_hash = $1 AND expires_at > now() AND email IS NOT NULL
            "#,
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| InviteRow {
            id: r.get("id"),
            org_id: OrgId(r.get("org_id")),
            email: r.get("email"),
            role: r.get("role"),
            expires_at: r.get("expires_at"),
            invited_by_user_id: UserId(r.get("invited_by_user_id")),
        }))
    }

    pub async fn delete_invite(&self, id: Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM org_invites WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Delete all invites for the given email. Used for account deletion.
    pub async fn delete_invites_by_email(&self, email: &str) -> Result<u64> {
        let result = sqlx::query("DELETE FROM org_invites WHERE email = $1")
            .bind(email)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Delete expired invites. Returns number of rows deleted.
    pub async fn delete_expired_invites(&self) -> Result<u64> {
        let now = Utc::now();
        let result = sqlx::query("DELETE FROM org_invites WHERE expires_at < $1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Soft-delete org. Sets deleted_at and deleted_by.
    pub async fn soft_delete_org(&self, org_id: OrgId, deleted_by: UserId) -> Result<bool> {
        let now = Utc::now();
        let result = sqlx::query(
            "UPDATE orgs SET deleted_at = $1, deleted_by = $2 WHERE id = $3 AND deleted_at IS NULL",
        )
        .bind(now)
        .bind(deleted_by.0)
        .bind(org_id.0)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Restore soft-deleted org.
    pub async fn restore_org(&self, org_id: OrgId) -> Result<bool> {
        let now = Utc::now();
        let result = sqlx::query(
            "UPDATE orgs SET deleted_at = NULL, deleted_by = NULL, updated_at = $1 WHERE id = $2 AND deleted_at IS NOT NULL",
        )
        .bind(now)
        .bind(org_id.0)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Soft-delete workspace. Sets deleted_at and deleted_by.
    pub async fn soft_delete_workspace(
        &self,
        workspace_id: WorkspaceId,
        deleted_by: UserId,
    ) -> Result<bool> {
        let now = Utc::now();
        let result = sqlx::query(
            "UPDATE workspaces SET deleted_at = $1, deleted_by = $2 WHERE id = $3 AND deleted_at IS NULL",
        )
        .bind(now)
        .bind(deleted_by.0)
        .bind(workspace_id.0)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Restore soft-deleted workspace.
    pub async fn restore_workspace(&self, workspace_id: WorkspaceId) -> Result<bool> {
        let now = Utc::now();
        let result = sqlx::query(
            "UPDATE workspaces SET deleted_at = NULL, deleted_by = NULL, updated_at = $1 WHERE id = $2 AND deleted_at IS NOT NULL",
        )
        .bind(now)
        .bind(workspace_id.0)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[derive(Clone, Debug)]
pub struct InviteRow {
    pub id: Uuid,
    pub org_id: OrgId,
    pub email: String,
    pub role: String,
    pub expires_at: DateTime<Utc>,
    pub invited_by_user_id: UserId,
}
