//! Auth repository: DB access for users, email codes, password reset tokens.

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::common::UserId;

/// Domain type for a registered user. Maps from `users` table.
#[derive(Clone, Debug)]
pub struct User {
    pub id: UserId,
    pub email: String,
    pub password_hash: Option<String>,
    pub google_sub: Option<String>,
    pub stripe_customer_id: Option<String>,
    pub failed_login_attempts: i32,
    pub locked_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Database access for the `users` table.
#[derive(Clone)]
pub struct UserRepository {
    pool: PgPool,
}

impl UserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        email: &str,
        password_hash: Option<&str>,
        google_sub: Option<&str>,
    ) -> Result<User> {
        let id = Uuid::now_v7();
        let now = Utc::now();
        let row = sqlx::query(
            r#"
            INSERT INTO users (id, email, password_hash, google_sub, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $5)
            RETURNING id, email, password_hash, google_sub, stripe_customer_id, failed_login_attempts, locked_until, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(email)
        .bind(password_hash)
        .bind(google_sub)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(User {
            id: UserId(row.get("id")),
            email: row.get("email"),
            password_hash: row.get("password_hash"),
            google_sub: row.get("google_sub"),
            stripe_customer_id: row.get("stripe_customer_id"),
            failed_login_attempts: row.get::<i32, _>("failed_login_attempts"),
            locked_until: row.get("locked_until"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    pub async fn get_by_id(&self, id: UserId) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, email, password_hash, google_sub, stripe_customer_id, failed_login_attempts, locked_until, created_at, updated_at FROM users WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| User {
            id: UserId(row.get("id")),
            email: row.get("email"),
            password_hash: row.get("password_hash"),
            google_sub: row.get("google_sub"),
            stripe_customer_id: row.get("stripe_customer_id"),
            failed_login_attempts: row.get::<i32, _>("failed_login_attempts"),
            locked_until: row.get("locked_until"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }))
    }

    pub async fn get_by_email(&self, email: &str) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, email, password_hash, google_sub, stripe_customer_id, failed_login_attempts, locked_until, created_at, updated_at FROM users WHERE email = $1 AND deleted_at IS NULL",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| User {
            id: UserId(row.get("id")),
            email: row.get("email"),
            password_hash: row.get("password_hash"),
            google_sub: row.get("google_sub"),
            stripe_customer_id: row.get("stripe_customer_id"),
            failed_login_attempts: row.get::<i32, _>("failed_login_attempts"),
            locked_until: row.get("locked_until"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }))
    }

    pub async fn update_stripe_customer_id(
        &self,
        user_id: UserId,
        stripe_customer_id: &str,
    ) -> Result<()> {
        let now = Utc::now();
        sqlx::query("UPDATE users SET stripe_customer_id = $1, updated_at = $2 WHERE id = $3")
            .bind(stripe_customer_id)
            .bind(now)
            .bind(user_id.0)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_google_sub(&self, user_id: UserId, google_sub: &str) -> Result<()> {
        let now = Utc::now();
        sqlx::query("UPDATE users SET google_sub = $1, updated_at = $2 WHERE id = $3")
            .bind(google_sub)
            .bind(now)
            .bind(user_id.0)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_password_hash(&self, user_id: UserId, password_hash: &str) -> Result<()> {
        let now = Utc::now();
        sqlx::query("UPDATE users SET password_hash = $1, updated_at = $2 WHERE id = $3")
            .bind(password_hash)
            .bind(now)
            .bind(user_id.0)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Increments failed_login_attempts. If it reaches max_attempts, sets locked_until.
    pub async fn increment_failed_login(
        &self,
        user_id: UserId,
        max_attempts: u32,
        locked_until: DateTime<Utc>,
    ) -> Result<()> {
        let now = Utc::now();
        sqlx::query(
            r#"
            UPDATE users SET
                failed_login_attempts = failed_login_attempts + 1,
                locked_until = CASE WHEN failed_login_attempts + 1 >= $1::int THEN $2 ELSE locked_until END,
                updated_at = $3
            WHERE id = $4
            "#,
        )
        .bind(i64::from(max_attempts))
        .bind(locked_until)
        .bind(now)
        .bind(user_id.0)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Resets failed attempts and lock after successful login.
    pub async fn reset_failed_login(&self, user_id: UserId) -> Result<()> {
        let now = Utc::now();
        sqlx::query(
            "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, updated_at = $1 WHERE id = $2",
        )
        .bind(now)
        .bind(user_id.0)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Soft-delete user. Sets deleted_at and deleted_by.
    pub async fn soft_delete(&self, user_id: UserId, deleted_by: Option<UserId>) -> Result<bool> {
        let now = Utc::now();
        let result = sqlx::query(
            "UPDATE users SET deleted_at = $1, deleted_by = $2, updated_at = $1 WHERE id = $3 AND deleted_at IS NULL",
        )
        .bind(now)
        .bind(deleted_by.map(|u| u.0))
        .bind(user_id.0)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Restore soft-deleted user. Clears deleted_at and deleted_by.
    pub async fn restore(&self, user_id: UserId) -> Result<bool> {
        let now = Utc::now();
        let result = sqlx::query(
            "UPDATE users SET deleted_at = NULL, deleted_by = NULL, updated_at = $1 WHERE id = $2 AND deleted_at IS NOT NULL",
        )
        .bind(now)
        .bind(user_id.0)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Get user by id including soft-deleted (for account deletion flow).
    pub async fn get_by_id_including_deleted(&self, id: UserId) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, email, password_hash, google_sub, stripe_customer_id, failed_login_attempts, locked_until, created_at, updated_at FROM users WHERE id = $1",
        )
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| User {
            id: UserId(row.get("id")),
            email: row.get("email"),
            password_hash: row.get("password_hash"),
            google_sub: row.get("google_sub"),
            stripe_customer_id: row.get("stripe_customer_id"),
            failed_login_attempts: row.get::<i32, _>("failed_login_attempts"),
            locked_until: row.get("locked_until"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }))
    }

    /// Get user by email including soft-deleted (for restore flow).
    pub async fn get_by_email_including_deleted(&self, email: &str) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, email, password_hash, google_sub, stripe_customer_id, failed_login_attempts, locked_until, created_at, updated_at FROM users WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| User {
            id: UserId(row.get("id")),
            email: row.get("email"),
            password_hash: row.get("password_hash"),
            google_sub: row.get("google_sub"),
            stripe_customer_id: row.get("stripe_customer_id"),
            failed_login_attempts: row.get::<i32, _>("failed_login_attempts"),
            locked_until: row.get("locked_until"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }))
    }

    /// Hard-delete user. Caller must have cleaned up dependent data (email_login_codes by email, org_invites by email, anonymized billing).
    pub async fn delete_permanently(&self, user_id: UserId) -> Result<bool> {
        let result = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id.0)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Returns deleted_at for user (to check if within retention window).
    pub async fn get_deleted_at(&self, user_id: UserId) -> Result<Option<DateTime<Utc>>> {
        let row =
            sqlx::query_scalar::<_, Option<DateTime<Utc>>>("SELECT deleted_at FROM users WHERE id = $1")
                .bind(user_id.0)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.flatten())
    }
}

/// Database access for `email_login_codes` (magic link / login codes).
#[derive(Clone)]
pub struct EmailCodeRepository {
    pool: PgPool,
}

impl EmailCodeRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl EmailCodeRepository {
    pub async fn create(&self, email: &str, code: &str, expires_at: DateTime<Utc>) -> Result<Uuid> {
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO email_login_codes (id, email, code, expires_at) VALUES ($1, $2, $3, $4)",
        )
        .bind(id)
        .bind(email)
        .bind(code)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn find_valid(&self, email: &str, code: &str) -> Result<Option<Uuid>> {
        let now = Utc::now();
        let row = sqlx::query(
            "SELECT id FROM email_login_codes WHERE email = $1 AND code = $2 AND expires_at > $3 AND used_at IS NULL",
        )
        .bind(email)
        .bind(code)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r: sqlx::postgres::PgRow| r.get("id")))
    }

    pub async fn mark_used(&self, id: Uuid) -> Result<()> {
        let now = Utc::now();
        sqlx::query("UPDATE email_login_codes SET used_at = $1 WHERE id = $2")
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Delete all login codes for the given email. Used for account deletion.
    pub async fn delete_by_email(&self, email: &str) -> Result<u64> {
        let result = sqlx::query("DELETE FROM email_login_codes WHERE email = $1")
            .bind(email)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Delete expired login codes. Returns number of rows deleted.
    pub async fn delete_expired(&self) -> Result<u64> {
        let now = Utc::now();
        let result = sqlx::query("DELETE FROM email_login_codes WHERE expires_at < $1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

#[derive(Clone)]
/// Database access for roles, permissions, and user-role assignments.
pub struct RbacRepository {
    pool: PgPool,
}

impl RbacRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Returns permission names for the user (via roles).
    pub async fn get_user_permissions(&self, user_id: UserId) -> Result<Vec<String>> {
        let rows = sqlx::query(
            "SELECT DISTINCT p.name FROM permissions p
             JOIN role_permissions rp ON rp.permission_id = p.id
             JOIN user_roles ur ON ur.role_id = rp.role_id
             WHERE ur.user_id = $1",
        )
        .bind(user_id.0)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r: sqlx::postgres::PgRow| r.get::<String, _>("name"))
            .collect())
    }

    /// Returns role names for the user.
    pub async fn get_user_roles(&self, user_id: UserId) -> Result<Vec<String>> {
        let rows = sqlx::query(
            "SELECT r.name FROM roles r
             JOIN user_roles ur ON ur.role_id = r.id
             WHERE ur.user_id = $1",
        )
        .bind(user_id.0)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r: sqlx::postgres::PgRow| r.get::<String, _>("name"))
            .collect())
    }

    /// Assigns a role to a user. Returns error if role does not exist.
    pub async fn assign_role(&self, user_id: UserId, role_name: &str) -> Result<()> {
        let role_id: Uuid = sqlx::query_scalar("SELECT id FROM roles WHERE name = $1")
            .bind(role_name)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Role '{}' not found", role_name))?;
        sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT (user_id, role_id) DO NOTHING")
            .bind(user_id.0)
            .bind(role_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Revokes a role from a user. Returns true if a row was deleted.
    pub async fn revoke_role(&self, user_id: UserId, role_name: &str) -> Result<bool> {
        let role_id: Option<Uuid> = sqlx::query_scalar("SELECT id FROM roles WHERE name = $1")
            .bind(role_name)
            .fetch_optional(&self.pool)
            .await?;
        let Some(role_id) = role_id else {
            return Ok(false);
        };
        let result = sqlx::query("DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2")
            .bind(user_id.0)
            .bind(role_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Lists all roles (id, name).
    pub async fn list_roles(&self) -> Result<Vec<(Uuid, String)>> {
        let rows = sqlx::query("SELECT id, name FROM roles ORDER BY name")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|r: sqlx::postgres::PgRow| (r.get("id"), r.get("name")))
            .collect())
    }

    /// Lists all permissions (id, name).
    pub async fn list_permissions(&self) -> Result<Vec<(Uuid, String)>> {
        let rows = sqlx::query("SELECT id, name FROM permissions ORDER BY name")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|r: sqlx::postgres::PgRow| (r.get("id"), r.get("name")))
            .collect())
    }

    /// Returns permission names for a role.
    pub async fn get_role_permissions(&self, role_name: &str) -> Result<Vec<String>> {
        let rows = sqlx::query(
            "SELECT p.name FROM permissions p
             JOIN role_permissions rp ON rp.permission_id = p.id
             JOIN roles r ON r.id = rp.role_id
             WHERE r.name = $1",
        )
        .bind(role_name)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r: sqlx::postgres::PgRow| r.get::<String, _>("name"))
            .collect())
    }
}

#[derive(Clone)]
/// Database access for `password_reset_tokens` table.
pub struct PasswordResetRepository {
    pool: PgPool,
}

impl PasswordResetRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        user_id: UserId,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<Uuid> {
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)",
        )
        .bind(id)
        .bind(user_id.0)
        .bind(token_hash)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn find_valid(&self, token_hash: &str) -> Result<Option<(Uuid, UserId)>> {
        let now = Utc::now();
        let row = sqlx::query(
            "SELECT id, user_id FROM password_reset_tokens WHERE token_hash = $1 AND expires_at > $2 AND used_at IS NULL",
        )
        .bind(token_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r: sqlx::postgres::PgRow| (r.get("id"), UserId(r.get("user_id")))))
    }

    pub async fn mark_used(&self, id: Uuid) -> Result<()> {
        let now = Utc::now();
        sqlx::query("UPDATE password_reset_tokens SET used_at = $1 WHERE id = $2")
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Delete expired password reset tokens. Returns number of rows deleted.
    pub async fn delete_expired(&self) -> Result<u64> {
        let now = Utc::now();
        let result = sqlx::query("DELETE FROM password_reset_tokens WHERE expires_at < $1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

#[derive(Clone)]
/// Database access for blacklisted JWT tokens (logout).
pub struct TokenBlacklistRepository {
    pool: PgPool,
}

impl TokenBlacklistRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn add(&self, jti: Uuid, exp: DateTime<Utc>) -> Result<()> {
        sqlx::query("INSERT INTO token_blacklist (jti, exp) VALUES ($1, $2)")
            .bind(jti)
            .bind(exp)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn is_blacklisted(&self, jti: Uuid) -> Result<bool> {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM token_blacklist WHERE jti = $1)")
                .bind(jti)
                .fetch_one(&self.pool)
                .await?;
        Ok(exists)
    }

    /// Delete expired blacklist entries (tokens past their exp). Returns number of rows deleted.
    pub async fn delete_expired(&self) -> Result<u64> {
        let now = Utc::now();
        let result = sqlx::query("DELETE FROM token_blacklist WHERE exp < $1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}
