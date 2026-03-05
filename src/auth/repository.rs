//! Auth repository: DB access for users, email codes, password reset tokens.

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::types::UserId;

#[derive(Clone, Debug)]
pub struct User {
    pub id: UserId,
    pub email: String,
    pub password_hash: Option<String>,
    pub google_sub: Option<String>,
    pub stripe_customer_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct UserRepository {
    pool: PgPool,
}

impl UserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, email: &str, password_hash: Option<&str>, google_sub: Option<&str>) -> Result<User> {
        let id = Uuid::now_v7();
        let now = Utc::now();
        let row = sqlx::query(
            r#"
            INSERT INTO users (id, email, password_hash, google_sub, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $5)
            RETURNING id, email, password_hash, google_sub, created_at, updated_at
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
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }

    pub async fn get_by_id(&self, id: UserId) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, email, password_hash, google_sub, stripe_customer_id, created_at, updated_at FROM users WHERE id = $1",
        )
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            Some(row) => Some(User {
                id: UserId(row.get("id")),
                email: row.get("email"),
                password_hash: row.get("password_hash"),
                google_sub: row.get("google_sub"),
                stripe_customer_id: row.get("stripe_customer_id"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            }),
            None => None,
        })
    }

    pub async fn get_by_email(&self, email: &str) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, email, password_hash, google_sub, stripe_customer_id, created_at, updated_at FROM users WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            Some(row) => Some(User {
                id: UserId(row.get("id")),
                email: row.get("email"),
                password_hash: row.get("password_hash"),
                google_sub: row.get("google_sub"),
                stripe_customer_id: row.get("stripe_customer_id"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            }),
            None => None,
        })
    }

    pub async fn update_stripe_customer_id(&self, user_id: UserId, stripe_customer_id: &str) -> Result<()> {
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
}

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
}

#[derive(Clone)]
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

    /// Assigns a role to a user.
    pub async fn assign_role(&self, user_id: UserId, role_name: &str) -> Result<()> {
        let role_id: Uuid = sqlx::query_scalar("SELECT id FROM roles WHERE name = $1")
            .bind(role_name)
            .fetch_one(&self.pool)
            .await?;
        sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT (user_id, role_id) DO NOTHING")
            .bind(user_id.0)
            .bind(role_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct PasswordResetRepository {
    pool: PgPool,
}

impl PasswordResetRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, user_id: UserId, token_hash: &str, expires_at: DateTime<Utc>) -> Result<Uuid> {
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
}

#[derive(Clone)]
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
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM token_blacklist WHERE jti = $1)")
            .bind(jti)
            .fetch_one(&self.pool)
            .await?;
        Ok(exists)
    }
}
