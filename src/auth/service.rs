//! Auth service: business logic for authentication flows.

use std::sync::Arc;

use anyhow::Result;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use oauth2::TokenResponse;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::email_sender::EmailSender;
use crate::auth::repository::{
    EmailCodeRepository, PasswordResetRepository, RbacRepository, TokenBlacklistRepository, User,
    UserRepository,
};
use crate::cfg::Config;
use crate::common::{ApiError, UserId};

const CODE_EXPIRY_MINUTES: i64 = 15;
const CODE_LENGTH: usize = 6;
/// Grace period in seconds: allow refresh with tokens expired up to this long ago.
const REFRESH_GRACE_SECS: i64 = 300; // 5 minutes

/// JWT payload: `sub` (user id), `jti` (token id for blacklist), `exp`, `iat`.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user id
    pub jti: String, // token id for logout/blacklist
    pub exp: i64,
    pub iat: i64,
}

/// Orchestrates auth flows: login codes, password reset, JWT, OAuth. Uses repositories and email sender.
#[derive(Clone)]
pub struct AuthService {
    user_repo: UserRepository,
    email_code_repo: EmailCodeRepository,
    password_reset_repo: PasswordResetRepository,
    token_blacklist_repo: TokenBlacklistRepository,
    rbac_repo: RbacRepository,
    email_sender: Arc<dyn EmailSender>,
    cfg: Config,
}

impl AuthService {
    pub fn new(
        user_repo: UserRepository,
        email_code_repo: EmailCodeRepository,
        password_reset_repo: PasswordResetRepository,
        token_blacklist_repo: TokenBlacklistRepository,
        rbac_repo: RbacRepository,
        email_sender: Arc<dyn EmailSender>,
        cfg: Config,
    ) -> Self {
        Self {
            user_repo,
            email_code_repo,
            password_reset_repo,
            token_blacklist_repo,
            rbac_repo,
            email_sender,
            cfg,
        }
    }

    pub async fn send_login_code(&self, email: &str) -> Result<(), ApiError> {
        let email = email.trim().to_lowercase();
        if email.is_empty() {
            return Err(ApiError::InvalidRequest("Email is required".into()));
        }
        if !email.contains('@') || email.len() < 5 {
            return Err(ApiError::InvalidRequest("Invalid email format".into()));
        }

        let code: String = (0..CODE_LENGTH)
            .map(|_| rand::thread_rng().gen_range(0..10).to_string())
            .collect();
        let expires_at = Utc::now() + Duration::minutes(CODE_EXPIRY_MINUTES);

        self.email_code_repo
            .create(&email, &code, expires_at)
            .await
            .map_err(ApiError::InternalError)?;

        self.email_sender
            .send_login_code(&email, &code)
            .await
            .map_err(ApiError::InternalError)?;

        Ok(())
    }

    pub async fn verify_code(&self, email: &str, code: &str) -> Result<User, ApiError> {
        let email = email.trim().to_lowercase();
        let code = code.trim();

        let code_id = self
            .email_code_repo
            .find_valid(&email, code)
            .await
            .map_err(ApiError::InternalError)?;

        let code_id = code_id.ok_or_else(|| ApiError::Unauthorized)?;

        self.email_code_repo
            .mark_used(code_id)
            .await
            .map_err(ApiError::InternalError)?;

        // Get or create user (passwordless signup)
        let user = match self
            .user_repo
            .get_by_email(&email)
            .await
            .map_err(ApiError::InternalError)?
        {
            Some(u) => u,
            None => {
                let user = self
                    .user_repo
                    .create(&email, None, None)
                    .await
                    .map_err(ApiError::InternalError)?;
                let _ = self.rbac_repo.assign_role(user.id, "member").await;
                user
            }
        };

        Ok(user)
    }

    pub async fn register(&self, email: &str, password: &str) -> Result<User, ApiError> {
        let email = email.trim().to_lowercase();
        if email.is_empty() {
            return Err(ApiError::InvalidRequest("Email is required".into()));
        }
        if !email.contains('@') || email.len() < 5 {
            return Err(ApiError::InvalidRequest("Invalid email format".into()));
        }
        if password.len() < 8 {
            return Err(ApiError::InvalidRequest(
                "Password must be at least 8 characters".into(),
            ));
        }

        if self
            .user_repo
            .get_by_email(&email)
            .await
            .map_err(ApiError::InternalError)?
            .is_some()
        {
            return Err(ApiError::Conflict("Email already registered".into()));
        }

        let hash = Self::hash_password(password)?;
        let user = self
            .user_repo
            .create(&email, Some(&hash), None)
            .await
            .map_err(ApiError::InternalError)?;
        let _ = self.rbac_repo.assign_role(user.id, "member").await;
        Ok(user)
    }

    pub async fn login_google(&self, code: &str, redirect_uri: &str) -> Result<User, ApiError> {
        let client_id = self
            .cfg
            .google_client_id
            .as_deref()
            .ok_or(ApiError::InternalError(anyhow::anyhow!(
                "Google OAuth not configured"
            )))?;
        let client_secret =
            self.cfg
                .google_client_secret
                .as_deref()
                .ok_or(ApiError::InternalError(anyhow::anyhow!(
                    "Google OAuth not configured"
                )))?;

        let client = oauth2::basic::BasicClient::new(
            oauth2::ClientId::new(client_id.to_string()),
            Some(oauth2::ClientSecret::new(client_secret.to_string())),
            oauth2::AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
                .map_err(|e| ApiError::InternalError(e.into()))?,
            Some(
                oauth2::TokenUrl::new("https://oauth2.googleapis.com/token".to_string())
                    .map_err(|e| ApiError::InternalError(e.into()))?,
            ),
        )
        .set_redirect_uri(
            oauth2::RedirectUrl::new(redirect_uri.to_string())
                .map_err(|e| ApiError::InternalError(e.into()))?,
        );

        let token_result = client
            .exchange_code(oauth2::AuthorizationCode::new(code.to_string()))
            .request_async(oauth2::reqwest::async_http_client)
            .await
            .map_err(|_| ApiError::Unauthorized)?;

        let access_token = token_result.access_token().secret();

        #[derive(serde::Deserialize)]
        struct UserInfo {
            sub: String,
            email: Option<String>,
            email_verified: Option<bool>,
        }

        let userinfo: UserInfo = reqwest::Client::new()
            .get("https://www.googleapis.com/oauth2/v3/userinfo")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| ApiError::InternalError(e.into()))?
            .json()
            .await
            .map_err(|e| ApiError::InternalError(e.into()))?;

        let email = userinfo
            .email
            .filter(|_| userinfo.email_verified.unwrap_or(true))
            .ok_or(ApiError::Unauthorized)?;

        let google_sub = &userinfo.sub;

        // Find or create user
        let user = match self
            .user_repo
            .get_by_email(&email)
            .await
            .map_err(ApiError::InternalError)?
        {
            Some(mut u) => {
                if u.google_sub.is_none() {
                    self.user_repo
                        .update_google_sub(u.id, google_sub)
                        .await
                        .map_err(ApiError::InternalError)?;
                    u.google_sub = Some(google_sub.clone());
                }
                u
            }
            None => {
                let user = self
                    .user_repo
                    .create(&email, None, Some(google_sub))
                    .await
                    .map_err(ApiError::InternalError)?;
                let _ = self.rbac_repo.assign_role(user.id, "member").await;
                user
            }
        };

        Ok(user)
    }

    pub async fn login_password(&self, email: &str, password: &str) -> Result<User, ApiError> {
        let email = email.trim().to_lowercase();
        let user = self
            .user_repo
            .get_by_email(&email)
            .await
            .map_err(ApiError::InternalError)?
            .ok_or(ApiError::Unauthorized)?;

        let hash = user
            .password_hash
            .as_deref()
            .ok_or(ApiError::Unauthorized)?;

        // Check lockout (optional: 0 = disabled)
        let max_attempts = self.cfg.login_lockout_max_attempts;
        if max_attempts > 0 {
            if let Some(locked_until) = user.locked_until {
                if locked_until > Utc::now() {
                    let mins = (locked_until - Utc::now()).num_minutes().max(1);
                    return Err(ApiError::AccountLocked(format!(
                        "Too many failed attempts. Try again in {} minute(s).",
                        mins
                    )));
                }
            }
        }

        let parsed = PasswordHash::new(hash).map_err(|_| ApiError::Unauthorized)?;
        if Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_err()
        {
            if max_attempts > 0 {
                let locked_until =
                    Utc::now() + Duration::minutes(self.cfg.login_lockout_duration_minutes as i64);
                self.user_repo
                    .increment_failed_login(user.id, max_attempts, locked_until)
                    .await
                    .map_err(ApiError::InternalError)?;
            }
            return Err(ApiError::Unauthorized);
        }

        if max_attempts > 0 {
            self.user_repo
                .reset_failed_login(user.id)
                .await
                .map_err(ApiError::InternalError)?;
        }

        Ok(user)
    }

    pub fn create_access_token(&self, user_id: UserId) -> Result<String, ApiError> {
        let secret =
            self.cfg.jwt_secret.as_deref().ok_or_else(|| {
                ApiError::InternalError(anyhow::anyhow!("JWT_SECRET not configured"))
            })?;

        let now = Utc::now();
        let exp = now + chrono::Duration::seconds(self.cfg.jwt_expiry_secs as i64);
        let jti = uuid::Uuid::now_v7().to_string();
        let claims = Claims {
            sub: user_id.0.to_string(),
            jti,
            exp: exp.timestamp(),
            iat: now.timestamp(),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .map_err(|e| ApiError::InternalError(e.into()))
    }

    pub async fn get_user(&self, user_id: UserId) -> Result<Option<User>, ApiError> {
        self.user_repo
            .get_by_id(user_id)
            .await
            .map_err(ApiError::InternalError)
    }

    pub async fn verify_token(&self, token: &str) -> Result<UserId, ApiError> {
        let secret =
            self.cfg.jwt_secret.as_deref().ok_or_else(|| {
                ApiError::InternalError(anyhow::anyhow!("JWT_SECRET not configured"))
            })?;

        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|_| ApiError::Unauthorized)?;

        let jti =
            uuid::Uuid::parse_str(&token_data.claims.jti).map_err(|_| ApiError::Unauthorized)?;
        let blacklisted = self
            .token_blacklist_repo
            .is_blacklisted(jti)
            .await
            .map_err(ApiError::InternalError)?;
        if blacklisted {
            return Err(ApiError::Unauthorized);
        }

        let uuid =
            uuid::Uuid::parse_str(&token_data.claims.sub).map_err(|_| ApiError::Unauthorized)?;
        Ok(UserId(uuid))
    }

    pub async fn password_reset_request(&self, email: &str) -> Result<(), ApiError> {
        let email = email.trim().to_lowercase();
        if email.is_empty() || !email.contains('@') {
            return Err(ApiError::InvalidRequest("Invalid email".into()));
        }

        let user = match self
            .user_repo
            .get_by_email(&email)
            .await
            .map_err(ApiError::InternalError)?
        {
            Some(u) => u,
            None => return Ok(()), // Don't leak existence; always return success
        };

        if user.password_hash.is_none() {
            return Ok(()); // No password set (e.g. Google-only), nothing to reset
        }

        let raw_token = uuid::Uuid::now_v7().to_string();
        let token_hash = format!("{:x}", Sha256::digest(raw_token.as_bytes()));

        let expires_at = Utc::now() + Duration::hours(1);
        self.password_reset_repo
            .create(user.id, &token_hash, expires_at)
            .await
            .map_err(ApiError::InternalError)?;

        let reset_link = format!(
            "{}/reset-password?token={}",
            self.cfg.base_url.trim_end_matches('/'),
            raw_token
        );
        self.email_sender
            .send_password_reset(&email, &reset_link)
            .await
            .map_err(ApiError::InternalError)?;

        Ok(())
    }

    pub async fn password_reset_confirm(
        &self,
        token: &str,
        new_password: &str,
    ) -> Result<(), ApiError> {
        if new_password.len() < 8 {
            return Err(ApiError::InvalidRequest(
                "Password must be at least 8 characters".into(),
            ));
        }

        let token_hash = format!("{:x}", Sha256::digest(token.as_bytes()));
        let (id, user_id) = self
            .password_reset_repo
            .find_valid(&token_hash)
            .await
            .map_err(ApiError::InternalError)?
            .ok_or(ApiError::InvalidRequest("Invalid or expired token".into()))?;

        self.password_reset_repo
            .mark_used(id)
            .await
            .map_err(ApiError::InternalError)?;

        let hash = Self::hash_password(new_password)?;
        self.user_repo
            .update_password_hash(user_id, &hash)
            .await
            .map_err(ApiError::InternalError)?;
        self.user_repo
            .reset_failed_login(user_id)
            .await
            .map_err(ApiError::InternalError)?;

        Ok(())
    }

    /// Refresh the access token. Accepts a valid or recently-expired token (within grace period).
    /// Blacklists the old token (rotation) and returns a new access token.
    pub async fn refresh_token(&self, token: &str) -> Result<String, ApiError> {
        let secret =
            self.cfg.jwt_secret.as_deref().ok_or_else(|| {
                ApiError::InternalError(anyhow::anyhow!("JWT_SECRET not configured"))
            })?;

        let mut validation = Validation::default();
        validation.validate_exp = false; // Allow expired tokens within grace period
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )
        .map_err(|_| ApiError::Unauthorized)?;

        let exp_ts = token_data.claims.exp;
        let now = Utc::now().timestamp();
        if exp_ts < now - REFRESH_GRACE_SECS {
            return Err(ApiError::Unauthorized);
        }

        let jti =
            uuid::Uuid::parse_str(&token_data.claims.jti).map_err(|_| ApiError::Unauthorized)?;
        let blacklisted = self
            .token_blacklist_repo
            .is_blacklisted(jti)
            .await
            .map_err(ApiError::InternalError)?;
        if blacklisted {
            return Err(ApiError::Unauthorized);
        }

        let exp = chrono::DateTime::from_timestamp(exp_ts, 0)
            .unwrap_or_else(Utc::now)
            .with_timezone(&Utc);
        self.token_blacklist_repo
            .add(jti, exp)
            .await
            .map_err(ApiError::InternalError)?;

        let user_id =
            uuid::Uuid::parse_str(&token_data.claims.sub).map_err(|_| ApiError::Unauthorized)?;
        self.create_access_token(UserId(user_id))
    }

    pub async fn logout(&self, token: &str) -> Result<(), ApiError> {
        let secret =
            self.cfg.jwt_secret.as_deref().ok_or_else(|| {
                ApiError::InternalError(anyhow::anyhow!("JWT_SECRET not configured"))
            })?;

        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|_| ApiError::Unauthorized)?;

        let jti =
            uuid::Uuid::parse_str(&token_data.claims.jti).map_err(|_| ApiError::Unauthorized)?;
        let exp = chrono::DateTime::from_timestamp(token_data.claims.exp, 0)
            .unwrap_or_else(Utc::now)
            .with_timezone(&Utc);

        self.token_blacklist_repo
            .add(jti, exp)
            .await
            .map_err(ApiError::InternalError)?;

        Ok(())
    }

    fn hash_password(password: &str) -> Result<String, ApiError> {
        let salt = SaltString::generate(&mut rand::thread_rng());
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| ApiError::InternalError(anyhow::anyhow!("{}", e)))
    }
}
