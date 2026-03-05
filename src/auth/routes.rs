//! Auth routes under /v1/auth/.

use axum::{
    extract::{Query, State},
    extract::rejection::JsonRejection,
    http::HeaderMap,
    response::Redirect,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use utoipa::ToSchema;

use crate::api_error::ApiError;
use crate::auth::extractor::RequireAuth;
use crate::auth::repository::User;
use crate::AppState;

#[derive(Deserialize, ToSchema)]
pub struct SendCodeRequest {
    pub email: String,
}

#[derive(Deserialize, ToSchema)]
pub struct VerifyCodeRequest {
    pub email: String,
    pub code: String,
}

#[derive(Deserialize, ToSchema)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize, ToSchema)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize, ToSchema)]
pub struct PasswordResetRequest {
    pub email: String,
}

#[derive(Deserialize, ToSchema)]
pub struct PasswordResetConfirmRequest {
    pub token: String,
    pub new_password: String,
}

#[derive(Serialize, ToSchema)]
pub struct AuthResponse {
    pub access_token: String,
    pub token_type: String,
}

#[derive(Serialize, ToSchema)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
}

impl From<User> for UserResponse {
    fn from(u: User) -> Self {
        Self {
            id: u.id.0.to_string(),
            email: u.email,
        }
    }
}

#[derive(serde::Deserialize)]
pub struct GoogleCallbackQuery {
    code: String,
    #[allow(dead_code)]
    state: Option<String>,
}

pub fn router() -> Router<AppState> {
    // Rate limit: 5 requests/min per IP for auth-sensitive endpoints (plan: 6.1).
    let auth_limit_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(12) // 1 replenishment every 12 sec = 5/min
            .burst_size(5)
            .finish()
            .unwrap(),
    );

    let rate_limited = Router::new()
        .route("/send-code", post(send_code))
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/password-reset/request", post(password_reset_request))
        .route_layer(GovernorLayer::new(auth_limit_conf));

    Router::new()
        .merge(rate_limited)
        .route("/verify-code", post(verify_code))
        .route("/password-reset/confirm", post(password_reset_confirm))
        .route("/google", get(google_redirect))
        .route("/google/callback", get(google_callback))
        .route("/me", get(me))
        .route("/logout", post(logout))
}

/// Send a 6-digit login code to the given email. Rate limited (5/min per IP).
#[utoipa::path(
    post,
    path = "/v1/auth/send-code",
    tag = "Auth",
    request_body = SendCodeRequest,
    responses(
        (status = 200, description = "Code sent", body = inline(serde_json::Value)),
        (status = 400, description = "Bad request", body = crate::api_error::ApiErrorResp),
        (status = 429, description = "Too many requests", body = crate::api_error::ApiErrorResp),
        (status = 500, description = "Internal error", body = crate::api_error::ApiErrorResp)
    )
)]
pub async fn send_code(
    State(state): State<AppState>,
    req: Result<Json<SendCodeRequest>, JsonRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let Json(req) = req?;
    let auth = state
        .auth_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!("Auth not configured")))?;
    auth.send_login_code(&req.email).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Verify the 6-digit code and return an access token.
#[utoipa::path(
    post,
    path = "/v1/auth/verify-code",
    tag = "Auth",
    request_body = VerifyCodeRequest,
    responses(
        (status = 200, description = "Token", body = AuthResponse),
        (status = 400, description = "Bad request", body = crate::api_error::ApiErrorResp),
        (status = 401, description = "Invalid code", body = crate::api_error::ApiErrorResp),
        (status = 500, description = "Internal error", body = crate::api_error::ApiErrorResp)
    )
)]
pub async fn verify_code(
    State(state): State<AppState>,
    req: Result<Json<VerifyCodeRequest>, JsonRejection>,
) -> Result<Json<AuthResponse>, ApiError> {
    let Json(req) = req?;
    let auth = state
        .auth_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!("Auth not configured")))?;
    let user = auth.verify_code(&req.email, &req.code).await?;
    let access_token = auth.create_access_token(user.id)?;
    Ok(Json(AuthResponse {
        access_token,
        token_type: "Bearer".to_string(),
    }))
}

/// Register with email and password. Rate limited.
#[utoipa::path(
    post,
    path = "/v1/auth/register",
    tag = "Auth",
    request_body = RegisterRequest,
    responses(
        (status = 200, description = "Token", body = AuthResponse),
        (status = 400, description = "Bad request", body = crate::api_error::ApiErrorResp),
        (status = 409, description = "Email already exists", body = crate::api_error::ApiErrorResp),
        (status = 429, description = "Too many requests", body = crate::api_error::ApiErrorResp),
        (status = 500, description = "Internal error", body = crate::api_error::ApiErrorResp)
    )
)]
pub async fn register(
    State(state): State<AppState>,
    req: Result<Json<RegisterRequest>, JsonRejection>,
) -> Result<Json<AuthResponse>, ApiError> {
    let Json(req) = req?;
    let auth = state
        .auth_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!("Auth not configured")))?;
    let user = auth.register(&req.email, &req.password).await?;
    let access_token = auth.create_access_token(user.id)?;
    Ok(Json(AuthResponse {
        access_token,
        token_type: "Bearer".to_string(),
    }))
}

/// Login with email and password. Rate limited.
#[utoipa::path(
    post,
    path = "/v1/auth/login",
    tag = "Auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Token", body = AuthResponse),
        (status = 400, description = "Bad request", body = crate::api_error::ApiErrorResp),
        (status = 401, description = "Invalid credentials", body = crate::api_error::ApiErrorResp),
        (status = 429, description = "Too many requests", body = crate::api_error::ApiErrorResp),
        (status = 500, description = "Internal error", body = crate::api_error::ApiErrorResp)
    )
)]
pub async fn login(
    State(state): State<AppState>,
    req: Result<Json<LoginRequest>, JsonRejection>,
) -> Result<Json<AuthResponse>, ApiError> {
    let Json(req) = req?;
    let auth = state
        .auth_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!("Auth not configured")))?;
    let user = auth.login_password(&req.email, &req.password).await?;
    let access_token = auth.create_access_token(user.id)?;
    Ok(Json(AuthResponse {
        access_token,
        token_type: "Bearer".to_string(),
    }))
}

/// Redirect to Google OAuth consent screen.
#[utoipa::path(
    get,
    path = "/v1/auth/google",
    tag = "Auth",
    responses(
        (status = 307, description = "Redirect to Google"),
        (status = 500, description = "Google OAuth not configured", body = crate::api_error::ApiErrorResp)
    )
)]
pub async fn google_redirect(State(state): State<AppState>) -> Result<Redirect, ApiError> {
    let client_id = state
        .cfg
        .google_client_id
        .as_deref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!("Google OAuth not configured")))?;

    let redirect_uri = format!("{}/v1/auth/google/callback", state.cfg.base_url.trim_end_matches('/'));
    let auth_url = oauth2::basic::BasicClient::new(
        oauth2::ClientId::new(client_id.to_string()),
        None,
        oauth2::AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
            .map_err(|e| ApiError::InternalError(e.into()))?,
        Some(
            oauth2::TokenUrl::new("https://oauth2.googleapis.com/token".to_string())
                .map_err(|e| ApiError::InternalError(e.into()))?,
        ),
    )
    .set_redirect_uri(
        oauth2::RedirectUrl::new(redirect_uri.clone()).map_err(|e| ApiError::InternalError(e.into()))?,
    )
    .authorize_url(oauth2::CsrfToken::new_random)
    .add_scope(oauth2::Scope::new("openid".to_string()))
    .add_scope(oauth2::Scope::new("email".to_string()))
    .add_scope(oauth2::Scope::new("profile".to_string()))
    .url();

    Ok(Redirect::temporary(auth_url.0.as_str()))
}

/// OAuth callback; exchange code for token.
#[utoipa::path(
    get,
    path = "/v1/auth/google/callback",
    tag = "Auth",
    params(("code" = String, Query, description = "OAuth code from Google")),
    responses(
        (status = 200, description = "Token", body = AuthResponse),
        (status = 400, description = "Bad request", body = crate::api_error::ApiErrorResp),
        (status = 500, description = "Internal error", body = crate::api_error::ApiErrorResp)
    )
)]
pub async fn google_callback(
    State(state): State<AppState>,
    Query(query): Query<GoogleCallbackQuery>,
) -> Result<Json<AuthResponse>, ApiError> {
    let auth = state
        .auth_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!("Auth not configured")))?;

    let redirect_uri = format!("{}/v1/auth/google/callback", state.cfg.base_url.trim_end_matches('/'));
    let user = auth.login_google(&query.code, &redirect_uri).await?;
    let access_token = auth.create_access_token(user.id)?;
    Ok(Json(AuthResponse {
        access_token,
        token_type: "Bearer".to_string(),
    }))
}

/// Request a password reset email. Rate limited.
#[utoipa::path(
    post,
    path = "/v1/auth/password-reset/request",
    tag = "Auth",
    request_body = PasswordResetRequest,
    responses(
        (status = 200, description = "If email exists, reset link sent", body = inline(serde_json::Value)),
        (status = 429, description = "Too many requests", body = crate::api_error::ApiErrorResp),
        (status = 500, description = "Internal error", body = crate::api_error::ApiErrorResp)
    )
)]
pub async fn password_reset_request(
    State(state): State<AppState>,
    req: Result<Json<PasswordResetRequest>, JsonRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let Json(req) = req?;
    let auth = state
        .auth_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!("Auth not configured")))?;
    auth.password_reset_request(&req.email).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Confirm password reset with token from email link.
#[utoipa::path(
    post,
    path = "/v1/auth/password-reset/confirm",
    tag = "Auth",
    request_body = PasswordResetConfirmRequest,
    responses(
        (status = 200, description = "Password reset", body = inline(serde_json::Value)),
        (status = 400, description = "Invalid or expired token", body = crate::api_error::ApiErrorResp),
        (status = 500, description = "Internal error", body = crate::api_error::ApiErrorResp)
    )
)]
pub async fn password_reset_confirm(
    State(state): State<AppState>,
    req: Result<Json<PasswordResetConfirmRequest>, JsonRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let Json(req) = req?;
    let auth = state
        .auth_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!("Auth not configured")))?;
    auth.password_reset_confirm(&req.token, &req.new_password).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Logout (blacklist the current token). Requires Authorization: Bearer &lt;token&gt;.
#[utoipa::path(
    post,
    path = "/v1/auth/logout",
    tag = "Auth",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Logged out", body = inline(serde_json::Value)),
        (status = 401, description = "Unauthorized", body = crate::api_error::ApiErrorResp)
    )
)]
pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;
    let auth = state
        .auth_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!("Auth not configured")))?;
    auth.logout(token).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Get current user. Requires Authorization: Bearer &lt;token&gt;.
#[utoipa::path(
    get,
    path = "/v1/auth/me",
    tag = "Auth",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Current user", body = UserResponse),
        (status = 401, description = "Unauthorized", body = crate::api_error::ApiErrorResp)
    )
)]
pub async fn me(RequireAuth(user): RequireAuth) -> Result<Json<UserResponse>, ApiError> {
    Ok(Json(user.into()))
}
