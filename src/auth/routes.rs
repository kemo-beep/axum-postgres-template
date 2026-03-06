//! Auth routes under /v1/auth/.

use axum::{
    extract::rejection::JsonRejection,
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect},
    routing::{get, post},
    Json, Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use cookie::time::Duration as CookieDuration;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use utoipa::ToSchema;

use crate::auth::extractor::RequireAuth;
use crate::cfg::Environment;
use crate::common::ApiError;
use crate::AppState;

fn build_auth_cookie(token: &str, cfg: &crate::cfg::Configuration) -> Cookie<'static> {
    Cookie::build((cfg.cookie_name.clone(), token.to_string()))
        .http_only(true)
        .secure(cfg.env == Environment::Production)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(CookieDuration::seconds(cfg.jwt_expiry_secs as i64))
        .build()
        .into_owned()
}

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
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
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
        .route("/refresh", post(refresh))
        .route("/logout", post(logout))
        .nest("/api-keys", crate::auth::api_key_routes::router())
}

/// Send a 6-digit login code to the given email. Rate limited (5/min per IP).
#[utoipa::path(
    post,
    path = "/v1/auth/send-code",
    tag = "Auth",
    request_body = SendCodeRequest,
    responses(
        (status = 200, description = "Code sent", body = inline(serde_json::Value)),
        (status = 400, description = "Bad request", body = crate::common::ApiErrorResp),
        (status = 429, description = "Too many requests", body = crate::common::ApiErrorResp),
        (status = 500, description = "Internal error", body = crate::common::ApiErrorResp)
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
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Auth not configured"
        )))?;
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
        (status = 400, description = "Bad request", body = crate::common::ApiErrorResp),
        (status = 401, description = "Invalid code", body = crate::common::ApiErrorResp),
        (status = 500, description = "Internal error", body = crate::common::ApiErrorResp)
    )
)]
pub async fn verify_code(
    State(state): State<AppState>,
    jar: CookieJar,
    req: Result<Json<VerifyCodeRequest>, JsonRejection>,
) -> Result<(CookieJar, Json<AuthResponse>), ApiError> {
    let Json(req) = req?;
    let auth = state
        .auth_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Auth not configured"
        )))?;
    let user = auth.verify_code(&req.email, &req.code).await?;
    let access_token = auth.create_access_token(user.id)?;
    let cookie = build_auth_cookie(&access_token, &state.cfg);
    Ok((
        jar.add(cookie),
        Json(AuthResponse {
            access_token,
            token_type: "Bearer".to_string(),
        }),
    ))
}

/// Register with email and password. Rate limited.
#[utoipa::path(
    post,
    path = "/v1/auth/register",
    tag = "Auth",
    request_body = RegisterRequest,
    responses(
        (status = 200, description = "Token", body = AuthResponse),
        (status = 400, description = "Bad request", body = crate::common::ApiErrorResp),
        (status = 409, description = "Email already exists", body = crate::common::ApiErrorResp),
        (status = 429, description = "Too many requests", body = crate::common::ApiErrorResp),
        (status = 500, description = "Internal error", body = crate::common::ApiErrorResp)
    )
)]
pub async fn register(
    State(state): State<AppState>,
    jar: CookieJar,
    req: Result<Json<RegisterRequest>, JsonRejection>,
) -> Result<(CookieJar, Json<AuthResponse>), ApiError> {
    let Json(req) = req?;
    let auth = state
        .auth_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Auth not configured"
        )))?;
    let user = auth.register(&req.email, &req.password).await?;
    let access_token = auth.create_access_token(user.id)?;
    let cookie = build_auth_cookie(&access_token, &state.cfg);
    Ok((
        jar.add(cookie),
        Json(AuthResponse {
            access_token,
            token_type: "Bearer".to_string(),
        }),
    ))
}

/// Login with email and password. Rate limited.
/// Account lockout: after N failed attempts (default 5), account is locked for X minutes (default 15).
#[utoipa::path(
    post,
    path = "/v1/auth/login",
    tag = "Auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Token", body = AuthResponse),
        (status = 400, description = "Bad request", body = crate::common::ApiErrorResp),
        (status = 401, description = "Invalid credentials", body = crate::common::ApiErrorResp),
        (status = 423, description = "Account temporarily locked", body = crate::common::ApiErrorResp),
        (status = 429, description = "Too many requests", body = crate::common::ApiErrorResp),
        (status = 500, description = "Internal error", body = crate::common::ApiErrorResp)
    )
)]
pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    req: Result<Json<LoginRequest>, JsonRejection>,
) -> Result<(CookieJar, Json<AuthResponse>), ApiError> {
    let Json(req) = req?;
    let auth = state
        .auth_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Auth not configured"
        )))?;
    let user = auth.login_password(&req.email, &req.password).await?;
    let access_token = auth.create_access_token(user.id)?;
    let cookie = build_auth_cookie(&access_token, &state.cfg);
    Ok((
        jar.add(cookie),
        Json(AuthResponse {
            access_token,
            token_type: "Bearer".to_string(),
        }),
    ))
}

/// Redirect to Google OAuth consent screen.
#[utoipa::path(
    get,
    path = "/v1/auth/google",
    tag = "Auth",
    responses(
        (status = 307, description = "Redirect to Google"),
        (status = 500, description = "Google OAuth not configured", body = crate::common::ApiErrorResp)
    )
)]
pub async fn google_redirect(State(state): State<AppState>) -> Result<Redirect, ApiError> {
    let client_id = state
        .cfg
        .google_client_id
        .as_deref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Google OAuth not configured"
        )))?;

    let redirect_uri = format!(
        "{}/v1/auth/google/callback",
        state.cfg.base_url.trim_end_matches('/')
    );
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
        oauth2::RedirectUrl::new(redirect_uri.clone())
            .map_err(|e| ApiError::InternalError(e.into()))?,
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
        (status = 400, description = "Bad request", body = crate::common::ApiErrorResp),
        (status = 500, description = "Internal error", body = crate::common::ApiErrorResp)
    )
)]
pub async fn google_callback(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<GoogleCallbackQuery>,
) -> Result<axum::response::Response, ApiError> {
    let auth = state
        .auth_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Auth not configured"
        )))?;

    let redirect_uri = format!(
        "{}/v1/auth/google/callback",
        state.cfg.base_url.trim_end_matches('/')
    );
    let user = auth.login_google(&query.code, &redirect_uri).await?;
    let access_token = auth.create_access_token(user.id)?;

    if let Some(ref frontend_url) = state.cfg.frontend_url {
        let base = frontend_url.trim_end_matches('/');
        let url = format!("{}/login?token={}", base, access_token);
        return Ok(Redirect::temporary(&url).into_response());
    }

    let cookie = build_auth_cookie(&access_token, &state.cfg);
    Ok((
        jar.add(cookie),
        Json(AuthResponse {
            access_token,
            token_type: "Bearer".to_string(),
        }),
    )
    .into_response())
}

/// Request a password reset email. Rate limited.
#[utoipa::path(
    post,
    path = "/v1/auth/password-reset/request",
    tag = "Auth",
    request_body = PasswordResetRequest,
    responses(
        (status = 200, description = "If email exists, reset link sent", body = inline(serde_json::Value)),
        (status = 429, description = "Too many requests", body = crate::common::ApiErrorResp),
        (status = 500, description = "Internal error", body = crate::common::ApiErrorResp)
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
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Auth not configured"
        )))?;
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
        (status = 400, description = "Invalid or expired token", body = crate::common::ApiErrorResp),
        (status = 500, description = "Internal error", body = crate::common::ApiErrorResp)
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
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Auth not configured"
        )))?;
    auth.password_reset_confirm(&req.token, &req.new_password)
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Refresh the access token. Accepts Bearer or cookie; returns new token and sets cookie.
/// Old token is blacklisted (rotation). Tokens expired up to 5 minutes ago are accepted.
#[utoipa::path(
    post,
    path = "/v1/auth/refresh",
    tag = "Auth",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "New token", body = AuthResponse),
        (status = 401, description = "Invalid or expired token", body = crate::common::ApiErrorResp)
    )
)]
pub async fn refresh(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<(CookieJar, Json<AuthResponse>), ApiError> {
    let token =
        crate::auth::extractor::token_from_headers_or_jar(&headers, &jar, &state.cfg.cookie_name)
            .ok_or(ApiError::Unauthorized)?;
    let auth = state
        .auth_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Auth not configured"
        )))?;
    let access_token = auth.refresh_token(&token).await?;
    let cookie = build_auth_cookie(&access_token, &state.cfg);
    Ok((
        jar.add(cookie),
        Json(AuthResponse {
            access_token,
            token_type: "Bearer".to_string(),
        }),
    ))
}

/// Logout (blacklist the current token). Requires Authorization: Bearer or session cookie.
#[utoipa::path(
    post,
    path = "/v1/auth/logout",
    tag = "Auth",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Logged out", body = inline(serde_json::Value)),
        (status = 401, description = "Unauthorized", body = crate::common::ApiErrorResp)
    )
)]
pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<(CookieJar, Json<serde_json::Value>), ApiError> {
    let token =
        crate::auth::extractor::token_from_headers_or_jar(&headers, &jar, &state.cfg.cookie_name)
            .ok_or(ApiError::Unauthorized)?;
    let auth = state
        .auth_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Auth not configured"
        )))?;
    auth.logout(&token).await?;
    let cookie_name = state.cfg.cookie_name.clone();
    let cleared_jar = jar.remove(Cookie::build(cookie_name).path("/").removal());
    Ok((cleared_jar, Json(serde_json::json!({ "ok": true }))))
}

/// Get current user. Requires Authorization: Bearer &lt;token&gt;.
#[utoipa::path(
    get,
    path = "/v1/auth/me",
    tag = "Auth",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Current user", body = UserResponse),
        (status = 401, description = "Unauthorized", body = crate::common::ApiErrorResp)
    )
)]
pub async fn me(
    State(state): State<AppState>,
    RequireAuth(user): RequireAuth,
) -> Result<Json<UserResponse>, ApiError> {
    let roles = state.rbac_service.get_user_roles(user.id).await?;
    let permissions = state.rbac_service.get_user_permissions(user.id).await?;
    Ok(Json(UserResponse {
        id: user.id.0.to_string(),
        email: user.email,
        roles,
        permissions,
    }))
}
