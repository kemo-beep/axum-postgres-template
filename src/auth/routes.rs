//! Auth routes under /v1/auth/.

use axum::{
    extract::rejection::JsonRejection,
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
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
use validator::Validate;

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

#[derive(Deserialize, ToSchema, Validate)]
pub struct SendCodeRequest {
    #[validate(email)]
    pub email: String,
}

#[derive(Deserialize, ToSchema, Validate)]
pub struct VerifyCodeRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(equal = 6))]
    pub code: String,
}

#[derive(Deserialize, ToSchema, Validate)]
pub struct RegisterRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8))]
    pub password: String,
}

#[derive(Deserialize, ToSchema, Validate)]
pub struct LoginRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 1))]
    pub password: String,
}

#[derive(Deserialize, ToSchema, Validate)]
pub struct PasswordResetRequest {
    #[validate(email)]
    pub email: String,
}

#[derive(Deserialize, ToSchema, Validate)]
pub struct PasswordResetConfirmRequest {
    #[validate(length(min = 1))]
    pub token: String,
    #[validate(length(min = 8))]
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

#[derive(Deserialize, ToSchema, Validate)]
pub struct RestoreRequest {
    #[validate(email)]
    pub email: String,
}

#[derive(Deserialize, ToSchema)]
pub struct DeletePermanentRequest {
    pub confirm: String,
}

#[derive(Deserialize, ToSchema, Validate)]
pub struct RestoreConfirmRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(equal = 6))]
    pub code: String,
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
        .route("/restore-request", post(restore_request))
        .route_layer(GovernorLayer::new(auth_limit_conf));

    Router::new()
        .merge(rate_limited)
        .route("/verify-code", post(verify_code))
        .route("/password-reset/confirm", post(password_reset_confirm))
        .route("/google", get(google_redirect))
        .route("/google/callback", get(google_callback))
        .route("/me", get(me))
        .route("/ws-token", get(ws_token))
        .route("/me/export", get(me_export))
        .route("/me/delete", post(me_delete))
        .route("/me/delete-permanent", post(me_delete_permanent))
        .route("/restore", post(restore))
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
    req.validate().map_err(|e| ApiError::UnprocessableEntity(e.to_string()))?;
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
    req.validate().map_err(|e| ApiError::UnprocessableEntity(e.to_string()))?;
    let auth = state
        .auth_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Auth not configured"
        )))?;
    let user = auth.verify_code(&req.email, &req.code).await?;
    state.org_service.ensure_default_org(user.id).await?;
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
    req.validate().map_err(|e| ApiError::UnprocessableEntity(e.to_string()))?;
    let auth = state
        .auth_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Auth not configured"
        )))?;
    let user = auth.register(&req.email, &req.password).await?;
    state.org_service.ensure_default_org(user.id).await?;
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
    req.validate().map_err(|e| ApiError::UnprocessableEntity(e.to_string()))?;
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
    state.org_service.ensure_default_org(user.id).await?;
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
    req.validate().map_err(|e| ApiError::UnprocessableEntity(e.to_string()))?;
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
    req.validate().map_err(|e| ApiError::UnprocessableEntity(e.to_string()))?;
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

/// Get a short-lived token for WebSocket connection. Requires auth.
pub async fn ws_token(
    State(state): State<AppState>,
    RequireAuth(user): RequireAuth,
) -> Result<Json<serde_json::Value>, ApiError> {
    let auth = state.auth_service.as_ref().ok_or(ApiError::InternalError(
        anyhow::anyhow!("Auth not configured"),
    ))?;
    let token = auth.create_ws_token(user.id)?;
    Ok(Json(serde_json::json!({ "token": token })))
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

/// Export all user data (GDPR right to portability).
#[utoipa::path(
    get,
    path = "/v1/auth/me/export",
    tag = "Auth",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "User data export", body = inline(serde_json::Value)),
        (status = 401, description = "Unauthorized", body = crate::common::ApiErrorResp)
    )
)]
pub async fn me_export(
    State(state): State<AppState>,
    RequireAuth(user): RequireAuth,
) -> Result<impl IntoResponse, ApiError> {
    let export =
        crate::auth::account_export::export_account_data(&state, user.id).await?;
    let json = serde_json::to_string_pretty(&export)
        .map_err(|e| ApiError::InternalError(e.into()))?;
    let headers = [
        (header::CONTENT_TYPE, HeaderValue::from_static("application/json")),
        (
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("attachment; filename=\"my-data.json\""),
        ),
    ];
    Ok((StatusCode::OK, headers, json))
}

/// Soft-delete current user. Requires auth. Account can be restored within retention (e.g. 30 days) via restore endpoint.
#[utoipa::path(
    post,
    path = "/v1/auth/me/delete",
    tag = "Auth",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Account soft-deleted", body = inline(serde_json::Value)),
        (status = 401, description = "Unauthorized", body = crate::common::ApiErrorResp)
    )
)]
pub async fn me_delete(
    State(state): State<AppState>,
    RequireAuth(user): RequireAuth,
) -> Result<Json<serde_json::Value>, ApiError> {
    let auth = state.auth_service.as_ref().ok_or(ApiError::InternalError(
        anyhow::anyhow!("Auth not configured"),
    ))?;
    auth.soft_delete_user(user.id).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Permanently delete account (GDPR erasure). Requires confirmation. Irreversible.
#[utoipa::path(
    post,
    path = "/v1/auth/me/delete-permanent",
    tag = "Auth",
    request_body = DeletePermanentRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Account permanently deleted", body = inline(serde_json::Value)),
        (status = 400, description = "Confirmation required or invalid", body = crate::common::ApiErrorResp),
        (status = 401, description = "Unauthorized", body = crate::common::ApiErrorResp)
    )
)]
pub async fn me_delete_permanent(
    State(state): State<AppState>,
    RequireAuth(user): RequireAuth,
    req: Result<Json<DeletePermanentRequest>, JsonRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    const CONFIRM_PHRASE: &str = "DELETE_MY_ACCOUNT";
    let Json(req) = req?;
    if req.confirm.trim() != CONFIRM_PHRASE {
        return Err(ApiError::InvalidRequest(
            format!("Confirmation must be exactly '{}'", CONFIRM_PHRASE).into(),
        ));
    }
    crate::auth::account_deletion::delete_account_permanently(&state, user.id).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Request restore code for soft-deleted account. Sends code to email if within retention.
#[utoipa::path(
    post,
    path = "/v1/auth/restore-request",
    tag = "Auth",
    request_body = RestoreRequest,
    responses(
        (status = 200, description = "Code sent if account eligible for restore", body = inline(serde_json::Value)),
        (status = 400, description = "Bad request", body = crate::common::ApiErrorResp)
    )
)]
pub async fn restore_request(
    State(state): State<AppState>,
    req: Result<Json<RestoreRequest>, JsonRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let Json(req) = req?;
    req.validate().map_err(|e| ApiError::UnprocessableEntity(e.to_string()))?;
    let auth = state.auth_service.as_ref().ok_or(ApiError::InternalError(
        anyhow::anyhow!("Auth not configured"),
    ))?;
    auth.request_restore(&req.email).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Restore soft-deleted account with email + code. Returns new access token.
#[utoipa::path(
    post,
    path = "/v1/auth/restore",
    tag = "Auth",
    request_body = RestoreConfirmRequest,
    responses(
        (status = 200, description = "Restored", body = AuthResponse),
        (status = 400, description = "Invalid code or expired retention", body = crate::common::ApiErrorResp)
    )
)]
pub async fn restore(
    State(state): State<AppState>,
    jar: CookieJar,
    req: Result<Json<RestoreConfirmRequest>, JsonRejection>,
) -> Result<(CookieJar, Json<AuthResponse>), ApiError> {
    let Json(req) = req?;
    req.validate().map_err(|e| ApiError::UnprocessableEntity(e.to_string()))?;
    let auth = state.auth_service.as_ref().ok_or(ApiError::InternalError(
        anyhow::anyhow!("Auth not configured"),
    ))?;
    let access_token = auth.restore_with_code(&req.email, &req.code).await?;
    let cookie = build_auth_cookie(&access_token, &state.cfg);
    Ok((
        jar.add(cookie),
        Json(AuthResponse {
            access_token,
            token_type: "Bearer".to_string(),
        }),
    ))
}
