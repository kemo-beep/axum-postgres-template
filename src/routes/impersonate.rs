//! Impersonation endpoint for support: create short-lived token to act as another user.

use axum::{
    extract::State,
    http::HeaderMap,
    Json,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::audit;
use crate::auth::extractor::{RequireAdminImpersonate, RequireAuth};
use crate::common::{ApiError, UserId};
use crate::AppState;

#[derive(Debug, Deserialize, ToSchema)]
pub struct ImpersonateRequest {
    pub user_id: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ImpersonateResponse {
    pub token: String,
    pub expires_in_secs: u64,
}

/// Create a short-lived impersonation token to act as the target user.
/// Requires admin:impersonate. Audit-logged.
#[utoipa::path(
    post,
    path = "/internal/impersonate",
    tag = "Internal",
    request_body = ImpersonateRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Impersonation token", body = ImpersonateResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "User not found"),
        (status = 500, description = "Internal error")
    )
)]
pub async fn impersonate(
    State(state): State<AppState>,
    headers: HeaderMap,
    RequireAdminImpersonate: RequireAdminImpersonate,
    RequireAuth(admin): RequireAuth,
    Json(req): Json<ImpersonateRequest>,
) -> Result<Json<ImpersonateResponse>, ApiError> {
    let target_id = Uuid::parse_str(&req.user_id).map_err(|_| ApiError::NotFound)?;
    let target_user_id = UserId(target_id);

    let auth = state
        .auth_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Auth not configured"
        )))?;

    let target = auth
        .get_user(target_user_id)
        .await?
        .ok_or(ApiError::NotFound)?;

    let token = auth.create_impersonation_token(admin.id, target.id)?;

    let ip = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(String::from);
    audit::log_impersonation_start_async(state.db.pool.clone(), admin.id, target.id, ip);

    Ok(Json(ImpersonateResponse {
        token,
        expires_in_secs: 900, // 15 minutes
    }))
}
