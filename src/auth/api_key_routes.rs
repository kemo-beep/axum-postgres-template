//! API key management routes: create, list, revoke, rotate.

use axum::{
    extract::rejection::JsonRejection,
    extract::{Path, State},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::api_key_repository::ApiKey;
use crate::auth::extractor::RequireAuth;
use crate::common::{ApiError, OrgId, WorkspaceId};
use crate::AppState;

#[derive(Deserialize, ToSchema)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub org_id: Option<String>,
    pub workspace_id: Option<String>,
    pub permissions: Vec<String>,
    pub expires_in_days: Option<u32>,
}

#[derive(Serialize, ToSchema)]
pub struct CreateApiKeyResponse {
    pub id: String,
    pub name: String,
    pub key: String,
}

#[derive(Serialize, ToSchema)]
pub struct ApiKeyInfoResponse {
    pub id: String,
    pub name: String,
    pub org_id: Option<String>,
    pub workspace_id: Option<String>,
    pub permissions: Vec<String>,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
}

fn api_key_to_info(api_key: &ApiKey) -> ApiKeyInfoResponse {
    ApiKeyInfoResponse {
        id: api_key.id.to_string(),
        name: api_key.name.clone(),
        org_id: api_key.org_id.map(|o| o.0.to_string()),
        workspace_id: api_key.workspace_id.map(|w| w.0.to_string()),
        permissions: api_key.permissions.clone(),
        expires_at: api_key.expires_at.map(|d| d.to_rfc3339()),
        last_used_at: api_key.last_used_at.map(|d| d.to_rfc3339()),
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_keys).post(create_key))
        .route("/{id}", delete(revoke_key))
        .route("/{id}/rotate", post(rotate_key))
}

/// Create a new API key. Returns the raw key once - store it securely.
#[utoipa::path(
    post,
    path = "/v1/auth/api-keys",
    tag = "API Keys",
    request_body = CreateApiKeyRequest,
    responses(
        (status = 200, description = "Key created", body = CreateApiKeyResponse),
        (status = 400, description = "Bad request", body = crate::common::ApiErrorResp),
        (status = 401, description = "Unauthorized", body = crate::common::ApiErrorResp),
        (status = 500, description = "Internal error", body = crate::common::ApiErrorResp)
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_key(
    State(state): State<AppState>,
    RequireAuth(user): RequireAuth,
    req: Result<Json<CreateApiKeyRequest>, JsonRejection>,
) -> Result<Json<CreateApiKeyResponse>, ApiError> {
    let api_key_svc = state
        .api_key_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "API key service not configured"
        )))?;

    let Json(req) = req?;
    let org_id = req
        .org_id
        .as_ref()
        .and_then(|s| Uuid::parse_str(s).ok())
        .map(OrgId::from_uuid);
    let workspace_id = req
        .workspace_id
        .as_ref()
        .and_then(|s| Uuid::parse_str(s).ok())
        .map(WorkspaceId::from_uuid);

    let (api_key, raw_key) = api_key_svc
        .create_key(
            user.id,
            &req.name,
            org_id,
            workspace_id,
            req.permissions,
            req.expires_in_days,
        )
        .await?;

    Ok(Json(CreateApiKeyResponse {
        id: api_key.id.to_string(),
        name: api_key.name,
        key: raw_key,
    }))
}

/// List API keys for the authenticated user. Key material is never returned.
#[utoipa::path(
    get,
    path = "/v1/auth/api-keys",
    tag = "API Keys",
    responses(
        (status = 200, description = "List of API keys", body = Vec<ApiKeyInfoResponse>),
        (status = 401, description = "Unauthorized", body = crate::common::ApiErrorResp),
        (status = 500, description = "Internal error", body = crate::common::ApiErrorResp)
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_keys(
    State(state): State<AppState>,
    RequireAuth(user): RequireAuth,
) -> Result<Json<Vec<ApiKeyInfoResponse>>, ApiError> {
    let api_key_svc = state
        .api_key_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "API key service not configured"
        )))?;

    let keys = api_key_svc.list_keys(user.id).await?;
    Ok(Json(keys.iter().map(api_key_to_info).collect()))
}

/// Revoke an API key. Only the owner can revoke.
#[utoipa::path(
    delete,
    path = "/v1/auth/api-keys/{id}",
    tag = "API Keys",
    params(("id" = String, Path, description = "API key ID")),
    responses(
        (status = 204, description = "Key revoked"),
        (status = 401, description = "Unauthorized", body = crate::common::ApiErrorResp),
        (status = 403, description = "Forbidden", body = crate::common::ApiErrorResp),
        (status = 404, description = "Not found", body = crate::common::ApiErrorResp),
        (status = 500, description = "Internal error", body = crate::common::ApiErrorResp)
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_key(
    State(state): State<AppState>,
    RequireAuth(user): RequireAuth,
    Path(id): Path<String>,
) -> Result<axum::http::StatusCode, ApiError> {
    let api_key_svc = state
        .api_key_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "API key service not configured"
        )))?;

    let key_uuid = Uuid::parse_str(&id).map_err(|_| ApiError::NotFound)?;
    let deleted = api_key_svc.revoke_key(key_uuid, user.id).await?;
    if !deleted {
        return Err(ApiError::NotFound);
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Rotate an API key: create a new key with same metadata and revoke the old one.
#[utoipa::path(
    post,
    path = "/v1/auth/api-keys/{id}/rotate",
    tag = "API Keys",
    params(("id" = String, Path, description = "API key ID")),
    responses(
        (status = 200, description = "New key created", body = CreateApiKeyResponse),
        (status = 401, description = "Unauthorized", body = crate::common::ApiErrorResp),
        (status = 403, description = "Forbidden", body = crate::common::ApiErrorResp),
        (status = 404, description = "Not found", body = crate::common::ApiErrorResp),
        (status = 500, description = "Internal error", body = crate::common::ApiErrorResp)
    ),
    security(("bearer_auth" = []))
)]
pub async fn rotate_key(
    State(state): State<AppState>,
    RequireAuth(user): RequireAuth,
    Path(id): Path<String>,
) -> Result<Json<CreateApiKeyResponse>, ApiError> {
    let api_key_svc = state
        .api_key_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "API key service not configured"
        )))?;

    let key_uuid = Uuid::parse_str(&id).map_err(|_| ApiError::NotFound)?;
    let (api_key, raw_key) = api_key_svc.rotate_key(key_uuid, user.id).await?;

    Ok(Json(CreateApiKeyResponse {
        id: api_key.id.to_string(),
        name: api_key.name,
        key: raw_key,
    }))
}
