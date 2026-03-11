//! Storage routes: presigned URLs for file access, upload.

use std::time::Duration;

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    middleware::from_extractor_with_state,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

use crate::auth::extractor::{
    RequireAuth, RequireFilesRead, RequireFilesWrite, RequireWorkspaceMember,
};
use crate::common::ApiError;
use crate::AppState;

#[derive(Serialize, ToSchema)]
pub struct PresignedUrlResponse {
    pub url: String,
}

#[derive(Deserialize)]
pub struct PresignedPutQuery {
    pub expires_secs: Option<u64>,
}

/// Returns presigned GET URL for the object. Requires Authorization: Bearer token.
#[utoipa::path(
    get,
    path = "/v1/files/{key}/url",
    tag = "Files",
    params(("key" = String, Path, description = "Object key")),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Presigned URL", body = PresignedUrlResponse),
        (status = 401, description = "Unauthorized", body = crate::common::ApiErrorResp),
        (status = 403, description = "Forbidden", body = crate::common::ApiErrorResp),
        (status = 500, description = "Storage not configured", body = crate::common::ApiErrorResp)
    )
)]
pub async fn get_presigned_url(
    State(state): State<AppState>,
    RequireAuth(_user): RequireAuth,
    Path(key): Path<String>,
) -> Result<Json<PresignedUrlResponse>, ApiError> {
    let storage = state
        .storage_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Storage not configured"
        )))?;

    let url = storage
        .presigned_get(&key, Duration::from_secs(3600))
        .await
        .map_err(ApiError::InternalError)?;

    Ok(Json(PresignedUrlResponse { url }))
}

/// Returns presigned PUT URL for uploading. Requires Authorization: Bearer token.
#[utoipa::path(
    get,
    path = "/v1/files/{key}/upload-url",
    tag = "Files",
    params(("key" = String, Path, description = "Object key")),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Presigned PUT URL", body = PresignedUrlResponse),
        (status = 401, description = "Unauthorized", body = crate::common::ApiErrorResp),
        (status = 403, description = "Forbidden", body = crate::common::ApiErrorResp),
        (status = 500, description = "Storage not configured", body = crate::common::ApiErrorResp)
    )
)]
pub async fn get_presigned_put_url(
    State(state): State<AppState>,
    RequireAuth(_user): RequireAuth,
    Path(key): Path<String>,
    Query(q): Query<PresignedPutQuery>,
) -> Result<Json<PresignedUrlResponse>, ApiError> {
    let storage = state
        .storage_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Storage not configured"
        )))?;

    let expires = q.expires_secs.unwrap_or(3600);
    let url = storage
        .presigned_put(&key, Duration::from_secs(expires))
        .await
        .map_err(ApiError::InternalError)?;

    Ok(Json(PresignedUrlResponse { url }))
}

#[derive(Deserialize, Validate)]
pub struct UploadRequest {
    #[validate(length(min = 1))]
    pub key: String,
}

/// Upload file directly. Requires Authorization: Bearer token.
#[utoipa::path(
    post,
    path = "/v1/files/upload",
    tag = "Files",
    request_body(content = Vec<u8>, content_type = "application/octet-stream", description = "File contents"),
    params(("key" = String, Query, description = "Object key")),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Uploaded", body = inline(serde_json::Value)),
        (status = 401, description = "Unauthorized", body = crate::common::ApiErrorResp),
        (status = 403, description = "Forbidden", body = crate::common::ApiErrorResp),
        (status = 500, description = "Storage not configured", body = crate::common::ApiErrorResp)
    )
)]
pub async fn upload(
    State(state): State<AppState>,
    RequireAuth(_user): RequireAuth,
    Query(req): Query<UploadRequest>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    req.validate().map_err(|e| ApiError::UnprocessableEntity(e.to_string()))?;
    let storage = state
        .storage_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Storage not configured"
        )))?;

    storage
        .upload(&req.key, body)
        .await
        .map_err(ApiError::InternalError)?;

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Build full storage key with org/workspace prefix.
fn workspace_key(
    org_id: crate::common::OrgId,
    workspace_id: crate::common::WorkspaceId,
    user_key: &str,
) -> String {
    format!("{}/{}/{}", org_id.0, workspace_id.0, user_key)
}

/// Returns presigned GET URL for workspace-scoped object.
#[utoipa::path(
    get,
    path = "/v1/orgs/{org_id}/workspaces/{workspace_id}/files/{key}/url",
    tag = "Files",
    params(
        ("org_id" = String, Path, description = "Org UUID"),
        ("workspace_id" = String, Path, description = "Workspace UUID"),
        ("key" = String, Path, description = "Object key")
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Presigned URL", body = PresignedUrlResponse),
        (status = 401, description = "Unauthorized", body = crate::common::ApiErrorResp),
        (status = 403, description = "Forbidden", body = crate::common::ApiErrorResp),
        (status = 500, description = "Storage not configured", body = crate::common::ApiErrorResp)
    )
)]
pub async fn get_presigned_url_workspace(
    State(state): State<AppState>,
    RequireWorkspaceMember(_user, org_id, workspace_id): RequireWorkspaceMember,
    Path(key): Path<String>,
) -> Result<Json<PresignedUrlResponse>, ApiError> {
    let storage = state
        .storage_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Storage not configured"
        )))?;

    let full_key = workspace_key(org_id, workspace_id, &key);
    let url = storage
        .presigned_get(&full_key, std::time::Duration::from_secs(3600))
        .await
        .map_err(ApiError::InternalError)?;

    Ok(Json(PresignedUrlResponse { url }))
}

/// Returns presigned PUT URL for workspace-scoped upload.
#[utoipa::path(
    get,
    path = "/v1/orgs/{org_id}/workspaces/{workspace_id}/files/{key}/upload-url",
    tag = "Files",
    params(
        ("org_id" = String, Path, description = "Org UUID"),
        ("workspace_id" = String, Path, description = "Workspace UUID"),
        ("key" = String, Path, description = "Object key")
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Presigned PUT URL", body = PresignedUrlResponse),
        (status = 401, description = "Unauthorized", body = crate::common::ApiErrorResp),
        (status = 403, description = "Forbidden", body = crate::common::ApiErrorResp),
        (status = 500, description = "Storage not configured", body = crate::common::ApiErrorResp)
    )
)]
pub async fn get_presigned_put_url_workspace(
    State(state): State<AppState>,
    RequireWorkspaceMember(_user, org_id, workspace_id): RequireWorkspaceMember,
    Path(key): Path<String>,
    Query(q): Query<PresignedPutQuery>,
) -> Result<Json<PresignedUrlResponse>, ApiError> {
    let storage = state
        .storage_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Storage not configured"
        )))?;

    let full_key = workspace_key(org_id, workspace_id, &key);
    let expires = q.expires_secs.unwrap_or(3600);
    let url = storage
        .presigned_put(&full_key, std::time::Duration::from_secs(expires))
        .await
        .map_err(ApiError::InternalError)?;

    Ok(Json(PresignedUrlResponse { url }))
}

/// Upload file to workspace-scoped path.
#[utoipa::path(
    post,
    path = "/v1/orgs/{org_id}/workspaces/{workspace_id}/files/upload",
    tag = "Files",
    params(
        ("org_id" = String, Path, description = "Org UUID"),
        ("workspace_id" = String, Path, description = "Workspace UUID"),
        ("key" = String, Query, description = "Object key")
    ),
    request_body(content = Vec<u8>, content_type = "application/octet-stream", description = "File contents"),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Uploaded", body = inline(serde_json::Value)),
        (status = 401, description = "Unauthorized", body = crate::common::ApiErrorResp),
        (status = 403, description = "Forbidden", body = crate::common::ApiErrorResp),
        (status = 500, description = "Storage not configured", body = crate::common::ApiErrorResp)
    )
)]
pub async fn upload_workspace(
    State(state): State<AppState>,
    RequireWorkspaceMember(_user, org_id, workspace_id): RequireWorkspaceMember,
    Query(UploadRequest { key }): Query<UploadRequest>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    let storage = state
        .storage_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Storage not configured"
        )))?;

    let full_key = workspace_key(org_id, workspace_id, &key);
    storage
        .upload(&full_key, body)
        .await
        .map_err(ApiError::InternalError)?;

    Ok(Json(serde_json::json!({ "ok": true })))
}

pub fn router(state: &AppState) -> Router<AppState> {
    let read_routes = Router::new()
        .route("/{key}/url", get(get_presigned_url))
        .route("/{key}/upload-url", get(get_presigned_put_url))
        .route_layer(from_extractor_with_state::<RequireFilesRead, _>(
            state.clone(),
        ));
    let write_routes =
        Router::new()
            .route("/upload", post(upload))
            .route_layer(from_extractor_with_state::<RequireFilesWrite, _>(
                state.clone(),
            ));
    read_routes.merge(write_routes)
}

/// Workspace-scoped storage router: mount at /v1/orgs/:org_id/workspaces/:workspace_id/files
pub fn workspace_files_router(state: &AppState) -> Router<AppState> {
    let read_routes = Router::new()
        .route("/{key}/url", get(get_presigned_url_workspace))
        .route("/{key}/upload-url", get(get_presigned_put_url_workspace))
        .route_layer(from_extractor_with_state::<RequireFilesRead, _>(
            state.clone(),
        ));
    let write_routes = Router::new()
        .route("/upload", post(upload_workspace))
        .route_layer(from_extractor_with_state::<RequireFilesWrite, _>(
            state.clone(),
        ));
    read_routes.merge(write_routes)
}
