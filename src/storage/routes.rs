//! Storage routes: presigned URLs for file access, upload.

use std::time::Duration;

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::api_error::ApiError;
use crate::auth::extractor::RequireAuth;
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
        (status = 401, description = "Unauthorized", body = crate::api_error::ApiErrorResp),
        (status = 500, description = "Storage not configured", body = crate::api_error::ApiErrorResp)
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
        .ok_or(ApiError::InternalError(anyhow::anyhow!("Storage not configured")))?;

    let url = storage
        .presigned_get(&key, Duration::from_secs(3600))
        .await
        .map_err(|e| ApiError::InternalError(e.into()))?;

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
        (status = 401, description = "Unauthorized", body = crate::api_error::ApiErrorResp),
        (status = 500, description = "Storage not configured", body = crate::api_error::ApiErrorResp)
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
        .ok_or(ApiError::InternalError(anyhow::anyhow!("Storage not configured")))?;

    let expires = q.expires_secs.unwrap_or(3600);
    let url = storage
        .presigned_put(&key, Duration::from_secs(expires))
        .await
        .map_err(|e| ApiError::InternalError(e.into()))?;

    Ok(Json(PresignedUrlResponse { url }))
}

#[derive(Deserialize)]
pub struct UploadRequest {
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
        (status = 401, description = "Unauthorized", body = crate::api_error::ApiErrorResp),
        (status = 500, description = "Storage not configured", body = crate::api_error::ApiErrorResp)
    )
)]
pub async fn upload(
    State(state): State<AppState>,
    RequireAuth(_user): RequireAuth,
    Query(UploadRequest { key }): Query<UploadRequest>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    let storage = state
        .storage_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!("Storage not configured")))?;

    storage
        .upload(&key, body)
        .await
        .map_err(|e| ApiError::InternalError(e.into()))?;

    Ok(Json(serde_json::json!({ "ok": true })))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/{key}/url", get(get_presigned_url))
        .route("/{key}/upload-url", get(get_presigned_put_url))
        .route("/upload", post(upload))
}
