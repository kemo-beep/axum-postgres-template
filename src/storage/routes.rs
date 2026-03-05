//! Storage routes: presigned URLs for file access.

use std::time::Duration;

use axum::{
    extract::{Path, State},
    routing::get,
    Json, Router,
};
use serde::Serialize;
use utoipa::ToSchema;

use crate::api_error::ApiError;
use crate::auth::extractor::RequireAuth;
use crate::AppState;

#[derive(Serialize, ToSchema)]
pub struct PresignedUrlResponse {
    pub url: String,
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

pub fn router() -> Router<AppState> {
    Router::new().route("/{key}/url", get(get_presigned_url))
}
