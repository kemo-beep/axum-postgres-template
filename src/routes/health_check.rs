use axum::Json;
use serde::Serialize;
use serde_json::{json, Value};
use utoipa::ToSchema;

use crate::common::{ApiError, ApiErrorResp};

#[derive(Serialize, ToSchema)]
struct HealthResponse {
    status: &'static str,
}

/// Health check endpoint.
///
/// Returns service health status. Used for liveness/readiness probes.
#[utoipa::path(
    get,
    path = "/health",
    tag = "Health",
    responses(
        (status = 200, description = "Service is healthy", body = HealthResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResp)
    )
)]
pub async fn health_check() -> Result<Json<Value>, ApiError> {
    Ok(Json(json!({ "status": "ok" })))
}
