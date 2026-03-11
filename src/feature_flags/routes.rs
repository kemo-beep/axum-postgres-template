//! Feature flag API routes.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::extractor::{RequireAdmin, RequireOrgMember};
use crate::common::{ApiError, OrgId};
use crate::AppState;

#[derive(Debug, Serialize, ToSchema)]
pub struct FeatureFlagItem {
    pub name: String,
    pub org_id: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FeatureFlagEffectiveItem {
    pub name: String,
    pub enabled: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetFlagRequest {
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct SetFlagQuery {
    pub org_id: Option<String>,
}

/// List all feature flags (global and per-org). Admin only.
#[utoipa::path(
    get,
    path = "/internal/feature-flags",
    tag = "Internal",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "All feature flags", body = Vec<FeatureFlagItem>),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 500, description = "Internal error")
    )
)]
pub async fn list_all(
    State(state): State<AppState>,
    RequireAdmin: RequireAdmin,
) -> Result<Json<Vec<FeatureFlagItem>>, ApiError> {
    let flags = state
        .feature_flag_service
        .list_all()
        .await
        .map_err(|e: sqlx::Error| ApiError::InternalError(e.into()))?;
    let items: Vec<FeatureFlagItem> = flags
        .into_iter()
        .map(|(name, org_id, enabled)| FeatureFlagItem {
            name,
            org_id: org_id.map(|o| o.0.to_string()),
            enabled,
        })
        .collect();
    Ok(Json(items))
}

/// List effective feature flags for an org (global + org overrides). Org member only.
#[utoipa::path(
    get,
    path = "/v1/orgs/{org_id}/feature-flags",
    tag = "Feature Flags",
    params(("org_id" = String, Path, description = "Org UUID")),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Effective flags for org", body = Vec<FeatureFlagEffectiveItem>),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 500, description = "Internal error")
    )
)]
pub async fn list_for_org(
    State(state): State<AppState>,
    RequireOrgMember(_, org_id): RequireOrgMember,
) -> Result<Json<Vec<FeatureFlagEffectiveItem>>, ApiError> {
    let flags = state
        .feature_flag_service
        .list_effective_for_org(org_id)
        .await
        .map_err(|e: sqlx::Error| ApiError::InternalError(e.into()))?;
    let items: Vec<FeatureFlagEffectiveItem> = flags
        .into_iter()
        .map(|(name, enabled)| FeatureFlagEffectiveItem { name, enabled })
        .collect();
    Ok(Json(items))
}

/// Set a global or per-org feature flag. Admin only.
#[utoipa::path(
    put,
    path = "/internal/feature-flags/{name}",
    tag = "Internal",
    params(("name" = String, Path, description = "Flag name"), ("org_id" = Option<String>, Query, description = "Org UUID for per-org override")),
    request_body = SetFlagRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Flag updated", body = inline(serde_json::Value)),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 500, description = "Internal error")
    )
)]
pub async fn set_flag(
    State(state): State<AppState>,
    RequireAdmin: RequireAdmin,
    Path(name): Path<String>,
    Query(query): Query<SetFlagQuery>,
    Json(req): Json<SetFlagRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if let Some(org_id_str) = &query.org_id {
        let org_uuid = Uuid::parse_str(org_id_str).map_err(|_| ApiError::InvalidRequest("Invalid org_id".into()))?;
        let org_id = OrgId(org_uuid);
        state
            .feature_flag_service
            .set_for_org(&name, org_id, req.enabled)
            .await
            .map_err(|e: sqlx::Error| ApiError::InternalError(e.into()))?;
    } else {
        state
            .feature_flag_service
            .set_global(&name, req.enabled)
            .await
            .map_err(|e: sqlx::Error| ApiError::InternalError(e.into()))?;
    }
    Ok(Json(serde_json::json!({ "ok": true })))
}

