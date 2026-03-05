//! RBAC REST API: roles, permissions, user-role assignment.

use axum::{
    extract::{Path, State},
    middleware::from_extractor_with_state,
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::extractor::{RequireAuth, RequireUsersRead};
use crate::common::{ApiError, UserId};
use crate::AppState;

#[derive(Serialize, ToSchema)]
pub struct RoleResponse {
    pub id: String,
    pub name: String,
}

#[derive(Serialize, ToSchema)]
pub struct PermissionResponse {
    pub id: String,
    pub name: String,
}

#[derive(Deserialize, ToSchema)]
pub struct AssignRoleRequest {
    pub user_id: String,
    pub role: String,
}

/// List all roles. Requires `users:read`.
#[utoipa::path(
    get,
    path = "/v1/roles",
    tag = "RBAC",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List of roles", body = Vec<RoleResponse>),
        (status = 401, description = "Unauthorized", body = crate::common::ApiErrorResp),
        (status = 403, description = "Forbidden", body = crate::common::ApiErrorResp),
        (status = 500, description = "Internal error", body = crate::common::ApiErrorResp)
    )
)]
pub async fn list_roles(
    State(state): State<AppState>,
    RequireAuth(_user): RequireAuth,
) -> Result<Json<Vec<RoleResponse>>, ApiError> {
    let roles = state.rbac_service.list_roles().await?;
    let resp: Vec<RoleResponse> = roles
        .into_iter()
        .map(|(id, name)| RoleResponse {
            id: id.to_string(),
            name,
        })
        .collect();
    Ok(Json(resp))
}

/// List all permissions. Requires `users:read`.
#[utoipa::path(
    get,
    path = "/v1/permissions",
    tag = "RBAC",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List of permissions", body = Vec<PermissionResponse>),
        (status = 401, description = "Unauthorized", body = crate::common::ApiErrorResp),
        (status = 403, description = "Forbidden", body = crate::common::ApiErrorResp),
        (status = 500, description = "Internal error", body = crate::common::ApiErrorResp)
    )
)]
pub async fn list_permissions(
    State(state): State<AppState>,
    RequireAuth(_user): RequireAuth,
) -> Result<Json<Vec<PermissionResponse>>, ApiError> {
    let perms = state.rbac_service.list_permissions().await?;
    let resp: Vec<PermissionResponse> = perms
        .into_iter()
        .map(|(id, name)| PermissionResponse {
            id: id.to_string(),
            name,
        })
        .collect();
    Ok(Json(resp))
}

/// List a user's roles. Requires `users:read` or viewing self.
#[utoipa::path(
    get,
    path = "/v1/users/{id}/roles",
    tag = "RBAC",
    params(("id" = String, Path, description = "User UUID")),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List of role names", body = Vec<String>),
        (status = 401, description = "Unauthorized", body = crate::common::ApiErrorResp),
        (status = 403, description = "Forbidden", body = crate::common::ApiErrorResp),
        (status = 404, description = "User not found", body = crate::common::ApiErrorResp),
        (status = 500, description = "Internal error", body = crate::common::ApiErrorResp)
    )
)]
pub async fn list_user_roles(
    State(state): State<AppState>,
    RequireAuth(caller): RequireAuth,
    Path(id): Path<String>,
) -> Result<Json<Vec<String>>, ApiError> {
    let id = Uuid::parse_str(&id).map_err(|_| ApiError::NotFound)?;
    let user_id = UserId(id);
    if caller.id != user_id {
        crate::auth::extractor::check_permission(
            &state,
            caller.id,
            crate::auth::permissions::USERS_READ,
        )
        .await?;
    }
    let auth = state
        .auth_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Auth not configured"
        )))?;
    if auth.get_user(user_id).await?.is_none() {
        return Err(ApiError::NotFound);
    }
    let roles = state.rbac_service.get_user_roles(user_id).await?;
    Ok(Json(roles))
}

/// Assign a role to a user. Requires `users:write`.
#[utoipa::path(
    post,
    path = "/v1/users/assign-role",
    tag = "RBAC",
    request_body = AssignRoleRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Role assigned"),
        (status = 400, description = "Invalid role", body = crate::common::ApiErrorResp),
        (status = 401, description = "Unauthorized", body = crate::common::ApiErrorResp),
        (status = 403, description = "Forbidden", body = crate::common::ApiErrorResp),
        (status = 404, description = "User or role not found", body = crate::common::ApiErrorResp),
        (status = 500, description = "Internal error", body = crate::common::ApiErrorResp)
    )
)]
pub async fn assign_role(
    State(state): State<AppState>,
    RequireAuth(caller): RequireAuth,
    Json(req): Json<AssignRoleRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::extractor::check_permission(
        &state,
        caller.id,
        crate::auth::permissions::USERS_WRITE,
    )
    .await?;
    let id = Uuid::parse_str(&req.user_id).map_err(|_| ApiError::NotFound)?;
    let user_id = UserId(id);
    let auth = state
        .auth_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Auth not configured"
        )))?;
    if auth.get_user(user_id).await?.is_none() {
        return Err(ApiError::NotFound);
    }
    state.rbac_service.assign_role(user_id, &req.role).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Revoke a role from a user. Requires `users:write`.
#[utoipa::path(
    delete,
    path = "/v1/users/{id}/roles/{role}",
    tag = "RBAC",
    params(("id" = String, Path, description = "User UUID"), ("role" = String, Path, description = "Role name")),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Role revoked"),
        (status = 401, description = "Unauthorized", body = crate::common::ApiErrorResp),
        (status = 403, description = "Forbidden", body = crate::common::ApiErrorResp),
        (status = 404, description = "User not found", body = crate::common::ApiErrorResp),
        (status = 500, description = "Internal error", body = crate::common::ApiErrorResp)
    )
)]
pub async fn revoke_role(
    State(state): State<AppState>,
    RequireAuth(caller): RequireAuth,
    Path((id, role)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::auth::extractor::check_permission(
        &state,
        caller.id,
        crate::auth::permissions::USERS_WRITE,
    )
    .await?;
    let id = Uuid::parse_str(&id).map_err(|_| ApiError::NotFound)?;
    let user_id = UserId(id);
    let auth = state
        .auth_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Auth not configured"
        )))?;
    if auth.get_user(user_id).await?.is_none() {
        return Err(ApiError::NotFound);
    }
    let _removed = state.rbac_service.revoke_role(user_id, &role).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Builds the RBAC router. Requires state for permission layers.
pub fn router(state: &AppState) -> Router<AppState> {
    let read_protected =
        Router::new()
            .route("/", get(list_roles))
            .route_layer(from_extractor_with_state::<RequireUsersRead, _>(
                state.clone(),
            ));
    let permissions_route =
        Router::new()
            .route("/", get(list_permissions))
            .route_layer(from_extractor_with_state::<RequireUsersRead, _>(
                state.clone(),
            ));
    let write_protected = Router::new()
        .route("/users/assign-role", post(assign_role))
        .route("/{id}/roles/{role}", delete(revoke_role));
    let user_roles_get = Router::new().route("/{id}/roles", get(list_user_roles));
    // list_user_roles uses RequireAuth in handler; allows self or users:read

    Router::new()
        .nest("/roles", read_protected)
        .nest("/permissions", permissions_route)
        .nest("/users", write_protected.merge(user_roles_get))
}
