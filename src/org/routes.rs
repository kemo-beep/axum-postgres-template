//! Org routes: orgs, workspaces, invites.

use axum::{
    extract::{Path, Query, State},
    routing::{get, patch, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use crate::auth::extractor::RequireAuth;
use crate::common::{ApiError, OrgId, PaginationQuery, UserId};
use crate::org::repository::{Org, Workspace};
use crate::AppState;

#[derive(Deserialize, ToSchema, Validate)]
pub struct CreateOrgRequest {
    #[validate(length(min = 1, max = 200))]
    pub name: String,
    #[validate(length(max = 100))]
    pub slug: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct OrgResponse {
    pub id: String,
    pub name: String,
    pub slug: String,
}

#[derive(Deserialize, ToSchema, Validate)]
pub struct CreateWorkspaceRequest {
    #[validate(length(min = 1, max = 200))]
    pub name: String,
    #[validate(length(max = 100))]
    pub slug: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct WorkspaceResponse {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub slug: String,
}

#[derive(Deserialize, ToSchema, Validate)]
pub struct CreateInviteRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 1, max = 50))]
    pub role: String,
}

#[derive(Serialize, ToSchema)]
pub struct InviteResponse {
    pub token: String,
}

#[derive(Deserialize, ToSchema, Validate)]
pub struct AcceptInviteRequest {
    #[validate(length(min = 1))]
    pub token: String,
}

#[derive(Serialize, ToSchema)]
pub struct OrgMemberResponse {
    pub user_id: String,
    pub email: Option<String>,
    pub role: String,
}

#[derive(Deserialize, ToSchema, Validate)]
pub struct UpdateMemberRoleRequest {
    #[validate(length(min = 1, max = 50))]
    pub role: String,
}

fn org_to_response(o: &Org) -> OrgResponse {
    OrgResponse {
        id: o.id.0.to_string(),
        name: o.name.clone(),
        slug: o.slug.clone(),
    }
}

fn workspace_to_response(w: &Workspace) -> WorkspaceResponse {
    WorkspaceResponse {
        id: w.id.0.to_string(),
        org_id: w.org_id.0.to_string(),
        name: w.name.clone(),
        slug: w.slug.clone(),
    }
}

/// List orgs the current user belongs to.
#[utoipa::path(
    get,
    path = "/v1/orgs",
    tag = "Orgs",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List of orgs", body = Vec<OrgResponse>),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal error")
    )
)]
pub async fn list_orgs(
    State(state): State<AppState>,
    RequireAuth(user): RequireAuth,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Json<Vec<OrgResponse>>, ApiError> {
    let limit = pagination.limit() as i64;
    let offset = pagination.offset() as i64;
    let orgs = state
        .org_service
        .get_user_orgs(user.id, limit, offset)
        .await?;
    Ok(Json(orgs.iter().map(org_to_response).collect()))
}

/// Create a new org.
#[utoipa::path(
    post,
    path = "/v1/orgs",
    tag = "Orgs",
    security(("bearer_auth" = [])),
    request_body = CreateOrgRequest,
    responses(
        (status = 200, description = "Created org", body = OrgResponse),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Slug already exists"),
        (status = 500, description = "Internal error")
    )
)]
pub async fn create_org(
    State(state): State<AppState>,
    RequireAuth(user): RequireAuth,
    Json(req): Json<CreateOrgRequest>,
) -> Result<Json<OrgResponse>, ApiError> {
    req.validate().map_err(|e| ApiError::UnprocessableEntity(e.to_string()))?;
    let slug = req.slug.as_deref();
    let org = state
        .org_service
        .create_org(user.id, &req.name, slug)
        .await?;
    Ok(Json(org_to_response(&org)))
}

/// Get a single org by id.
#[utoipa::path(
    get,
    path = "/v1/orgs/{org_id}",
    tag = "Orgs",
    params(("org_id" = String, Path, description = "Org UUID")),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Org", body = OrgResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
        (status = 500, description = "Internal error")
    )
)]
pub async fn get_org(
    State(state): State<AppState>,
    RequireAuth(user): RequireAuth,
    Path(org_id): Path<String>,
) -> Result<Json<OrgResponse>, ApiError> {
    let org_id = Uuid::parse_str(&org_id).map_err(|_| ApiError::NotFound)?;
    let org_id = OrgId::from_uuid(org_id);
    let org = state.org_service.get_org(org_id, user.id).await?;
    Ok(Json(org_to_response(&org)))
}

/// List members of an org (with email for display).
#[utoipa::path(
    get,
    path = "/v1/orgs/{org_id}/members",
    tag = "Orgs",
    params(("org_id" = String, Path, description = "Org UUID")),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List of members", body = Vec<OrgMemberResponse>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
        (status = 500, description = "Internal error")
    )
)]
pub async fn list_members(
    State(state): State<AppState>,
    RequireAuth(user): RequireAuth,
    Path(org_id): Path<String>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Json<Vec<OrgMemberResponse>>, ApiError> {
    let org_id = Uuid::parse_str(&org_id).map_err(|_| ApiError::NotFound)?;
    let org_id = OrgId::from_uuid(org_id);
    let limit = pagination.limit() as i64;
    let offset = pagination.offset() as i64;
    let members = state
        .org_service
        .list_members_with_email(org_id, user.id, limit, offset)
        .await?;
    Ok(Json(
        members
            .iter()
            .map(|m| OrgMemberResponse {
                user_id: m.user_id.0.to_string(),
                email: Some(m.email.clone()),
                role: m.role.clone(),
            })
            .collect(),
    ))
}

/// Update a member's role. Requires admin or owner.
#[utoipa::path(
    patch,
    path = "/v1/orgs/{org_id}/members/{user_id}",
    tag = "Orgs",
    params(("org_id" = String, Path), ("user_id" = String, Path)),
    security(("bearer_auth" = [])),
    request_body = UpdateMemberRoleRequest,
    responses(
        (status = 200, description = "Member updated"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
        (status = 500, description = "Internal error")
    )
)]
pub async fn update_member(
    State(state): State<AppState>,
    RequireAuth(user): RequireAuth,
    Path((org_id, user_id)): Path<(String, String)>,
    Json(req): Json<UpdateMemberRoleRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    req.validate().map_err(|e| ApiError::UnprocessableEntity(e.to_string()))?;
    let org_id = Uuid::parse_str(&org_id).map_err(|_| ApiError::NotFound)?;
    let org_id = OrgId::from_uuid(org_id);
    let target_uuid = Uuid::parse_str(&user_id).map_err(|_| ApiError::NotFound)?;
    let target_user_id = UserId(target_uuid);
    state
        .org_service
        .update_member_role(org_id, user.id, target_user_id, &req.role)
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Remove a member from the org. Requires admin or owner.
#[utoipa::path(
    delete,
    path = "/v1/orgs/{org_id}/members/{user_id}",
    tag = "Orgs",
    params(("org_id" = String, Path), ("user_id" = String, Path)),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Member removed"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
        (status = 500, description = "Internal error")
    )
)]
pub async fn remove_member(
    State(state): State<AppState>,
    RequireAuth(user): RequireAuth,
    Path((org_id, user_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let org_id = Uuid::parse_str(&org_id).map_err(|_| ApiError::NotFound)?;
    let org_id = OrgId::from_uuid(org_id);
    let target_uuid = Uuid::parse_str(&user_id).map_err(|_| ApiError::NotFound)?;
    let target_user_id = UserId(target_uuid);
    state
        .org_service
        .remove_member(org_id, user.id, target_user_id)
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Create an invite for an org.
#[utoipa::path(
    post,
    path = "/v1/orgs/{org_id}/invites",
    tag = "Orgs",
    params(("org_id" = String, Path, description = "Org UUID")),
    security(("bearer_auth" = [])),
    request_body = CreateInviteRequest,
    responses(
        (status = 200, description = "Invite created", body = InviteResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
        (status = 500, description = "Internal error")
    )
)]
pub async fn create_invite(
    State(state): State<AppState>,
    RequireAuth(user): RequireAuth,
    Path(org_id): Path<String>,
    Json(req): Json<CreateInviteRequest>,
) -> Result<Json<InviteResponse>, ApiError> {
    req.validate().map_err(|e| ApiError::UnprocessableEntity(e.to_string()))?;
    let org_id = Uuid::parse_str(&org_id).map_err(|_| ApiError::NotFound)?;
    let org_id = OrgId::from_uuid(org_id);
    let token = state
        .org_service
        .create_invite(org_id, user.id, &req.email, &req.role)
        .await?;
    Ok(Json(InviteResponse { token }))
}

/// Accept an invite (current user).
#[utoipa::path(
    post,
    path = "/v1/invites/accept",
    tag = "Orgs",
    security(("bearer_auth" = [])),
    request_body = AcceptInviteRequest,
    responses(
        (status = 200, description = "Invite accepted"),
        (status = 400, description = "Invalid or expired invite"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal error")
    )
)]
pub async fn accept_invite(
    State(state): State<AppState>,
    RequireAuth(user): RequireAuth,
    Json(req): Json<AcceptInviteRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    req.validate().map_err(|e| ApiError::UnprocessableEntity(e.to_string()))?;
    state.org_service.accept_invite(&req.token, user.id).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// List workspaces in an org.
#[utoipa::path(
    get,
    path = "/v1/orgs/{org_id}/workspaces",
    tag = "Orgs",
    params(("org_id" = String, Path, description = "Org UUID")),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List of workspaces", body = Vec<WorkspaceResponse>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
        (status = 500, description = "Internal error")
    )
)]
pub async fn list_workspaces(
    State(state): State<AppState>,
    RequireAuth(user): RequireAuth,
    Path(org_id): Path<String>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Json<Vec<WorkspaceResponse>>, ApiError> {
    let org_id = Uuid::parse_str(&org_id).map_err(|_| ApiError::NotFound)?;
    let org_id = OrgId::from_uuid(org_id);
    let limit = pagination.limit() as i64;
    let offset = pagination.offset() as i64;
    let workspaces = state
        .org_service
        .list_workspaces(org_id, user.id, limit, offset)
        .await?;
    Ok(Json(workspaces.iter().map(workspace_to_response).collect()))
}

/// Create a workspace in an org.
#[utoipa::path(
    post,
    path = "/v1/orgs/{org_id}/workspaces",
    tag = "Orgs",
    params(("org_id" = String, Path, description = "Org UUID")),
    security(("bearer_auth" = [])),
    request_body = CreateWorkspaceRequest,
    responses(
        (status = 200, description = "Created workspace", body = WorkspaceResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not found"),
        (status = 500, description = "Internal error")
    )
)]
pub async fn create_workspace(
    State(state): State<AppState>,
    RequireAuth(user): RequireAuth,
    Path(org_id): Path<String>,
    Json(req): Json<CreateWorkspaceRequest>,
) -> Result<Json<WorkspaceResponse>, ApiError> {
    req.validate().map_err(|e| ApiError::UnprocessableEntity(e.to_string()))?;
    let org_id = Uuid::parse_str(&org_id).map_err(|_| ApiError::NotFound)?;
    let org_id = OrgId::from_uuid(org_id);
    let slug = req.slug.as_deref();
    let ws = state
        .org_service
        .create_workspace(org_id, user.id, &req.name, slug)
        .await?;
    Ok(Json(workspace_to_response(&ws)))
}

/// Build the org router.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_orgs).post(create_org))
        .route("/{org_id}", get(get_org))
        .route("/{org_id}/members", get(list_members))
        .route(
            "/{org_id}/members/{user_id}",
            patch(update_member).delete(remove_member),
        )
        .route("/{org_id}/invites", post(create_invite))
        .route(
            "/{org_id}/workspaces",
            get(list_workspaces).post(create_workspace),
        )
        .route(
            "/{org_id}/feature-flags",
            get(crate::feature_flags::routes::list_for_org),
        )
}

/// Router for invite-only routes (e.g. /v1/invites/accept).
pub fn invite_router() -> Router<AppState> {
    Router::new().route("/accept", post(accept_invite))
}
