//! Auth extractors: RequireAuth, RequirePermission, RequireOrgMember, RequireWorkspaceMember.

use axum::extract::{FromRequestParts, Path};
use axum::http::request::Parts;
use axum::http::HeaderMap;
use axum_extra::extract::cookie::CookieJar;
use uuid::Uuid;

use crate::auth::permissions;
use crate::auth::repository::{RbacRepository, User};
use crate::common::{ApiError, OrgId, WorkspaceId};
use crate::org::repository::OrgRepository;
use crate::AppState;

/// Inserted by permission extractors when auth + permission check passes.
/// RequireAuth checks for this first to avoid double auth.
#[derive(Clone)]
pub struct AuthenticatedUser(pub User);

/// Extractor that requires a valid JWT and loads the user.
/// If a permission layer ran first and inserted AuthenticatedUser, uses that.
pub struct RequireAuth(pub User);

/// Wrapper for user when permission is required. Use with `require_permission` layer.
pub struct RequirePermission(pub User);

/// Wrapper for user when role is required. Use with `require_role` layer.
pub struct RequireRole(pub User);

pub(crate) fn bearer_token(parts: &Parts) -> Option<&str> {
    let auth = parts.headers.get("authorization")?;
    let auth = auth.to_str().ok()?;
    auth.strip_prefix("Bearer ")
}

/// Returns the auth token from Authorization: Bearer or from the session cookie.
pub(crate) fn token_from_parts(parts: &Parts, cookie_name: &str) -> Option<String> {
    bearer_token(parts)
        .map(String::from)
        .or_else(|| {
            let jar = CookieJar::from_headers(&parts.headers);
            jar.get(cookie_name).map(|c| c.value().to_string())
        })
}

/// Returns the auth token from Authorization: Bearer or from the session cookie.
pub(crate) fn token_from_headers_or_jar(
    headers: &HeaderMap,
    jar: &CookieJar,
    cookie_name: &str,
) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(String::from)
        .or_else(|| jar.get(cookie_name).map(|c| c.value().to_string()))
}

impl RequireAuth {
    pub fn user(&self) -> &User {
        &self.0
    }
}

impl RequirePermission {
    pub fn user(&self) -> &User {
        &self.0
    }
}

impl RequireRole {
    pub fn user(&self) -> &User {
        &self.0
    }
}

impl FromRequestParts<AppState> for RequireAuth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        if let Some(prev) = parts.extensions.get::<AuthenticatedUser>() {
            return Ok(RequireAuth(prev.0.clone()));
        }

        let token = token_from_parts(parts, &state.cfg.cookie_name)
            .ok_or(ApiError::Unauthorized)?;

        let auth_service = state.auth_service.as_ref().ok_or(ApiError::InternalError(
            anyhow::anyhow!("Auth service not configured"),
        ))?;

        let user_id = auth_service.verify_token(&token).await?;
        let user = auth_service
            .get_user(user_id)
            .await?
            .ok_or(ApiError::Unauthorized)?;

        Ok(RequireAuth(user))
    }
}

/// Macro to define a permission extractor. Runs auth, checks permission, inserts user for RequireAuth.
#[macro_export]
macro_rules! define_permission_extractor {
    ($name:ident, $permission:expr) => {
        pub struct $name;

        impl axum::extract::FromRequestParts<$crate::AppState> for $name {
            type Rejection = $crate::common::ApiError;

            async fn from_request_parts(
                parts: &mut axum::http::request::Parts,
                state: &$crate::AppState,
            ) -> Result<Self, Self::Rejection> {
                let token = $crate::auth::extractor::token_from_parts(parts, &state.cfg.cookie_name)
                    .ok_or($crate::common::ApiError::Unauthorized)?;

                let auth_service = state.auth_service.as_ref().ok_or(
                    $crate::common::ApiError::InternalError(
                        anyhow::anyhow!("Auth service not configured"),
                    ),
                )?;

                let user_id = auth_service.verify_token(token.as_str()).await?;
                let user = auth_service
                    .get_user(user_id)
                    .await?
                    .ok_or($crate::common::ApiError::Unauthorized)?;

                $crate::auth::extractor::check_permission(state, user.id, $permission).await?;
                parts.extensions.insert($crate::auth::extractor::AuthenticatedUser(user));
                Ok($name)
            }
        }
    };
}

define_permission_extractor!(RequireUsersRead, permissions::USERS_READ);
define_permission_extractor!(RequireUsersWrite, permissions::USERS_WRITE);
define_permission_extractor!(RequireBillingManage, permissions::BILLING_MANAGE);
define_permission_extractor!(RequireFilesRead, permissions::FILES_READ);
define_permission_extractor!(RequireFilesWrite, permissions::FILES_WRITE);

/// Extractor that requires auth and org membership. Use on routes with path param `:org_id`.
/// Yields (User, OrgId).
pub struct RequireOrgMember(pub User, pub OrgId);

impl RequireOrgMember {
    pub fn user(&self) -> &User {
        &self.0
    }
    pub fn org_id(&self) -> OrgId {
        self.1
    }
}

impl FromRequestParts<AppState> for RequireOrgMember {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let user = RequireAuth::from_request_parts(parts, state).await?.0;
        let Path(org_id_str): Path<String> = Path::from_request_parts(parts, state)
            .await
            .map_err(|_| ApiError::NotFound)?;
        let org_uuid = Uuid::parse_str(&org_id_str).map_err(|_| ApiError::NotFound)?;
        let org_id = OrgId::from_uuid(org_uuid);
        let repo = OrgRepository::new(state.db.pool.clone());
        repo.ensure_user_in_org(user.id, org_id).await?;
        Ok(RequireOrgMember(user, org_id))
    }
}

/// Extractor that requires auth and workspace access (user must be org member).
/// Use on routes with path params `:org_id` and `:workspace_id`.
pub struct RequireWorkspaceMember(pub User, pub OrgId, pub WorkspaceId);

impl RequireWorkspaceMember {
    pub fn user(&self) -> &User {
        &self.0
    }
    pub fn org_id(&self) -> OrgId {
        self.1
    }
    pub fn workspace_id(&self) -> WorkspaceId {
        self.2
    }
}

impl FromRequestParts<AppState> for RequireWorkspaceMember {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let user = RequireAuth::from_request_parts(parts, state).await?.0;
        let Path((org_id_str, workspace_id_str)): Path<(String, String)> =
            Path::from_request_parts(parts, state)
                .await
                .map_err(|_| ApiError::NotFound)?;
        let org_uuid = Uuid::parse_str(&org_id_str).map_err(|_| ApiError::NotFound)?;
        let ws_uuid = Uuid::parse_str(&workspace_id_str).map_err(|_| ApiError::NotFound)?;
        let org_id = OrgId::from_uuid(org_uuid);
        let workspace_id = WorkspaceId::from_uuid(ws_uuid);
        let repo = OrgRepository::new(state.db.pool.clone());
        repo.ensure_workspace_access(user.id, workspace_id).await?;
        Ok(RequireWorkspaceMember(user, org_id, workspace_id))
    }
}

/// Checks if the user has the given permission. Use in handlers after RequireAuth.
pub async fn check_permission(
    state: &AppState,
    user_id: crate::common::UserId,
    permission: &str,
) -> Result<(), ApiError> {
    let rbac = RbacRepository::new(state.db.pool.clone());
    let perms = rbac
        .get_user_permissions(user_id)
        .await
        .map_err(|e| ApiError::InternalError(e.into()))?;
    if perms.contains(&permission.to_string()) {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

/// Checks if the user has the given role. Use in handlers after RequireAuth.
pub async fn check_role(
    state: &AppState,
    user_id: crate::common::UserId,
    role: &str,
) -> Result<(), ApiError> {
    let rbac = RbacRepository::new(state.db.pool.clone());
    let roles = rbac
        .get_user_roles(user_id)
        .await
        .map_err(|e| ApiError::InternalError(e.into()))?;
    if roles.contains(&role.to_string()) {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}
