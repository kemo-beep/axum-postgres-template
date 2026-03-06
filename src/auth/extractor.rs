//! Auth extractors: RequireAuth, RequirePermission, RequireOrgMember, RequireWorkspaceMember.

use axum::extract::{FromRequestParts, Path};
use axum::http::request::Parts;
use axum::http::HeaderMap;
use axum_extra::extract::cookie::CookieJar;
use uuid::Uuid;

use crate::auth::permissions;
use crate::auth::repository::User;
use crate::common::{ApiError, OrgId, WorkspaceId};
use crate::AppState;

/// User loaded after successful auth. Inserted by permission extractors when auth + permission check passes.
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

/// Returns the API key from X-API-Key header, if present.
pub(crate) fn api_key_from_headers(parts: &Parts) -> Option<&str> {
    let value = parts.headers.get("x-api-key")?;
    value
        .to_str()
        .ok()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
}

/// Returns the auth token from Authorization: Bearer or from the session cookie.
pub(crate) fn token_from_parts(parts: &Parts, cookie_name: &str) -> Option<String> {
    bearer_token(parts).map(String::from).or_else(|| {
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

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        if let Some(prev) = parts.extensions.get::<AuthenticatedUser>() {
            return Ok(RequireAuth(prev.0.clone()));
        }

        if let Some(api_key) = api_key_from_headers(parts) {
            let api_key_svc = state
                .api_key_service
                .as_ref()
                .ok_or(ApiError::InternalError(anyhow::anyhow!(
                    "Auth service not configured"
                )))?;
            let (user, scope) = api_key_svc.validate_api_key(api_key).await?;
            parts.extensions.insert(crate::auth::ApiKeyScope {
                api_key_id: scope.api_key_id,
                org_id: scope.org_id,
                workspace_id: scope.workspace_id,
                permissions: scope.permissions,
            });
            parts.extensions.insert(AuthenticatedUser(user.clone()));
            // Spawn audit log (non-blocking). Status logged as 0 since we don't have response yet.
            if state.api_key_service.is_some() {
                let method = parts.method.as_str().to_string();
                let path = parts.uri.path().to_string();
                let ip = parts
                    .headers
                    .get("x-forwarded-for")
                    .or_else(|| parts.headers.get("x-real-ip"))
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.split(',').next())
                    .map(String::from);
                let api_key_repo =
                    crate::auth::api_key_repository::ApiKeyRepository::new(state.db.pool.clone());
                crate::auth::api_key_service::ApiKeyService::log_usage_async(
                    api_key_repo,
                    scope.api_key_id,
                    method,
                    path,
                    0,
                    ip,
                );
            }
            return Ok(RequireAuth(user));
        }

        let token =
            token_from_parts(parts, &state.cfg.cookie_name).ok_or(ApiError::Unauthorized)?;

        let auth_service =
            state
                .auth_service
                .as_ref()
                .ok_or(ApiError::InternalError(anyhow::anyhow!(
                    "Auth service not configured"
                )))?;

        let user_id = auth_service.verify_token(&token).await?;
        let user = auth_service
            .get_user(user_id)
            .await?
            .ok_or(ApiError::Unauthorized)?;

        Ok(RequireAuth(user))
    }
}

/// Authenticate (JWT or API key) and check permission. Inserts AuthenticatedUser and ApiKeyScope when using API key.
pub(crate) async fn auth_and_check_permission(
    parts: &mut Parts,
    state: &AppState,
    permission: &str,
) -> Result<User, ApiError> {
    if let Some(prev) = parts.extensions.get::<AuthenticatedUser>() {
        let user = &prev.0;
        if let Some(scope) = parts.extensions.get::<crate::auth::ApiKeyScope>() {
            if scope.permissions.contains(&permission.to_string()) {
                return Ok(user.clone());
            }
        } else {
            check_permission(state, user.id, permission).await?;
            return Ok(user.clone());
        }
    }

    if let Some(api_key) = api_key_from_headers(parts) {
        let api_key_svc = state
            .api_key_service
            .as_ref()
            .ok_or(ApiError::InternalError(anyhow::anyhow!(
                "Auth service not configured"
            )))?;
        let (user, scope) = api_key_svc.validate_api_key(api_key).await?;
        if !scope.permissions.contains(&permission.to_string()) {
            return Err(ApiError::Forbidden);
        }
        parts.extensions.insert(crate::auth::ApiKeyScope {
            api_key_id: scope.api_key_id,
            org_id: scope.org_id,
            workspace_id: scope.workspace_id,
            permissions: scope.permissions,
        });
        parts.extensions.insert(AuthenticatedUser(user.clone()));
        let method = parts.method.as_str().to_string();
        let path = parts.uri.path().to_string();
        let ip = parts
            .headers
            .get("x-forwarded-for")
            .or_else(|| parts.headers.get("x-real-ip"))
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(String::from);
        let api_key_repo =
            crate::auth::api_key_repository::ApiKeyRepository::new(state.db.pool.clone());
        crate::auth::api_key_service::ApiKeyService::log_usage_async(
            api_key_repo,
            scope.api_key_id,
            method,
            path,
            0,
            ip,
        );
        return Ok(user);
    }

    let token = token_from_parts(parts, &state.cfg.cookie_name).ok_or(ApiError::Unauthorized)?;
    let auth_service =
        state
            .auth_service
            .as_ref()
            .ok_or(ApiError::InternalError(anyhow::anyhow!(
                "Auth service not configured"
            )))?;
    let user_id = auth_service.verify_token(&token).await?;
    let user = auth_service
        .get_user(user_id)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    check_permission(state, user.id, permission).await?;
    parts.extensions.insert(AuthenticatedUser(user.clone()));
    Ok(user)
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
                $crate::auth::extractor::auth_and_check_permission(parts, state, $permission)
                    .await?;
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

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let user = RequireAuth::from_request_parts(parts, state).await?.0;
        let Path(org_id_str): Path<String> = Path::from_request_parts(parts, state)
            .await
            .map_err(|_| ApiError::NotFound)?;
        let org_uuid = Uuid::parse_str(&org_id_str).map_err(|_| ApiError::NotFound)?;
        let org_id = OrgId::from_uuid(org_uuid);

        if let Some(scope) = parts.extensions.get::<crate::auth::ApiKeyScope>() {
            if let Some(key_org_id) = scope.org_id {
                if key_org_id != org_id {
                    return Err(ApiError::Forbidden);
                }
                return Ok(RequireOrgMember(user, org_id));
            }
        }

        state
            .org_service
            .ensure_user_in_org(user.id, org_id)
            .await?;
        Ok(RequireOrgMember(user, org_id))
    }
}

/// Extractor for org-scoped billing routes. Requires auth, org membership, and either
/// the global `billing:manage` permission or org role `owner`/`admin`.
/// Yields (User, OrgId).
pub struct RequireOrgBillingAccess(pub User, pub OrgId);

impl RequireOrgBillingAccess {
    pub fn user(&self) -> &User {
        &self.0
    }
    pub fn org_id(&self) -> OrgId {
        self.1
    }
}

impl FromRequestParts<AppState> for RequireOrgBillingAccess {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let user = RequireAuth::from_request_parts(parts, state).await?.0;
        let Path(org_id_str): Path<String> = Path::from_request_parts(parts, state)
            .await
            .map_err(|_| ApiError::NotFound)?;
        let org_uuid = Uuid::parse_str(&org_id_str).map_err(|_| ApiError::NotFound)?;
        let org_id = OrgId::from_uuid(org_uuid);

        if let Some(scope) = parts.extensions.get::<crate::auth::ApiKeyScope>() {
            if let Some(key_org_id) = scope.org_id {
                if key_org_id != org_id {
                    return Err(ApiError::Forbidden);
                }
                if !scope.permissions.contains(&permissions::BILLING_MANAGE.to_string()) {
                    return Err(ApiError::Forbidden);
                }
                return Ok(RequireOrgBillingAccess(user, org_id));
            }
        }

        state
            .org_service
            .ensure_user_in_org(user.id, org_id)
            .await?;

        let has_permission = state
            .rbac_service
            .check_permission(user.id, permissions::BILLING_MANAGE)
            .await
            .is_ok();

        if has_permission {
            return Ok(RequireOrgBillingAccess(user, org_id));
        }

        let member_role = state
            .org_service
            .get_member_role(org_id, user.id)
            .await?;

        if member_role.as_deref().is_some_and(|r| r == "owner" || r == "admin") {
            return Ok(RequireOrgBillingAccess(user, org_id));
        }

        Err(ApiError::Forbidden)
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

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let user = RequireAuth::from_request_parts(parts, state).await?.0;
        let Path((org_id_str, workspace_id_str)): Path<(String, String)> =
            Path::from_request_parts(parts, state)
                .await
                .map_err(|_| ApiError::NotFound)?;
        let org_uuid = Uuid::parse_str(&org_id_str).map_err(|_| ApiError::NotFound)?;
        let ws_uuid = Uuid::parse_str(&workspace_id_str).map_err(|_| ApiError::NotFound)?;
        let org_id = OrgId::from_uuid(org_uuid);
        let workspace_id = WorkspaceId::from_uuid(ws_uuid);

        if let Some(scope) = parts.extensions.get::<crate::auth::ApiKeyScope>() {
            if let (Some(key_org_id), Some(key_workspace_id)) = (scope.org_id, scope.workspace_id) {
                if key_org_id == org_id && key_workspace_id == workspace_id {
                    return Ok(RequireWorkspaceMember(user, org_id, workspace_id));
                }
            }
            if let Some(key_org_id) = scope.org_id {
                if key_org_id != org_id {
                    return Err(ApiError::Forbidden);
                }
                let org_repo = crate::org::repository::OrgRepository::new(state.db.pool.clone());
                let ws = org_repo
                    .get_workspace(workspace_id)
                    .await
                    .map_err(ApiError::InternalError)?
                    .ok_or(ApiError::NotFound)?;
                if ws.org_id != org_id {
                    return Err(ApiError::Forbidden);
                }
                return Ok(RequireWorkspaceMember(user, org_id, workspace_id));
            }
            if scope.workspace_id.is_some() {
                return Err(ApiError::Forbidden);
            }
        }

        state
            .org_service
            .ensure_workspace_access(user.id, workspace_id)
            .await?;
        Ok(RequireWorkspaceMember(user, org_id, workspace_id))
    }
}

/// Checks if the user has the given permission. Use in handlers after RequireAuth.
pub async fn check_permission(
    state: &AppState,
    user_id: crate::common::UserId,
    permission: &str,
) -> Result<(), ApiError> {
    state
        .rbac_service
        .check_permission(user_id, permission)
        .await
}

/// Checks if the user has the given role. Use in handlers after RequireAuth.
pub async fn check_role(
    state: &AppState,
    user_id: crate::common::UserId,
    role: &str,
) -> Result<(), ApiError> {
    state.rbac_service.check_role(user_id, role).await
}
