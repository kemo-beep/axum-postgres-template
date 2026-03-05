//! Auth extractors: RequireAuth, RequirePermission, RequireRole.

use axum::{extract::FromRequestParts, http::request::Parts};

use crate::api_error::ApiError;
use crate::auth::repository::{RbacRepository, User};
use crate::AppState;

/// Extractor that requires a valid JWT and loads the user.
pub struct RequireAuth(pub User);

/// Wrapper for user when permission is required. Use with `require_permission` layer.
pub struct RequirePermission(pub User);

/// Wrapper for user when role is required. Use with `require_role` layer.
pub struct RequireRole(pub User);

fn bearer_token(parts: &Parts) -> Option<&str> {
    let auth = parts.headers.get("authorization")?;
    let auth = auth.to_str().ok()?;
    auth.strip_prefix("Bearer ")
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
        let token = bearer_token(parts).ok_or(ApiError::Unauthorized)?;

        let auth_service = state.auth_service.as_ref().ok_or(ApiError::InternalError(
            anyhow::anyhow!("Auth service not configured"),
        ))?;

        let user_id = auth_service.verify_token(token).await?;
        let user = auth_service
            .get_user(user_id)
            .await?
            .ok_or(ApiError::Unauthorized)?;

        Ok(RequireAuth(user))
    }
}

/// Checks if the user has the given permission. Use in handlers after RequireAuth.
pub async fn check_permission(
    state: &AppState,
    user_id: crate::types::UserId,
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
    user_id: crate::types::UserId,
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
