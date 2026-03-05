//! RBAC service: roles, permissions, user-role assignment.
//! Wraps RbacRepository; handlers and extractors use this instead of the repository.

use uuid::Uuid;

use crate::auth::repository::RbacRepository;
use crate::common::{ApiError, UserId};

#[derive(Clone)]
pub struct RbacService {
    repo: RbacRepository,
}

impl RbacService {
    pub fn new(repo: RbacRepository) -> Self {
        Self { repo }
    }

    pub async fn list_roles(&self) -> Result<Vec<(Uuid, String)>, ApiError> {
        self.repo
            .list_roles()
            .await
            .map_err(ApiError::InternalError)
    }

    pub async fn list_permissions(&self) -> Result<Vec<(Uuid, String)>, ApiError> {
        self.repo
            .list_permissions()
            .await
            .map_err(ApiError::InternalError)
    }

    pub async fn get_user_roles(&self, user_id: UserId) -> Result<Vec<String>, ApiError> {
        self.repo
            .get_user_roles(user_id)
            .await
            .map_err(ApiError::InternalError)
    }

    pub async fn get_user_permissions(&self, user_id: UserId) -> Result<Vec<String>, ApiError> {
        self.repo
            .get_user_permissions(user_id)
            .await
            .map_err(ApiError::InternalError)
    }

    pub async fn assign_role(&self, user_id: UserId, role_name: &str) -> Result<(), ApiError> {
        self.repo
            .assign_role(user_id, role_name)
            .await
            .map_err(ApiError::InternalError)
    }

    pub async fn revoke_role(&self, user_id: UserId, role_name: &str) -> Result<bool, ApiError> {
        self.repo
            .revoke_role(user_id, role_name)
            .await
            .map_err(ApiError::InternalError)
    }

    pub async fn check_permission(
        &self,
        user_id: UserId,
        permission: &str,
    ) -> Result<(), ApiError> {
        let perms = self.get_user_permissions(user_id).await?;
        if perms.contains(&permission.to_string()) {
            Ok(())
        } else {
            Err(ApiError::Forbidden)
        }
    }

    pub async fn check_role(&self, user_id: UserId, role: &str) -> Result<(), ApiError> {
        let roles = self.get_user_roles(user_id).await?;
        if roles.contains(&role.to_string()) {
            Ok(())
        } else {
            Err(ApiError::Forbidden)
        }
    }
}
