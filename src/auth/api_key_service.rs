//! API key service: create, validate, revoke, rotate keys; audit logging.

use chrono::{Duration, Utc};
use rand::Rng;
use sha2::{Digest, Sha256};

use crate::auth::api_key_repository::{ApiKey, ApiKeyRepository};
use crate::auth::permissions;
use crate::auth::repository::UserRepository;
use crate::common::{ApiError, OrgId, UserId, WorkspaceId};
use crate::org::repository::OrgRepository;

/// Scope attached to an API-key-authenticated request.
#[derive(Clone, Debug)]
pub struct ApiKeyScope {
    pub api_key_id: uuid::Uuid,
    pub org_id: Option<OrgId>,
    pub workspace_id: Option<WorkspaceId>,
    pub permissions: Vec<String>,
}

/// Allowed permissions for API keys. Keys can only request a subset.
const ALLOWED_PERMISSIONS: &[&str] = &[
    permissions::USERS_READ,
    permissions::USERS_WRITE,
    permissions::BILLING_MANAGE,
    permissions::FILES_READ,
    permissions::FILES_WRITE,
    permissions::ORGS_MANAGE,
    permissions::WORKSPACES_MANAGE,
];

/// Read-only permission set for shorthand.
const READ_ONLY_PERMISSIONS: &[&str] = &[permissions::USERS_READ, permissions::FILES_READ];

fn hash_key(raw: &str) -> String {
    let hash = Sha256::digest(raw.as_bytes());
    hex::encode(hash)
}

fn generate_raw_key() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    format!("sk_{}", hex::encode(bytes))
}

#[derive(Clone)]
pub struct ApiKeyService {
    api_key_repo: ApiKeyRepository,
    user_repo: UserRepository,
    org_repo: OrgRepository,
}

impl ApiKeyService {
    pub fn new(
        api_key_repo: ApiKeyRepository,
        user_repo: UserRepository,
        org_repo: OrgRepository,
    ) -> Self {
        Self {
            api_key_repo,
            user_repo,
            org_repo,
        }
    }

    /// Validate API key and return (User, ApiKeyScope). Rejects expired keys.
    pub async fn validate_api_key(
        &self,
        raw_key: &str,
    ) -> Result<(crate::auth::repository::User, ApiKeyScope), ApiError> {
        let key_hash = hash_key(raw_key);
        let api_key = self
            .api_key_repo
            .get_by_key_hash(&key_hash)
            .await
            .map_err(ApiError::InternalError)?
            .ok_or(ApiError::Unauthorized)?;

        if let Some(exp) = api_key.expires_at {
            if exp < Utc::now() {
                return Err(ApiError::Unauthorized);
            }
        }

        let user = self
            .user_repo
            .get_by_id(api_key.user_id)
            .await
            .map_err(ApiError::InternalError)?
            .ok_or(ApiError::Unauthorized)?;

        let scope = ApiKeyScope {
            api_key_id: api_key.id,
            org_id: api_key.org_id,
            workspace_id: api_key.workspace_id,
            permissions: api_key.permissions.clone(),
        };

        Ok((user, scope))
    }

    /// Create a new API key. Returns (ApiKey, raw_key) - raw_key shown once.
    pub async fn create_key(
        &self,
        user_id: UserId,
        name: &str,
        org_id: Option<OrgId>,
        workspace_id: Option<WorkspaceId>,
        permissions: Vec<String>,
        expires_in_days: Option<u32>,
    ) -> Result<(ApiKey, String), ApiError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(ApiError::InvalidRequest("Name is required".into()));
        }

        // Validate permissions
        let perms = Self::resolve_permissions(&permissions)?;

        // If org/workspace scoped, verify user has access
        if let Some(oid) = org_id {
            self.org_repo.ensure_user_in_org(user_id, oid).await?;
        }
        if let Some(wid) = workspace_id {
            self.org_repo.ensure_workspace_access(user_id, wid).await?;
        }
        if workspace_id.is_some() && org_id.is_none() {
            return Err(ApiError::InvalidRequest(
                "Workspace scope requires org_id".into(),
            ));
        }

        let expires_at = expires_in_days.map(|d| Utc::now() + Duration::days(d as i64));

        let raw_key = generate_raw_key();
        let key_hash = hash_key(&raw_key);

        let api_key = self
            .api_key_repo
            .create(
                &key_hash,
                user_id,
                name,
                org_id,
                workspace_id,
                &perms,
                expires_at,
            )
            .await
            .map_err(ApiError::InternalError)?;

        Ok((api_key, raw_key))
    }

    /// Resolve permissions: if empty, reject; if contains "read_only" shorthand, expand; else validate each.
    fn resolve_permissions(perms: &[String]) -> Result<Vec<String>, ApiError> {
        if perms.is_empty() {
            return Err(ApiError::InvalidRequest(
                "At least one permission is required".into(),
            ));
        }
        if perms.len() == 1 && perms[0].eq_ignore_ascii_case("read_only") {
            return Ok(READ_ONLY_PERMISSIONS
                .iter()
                .map(|s| (*s).to_string())
                .collect());
        }
        for p in perms {
            if !ALLOWED_PERMISSIONS.contains(&p.as_str()) {
                return Err(ApiError::InvalidRequest(format!(
                    "Invalid permission: {}",
                    p
                )));
            }
        }
        Ok(perms.to_vec())
    }

    pub async fn list_keys(&self, user_id: UserId) -> Result<Vec<ApiKey>, ApiError> {
        self.api_key_repo
            .list_by_user_id(user_id)
            .await
            .map_err(ApiError::InternalError)
    }

    pub async fn revoke_key(&self, key_id: uuid::Uuid, user_id: UserId) -> Result<bool, ApiError> {
        let deleted = self
            .api_key_repo
            .delete(key_id, user_id)
            .await
            .map_err(ApiError::InternalError)?;
        Ok(deleted)
    }

    /// Rotate key: create new key with same metadata, revoke old. Returns (new ApiKey, new raw_key).
    pub async fn rotate_key(
        &self,
        key_id: uuid::Uuid,
        user_id: UserId,
    ) -> Result<(ApiKey, String), ApiError> {
        let old = self
            .api_key_repo
            .get_by_id(key_id)
            .await
            .map_err(ApiError::InternalError)?
            .ok_or(ApiError::NotFound)?;

        if old.user_id != user_id {
            return Err(ApiError::Forbidden);
        }

        let raw_key = generate_raw_key();
        let key_hash = hash_key(&raw_key);

        let new_key = self
            .api_key_repo
            .create(
                &key_hash,
                user_id,
                &old.name,
                old.org_id,
                old.workspace_id,
                &old.permissions,
                old.expires_at,
            )
            .await
            .map_err(ApiError::InternalError)?;

        let _ = self.api_key_repo.delete(key_id, user_id).await;

        Ok((new_key, raw_key))
    }

    pub async fn update_last_used(&self, api_key_id: uuid::Uuid) -> Result<(), ApiError> {
        self.api_key_repo
            .update_last_used_at(api_key_id)
            .await
            .map_err(ApiError::InternalError)
    }

    /// Log API key usage. Call with tokio::spawn for non-blocking audit.
    pub fn log_usage_async(
        api_key_repo: ApiKeyRepository,
        api_key_id: uuid::Uuid,
        method: String,
        path: String,
        status: u16,
        ip: Option<String>,
    ) {
        tokio::spawn(async move {
            let ip_ref = ip.as_deref();
            if let Err(e) = api_key_repo
                .log_usage(api_key_id, &method, &path, status, ip_ref)
                .await
            {
                tracing::warn!(%api_key_id, error = %e, "Failed to log API key usage");
            }
        });
    }
}
