//! Org service: business logic for orgs, workspaces, invites.

use chrono::{Duration, Utc};
use rand::Rng;

use crate::auth::repository::UserRepository;
use crate::common::{ApiError, OrgId, UserId};
use crate::org::repository::OrgRepository;

pub struct OrgService {
    repo: OrgRepository,
    user_repo: UserRepository,
}

impl OrgService {
    pub fn new(repo: OrgRepository, user_repo: UserRepository) -> Self {
        Self { repo, user_repo }
    }

    pub async fn create_org(
        &self,
        user_id: UserId,
        name: &str,
        slug: Option<&str>,
    ) -> Result<crate::org::repository::Org, ApiError> {
        let slug = slug
            .map(|s| s.to_string())
            .unwrap_or_else(|| slugify(name));
        if slug.is_empty() {
            return Err(ApiError::InvalidRequest("Invalid org name".into()));
        }
        if self.repo.get_org_by_slug(&slug).await.map_err(|e| ApiError::InternalError(e.into()))?.is_some() {
            return Err(ApiError::Conflict("Org slug already exists".into()));
        }
        self.repo
            .create_org(user_id, name, &slug)
            .await
            .map_err(|e| ApiError::InternalError(e.into()))
    }

    pub async fn get_user_orgs(&self, user_id: UserId) -> Result<Vec<crate::org::repository::Org>, ApiError> {
        self.repo
            .get_user_orgs(user_id)
            .await
            .map_err(|e| ApiError::InternalError(e.into()))
    }

    pub async fn get_org(&self, org_id: OrgId, user_id: UserId) -> Result<crate::org::repository::Org, ApiError> {
        self.repo.ensure_user_in_org(user_id, org_id).await?;
        self.repo
            .get_org(org_id)
            .await
            .map_err(|e| ApiError::InternalError(e.into()))?
            .ok_or(ApiError::NotFound)
    }

    pub async fn create_workspace(
        &self,
        org_id: OrgId,
        user_id: UserId,
        name: &str,
        slug: Option<&str>,
    ) -> Result<crate::org::repository::Workspace, ApiError> {
        self.repo.ensure_user_in_org(user_id, org_id).await?;
        let slug = slug
            .map(|s| s.to_string())
            .unwrap_or_else(|| slugify(name));
        if slug.is_empty() {
            return Err(ApiError::InvalidRequest("Invalid workspace name".into()));
        }
        self.repo
            .create_workspace(org_id, name, &slug)
            .await
            .map_err(|e| ApiError::InternalError(e.into()))
    }

    pub async fn list_workspaces(
        &self,
        org_id: OrgId,
        user_id: UserId,
    ) -> Result<Vec<crate::org::repository::Workspace>, ApiError> {
        self.repo.ensure_user_in_org(user_id, org_id).await?;
        self.repo
            .list_workspaces(org_id)
            .await
            .map_err(|e| ApiError::InternalError(e.into()))
    }

    pub async fn create_invite(
        &self,
        org_id: OrgId,
        inviter_id: UserId,
        email: &str,
        role: &str,
    ) -> Result<String, ApiError> {
        if role != "admin" && role != "member" {
            return Err(ApiError::InvalidRequest("Role must be admin or member".into()));
        }
        self.repo.ensure_user_in_org(inviter_id, org_id).await?;
        let member_role = self
            .repo
            .get_member_role(org_id, inviter_id)
            .await
            .map_err(|e| ApiError::InternalError(e.into()))?
            .ok_or(ApiError::NotFound)?;
        if member_role != "owner" && member_role != "admin" {
            return Err(ApiError::Forbidden);
        }
        let token = generate_invite_token();
        let expires_at = Utc::now() + Duration::days(7);
        self.repo
            .create_invite(org_id, email, role, inviter_id, &token, expires_at)
            .await
            .map_err(|e| ApiError::InternalError(e.into()))?;
        Ok(token)
    }

    pub async fn accept_invite(&self, token: &str, user_id: UserId) -> Result<(), ApiError> {
        let invite = self
            .repo
            .find_invite_by_token(token)
            .await
            .map_err(|e| ApiError::InternalError(e.into()))?
            .ok_or(ApiError::InvalidRequest("Invalid or expired invite".into()))?;
        let user = self
            .user_repo
            .get_by_id(user_id)
            .await
            .map_err(|e| ApiError::InternalError(e.into()))?
            .ok_or(ApiError::NotFound)?;
        if !user.email.eq_ignore_ascii_case(&invite.email) {
            return Err(ApiError::InvalidRequest("Invite email does not match your account".into()));
        }
        self.repo
            .add_member(invite.org_id, user_id, &invite.role)
            .await
            .map_err(|e| ApiError::InternalError(e.into()))?;
        self.repo
            .delete_invite(invite.id)
            .await
            .map_err(|e| ApiError::InternalError(e.into()))?;
        Ok(())
    }
}

fn slugify(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn generate_invite_token() -> String {
    let bytes: [u8; 32] = rand::thread_rng().gen();
    hex::encode(bytes)
}
