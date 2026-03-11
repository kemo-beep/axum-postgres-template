//! Org service: business logic for orgs, workspaces, invites.

use chrono::{Duration, Utc};
use rand::Rng;

use crate::auth::repository::UserRepository;
use crate::common::{ApiError, OrgId, UserId, WorkspaceId};
use crate::org::repository::{OrgMember, OrgMemberWithEmail, OrgRepository};

/// Business logic for orgs, workspaces, and invites. Validates slugs and access.
#[derive(Clone)]
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
        let slug = slug.map(|s| s.to_string()).unwrap_or_else(|| slugify(name));
        if slug.is_empty() {
            return Err(ApiError::InvalidRequest("Invalid org name".into()));
        }
        if self
            .repo
            .get_org_by_slug(&slug)
            .await
            .map_err(ApiError::InternalError)?
            .is_some()
        {
            return Err(ApiError::Conflict("Org slug already exists".into()));
        }
        self.repo
            .create_org(user_id, name, &slug)
            .await
            .map_err(ApiError::InternalError)
    }

    pub async fn get_user_orgs(
        &self,
        user_id: UserId,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<crate::org::repository::Org>, ApiError> {
        self.repo
            .get_user_orgs(user_id, limit, offset)
            .await
            .map_err(ApiError::InternalError)
    }

    pub async fn get_org(
        &self,
        org_id: OrgId,
        user_id: UserId,
    ) -> Result<crate::org::repository::Org, ApiError> {
        self.repo.ensure_user_in_org(user_id, org_id).await?;
        self.repo
            .get_org(org_id)
            .await
            .map_err(ApiError::InternalError)?
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
        let slug = slug.map(|s| s.to_string()).unwrap_or_else(|| slugify(name));
        if slug.is_empty() {
            return Err(ApiError::InvalidRequest("Invalid workspace name".into()));
        }
        self.repo
            .create_workspace(org_id, name, &slug)
            .await
            .map_err(ApiError::InternalError)
    }

    pub async fn list_workspaces(
        &self,
        org_id: OrgId,
        user_id: UserId,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<crate::org::repository::Workspace>, ApiError> {
        self.repo.ensure_user_in_org(user_id, org_id).await?;
        self.repo
            .list_workspaces(org_id, limit, offset)
            .await
            .map_err(ApiError::InternalError)
    }

    pub async fn list_members(
        &self,
        org_id: OrgId,
        user_id: UserId,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<OrgMember>, ApiError> {
        self.repo.ensure_user_in_org(user_id, org_id).await?;
        self.repo
            .get_org_members(org_id, limit, offset)
            .await
            .map_err(ApiError::InternalError)
    }

    /// List members with email. Use for display in member management UI.
    pub async fn list_members_with_email(
        &self,
        org_id: OrgId,
        actor_id: UserId,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<OrgMemberWithEmail>, ApiError> {
        self.repo.ensure_user_in_org(actor_id, org_id).await?;
        self.repo
            .get_org_members_with_users(org_id, limit, offset)
            .await
            .map_err(ApiError::InternalError)
    }

    /// Update a member's role. Actor must be owner or admin. Cannot change owner's role unless actor is owner. Cannot demote last owner.
    pub async fn update_member_role(
        &self,
        org_id: OrgId,
        actor_id: UserId,
        target_user_id: UserId,
        new_role: &str,
    ) -> Result<(), ApiError> {
        if new_role != "admin" && new_role != "member" {
            return Err(ApiError::InvalidRequest(
                "Role must be admin or member".into(),
            ));
        }
        let actor_role = self
            .repo
            .get_member_role(org_id, actor_id)
            .await
            .map_err(ApiError::InternalError)?
            .ok_or(ApiError::NotFound)?;
        if actor_role != "owner" && actor_role != "admin" {
            return Err(ApiError::Forbidden);
        }
        let target_role = self
            .repo
            .get_member_role(org_id, target_user_id)
            .await
            .map_err(ApiError::InternalError)?
            .ok_or(ApiError::NotFound)?;
        if target_role == "owner" && actor_role != "owner" {
            return Err(ApiError::Forbidden);
        }
        if target_role == "owner" && new_role != "owner" {
            let owners = self
                .repo
                .count_members_with_role(org_id, "owner")
                .await
                .map_err(ApiError::InternalError)?;
            if owners <= 1 {
                return Err(ApiError::InvalidRequest(
                    "Cannot demote the last owner".into(),
                ));
            }
        }
        self.repo
            .add_member(org_id, target_user_id, new_role)
            .await
            .map_err(ApiError::InternalError)?;
        Ok(())
    }

    /// Remove a member from the org. Actor must be owner or admin. Cannot remove self if last owner.
    pub async fn remove_member(
        &self,
        org_id: OrgId,
        actor_id: UserId,
        target_user_id: UserId,
    ) -> Result<(), ApiError> {
        let actor_role = self
            .repo
            .get_member_role(org_id, actor_id)
            .await
            .map_err(ApiError::InternalError)?
            .ok_or(ApiError::NotFound)?;
        if actor_role != "owner" && actor_role != "admin" {
            return Err(ApiError::Forbidden);
        }
        let target_role = self
            .repo
            .get_member_role(org_id, target_user_id)
            .await
            .map_err(ApiError::InternalError)?
            .ok_or(ApiError::NotFound)?;
        if target_role == "owner" && actor_role != "owner" {
            return Err(ApiError::Forbidden);
        }
        if target_user_id == actor_id {
            let owners = self
                .repo
                .count_members_with_role(org_id, "owner")
                .await
                .map_err(ApiError::InternalError)?;
            if owners <= 1 {
                return Err(ApiError::InvalidRequest(
                    "Cannot remove yourself as the last owner".into(),
                ));
            }
        }
        self.repo
            .remove_member(org_id, target_user_id)
            .await
            .map_err(ApiError::InternalError)?;
        Ok(())
    }

    pub async fn ensure_user_in_org(&self, user_id: UserId, org_id: OrgId) -> Result<(), ApiError> {
        self.repo.ensure_user_in_org(user_id, org_id).await
    }

    pub async fn get_member_role(
        &self,
        org_id: OrgId,
        user_id: UserId,
    ) -> Result<Option<String>, ApiError> {
        self.repo
            .get_member_role(org_id, user_id)
            .await
            .map_err(ApiError::InternalError)
    }

    pub async fn ensure_workspace_access(
        &self,
        user_id: UserId,
        workspace_id: WorkspaceId,
    ) -> Result<(), ApiError> {
        self.repo
            .ensure_workspace_access(user_id, workspace_id)
            .await
    }

    pub async fn create_invite(
        &self,
        org_id: OrgId,
        inviter_id: UserId,
        email: &str,
        role: &str,
    ) -> Result<String, ApiError> {
        if role != "admin" && role != "member" {
            return Err(ApiError::InvalidRequest(
                "Role must be admin or member".into(),
            ));
        }
        self.repo.ensure_user_in_org(inviter_id, org_id).await?;
        let member_role = self
            .repo
            .get_member_role(org_id, inviter_id)
            .await
            .map_err(ApiError::InternalError)?
            .ok_or(ApiError::NotFound)?;
        if member_role != "owner" && member_role != "admin" {
            return Err(ApiError::Forbidden);
        }
        let token = generate_invite_token();
        let expires_at = Utc::now() + Duration::days(7);
        self.repo
            .create_invite(org_id, email, role, inviter_id, &token, expires_at)
            .await
            .map_err(ApiError::InternalError)?;
        Ok(token)
    }

    /// Ensures the user has at least one org. Creates a default "Personal" org if they have none.
    /// Idempotent: safe to call on every signup; only creates when user has zero orgs.
    pub async fn ensure_default_org(&self, user_id: UserId) -> Result<(), ApiError> {
        let orgs = self
            .repo
            .get_user_orgs(user_id, 1, 0)
            .await
            .map_err(ApiError::InternalError)?;
        if !orgs.is_empty() {
            return Ok(());
        }
        let slug = format!(
            "personal-{:08x}",
            (user_id.0.as_u128() & 0xFFFF_FFFF) as u32
        );
        self.repo
            .create_org(user_id, "Personal", &slug)
            .await
            .map_err(ApiError::InternalError)?;
        Ok(())
    }

    pub async fn accept_invite(&self, token: &str, user_id: UserId) -> Result<(), ApiError> {
        let invite = self
            .repo
            .find_invite_by_token(token)
            .await
            .map_err(ApiError::InternalError)?
            .ok_or(ApiError::InvalidRequest("Invalid or expired invite".into()))?;
        let user = self
            .user_repo
            .get_by_id(user_id)
            .await
            .map_err(ApiError::InternalError)?
            .ok_or(ApiError::NotFound)?;
        if !user.email.eq_ignore_ascii_case(&invite.email) {
            return Err(ApiError::InvalidRequest(
                "Invite email does not match your account".into(),
            ));
        }
        self.repo
            .add_member(invite.org_id, user_id, &invite.role)
            .await
            .map_err(ApiError::InternalError)?;
        self.repo
            .delete_invite(invite.id)
            .await
            .map_err(ApiError::InternalError)?;
        Ok(())
    }
}

fn slugify(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
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
