//! Feature flag service: check and manage global and per-org flags.

use crate::common::OrgId;
use crate::feature_flags::repository::FeatureFlagRepository;

#[derive(Clone)]
pub struct FeatureFlagService {
    repo: FeatureFlagRepository,
}

impl FeatureFlagService {
    pub fn new(repo: FeatureFlagRepository) -> Self {
        Self { repo }
    }

    /// Returns true if the flag is enabled. Global first; org overrides when present.
    pub async fn is_enabled(
        &self,
        name: &str,
        org_id: Option<OrgId>,
    ) -> Result<bool, sqlx::Error> {
        let global = self.repo.get_global(name).await?;
        let org_value = match org_id {
            Some(oid) => self.repo.get_for_org(name, oid).await?,
            None => None,
        };
        // Org override wins over global; if no org override, use global; default false
        Ok(org_value.or(global).unwrap_or(false))
    }

    pub async fn set_global(&self, name: &str, enabled: bool) -> Result<(), sqlx::Error> {
        self.repo.upsert_global(name, enabled).await
    }

    pub async fn set_for_org(
        &self,
        name: &str,
        org_id: OrgId,
        enabled: bool,
    ) -> Result<(), sqlx::Error> {
        self.repo.upsert_for_org(name, org_id, enabled).await
    }

    pub async fn list_all(&self) -> Result<Vec<(String, Option<OrgId>, bool)>, sqlx::Error> {
        let rows = self.repo.list_all().await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.name,
                    r.org_id.map(|u| OrgId(u)),
                    r.enabled,
                )
            })
            .collect())
    }

    pub async fn list_effective_for_org(
        &self,
        org_id: OrgId,
    ) -> Result<Vec<(String, bool)>, sqlx::Error> {
        self.repo.list_effective_for_org(org_id).await
    }
}
