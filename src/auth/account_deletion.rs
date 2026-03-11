//! Account deletion (GDPR right to erasure): permanent removal of user data.
use tracing::warn;

use crate::auth::repository::{
    EmailCodeRepository, UserRepository,
};
use crate::billing::repository::BillingRepository;
use crate::common::{ApiError, UserId};
use crate::org::repository::OrgRepository;
use crate::AppState;

/// Permanently delete user and all associated data (GDPR erasure).
/// Order: Stripe customer -> R2 storage -> email_login_codes -> org_invites -> anonymize billing -> delete user (CASCADE).
pub async fn delete_account_permanently(state: &AppState, user_id: UserId) -> Result<(), ApiError> {
    let user_repo = UserRepository::new(state.db.pool.clone());
    let user = user_repo
        .get_by_id_including_deleted(user_id)
        .await
        .map_err(ApiError::InternalError)?
        .ok_or_else(|| ApiError::NotFound)?;

    let email = user.email.clone();

    // 1. Delete Stripe customer (cancels subscriptions)
    if let Some(ref cid) = user.stripe_customer_id {
        if let Some(ref billing) = state.billing_service {
            if let Err(e) = billing.delete_stripe_customer(cid).await {
                warn!(stripe_customer_id = %cid, "Failed to delete Stripe customer during account deletion: {:?}", e);
                // Continue with local deletion; Stripe may need manual cleanup
            }
        }
    }

    // 2. Delete R2 objects for orgs/workspaces the user belonged to
    if let Some(ref storage) = state.storage_service {
        let org_repo = OrgRepository::new(state.db.pool.clone());
        let orgs = org_repo.get_user_orgs(user_id, 1000, 0).await.map_err(ApiError::InternalError)?;
        for org in orgs {
            let prefix = format!("{}/", org.id.0);
            if let Err(e) = storage.delete_prefix(&prefix).await {
                warn!(prefix = %prefix, "Failed to delete R2 prefix during account deletion: {:?}", e);
            }
        }
    }

    // 3. Delete email_login_codes by email (no FK to user)
    let email_code_repo = EmailCodeRepository::new(state.db.pool.clone());
    email_code_repo
        .delete_by_email(&email)
        .await
        .map_err(ApiError::InternalError)?;

    // 4. Delete org_invites where email = user email
    let org_repo = OrgRepository::new(state.db.pool.clone());
    org_repo
        .delete_invites_by_email(&email)
        .await
        .map_err(ApiError::InternalError)?;

    // 5. Anonymize billing_email in subscription_transactions (must be before user delete)
    let billing_repo = BillingRepository::new(state.db.pool.clone());
    billing_repo
        .anonymize_billing_email_for_user(user_id)
        .await
        .map_err(ApiError::InternalError)?;

    // 6. Hard delete user (CASCADE handles: password_reset_tokens, user_roles, api_keys, api_key_usage_log,
    //    org_members, workspace_members, subscriptions, subscription_transactions, user_credits, credit_transactions, org_invites by invited_by)
    user_repo
        .delete_permanently(user_id)
        .await
        .map_err(ApiError::InternalError)?;

    Ok(())
}
