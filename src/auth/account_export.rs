//! Data export for GDPR right to portability.

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::auth::api_key_repository::ApiKeyRepository;
use crate::auth::repository::UserRepository;
use crate::billing::repository::BillingRepository;
use crate::common::{ApiError, UserId};
use crate::org::repository::OrgRepository;
use crate::AppState;

#[derive(Serialize)]
pub struct UserExport {
    pub id: String,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub google_sub: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Serialize)]
pub struct OrgMembershipExport {
    pub org_id: String,
    pub org_name: String,
    pub role: String,
}

#[derive(Serialize)]
pub struct ApiKeyExport {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    pub permissions: Vec<String>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
pub struct SubscriptionExport {
    pub org_id: Option<String>,
    pub plan_name: Option<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_period_end: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
pub struct SubscriptionTransactionExport {
    pub id: String,
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount_cents: Option<i64>,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct CreditTransactionExport {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    pub amount_tokens: i64,
    pub amount_cents: i64,
    pub kind: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct AccountExport {
    pub user: UserExport,
    pub org_memberships: Vec<OrgMembershipExport>,
    pub api_keys: Vec<ApiKeyExport>,
    pub subscriptions: Vec<SubscriptionExport>,
    pub subscription_transactions: Vec<SubscriptionTransactionExport>,
    pub user_credits: Option<i64>,
    pub credit_transactions: Vec<CreditTransactionExport>,
}

/// Export all user data for GDPR portability.
pub async fn export_account_data(state: &AppState, user_id: UserId) -> Result<AccountExport, ApiError> {
    let user_repo = UserRepository::new(state.db.pool.clone());
    let org_repo = OrgRepository::new(state.db.pool.clone());
    let billing_repo = BillingRepository::new(state.db.pool.clone());
    let api_key_repo = ApiKeyRepository::new(state.db.pool.clone());

    let user = user_repo
        .get_by_id(user_id)
        .await
        .map_err(ApiError::InternalError)?
        .ok_or(ApiError::NotFound)?;

    let org_memberships = {
        let orgs = org_repo
            .get_user_orgs(user_id, 1000, 0)
            .await
            .map_err(ApiError::InternalError)?;
        let mut out = Vec::new();
        for o in orgs {
            let role = org_repo
                .get_member_role(o.id, user_id)
                .await
                .ok()
                .flatten()
                .unwrap_or_else(|| "member".to_string());
            out.push(OrgMembershipExport {
                org_id: o.id.0.to_string(),
                org_name: o.name,
                role,
            });
        }
        out
    };

    let api_keys = api_key_repo
        .list_by_user_id(user_id, 1000, 0)
        .await
        .map_err(ApiError::InternalError)?
        .into_iter()
        .map(|k| ApiKeyExport {
            id: k.id.to_string(),
            name: k.name,
            org_id: k.org_id.map(|o| o.0.to_string()),
            workspace_id: k.workspace_id.map(|w| w.0.to_string()),
            permissions: k.permissions,
            created_at: k.created_at,
            last_used_at: k.last_used_at,
        })
        .collect();

    let (subscriptions, subscription_transactions) = {
        let subs = billing_repo
            .list_subscriptions_by_user(user_id)
            .await
            .map_err(ApiError::InternalError)?;
        let plan_ids: Vec<Uuid> = subs.iter().filter_map(|s| s.plan_id).collect();
        let plans = if plan_ids.is_empty() {
            vec![]
        } else {
            billing_repo.list_subscription_plans().await.map_err(ApiError::InternalError)?
        };
        let plan_map: std::collections::HashMap<Uuid, String> = plans
            .into_iter()
            .map(|p| (p.id, p.name))
            .collect();

        let sub_exports: Vec<SubscriptionExport> = subs
            .iter()
            .map(|s| SubscriptionExport {
                org_id: s.org_id.map(|o| o.0.to_string()),
                plan_name: s.plan_id.and_then(|id| plan_map.get(&id).cloned()),
                status: s.status.clone(),
                current_period_end: s.current_period_end,
            })
            .collect();

        let txns = billing_repo
            .list_subscription_transactions(user_id, 1000, 0)
            .await
            .map_err(ApiError::InternalError)?;
        let tx_exports: Vec<SubscriptionTransactionExport> = txns
            .into_iter()
            .map(|t| SubscriptionTransactionExport {
                id: t.id.to_string(),
                event_type: t.event_type,
                amount_cents: t.amount_cents,
                occurred_at: t.occurred_at,
            })
            .collect();

        (sub_exports, tx_exports)
    };

    let user_credits = billing_repo
        .get_user_credits(user_id)
        .await
        .map_err(ApiError::InternalError)?
        .map(|uc| uc.balance);

    let credit_transactions = billing_repo
        .list_credit_transactions(user_id, 1000, 0)
        .await
        .map_err(ApiError::InternalError)?
        .into_iter()
        .map(|c| CreditTransactionExport {
            id: c.id.to_string(),
            org_id: c.org_id.map(|o| o.0.to_string()),
            amount_tokens: c.amount_tokens,
            amount_cents: c.amount_cents,
            kind: c.kind,
            created_at: c.created_at,
        })
        .collect();

    Ok(AccountExport {
        user: UserExport {
            id: user.id.0.to_string(),
            email: user.email,
            google_sub: user.google_sub,
            created_at: user.created_at,
        },
        org_memberships,
        api_keys,
        subscriptions,
        subscription_transactions,
        user_credits,
        credit_transactions,
    })
}
