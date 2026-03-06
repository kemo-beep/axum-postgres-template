//! Billing repository: subscription plans, subscriptions, token packages, transactions.

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::common::{OrgId, UserId};

/// Subscription plan synced from Stripe. Maps from `subscription_plans` table.
#[derive(Clone, Debug, serde::Serialize)]
pub struct SubscriptionPlan {
    pub id: Uuid,
    pub stripe_product_id: String,
    pub stripe_price_id: String,
    pub name: String,
    pub interval: String,
    pub amount_cents: i64,
    pub currency: String,
    pub features: serde_json::Value,
    pub active: bool,
}

/// Active or past subscription. Maps from `subscriptions` table.
#[derive(Clone, Debug)]
pub struct Subscription {
    pub id: Uuid,
    pub user_id: UserId,
    pub org_id: Option<OrgId>,
    pub stripe_customer_id: String,
    pub stripe_subscription_id: String,
    pub plan_id: Option<Uuid>,
    pub status: String,
    pub current_period_start: Option<DateTime<Utc>>,
    pub current_period_end: Option<DateTime<Utc>>,
    pub cancel_at_period_end: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct SubscriptionTransaction {
    pub id: Uuid,
    pub user_id: UserId,
    pub org_id: Option<OrgId>,
    pub subscription_id: Uuid,
    pub event_type: String,
    pub stripe_invoice_id: Option<String>,
    pub amount_cents: Option<i64>,
    pub currency: Option<String>,
    pub receipt_url: Option<String>,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct TokenPackage {
    pub id: Uuid,
    pub stripe_product_id: String,
    pub stripe_price_id: String,
    pub name: String,
    pub tokens: i64,
    pub amount_cents: i64,
    pub currency: String,
    pub active: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct CreditTransaction {
    pub id: Uuid,
    pub user_id: UserId,
    pub org_id: Option<OrgId>,
    pub package_id: Option<Uuid>,
    pub amount_tokens: i64,
    pub amount_cents: i64,
    pub currency: String,
    pub kind: String,
    pub receipt_url: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Database access for plans, subscriptions, packages, and transactions.
#[derive(Clone)]
pub struct BillingRepository {
    pool: PgPool,
}

impl BillingRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn list_subscription_plans(&self) -> Result<Vec<SubscriptionPlan>> {
        let rows = sqlx::query(
            "SELECT id, stripe_product_id, stripe_price_id, name, interval, amount_cents, currency, features, active
             FROM subscription_plans WHERE active = true ORDER BY amount_cents",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r: sqlx::postgres::PgRow| SubscriptionPlan {
                id: r.get("id"),
                stripe_product_id: r.get("stripe_product_id"),
                stripe_price_id: r.get("stripe_price_id"),
                name: r.get("name"),
                interval: r.get("interval"),
                amount_cents: r.get("amount_cents"),
                currency: r.get("currency"),
                features: r.get("features"),
                active: r.get("active"),
            })
            .collect())
    }

    pub async fn list_token_packages(&self) -> Result<Vec<TokenPackage>> {
        let rows = sqlx::query(
            "SELECT id, stripe_product_id, stripe_price_id, name, tokens, amount_cents, currency, active
             FROM token_packages WHERE active = true ORDER BY amount_cents",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r: sqlx::postgres::PgRow| TokenPackage {
                id: r.get("id"),
                stripe_product_id: r.get("stripe_product_id"),
                stripe_price_id: r.get("stripe_price_id"),
                name: r.get("name"),
                tokens: r.get("tokens"),
                amount_cents: r.get("amount_cents"),
                currency: r.get("currency"),
                active: r.get("active"),
            })
            .collect())
    }

    pub async fn get_plan_by_stripe_price_id(
        &self,
        stripe_price_id: &str,
    ) -> Result<Option<SubscriptionPlan>> {
        let row = sqlx::query(
            "SELECT id, stripe_product_id, stripe_price_id, name, interval, amount_cents, currency, features, active
             FROM subscription_plans WHERE stripe_price_id = $1 AND active = true",
        )
        .bind(stripe_price_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r: sqlx::postgres::PgRow| SubscriptionPlan {
            id: r.get("id"),
            stripe_product_id: r.get("stripe_product_id"),
            stripe_price_id: r.get("stripe_price_id"),
            name: r.get("name"),
            interval: r.get("interval"),
            amount_cents: r.get("amount_cents"),
            currency: r.get("currency"),
            features: r.get("features"),
            active: r.get("active"),
        }))
    }

    pub async fn get_package_by_stripe_price_id(
        &self,
        stripe_price_id: &str,
    ) -> Result<Option<TokenPackage>> {
        let row = sqlx::query(
            "SELECT id, stripe_product_id, stripe_price_id, name, tokens, amount_cents, currency, active
             FROM token_packages WHERE stripe_price_id = $1 AND active = true",
        )
        .bind(stripe_price_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r: sqlx::postgres::PgRow| TokenPackage {
            id: r.get("id"),
            stripe_product_id: r.get("stripe_product_id"),
            stripe_price_id: r.get("stripe_price_id"),
            name: r.get("name"),
            tokens: r.get("tokens"),
            amount_cents: r.get("amount_cents"),
            currency: r.get("currency"),
            active: r.get("active"),
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_subscription(
        &self,
        user_id: UserId,
        org_id: OrgId,
        stripe_customer_id: &str,
        stripe_subscription_id: &str,
        plan_id: Option<Uuid>,
        status: &str,
        current_period_start: Option<DateTime<Utc>>,
        current_period_end: Option<DateTime<Utc>>,
    ) -> Result<Subscription> {
        let id = Uuid::now_v7();
        let now = Utc::now();
        let row = sqlx::query(
            r#"
            INSERT INTO subscriptions (id, user_id, org_id, stripe_customer_id, stripe_subscription_id, plan_id, status,
                current_period_start, current_period_end, cancel_at_period_end, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, false, $10, $10)
            RETURNING id, user_id, org_id, stripe_customer_id, stripe_subscription_id, plan_id, status,
                current_period_start, current_period_end, cancel_at_period_end
            "#,
        )
        .bind(id)
        .bind(user_id.0)
        .bind(org_id.0)
        .bind(stripe_customer_id)
        .bind(stripe_subscription_id)
        .bind(plan_id)
        .bind(status)
        .bind(current_period_start)
        .bind(current_period_end)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(Subscription {
            id: row.get("id"),
            user_id: UserId(row.get("user_id")),
            org_id: row.get::<Option<Uuid>, _>("org_id").map(OrgId::from_uuid),
            stripe_customer_id: row.get("stripe_customer_id"),
            stripe_subscription_id: row.get("stripe_subscription_id"),
            plan_id: row.get("plan_id"),
            status: row.get("status"),
            current_period_start: row.get("current_period_start"),
            current_period_end: row.get("current_period_end"),
            cancel_at_period_end: row.get("cancel_at_period_end"),
        })
    }

    pub async fn get_subscription_by_org(&self, org_id: OrgId) -> Result<Option<Subscription>> {
        let row = sqlx::query(
            "SELECT id, user_id, org_id, stripe_customer_id, stripe_subscription_id, plan_id, status,
                    current_period_start, current_period_end, cancel_at_period_end
             FROM subscriptions WHERE org_id = $1 AND status IN ('active', 'trialing', 'past_due', 'unpaid') ORDER BY created_at DESC LIMIT 1",
        )
        .bind(org_id.0)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r: sqlx::postgres::PgRow| Subscription {
            id: r.get("id"),
            user_id: UserId(r.get("user_id")),
            org_id: r.get::<Option<Uuid>, _>("org_id").map(OrgId::from_uuid),
            stripe_customer_id: r.get("stripe_customer_id"),
            stripe_subscription_id: r.get("stripe_subscription_id"),
            plan_id: r.get("plan_id"),
            status: r.get("status"),
            current_period_start: r.get("current_period_start"),
            current_period_end: r.get("current_period_end"),
            cancel_at_period_end: r.get("cancel_at_period_end"),
        }))
    }

    pub async fn update_subscription_plan(
        &self,
        stripe_subscription_id: &str,
        plan_id: Uuid,
    ) -> Result<()> {
        let now = Utc::now();
        sqlx::query(
            "UPDATE subscriptions SET plan_id = $1, updated_at = $2 WHERE stripe_subscription_id = $3",
        )
        .bind(plan_id)
        .bind(now)
        .bind(stripe_subscription_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_subscription_by_stripe_id(
        &self,
        stripe_subscription_id: &str,
    ) -> Result<Option<Subscription>> {
        let row = sqlx::query(
            "SELECT id, user_id, org_id, stripe_customer_id, stripe_subscription_id, plan_id, status,
                    current_period_start, current_period_end, cancel_at_period_end
             FROM subscriptions WHERE stripe_subscription_id = $1",
        )
        .bind(stripe_subscription_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r: sqlx::postgres::PgRow| Subscription {
            id: r.get("id"),
            user_id: UserId(r.get("user_id")),
            org_id: r.get::<Option<Uuid>, _>("org_id").map(OrgId::from_uuid),
            stripe_customer_id: r.get("stripe_customer_id"),
            stripe_subscription_id: r.get("stripe_subscription_id"),
            plan_id: r.get("plan_id"),
            status: r.get("status"),
            current_period_start: r.get("current_period_start"),
            current_period_end: r.get("current_period_end"),
            cancel_at_period_end: r.get("cancel_at_period_end"),
        }))
    }

    pub async fn update_subscription_status(
        &self,
        stripe_subscription_id: &str,
        status: &str,
        current_period_start: Option<DateTime<Utc>>,
        current_period_end: Option<DateTime<Utc>>,
        cancel_at_period_end: bool,
    ) -> Result<()> {
        let now = Utc::now();
        sqlx::query(
            "UPDATE subscriptions SET status = $1, current_period_start = $2, current_period_end = $3,
             cancel_at_period_end = $4, updated_at = $5 WHERE stripe_subscription_id = $6",
        )
        .bind(status)
        .bind(current_period_start)
        .bind(current_period_end)
        .bind(cancel_at_period_end)
        .bind(now)
        .bind(stripe_subscription_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn add_subscription_transaction(
        &self,
        user_id: UserId,
        org_id: Option<OrgId>,
        subscription_id: Uuid,
        event_type: &str,
        stripe_invoice_id: Option<&str>,
        amount_cents: Option<i64>,
        currency: Option<&str>,
        receipt_url: Option<&str>,
    ) -> Result<Uuid> {
        let id = Uuid::now_v7();
        let now = Utc::now();
        sqlx::query(
            "INSERT INTO subscription_transactions (id, user_id, org_id, subscription_id, event_type, stripe_invoice_id,
             amount_cents, currency, receipt_url, occurred_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(id)
        .bind(user_id.0)
        .bind(org_id.map(|o| o.0))
        .bind(subscription_id)
        .bind(event_type)
        .bind(stripe_invoice_id)
        .bind(amount_cents)
        .bind(currency)
        .bind(receipt_url)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn add_credit_transaction(
        &self,
        user_id: UserId,
        org_id: OrgId,
        package_id: Option<Uuid>,
        amount_tokens: i64,
        amount_cents: i64,
        currency: &str,
        kind: &str,
        stripe_payment_intent_id: Option<&str>,
        stripe_charge_id: Option<&str>,
        receipt_url: Option<&str>,
    ) -> Result<Uuid> {
        let id = Uuid::now_v7();
        let now = Utc::now();
        sqlx::query(
            "INSERT INTO credit_transactions (id, user_id, org_id, package_id, amount_tokens, amount_cents, currency, kind,
             stripe_payment_intent_id, stripe_charge_id, receipt_url, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"
        )
        .bind(id)
        .bind(user_id.0)
        .bind(org_id.0)
        .bind(package_id)
        .bind(amount_tokens)
        .bind(amount_cents)
        .bind(currency)
        .bind(kind)
        .bind(stripe_payment_intent_id)
        .bind(stripe_charge_id)
        .bind(receipt_url)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn upsert_user_credits(&self, user_id: UserId, delta: i64) -> Result<()> {
        let now = Utc::now();
        sqlx::query(
            r#"
            INSERT INTO user_credits (user_id, balance, updated_at) VALUES ($1, $2, $3)
            ON CONFLICT (user_id) DO UPDATE SET balance = user_credits.balance + $2, updated_at = $3
            "#,
        )
        .bind(user_id.0)
        .bind(delta)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn upsert_org_credits(&self, org_id: OrgId, delta: i64) -> Result<()> {
        let now = Utc::now();
        sqlx::query(
            r#"
            INSERT INTO org_credits (org_id, balance, updated_at) VALUES ($1, $2, $3)
            ON CONFLICT (org_id) DO UPDATE SET balance = org_credits.balance + $2, updated_at = $3
            "#,
        )
        .bind(org_id.0)
        .bind(delta)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_subscription_transactions(
        &self,
        user_id: UserId,
    ) -> Result<Vec<SubscriptionTransaction>> {
        let rows = sqlx::query(
            "SELECT id, user_id, org_id, subscription_id, event_type, stripe_invoice_id, amount_cents, currency, receipt_url, occurred_at
             FROM subscription_transactions WHERE user_id = $1 ORDER BY occurred_at DESC",
        )
        .bind(user_id.0)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r: sqlx::postgres::PgRow| SubscriptionTransaction {
                id: r.get("id"),
                user_id: UserId(r.get("user_id")),
                org_id: r.get::<Option<Uuid>, _>("org_id").map(OrgId::from_uuid),
                subscription_id: r.get("subscription_id"),
                event_type: r.get("event_type"),
                stripe_invoice_id: r.get("stripe_invoice_id"),
                amount_cents: r.get("amount_cents"),
                currency: r.get("currency"),
                receipt_url: r.get("receipt_url"),
                occurred_at: r.get("occurred_at"),
            })
            .collect())
    }

    pub async fn list_subscription_transactions_by_org(
        &self,
        org_id: OrgId,
    ) -> Result<Vec<SubscriptionTransaction>> {
        let rows = sqlx::query(
            "SELECT id, user_id, org_id, subscription_id, event_type, stripe_invoice_id, amount_cents, currency, receipt_url, occurred_at
             FROM subscription_transactions WHERE org_id = $1 ORDER BY occurred_at DESC",
        )
        .bind(org_id.0)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r: sqlx::postgres::PgRow| SubscriptionTransaction {
                id: r.get("id"),
                user_id: UserId(r.get("user_id")),
                org_id: r.get::<Option<Uuid>, _>("org_id").map(OrgId::from_uuid),
                subscription_id: r.get("subscription_id"),
                event_type: r.get("event_type"),
                stripe_invoice_id: r.get("stripe_invoice_id"),
                amount_cents: r.get("amount_cents"),
                currency: r.get("currency"),
                receipt_url: r.get("receipt_url"),
                occurred_at: r.get("occurred_at"),
            })
            .collect())
    }

    pub async fn list_credit_transactions(
        &self,
        user_id: UserId,
    ) -> Result<Vec<CreditTransaction>> {
        let rows = sqlx::query(
            "SELECT id, user_id, org_id, package_id, amount_tokens, amount_cents, currency, kind, receipt_url, created_at
             FROM credit_transactions WHERE user_id = $1 ORDER BY created_at DESC",
        )
        .bind(user_id.0)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r: sqlx::postgres::PgRow| CreditTransaction {
                id: r.get("id"),
                user_id: UserId(r.get("user_id")),
                org_id: r.get::<Option<Uuid>, _>("org_id").map(OrgId::from_uuid),
                package_id: r.get("package_id"),
                amount_tokens: r.get("amount_tokens"),
                amount_cents: r.get("amount_cents"),
                currency: r.get("currency"),
                kind: r.get("kind"),
                receipt_url: r.get("receipt_url"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    pub async fn list_credit_transactions_by_org(
        &self,
        org_id: OrgId,
    ) -> Result<Vec<CreditTransaction>> {
        let rows = sqlx::query(
            "SELECT id, user_id, org_id, package_id, amount_tokens, amount_cents, currency, kind, receipt_url, created_at
             FROM credit_transactions WHERE org_id = $1 ORDER BY created_at DESC",
        )
        .bind(org_id.0)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r: sqlx::postgres::PgRow| CreditTransaction {
                id: r.get("id"),
                user_id: UserId(r.get("user_id")),
                org_id: r.get::<Option<Uuid>, _>("org_id").map(OrgId::from_uuid),
                package_id: r.get("package_id"),
                amount_tokens: r.get("amount_tokens"),
                amount_cents: r.get("amount_cents"),
                currency: r.get("currency"),
                kind: r.get("kind"),
                receipt_url: r.get("receipt_url"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_subscription_plan(
        &self,
        stripe_product_id: &str,
        stripe_price_id: &str,
        name: &str,
        interval: &str,
        amount_cents: i64,
        currency: &str,
        features: &serde_json::Value,
        active: bool,
    ) -> Result<Uuid> {
        let id = Uuid::now_v7();
        let now = Utc::now();
        let row = sqlx::query(
            r#"
            INSERT INTO subscription_plans (id, stripe_product_id, stripe_price_id, name, interval, amount_cents, currency, features, active, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)
            ON CONFLICT (stripe_price_id) DO UPDATE SET
                stripe_product_id = $2, name = $4, interval = $5, amount_cents = $6, currency = $7, features = $8, active = $9, updated_at = $10
            RETURNING id
            "#,
        )
        .bind(id)
        .bind(stripe_product_id)
        .bind(stripe_price_id)
        .bind(name)
        .bind(interval)
        .bind(amount_cents)
        .bind(currency)
        .bind(features)
        .bind(active)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get("id"))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_token_package(
        &self,
        stripe_product_id: &str,
        stripe_price_id: &str,
        name: &str,
        tokens: i64,
        amount_cents: i64,
        currency: &str,
        active: bool,
    ) -> Result<Uuid> {
        let id = Uuid::now_v7();
        let now = Utc::now();
        let row = sqlx::query(
            r#"
            INSERT INTO token_packages (id, stripe_product_id, stripe_price_id, name, tokens, amount_cents, currency, active, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)
            ON CONFLICT (stripe_price_id) DO UPDATE SET
                stripe_product_id = $2, name = $4, tokens = $5, amount_cents = $6, currency = $7, active = $8, updated_at = $9
            RETURNING id
            "#,
        )
        .bind(id)
        .bind(stripe_product_id)
        .bind(stripe_price_id)
        .bind(name)
        .bind(tokens)
        .bind(amount_cents)
        .bind(currency)
        .bind(active)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get("id"))
    }

    pub async fn delete_subscription_plan_by_price_id(&self, stripe_price_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM subscription_plans WHERE stripe_price_id = $1")
            .bind(stripe_price_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete_token_package_by_price_id(&self, stripe_price_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM token_packages WHERE stripe_price_id = $1")
            .bind(stripe_price_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn deactivate_subscription_plan_by_price_id(
        &self,
        stripe_price_id: &str,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE subscription_plans SET active = false, updated_at = now() WHERE stripe_price_id = $1",
        )
        .bind(stripe_price_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn deactivate_token_package_by_price_id(
        &self,
        stripe_price_id: &str,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE token_packages SET active = false, updated_at = now() WHERE stripe_price_id = $1",
        )
        .bind(stripe_price_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn deactivate_subscription_plans_by_product_id(
        &self,
        stripe_product_id: &str,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE subscription_plans SET active = false, updated_at = now() WHERE stripe_product_id = $1",
        )
        .bind(stripe_product_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn deactivate_token_packages_by_product_id(
        &self,
        stripe_product_id: &str,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE token_packages SET active = false, updated_at = now() WHERE stripe_product_id = $1",
        )
        .bind(stripe_product_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_subscription_plans_by_product_id(
        &self,
        stripe_product_id: &str,
        name: &str,
        features: &serde_json::Value,
        active: bool,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE subscription_plans SET name = $2, features = $3, active = $4, updated_at = now() WHERE stripe_product_id = $1",
        )
        .bind(stripe_product_id)
        .bind(name)
        .bind(features)
        .bind(active)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_token_packages_by_product_id(
        &self,
        stripe_product_id: &str,
        name: &str,
        tokens: Option<i64>,
        active: bool,
    ) -> Result<()> {
        if let Some(t) = tokens {
            sqlx::query(
                "UPDATE token_packages SET name = $2, tokens = $3, active = $4, updated_at = now() WHERE stripe_product_id = $1",
            )
            .bind(stripe_product_id)
            .bind(name)
            .bind(t)
            .bind(active)
            .execute(&self.pool)
            .await?;
        } else {
            sqlx::query(
                "UPDATE token_packages SET name = $2, active = $3, updated_at = now() WHERE stripe_product_id = $1",
            )
            .bind(stripe_product_id)
            .bind(name)
            .bind(active)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }
}
