//! Billing service: Stripe Checkout, Customer Portal, webhook processing,
//! subscription cancel/upgrade/downgrade, grace period and dunning.

use std::time::Duration;

use anyhow::Result;
use chrono::TimeZone;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use stripe::{
    CancelSubscription, CheckoutSession, CheckoutSessionMode, Client, CreateBillingPortalSession,
    CreateCheckoutSession, CreateCheckoutSessionLineItems, CreateCheckoutSessionSubscriptionData,
    CreateCustomer, Customer, IdOrCreate, ListPrices, Price, PriceId, Product, Subscription,
    SubscriptionId, UpdateSubscription, UpdateSubscriptionItems,
};
use stripe::RetrieveCheckoutSessionLineItems;
use subtle::ConstantTimeEq;
use tracing::{info, warn};

use std::sync::Arc;

use crate::auth::repository::UserRepository;
use crate::auth::EmailSender;
use crate::billing::repository::BillingRepository;
use crate::services::{JobQueue, ObservantJobQueue};
use crate::cfg::StripeConfig;
use crate::common::{ApiError, OrgId, UserId};
use crate::org::repository::OrgRepository;

type HmacSha256 = Hmac<Sha256>;

const STRIPE_TIMEOUT: Duration = Duration::from_secs(30);

async fn stripe_timeout<F, T>(future: F) -> Result<T, ApiError>
where
    F: std::future::Future<Output = Result<T, stripe::StripeError>>,
{
    tokio::time::timeout(STRIPE_TIMEOUT, future)
        .await
        .map_err(|_| ApiError::InternalError(anyhow::anyhow!("Stripe request timed out")))?
        .map_err(|e| ApiError::InternalError(anyhow::anyhow!("Stripe: {}", e)))
}

/// Stripe integration: Checkout, Portal, webhooks, subscription management.
#[derive(Clone)]
pub struct BillingService {
    stripe_client: Client,
    stripe_config: StripeConfig,
    billing_repo: BillingRepository,
    user_repo: UserRepository,
    org_repo: OrgRepository,
    email_sender: Arc<dyn EmailSender>,
    job_queue: Arc<ObservantJobQueue>,
    frontend_url: Option<String>,
}

impl BillingService {
    pub async fn list_plans(&self) -> Result<Vec<crate::billing::repository::SubscriptionPlan>> {
        self.billing_repo.list_subscription_plans().await
    }

    pub async fn list_packages(&self) -> Result<Vec<crate::billing::repository::TokenPackage>> {
        self.billing_repo.list_token_packages().await
    }

    /// Reconcile subscriptions that should be canceled (cancel_at_period_end + period ended).
    /// Call periodically (e.g. hourly) as a fallback when webhooks are missed.
    pub async fn reconcile_stale_cancel_at_period_end(&self) -> Result<u64> {
        self.billing_repo
            .reconcile_stale_cancel_at_period_end()
            .await
    }

    /// Send trial ending soon reminders for trialing subscriptions ending in 1-3 days.
    pub async fn send_trial_ending_reminders(&self) -> Result<u32> {
        use chrono::Datelike;
        let subs = self.billing_repo.list_trials_ending_soon(3).await?;
        let mut sent = 0u32;
        for (sub, plan_name) in subs {
            let user = match self.user_repo.get_by_id(sub.user_id).await.ok().flatten() {
                Some(u) => u,
                None => continue,
            };
            let trial_end = match sub.trial_end {
                Some(t) => t,
                None => continue,
            };
            let trial_end_str = format!(
                "{}-{:02}-{:02}",
                trial_end.year(),
                trial_end.month(),
                trial_end.day()
            );
            let billing_url = sub.org_id.and_then(|org_id| {
                self.frontend_url
                    .as_ref()
                    .map(|base| format!("{}/orgs/{}?tab=billing", base.trim_end_matches('/'), org_id.0))
            });
            if let Err(e) = self
                .email_sender
                .send_trial_ending_soon(
                    &user.email,
                    &plan_name,
                    &trial_end_str,
                    billing_url.as_deref(),
                )
                .await
            {
                tracing::warn!(sub = %sub.stripe_subscription_id, "Trial reminder email failed: {:?}", e);
            } else {
                sent += 1;
            }
        }
        Ok(sent)
    }

    /// Send past-due reminders for subscriptions with status past_due.
    pub async fn send_past_due_reminders(&self) -> Result<u32> {
        let subs = self.billing_repo.list_past_due_subscriptions().await?;
        let mut sent = 0u32;
        for sub in subs {
            let user = match self.user_repo.get_by_id(sub.user_id).await.ok().flatten() {
                Some(u) => u,
                None => continue,
            };
            let hosted_url = self
                .billing_repo
                .get_latest_payment_failed_invoice_url(sub.id)
                .await
                .ok()
                .flatten();
            let billing_url = sub.org_id.and_then(|org_id| {
                self.frontend_url
                    .as_ref()
                    .map(|base| format!("{}/orgs/{}?tab=billing", base.trim_end_matches('/'), org_id.0))
            });
            if let Err(e) = self
                .email_sender
                .send_past_due_reminder(
                    &user.email,
                    hosted_url.as_deref(),
                    billing_url.as_deref(),
                )
                .await
            {
                tracing::warn!(sub = %sub.stripe_subscription_id, "Past-due reminder email failed: {:?}", e);
            } else {
                sent += 1;
            }
        }
        Ok(sent)
    }

    /// Get the current user's subscription plan name (e.g. "Pro") if they have an active
    /// subscription in any of their orgs. Returns the highest-tier plan.
    pub async fn get_user_subscription_plan_name(
        &self,
        user_id: UserId,
    ) -> Result<Option<String>, ApiError> {
        self.billing_repo
            .get_user_active_plan_name(user_id)
            .await
            .map_err(ApiError::InternalError)
    }

    pub async fn list_transactions(
        &self,
        user_id: UserId,
        limit: i64,
        offset: i64,
    ) -> Result<(
        Vec<crate::billing::repository::SubscriptionTransaction>,
        Vec<crate::billing::repository::CreditTransaction>,
    )> {
        let sub = self
            .billing_repo
            .list_subscription_transactions(user_id, limit, offset)
            .await?;
        let credit = self
            .billing_repo
            .list_credit_transactions(user_id, limit, offset)
            .await?;
        Ok((sub, credit))
    }

    /// Get org's active subscription with plan details. Returns None when no subscription.
    pub async fn get_subscription_by_org(
        &self,
        org_id: OrgId,
    ) -> Result<
        Option<(
            crate::billing::repository::Subscription,
            Option<crate::billing::repository::SubscriptionPlan>,
        )>,
        ApiError,
    > {
        let sub = self
            .billing_repo
            .get_subscription_by_org(org_id)
            .await
            .map_err(ApiError::InternalError)?;
        let Some(sub) = sub else {
            return Ok(None);
        };
        let plan = match sub.plan_id {
            Some(plan_id) => self
                .billing_repo
                .get_plan_by_id(plan_id)
                .await
                .map_err(ApiError::InternalError)?,
            None => None,
        };
        Ok(Some((sub, plan)))
    }

    pub async fn list_transactions_by_org(
        &self,
        org_id: OrgId,
        limit: i64,
        offset: i64,
    ) -> Result<(
        Vec<crate::billing::repository::SubscriptionTransaction>,
        Vec<crate::billing::repository::CreditTransaction>,
    )> {
        let sub = self
            .billing_repo
            .list_subscription_transactions_by_org(org_id, limit, offset)
            .await?;
        let credit = self
            .billing_repo
            .list_credit_transactions_by_org(org_id, limit, offset)
            .await?;
        Ok((sub, credit))
    }

    pub fn new(
        stripe_config: StripeConfig,
        billing_repo: BillingRepository,
        user_repo: UserRepository,
        org_repo: OrgRepository,
        email_sender: Arc<dyn EmailSender>,
        job_queue: Arc<ObservantJobQueue>,
        frontend_url: Option<String>,
    ) -> Self {
        let stripe_client = Client::new(stripe_config.secret_key.clone());
        Self {
            stripe_client,
            stripe_config,
            billing_repo,
            user_repo,
            org_repo,
            email_sender,
            job_queue,
            frontend_url,
        }
    }

    /// Create a Checkout Session (subscription or payment mode). Returns the redirect URL.
    pub async fn create_checkout_session(
        &self,
        user_id: UserId,
        org_id: OrgId,
        mode: CheckoutSessionMode,
        price_id: &str,
        success_url: &str,
        cancel_url: &str,
    ) -> Result<String, ApiError> {
        let user = self
            .user_repo
            .get_by_id(user_id)
            .await
            .map_err(ApiError::InternalError)?
            .ok_or(ApiError::NotFound)?;

        // When mode is subscription, ensure the price is a recurring subscription price.
        if mode == CheckoutSessionMode::Subscription {
            let plan = self
                .billing_repo
                .get_plan_by_stripe_price_id(price_id)
                .await
                .map_err(ApiError::InternalError)?;
            if plan.is_none() {
                return Err(ApiError::InvalidRequest(
                    "Price must belong to a subscription plan".into(),
                ));
            }
            let price_id_parsed = price_id
                .parse::<PriceId>()
                .map_err(|_| ApiError::InvalidRequest("Invalid price id".into()))?;
            match stripe_timeout(Price::retrieve(&self.stripe_client, &price_id_parsed, &[])).await {
                Ok(price) => {
                    let is_recurring = price
                        .type_
                        .as_ref()
                        .map(|t| t.to_string().as_str() == "recurring")
                        .unwrap_or(false)
                        || price.recurring.is_some();
                    if !is_recurring {
                        return Err(ApiError::InvalidRequest(
                            "Subscription checkout requires a recurring price. \
                             This plan may be a one-time purchase—check your Stripe configuration."
                                .into(),
                        ));
                    }
                }
                Err(e) => {
                    return Err(ApiError::InternalError(anyhow::anyhow!(
                        "Stripe: failed to validate price: {}",
                        e
                    )))
                }
            }
        }

        let client_ref = user_id.0.to_string();
        let mut params = CreateCheckoutSession::new();
        params.mode = Some(mode);
        params.success_url = Some(success_url);
        params.cancel_url = Some(cancel_url);
        params.client_reference_id = Some(&client_ref);
        params.metadata = Some(std::collections::HashMap::from([
            ("user_id".to_string(), user_id.0.to_string()),
            ("org_id".to_string(), org_id.0.to_string()),
        ]));
        params.line_items = Some(vec![CreateCheckoutSessionLineItems {
            price: Some(price_id.to_string()),
            quantity: Some(1),
            ..Default::default()
        }]);

        if mode == CheckoutSessionMode::Subscription {
            let mut sub_data = CreateCheckoutSessionSubscriptionData {
                trial_period_days: Some(3),
                ..Default::default()
            };
            sub_data.metadata = Some(std::collections::HashMap::from([
                ("user_id".to_string(), user_id.0.to_string()),
                ("org_id".to_string(), org_id.0.to_string()),
            ]));
            params.subscription_data = Some(sub_data);
        }

        let customer_id = if let Some(ref cid) = user.stripe_customer_id {
            Some(
                cid.parse::<stripe::CustomerId>()
                    .map_err(|e| ApiError::InternalError(anyhow::anyhow!("{}", e)))?,
            )
        } else {
            let customer = stripe_timeout(Customer::create(
                &self.stripe_client,
                CreateCustomer {
                    email: Some(&user.email),
                    metadata: Some(std::collections::HashMap::from([(
                        "user_id".to_string(),
                        user_id.0.to_string(),
                    )])),
                    ..Default::default()
                },
            ))
            .await?;

            self.user_repo
                .update_stripe_customer_id(user_id, customer.id.as_str())
                .await
                .map_err(ApiError::InternalError)?;

            Some(customer.id)
        };

        params.customer = Some(customer_id.unwrap());

        let session = stripe_timeout(CheckoutSession::create(&self.stripe_client, params)).await?;

        session
            .url
            .ok_or_else(|| ApiError::InternalError(anyhow::anyhow!("No checkout URL returned")))
    }

    /// Create a Stripe Customer Portal session. Returns the redirect URL.
    pub async fn create_portal_session(
        &self,
        user_id: UserId,
        return_url: &str,
    ) -> Result<String, ApiError> {
        let user = self
            .user_repo
            .get_by_id(user_id)
            .await
            .map_err(ApiError::InternalError)?
            .ok_or(ApiError::NotFound)?;

        let customer_id = user
            .stripe_customer_id
            .as_deref()
            .ok_or_else(|| ApiError::InvalidRequest("No Stripe customer linked".into()))?;

        let customer = customer_id
            .parse::<stripe::CustomerId>()
            .map_err(|e| ApiError::InternalError(anyhow::anyhow!("{}", e)))?;
        let mut params = CreateBillingPortalSession::new(customer);
        params.return_url = Some(return_url);

        let session =
            stripe_timeout(stripe::BillingPortalSession::create(&self.stripe_client, params))
                .await?;

        Ok(session.url.to_string())
    }

    /// Delete a Stripe customer (GDPR erasure). Cancels active subscriptions. Use with caution.
    pub async fn delete_stripe_customer(&self, customer_id: &str) -> Result<(), ApiError> {
        let cid = customer_id
            .parse::<stripe::CustomerId>()
            .map_err(|e| ApiError::InternalError(anyhow::anyhow!("{}", e)))?;
        stripe_timeout(Customer::delete(&self.stripe_client, &cid)).await?;
        Ok(())
    }

    /// Cancel subscription at period end (customer keeps access until current_period_end).
    pub async fn cancel_subscription_at_period_end(
        &self,
        user_id: UserId,
        org_id: OrgId,
    ) -> Result<(), ApiError> {
        let sub = self
            .billing_repo
            .get_subscription_by_org(org_id)
            .await
            .map_err(ApiError::InternalError)?
            .ok_or_else(|| ApiError::NotFound)?;

        if sub.user_id != user_id {
            return Err(ApiError::Forbidden);
        }

        if !matches!(sub.status.as_str(), "active" | "trialing") {
            return Err(ApiError::InvalidRequest(
                "Subscription is not active or trialing".into(),
            ));
        }

        if sub.cancel_at_period_end {
            return Err(ApiError::InvalidRequest(
                "Subscription is already set to cancel at period end".into(),
            ));
        }

        let sub_id = sub
            .stripe_subscription_id
            .parse::<SubscriptionId>()
            .map_err(|e| ApiError::InternalError(anyhow::anyhow!("{}", e)))?;

        let params = UpdateSubscription {
            cancel_at_period_end: Some(true),
            ..Default::default()
        };

        stripe_timeout(Subscription::update(&self.stripe_client, &sub_id, params)).await?;

        Ok(())
    }

    /// Cancel subscription immediately.
    pub async fn cancel_subscription_immediately(
        &self,
        user_id: UserId,
        org_id: OrgId,
    ) -> Result<(), ApiError> {
        let sub = self
            .billing_repo
            .get_subscription_by_org(org_id)
            .await
            .map_err(ApiError::InternalError)?
            .ok_or_else(|| ApiError::NotFound)?;

        if sub.user_id != user_id {
            return Err(ApiError::Forbidden);
        }

        if !matches!(sub.status.as_str(), "active" | "trialing" | "past_due") {
            return Err(ApiError::InvalidRequest(
                "Subscription cannot be canceled in its current state".into(),
            ));
        }

        let sub_id = sub
            .stripe_subscription_id
            .parse::<SubscriptionId>()
            .map_err(|e| ApiError::InternalError(anyhow::anyhow!("{}", e)))?;

        let params = CancelSubscription::default();
        stripe_timeout(Subscription::cancel(&self.stripe_client, &sub_id, params)).await?;

        Ok(())
    }

    /// Change subscription plan (upgrade or downgrade). Stripe prorates automatically.
    pub async fn change_subscription_plan(
        &self,
        user_id: UserId,
        org_id: OrgId,
        new_price_id: &str,
    ) -> Result<(), ApiError> {
        let sub = self
            .billing_repo
            .get_subscription_by_org(org_id)
            .await
            .map_err(ApiError::InternalError)?
            .ok_or_else(|| ApiError::NotFound)?;

        if sub.user_id != user_id {
            return Err(ApiError::Forbidden);
        }

        if !matches!(sub.status.as_str(), "active" | "trialing") {
            return Err(ApiError::InvalidRequest(
                "Subscription must be active or trialing to change plan".into(),
            ));
        }

        let plan = self
            .billing_repo
            .get_plan_by_stripe_price_id(new_price_id)
            .await
            .map_err(ApiError::InternalError)?
            .ok_or_else(|| ApiError::InvalidRequest("Invalid price or plan".into()))?;

        let sub_id = sub
            .stripe_subscription_id
            .parse::<SubscriptionId>()
            .map_err(|e| ApiError::InternalError(anyhow::anyhow!("{}", e)))?;

        let stripe_sub =
            stripe_timeout(Subscription::retrieve(&self.stripe_client, &sub_id, &[])).await?;

        let subscription_item_id = stripe_sub
            .items
            .data
            .first()
            .map(|i| i.id.as_str())
            .ok_or_else(|| {
                ApiError::InternalError(anyhow::anyhow!("No subscription item found"))
            })?;

        let item = UpdateSubscriptionItems {
            id: Some(subscription_item_id.to_string()),
            price: Some(new_price_id.to_string()),
            ..Default::default()
        };

        // Stripe defaults to create_prorations; proration applies on plan change.
        let params = UpdateSubscription {
            items: Some(vec![item]),
            ..Default::default()
        };

        stripe_timeout(Subscription::update(&self.stripe_client, &sub_id, params)).await?;

        self.billing_repo
            .update_subscription_plan(&sub.stripe_subscription_id, plan.id)
            .await
            .map_err(ApiError::InternalError)?;

        Ok(())
    }

    /// Verify Stripe webhook signature and return the raw event payload (already parsed).
    pub fn verify_webhook(
        &self,
        body: &[u8],
        signature: &str,
    ) -> Result<serde_json::Value, ApiError> {
        let mut timestamp = "";
        let mut expected_sig = "";
        for part in signature.split(',') {
            if part.starts_with("t=") {
                timestamp = part.strip_prefix("t=").unwrap_or("");
            } else if part.starts_with("v1=") {
                expected_sig = part.strip_prefix("v1=").unwrap_or("");
            }
        }

        if timestamp.is_empty() || expected_sig.is_empty() {
            return Err(ApiError::InvalidRequest(
                "Invalid Stripe signature format".into(),
            ));
        }

        let payload = format!(
            "{}.{}",
            timestamp,
            std::str::from_utf8(body)
                .map_err(|_| ApiError::InvalidRequest("Invalid body".into()))?
        );
        let mut mac = HmacSha256::new_from_slice(self.stripe_config.webhook_secret.as_bytes())
            .map_err(|_| ApiError::InternalError(anyhow::anyhow!("HMAC init failed")))?;
        mac.update(payload.as_bytes());
        let computed = mac.finalize().into_bytes();
        let expected_bytes: Vec<u8> = hex::decode(expected_sig)
            .map_err(|_| ApiError::InvalidRequest("Invalid signature format".into()))?;
        if computed.len() != expected_bytes.len()
            || !bool::from(computed.as_slice().ct_eq(expected_bytes.as_slice()))
        {
            return Err(ApiError::InvalidRequest(
                "Webhook signature mismatch".into(),
            ));
        }

        serde_json::from_slice(body).map_err(|e| {
            ApiError::InvalidRequest(anyhow::anyhow!("Invalid JSON: {}", e).to_string())
        })
    }

    /// Process a verified webhook event. Spawn in background in production.
    pub async fn process_webhook_event(&self, event: &serde_json::Value) -> Result<(), ApiError> {
        let event_type: String = event
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        info!("Processing Stripe webhook: {}", event_type);

        // Log full event for debugging field mapping (remove or reduce in production)
        if let Ok(pretty) = serde_json::to_string_pretty(event) {
            info!("Stripe webhook payload:\n{}", pretty);
        }

        match event_type.as_str() {
            "checkout.session.completed" => self.handle_checkout_completed(event).await,
            "customer.subscription.created" => self.handle_subscription_created(event).await,
            "customer.subscription.updated" => self.handle_subscription_updated(event).await,
            "customer.subscription.deleted" => self.handle_subscription_deleted(event).await,
            "invoice.payment_succeeded" | "invoice.payment_failed" => {
                self.handle_invoice_event(event).await
            }
            "charge.refunded" => self.handle_charge_refunded(event).await,
            "product.created" | "product.updated" | "product.deleted" | "price.created"
            | "price.updated" | "price.deleted" => self.handle_product_price_event(event).await,
            _ => Ok(()),
        }
    }

    /// Extracts ID from Stripe object (handles both ID string and expanded object).
    fn extract_id(obj: Option<&serde_json::Value>, key: &str) -> Option<String> {
        let v = obj?.get(key)?;
        v.as_str()
            .map(String::from)
            .or_else(|| v.get("id").and_then(|id| id.as_str()).map(String::from))
    }

    /// Extracts receipt URL from checkout session (invoice.hosted_invoice_url or charge.receipt_url when expanded).
    fn extract_receipt_url(session: &serde_json::Value) -> Option<String> {
        if let Some(inv) = session.get("invoice") {
            if let Some(url) = inv.get("hosted_invoice_url").and_then(|v| v.as_str()) {
                return Some(url.to_string());
            }
        }
        if let Some(pi) = session.get("payment_intent") {
            if let Some(charge) = pi.get("latest_charge") {
                if let Some(url) = charge.get("receipt_url").and_then(|v| v.as_str()) {
                    return Some(url.to_string());
                }
            }
        }
        None
    }

    /// Extracts hosted_invoice_url and invoice_pdf from a Stripe invoice object.
    fn extract_invoice_urls(inv: &serde_json::Value) -> (Option<String>, Option<String>) {
        let hosted = inv
            .get("hosted_invoice_url")
            .and_then(|v| v.as_str())
            .map(String::from);
        let pdf = inv.get("invoice_pdf").and_then(|v| v.as_str()).map(String::from);
        (hosted, pdf)
    }

    async fn handle_checkout_completed(&self, event: &serde_json::Value) -> Result<(), ApiError> {
        let session = event
            .get("data")
            .and_then(|d| d.get("object"))
            .ok_or_else(|| ApiError::InvalidRequest("Missing session object".into()))?;

        let mode = session.get("mode").and_then(|m| m.as_str()).unwrap_or("");
        let customer_id = Self::extract_id(Some(session), "customer")
            .ok_or_else(|| ApiError::InvalidRequest("Missing customer".into()))?;

        // Resolve user_id: from client_reference_id (our sessions) or from Stripe Customer metadata (Portal sessions).
        let user_id = {
            if let Some(cref) = session.get("client_reference_id").and_then(|v| v.as_str()) {
                UserId(
                    uuid::Uuid::parse_str(cref)
                        .map_err(|_| ApiError::InvalidRequest("Invalid client_reference_id".into()))?,
                )
            } else {
                // Portal-created sessions don't have client_reference_id; resolve from Customer metadata.
                let customer_id_parsed = customer_id
                    .parse::<stripe::CustomerId>()
                    .map_err(|_| ApiError::InvalidRequest("Invalid customer id".into()))?;
                let customer = stripe_timeout(Customer::retrieve(
                    &self.stripe_client,
                    &customer_id_parsed,
                    &[],
                ))
                .await?;
                let user_id_str = customer
                    .metadata
                    .as_ref()
                    .and_then(|m| m.get("user_id").map(|s| s.as_str()))
                    .ok_or_else(|| {
                        ApiError::InvalidRequest(
                            "Session has no client_reference_id and Customer has no user_id metadata".into(),
                        )
                    })?;
                UserId(
                    uuid::Uuid::parse_str(user_id_str)
                        .map_err(|_| ApiError::InvalidRequest("Invalid user_id in Customer metadata".into()))?,
                )
            }
        };

        let org_id = session
            .get("metadata")
            .and_then(|m| m.get("org_id"))
            .and_then(|v| v.as_str())
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .map(OrgId::from_uuid);

        if mode == "subscription" {
            let sub_id = Self::extract_id(Some(session), "subscription")
                .ok_or_else(|| ApiError::InvalidRequest("Missing subscription".into()))?;

            // Webhooks don't include line_items by default; fetch via API when empty
            let mut price_id = session
                .get("line_items")
                .and_then(|li| li.get("data"))
                .and_then(|d| d.as_array())
                .and_then(|arr| arr.first())
                .and_then(|first| first.get("price"))
                .and_then(|p| {
                    p.as_str()
                        .map(String::from)
                        .or_else(|| p.get("id").and_then(|id| id.as_str()).map(String::from))
                })
                .unwrap_or_default();

            if price_id.is_empty() {
                if let Some(session_id) = session.get("id").and_then(|v| v.as_str()) {
                    if let Ok(parsed) = session_id.parse::<stripe::CheckoutSessionId>() {
                        let params = RetrieveCheckoutSessionLineItems::default();
                        if let Ok(list) = stripe_timeout(CheckoutSession::retrieve_line_items(
                            &self.stripe_client,
                            &parsed,
                            &params,
                        ))
                        .await
                        {
                            if let Some(first) = list.data.first() {
                                if let Some(ref price) = first.price {
                                    price_id = price.id.as_str().to_string();
                                }
                            }
                        }
                    }
                }
            }

            let plan = self
                .billing_repo
                .get_plan_by_stripe_price_id(&price_id)
                .await
                .map_err(ApiError::InternalError)?;
            let plan_id = plan.map(|p| p.id);

            let org_for_create = match org_id {
                Some(o) => o,
                None => {
                    let orgs = self
                        .org_repo
                        .get_user_orgs(user_id, 1, 0)
                        .await
                        .map_err(ApiError::InternalError)?;
                    orgs.into_iter()
                        .next()
                        .map(|o| o.id)
                        .ok_or_else(|| {
                            ApiError::InvalidRequest(
                                "Missing org_id in metadata and user has no org membership".into(),
                            )
                        })?
                }
            };

            let subscription = match self
                .billing_repo
                .get_subscription_by_stripe_id(&sub_id)
                .await
                .map_err(ApiError::InternalError)?
            {
                Some(s) => s,
                None => {
                    let org = org_for_create;
                    let sub = self
                        .billing_repo
                        .create_subscription(
                            user_id,
                            org,
                            &customer_id,
                            &sub_id,
                            plan_id,
                            "active",
                            None,
                            None,
                        )
                        .await
                        .map_err(ApiError::InternalError)?;

                    // Fetch Stripe subscription and sync period, trial, status, etc. immediately
                    if let Ok(parsed) = sub_id.parse::<SubscriptionId>() {
                        if let Ok(stripe_sub) =
                            stripe_timeout(Subscription::retrieve(&self.stripe_client, &parsed, &[]))
                                .await
                        {
                            let sub_json = serde_json::to_value(&stripe_sub).ok();
                            if let Some(obj) = sub_json.as_ref() {
                                let status = obj
                                    .get("status")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("active");
                                let cancel_at_period_end = obj
                                    .get("cancel_at_period_end")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false);
                                let period_start = obj
                                    .get("current_period_start")
                                    .and_then(|v| v.as_i64())
                                    .and_then(|ts| chrono::Utc.timestamp_opt(ts, 0).single());
                                let period_end = obj
                                    .get("current_period_end")
                                    .and_then(|v| v.as_i64())
                                    .and_then(|ts| chrono::Utc.timestamp_opt(ts, 0).single());
                                let trial_start = obj
                                    .get("trial_start")
                                    .and_then(|v| v.as_i64())
                                    .and_then(|ts| chrono::Utc.timestamp_opt(ts, 0).single());
                                let trial_end = obj
                                    .get("trial_end")
                                    .and_then(|v| v.as_i64())
                                    .and_then(|ts| chrono::Utc.timestamp_opt(ts, 0).single());
                                let latest_invoice_id = obj
                                    .get("latest_invoice")
                                    .and_then(|v| v.as_str().map(String::from))
                                    .or_else(|| Self::extract_id(obj.get("latest_invoice"), "id"));

                                let _ = self
                                    .billing_repo
                                    .update_subscription_status(
                                        &sub_id,
                                        status,
                                        period_start,
                                        period_end,
                                        cancel_at_period_end,
                                        trial_start,
                                        trial_end,
                                        None,
                                        latest_invoice_id.as_deref(),
                                        None,
                                        None,
                                    )
                                    .await;
                            }
                        }
                    }

                    sub
                }
            };

            let receipt_url = Self::extract_receipt_url(session);
            let hosted = receipt_url.clone();
            let billing_email = session
                .get("customer_details")
                .and_then(|cd| cd.get("email"))
                .and_then(|v| v.as_str())
                .map(String::from)
                .or_else(|| session.get("customer_email").and_then(|v| v.as_str()).map(String::from));
            self.billing_repo
                .add_subscription_transaction(
                    user_id,
                    subscription.org_id.or(org_id),
                    subscription.id,
                    "created",
                    None,
                    None,
                    None,
                    receipt_url.as_deref(),
                    hosted.as_deref(),
                    None,
                    Some("created"),
                    billing_email.as_deref(),
                )
                .await
                .map_err(ApiError::InternalError)?;
        } else if mode == "payment" {
            let amount_total = session
                .get("amount_total")
                .and_then(|a| a.as_i64())
                .unwrap_or(0);
            let currency = session
                .get("currency")
                .and_then(|c| c.as_str())
                .unwrap_or("usd");

            let line_items = session.get("line_items");
            let price_value = line_items
                .and_then(|li| li.get("data"))
                .and_then(|d| d.as_array())
                .and_then(|arr| arr.first())
                .and_then(|first| first.get("price"));
            let price_id = price_value
                .and_then(|p| p.as_str())
                .or_else(|| price_value.and_then(|p| p.get("id").and_then(|id| id.as_str())))
                .unwrap_or("");

            let package = self
                .billing_repo
                .get_package_by_stripe_price_id(price_id)
                .await
                .map_err(ApiError::InternalError)?;

            let (tokens, package_id) = package.map(|p| (p.tokens, Some(p.id))).unwrap_or((0, None));

            let receipt_url = Self::extract_receipt_url(session);
            let payment_intent_id = Self::extract_id(session.get("payment_intent"), "id")
                .or_else(|| session.get("payment_intent").and_then(|v| v.as_str()).map(String::from));

            let org = org_id
                .ok_or_else(|| ApiError::InvalidRequest("Missing org_id in metadata".into()))?;

            self.billing_repo
                .add_credit_transaction(
                    user_id,
                    org,
                    package_id,
                    tokens,
                    amount_total,
                    currency,
                    "purchase",
                    payment_intent_id.as_deref(),
                    None,
                    receipt_url.as_deref(),
                )
                .await
                .map_err(ApiError::InternalError)?;

            if tokens > 0 {
                self.billing_repo
                    .upsert_org_credits(org, tokens)
                    .await
                    .map_err(ApiError::InternalError)?;
            }
        }

        Ok(())
    }

    async fn handle_subscription_created(&self, event: &serde_json::Value) -> Result<(), ApiError> {
        let sub = event
            .get("data")
            .and_then(|d| d.get("object"))
            .ok_or_else(|| ApiError::InvalidRequest("Missing subscription object".into()))?;

        let stripe_id = Self::extract_id(Some(sub), "id")
            .ok_or_else(|| ApiError::InvalidRequest("Missing subscription id".into()))?;

        let db_sub = match self
            .billing_repo
            .get_subscription_by_stripe_id(&stripe_id)
            .await
            .map_err(ApiError::InternalError)?
        {
            Some(s) => s,
            None => {
                // Subscription not in DB yet (created may fire before checkout.session.completed)
                let customer_id = Self::extract_id(Some(sub), "customer")
                    .ok_or_else(|| ApiError::InvalidRequest("Missing customer".into()))?;
                let customer_id_parsed = customer_id
                    .parse::<stripe::CustomerId>()
                    .map_err(|_| ApiError::InvalidRequest("Invalid customer id".into()))?;
                let customer = stripe_timeout(Customer::retrieve(
                    &self.stripe_client,
                    &customer_id_parsed,
                    &[],
                ))
                .await?;
                let user_id_str = customer
                    .metadata
                    .as_ref()
                    .and_then(|m| m.get("user_id").map(|s| s.as_str()))
                    .ok_or_else(|| ApiError::InvalidRequest("Customer has no user_id metadata".into()))?;
                let user_id = UserId(
                    uuid::Uuid::parse_str(user_id_str)
                        .map_err(|_| ApiError::InvalidRequest("Invalid user_id in Customer metadata".into()))?,
                );
                let org_id = sub
                    .get("metadata")
                    .and_then(|m| m.get("org_id"))
                    .and_then(|v| v.as_str())
                    .and_then(|s| uuid::Uuid::parse_str(s).ok())
                    .map(OrgId::from_uuid)
                    .or_else(|| None);
                let org_id = match org_id {
                    Some(o) => o,
                    None => {
                        let orgs = self
                            .org_repo
                            .get_user_orgs(user_id, 1, 0)
                            .await
                            .map_err(ApiError::InternalError)?;
                        orgs.into_iter()
                            .next()
                            .map(|o| o.id)
                            .ok_or_else(|| ApiError::InvalidRequest("User has no org membership".into()))?
                    }
                };
                let plan_id = if let Some(items) = sub.get("items").and_then(|i| i.get("data")).and_then(|d| d.as_array()) {
                    if let Some(first) = items.first() {
                        let price_id = first
                            .get("price")
                            .and_then(|p| p.as_str().map(String::from).or_else(|| p.get("id").and_then(|id| id.as_str()).map(String::from)));
                        if let Some(ref pid) = price_id {
                            self.billing_repo
                                .get_plan_by_stripe_price_id(pid)
                                .await
                                .ok()
                                .flatten()
                                .map(|p| p.id)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };
                let status = sub.get("status").and_then(|v| v.as_str()).unwrap_or("active");
                self.billing_repo
                    .create_subscription(
                        user_id,
                        org_id,
                        &customer_id,
                        &stripe_id,
                        plan_id,
                        status,
                        None,
                        None,
                    )
                    .await
                    .map_err(ApiError::InternalError)?;
                // Fall through to update logic - we'll sync full data
                self.billing_repo
                    .get_subscription_by_stripe_id(&stripe_id)
                    .await
                    .map_err(ApiError::InternalError)?
                    .ok_or_else(|| ApiError::InternalError(anyhow::anyhow!("Just created sub not found")))?
            }
        };

        let status = sub
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let cancel_at_period_end = sub
            .get("cancel_at_period_end")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let period_start = sub
            .get("current_period_start")
            .and_then(|v| v.as_i64())
            .and_then(|ts| chrono::Utc.timestamp_opt(ts, 0).single());
        let period_end = sub
            .get("current_period_end")
            .and_then(|v| v.as_i64())
            .and_then(|ts| chrono::Utc.timestamp_opt(ts, 0).single());
        let trial_start = sub
            .get("trial_start")
            .and_then(|v| v.as_i64())
            .and_then(|ts| chrono::Utc.timestamp_opt(ts, 0).single());
        let trial_end = sub
            .get("trial_end")
            .and_then(|v| v.as_i64())
            .and_then(|ts| chrono::Utc.timestamp_opt(ts, 0).single());
        let latest_invoice_id = sub
            .get("latest_invoice")
            .and_then(|v| v.as_str().map(String::from))
            .or_else(|| Self::extract_id(sub.get("latest_invoice"), "id"));
        let canceled_at = if status == "canceled" {
            Some(chrono::Utc::now())
        } else {
            None
        };

            let paused_at = if status == "paused" {
                Some(chrono::Utc::now())
            } else {
                None
            };

            self.billing_repo
                .update_subscription_status(
                    &stripe_id,
                    status,
                    period_start,
                    period_end,
                    cancel_at_period_end,
                    trial_start,
                    trial_end,
                    canceled_at,
                    latest_invoice_id.as_deref(),
                    None,
                    paused_at,
                )
                .await
                .map_err(ApiError::InternalError)?;

        // Sync plan_id if items changed (upgrade/downgrade)
        if let Some(items) = sub
            .get("items")
            .and_then(|i| i.get("data"))
            .and_then(|d| d.as_array())
        {
            if let Some(first) = items.first() {
                let price = first.get("price").and_then(|p| {
                    p.as_str()
                        .map(String::from)
                        .or_else(|| p.get("id").and_then(|id| id.as_str()).map(String::from))
                });
                if let Some(price_id) = price {
                    if let Ok(Some(plan)) = self
                        .billing_repo
                        .get_plan_by_stripe_price_id(&price_id)
                        .await
                    {
                        if db_sub.plan_id != Some(plan.id) {
                            self.billing_repo
                                .update_subscription_plan(&stripe_id, plan.id)
                                .await
                                .map_err(ApiError::InternalError)?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_subscription_updated(&self, event: &serde_json::Value) -> Result<(), ApiError> {
        let sub = event
            .get("data")
            .and_then(|d| d.get("object"))
            .ok_or_else(|| ApiError::InvalidRequest("Missing subscription object".into()))?;

        let stripe_id = Self::extract_id(Some(sub), "id")
            .ok_or_else(|| ApiError::InvalidRequest("Missing subscription id".into()))?;

        let db_sub = match self
            .billing_repo
            .get_subscription_by_stripe_id(&stripe_id)
            .await
            .map_err(ApiError::InternalError)?
        {
            Some(s) => s,
            None => {
                info!("Subscription {} not in DB, skipping sync", stripe_id);
                return Ok(());
            }
        };

        let status = sub
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let cancel_at_period_end = sub
            .get("cancel_at_period_end")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let period_start = sub
            .get("current_period_start")
            .and_then(|v| v.as_i64())
            .and_then(|ts| chrono::Utc.timestamp_opt(ts, 0).single());
        let period_end = sub
            .get("current_period_end")
            .and_then(|v| v.as_i64())
            .and_then(|ts| chrono::Utc.timestamp_opt(ts, 0).single());
        let trial_start = sub
            .get("trial_start")
            .and_then(|v| v.as_i64())
            .and_then(|ts| chrono::Utc.timestamp_opt(ts, 0).single());
        let trial_end = sub
            .get("trial_end")
            .and_then(|v| v.as_i64())
            .and_then(|ts| chrono::Utc.timestamp_opt(ts, 0).single());
        let latest_invoice_id = sub
            .get("latest_invoice")
            .and_then(|v| v.as_str().map(String::from))
            .or_else(|| Self::extract_id(sub.get("latest_invoice"), "id"));
        let canceled_at = if status == "canceled" {
            Some(chrono::Utc::now())
        } else {
            None
        };

        let paused_at = if status == "paused" {
            Some(chrono::Utc::now())
        } else {
            None
        };

        self.billing_repo
            .update_subscription_status(
                &stripe_id,
                status,
                period_start,
                period_end,
                cancel_at_period_end,
                trial_start,
                trial_end,
                canceled_at,
                latest_invoice_id.as_deref(),
                None,
                paused_at,
            )
            .await
            .map_err(ApiError::InternalError)?;

        // Sync plan_id if items changed (upgrade/downgrade)
        if let Some(items) = sub
            .get("items")
            .and_then(|i| i.get("data"))
            .and_then(|d| d.as_array())
        {
            if let Some(first) = items.first() {
                let price = first.get("price").and_then(|p| {
                    p.as_str()
                        .map(String::from)
                        .or_else(|| p.get("id").and_then(|id| id.as_str()).map(String::from))
                });
                if let Some(price_id) = price {
                    if let Ok(Some(plan)) = self
                        .billing_repo
                        .get_plan_by_stripe_price_id(&price_id)
                        .await
                    {
                        if db_sub.plan_id != Some(plan.id) {
                            self.billing_repo
                                .update_subscription_plan(&stripe_id, plan.id)
                                .await
                                .map_err(ApiError::InternalError)?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_subscription_deleted(&self, event: &serde_json::Value) -> Result<(), ApiError> {
        let sub = event
            .get("data")
            .and_then(|d| d.get("object"))
            .ok_or_else(|| ApiError::InvalidRequest("Missing subscription object".into()))?;

        let stripe_id = Self::extract_id(Some(sub), "id")
            .ok_or_else(|| ApiError::InvalidRequest("Missing subscription id".into()))?;

        if let Some(db_sub) = self
            .billing_repo
            .get_subscription_by_stripe_id(&stripe_id)
            .await
            .map_err(ApiError::InternalError)?
        {
            self.billing_repo
                .update_subscription_status(
                    &stripe_id,
                    "canceled",
                    None,
                    None,
                    false,
                    None,
                    None,
                    Some(chrono::Utc::now()),
                    None,
                    None,
                    None,
                )
                .await
                .map_err(ApiError::InternalError)?;

            self.billing_repo
                .add_subscription_transaction(
                    db_sub.user_id,
                    db_sub.org_id,
                    db_sub.id,
                    "canceled",
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some("canceled"),
                    None,
                )
                .await
                .map_err(ApiError::InternalError)?;
        }

        Ok(())
    }

    async fn handle_charge_refunded(&self, event: &serde_json::Value) -> Result<(), ApiError> {
        let charge = event
            .get("data")
            .and_then(|d| d.get("object"))
            .ok_or_else(|| ApiError::InvalidRequest("Missing charge object".into()))?;

        let payment_intent_id = Self::extract_id(charge.get("payment_intent"), "id")
            .or_else(|| charge.get("payment_intent").and_then(|v| v.as_str()).map(String::from));

        let Some(pi_id) = payment_intent_id else {
            return Ok(());
        };

        if self
            .billing_repo
            .has_refund_for_payment_intent(&pi_id)
            .await
            .map_err(ApiError::InternalError)?
        {
            return Ok(());
        }

        let Some((user_id, org_id, amount_tokens, amount_cents)) = self
            .billing_repo
            .get_purchase_by_stripe_payment_intent_id(&pi_id)
            .await
            .map_err(ApiError::InternalError)?
        else {
            return Ok(());
        };

        let amount_refunded = charge.get("amount_refunded").and_then(|v| v.as_i64()).unwrap_or(0);
        let amount = charge.get("amount").and_then(|v| v.as_i64()).unwrap_or(1);
        let tokens_to_reverse = if amount > 0 {
            (amount_refunded as f64 / amount as f64 * amount_tokens as f64) as i64
        } else {
            amount_tokens
        };

        if tokens_to_reverse <= 0 {
            return Ok(());
        }

        let refund_amount_cents = if amount > 0 {
            amount_refunded
        } else {
            amount_cents
        };

        self.billing_repo
            .add_credit_transaction(
                user_id,
                org_id,
                None,
                -tokens_to_reverse,
                -refund_amount_cents,
                "usd",
                "refund",
                Some(&pi_id),
                charge.get("id").and_then(|v| v.as_str()),
                None,
            )
            .await
            .map_err(ApiError::InternalError)?;

        self.billing_repo
            .upsert_org_credits(org_id, -tokens_to_reverse)
            .await
            .map_err(ApiError::InternalError)?;

        info!(
            payment_intent = %pi_id,
            org_id = %org_id.0,
            tokens_reversed = tokens_to_reverse,
            "Processed refund for token purchase"
        );

        Ok(())
    }

    async fn handle_invoice_event(&self, event: &serde_json::Value) -> Result<(), ApiError> {
        let event_type = event.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let inv = event
            .get("data")
            .and_then(|d| d.get("object"))
            .ok_or_else(|| ApiError::InvalidRequest("Missing invoice object".into()))?;

        let sub_id = inv
            .get("subscription")
            .and_then(|v| v.as_str().map(String::from))
            .or_else(|| Self::extract_id(inv.get("subscription"), "id"));
        let stripe_invoice_id = inv.get("id").and_then(|v| v.as_str()).map(String::from);
        let amount_paid = inv.get("amount_paid").and_then(|v| v.as_i64());
        let currency = inv
            .get("currency")
            .and_then(|v| v.as_str())
            .map(String::from);
        let (hosted_url, invoice_pdf_url) = Self::extract_invoice_urls(inv);

        let Some(stripe_sub_id) = sub_id else {
            return Ok(());
        };

        let db_sub = match self
            .billing_repo
            .get_subscription_by_stripe_id(&stripe_sub_id)
            .await
            .map_err(ApiError::InternalError)?
        {
            Some(s) => s,
            None => return Ok(()),
        };

        let billing_email = inv.get("customer_email").and_then(|v| v.as_str()).map(String::from);

        match event_type {
            "invoice.payment_succeeded" => {
                self.billing_repo
                    .add_subscription_transaction(
                        db_sub.user_id,
                        db_sub.org_id,
                        db_sub.id,
                        "renewed",
                        stripe_invoice_id.as_deref(),
                        amount_paid,
                        currency.as_deref(),
                        hosted_url.as_deref(),
                        hosted_url.as_deref(),
                        invoice_pdf_url.as_deref(),
                        Some("paid"),
                        billing_email.as_deref(),
                    )
                    .await
                    .map_err(ApiError::InternalError)?;

                let paid_at = inv
                    .get("status_transitions")
                    .and_then(|st| st.get("paid_at"))
                    .and_then(|v| v.as_i64())
                    .and_then(|ts| chrono::Utc.timestamp_opt(ts, 0).single())
                    .or_else(|| {
                        inv.get("created")
                            .and_then(|v| v.as_i64())
                            .and_then(|ts| chrono::Utc.timestamp_opt(ts, 0).single())
                    });
                if let Some(paid_at) = paid_at {
                    let _ = self
                        .billing_repo
                        .update_subscription_last_payment(&stripe_sub_id, paid_at)
                        .await;
                }
            }
            "invoice.payment_failed" => {
                self.billing_repo
                    .add_subscription_transaction(
                        db_sub.user_id,
                        db_sub.org_id,
                        db_sub.id,
                        "payment_failed",
                        stripe_invoice_id.as_deref(),
                        inv.get("amount_due").and_then(|v| v.as_i64()),
                        currency.as_deref(),
                        hosted_url.as_deref(),
                        hosted_url.as_deref(),
                        invoice_pdf_url.as_deref(),
                        Some("failed"),
                        billing_email.as_deref(),
                    )
                    .await
                    .map_err(ApiError::InternalError)?;

                warn!(
                    subscription_id = %stripe_sub_id,
                    invoice_id = ?stripe_invoice_id,
                    "Invoice payment failed (dunning: Stripe will retry automatically)"
                );

                // Notify user asynchronously
                let to_email = match &billing_email {
                    Some(email) => Some(email.clone()),
                    None => self
                        .user_repo
                        .get_by_id(db_sub.user_id)
                        .await
                        .ok()
                        .flatten()
                        .map(|u| u.email),
                };
                if let Some(to) = to_email {
                    let email_sender = self.email_sender.clone();
                    let hosted = hosted_url.clone();
                    let update_url = db_sub.org_id.and_then(|org_id| {
                        self.frontend_url
                            .as_ref()
                            .map(|base| format!("{}/orgs/{}?tab=billing", base.trim_end_matches('/'), org_id.0))
                    });
                    self.job_queue.spawn_result("send_payment_failed", move || {
                        let es = email_sender.clone();
                        let t = to.clone();
                        let h = hosted.clone();
                        let u = update_url.clone();
                        async move {
                            es.send_payment_failed(&t, h.as_deref(), u.as_deref()).await
                        }
                    });
                }
            }
            _ => {}
        }

        Ok(())
    }

    async fn handle_product_price_event(&self, event: &serde_json::Value) -> Result<(), ApiError> {
        let event_type = event.get("type").and_then(|v| v.as_str()).unwrap_or("");
        match event_type {
            "price.created" | "price.updated" | "price.deleted" => self.handle_price_event(event).await,
            "product.created" | "product.updated" | "product.deleted" => {
                self.handle_product_event(event).await
            }
            _ => Ok(()),
        }
    }

    async fn handle_price_event(&self, event: &serde_json::Value) -> Result<(), ApiError> {
        let price_obj = event
            .get("data")
            .and_then(|d| d.get("object"))
            .ok_or_else(|| ApiError::InvalidRequest("Missing price object".into()))?;

        let price_id_str = price_obj
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ApiError::InvalidRequest("Missing price id".into()))?;

        let price_id = price_id_str
            .parse::<PriceId>()
            .map_err(|_| ApiError::InvalidRequest("Invalid price id".into()))?;

        let price = match stripe_timeout(Price::retrieve(
            &self.stripe_client,
            &price_id,
            &["product"],
        ))
        .await
        {
            Ok(p) => p,
            Err(e) => {
                warn!("Stripe Price retrieve failed ({}): {:?}", price_id_str, e);
                return Ok(());
            }
        };

        let is_deleted = event.get("type").and_then(|v| v.as_str()) == Some("price.deleted");
        self.upsert_or_deactivate_price(&price, is_deleted).await
    }

    /// Upsert subscription plan or token package from a Stripe Price (with product expanded).
    /// For product.updated events, we list all prices and call this for each—ensuring new prices get created.
    async fn upsert_or_deactivate_price(
        &self,
        price: &Price,
        force_deactivate: bool,
    ) -> Result<(), ApiError> {
        let price_id_str = price.id.as_str();
        let price_active = price.active.unwrap_or(true) && !price.deleted;
        let price_type = price.type_.as_ref().map(|t| t.to_string());

        if force_deactivate || !price_active {
            self.billing_repo
                .deactivate_subscription_plan_by_price_id(price_id_str)
                .await
                .map_err(ApiError::InternalError)?;
            self.billing_repo
                .deactivate_token_package_by_price_id(price_id_str)
                .await
                .map_err(ApiError::InternalError)?;
            return Ok(());
        }

        let (product_id, product_name, product_active, metadata) = match &price.product {
            Some(stripe::Expandable::Object(product)) => {
                let name = product
                    .name
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .unwrap_or("Unnamed")
                    .to_string();
                let meta = product.metadata.as_ref().cloned().unwrap_or_default();
                (product.id.to_string(), name, product.active.unwrap_or(true) && !product.deleted, meta)
            }
            Some(stripe::Expandable::Id(pid)) => {
                match stripe_timeout(Product::retrieve(&self.stripe_client, pid, &[])).await {
                    Ok(product) => {
                        let name = product
                            .name
                            .as_deref()
                            .filter(|s| !s.is_empty())
                            .unwrap_or("Unnamed")
                            .to_string();
                        let meta = product.metadata.as_ref().cloned().unwrap_or_default();
                        (
                            product.id.to_string(),
                            name,
                            product.active.unwrap_or(true) && !product.deleted,
                            meta,
                        )
                    }
                    Err(e) => {
                        warn!("Stripe Product retrieve failed ({}): {:?}", pid, e);
                        return Ok(());
                    }
                }
            }
            None => {
                warn!("Price {} has no product", price_id_str);
                return Ok(());
            }
        };

        let unit_amount = price.unit_amount;
        if unit_amount.is_none() {
            warn!("Skipping tiered/metered price {}", price_id_str);
            return Ok(());
        }
        let amount_cents = unit_amount.unwrap();
        let currency = price
            .currency
            .as_ref()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "usd".to_string());

        match price_type.as_deref() {
            Some("recurring") => {
                let interval = price
                    .recurring
                    .as_ref()
                    .map(|r| r.interval.to_string())
                    .unwrap_or_else(|| "month".to_string());
                let features = Self::parse_features_from_metadata(&metadata);
                let active = product_active && price_active;
                self.billing_repo
                    .upsert_subscription_plan(
                        &product_id,
                        price_id_str,
                        &product_name,
                        &interval,
                        amount_cents,
                        &currency,
                        &features,
                        active,
                    )
                    .await
                    .map_err(ApiError::InternalError)?;
            }
            Some("one_time") => {
                let tokens = metadata
                    .get("tokens")
                    .and_then(|s| s.parse::<i64>().ok());
                match tokens {
                    Some(t) => {
                        let active = product_active && price_active;
                        self.billing_repo
                            .upsert_token_package(
                                &product_id,
                                price_id_str,
                                &product_name,
                                t,
                                amount_cents,
                                &currency,
                                active,
                            )
                            .await
                            .map_err(ApiError::InternalError)?;
                    }
                    None => {
                        warn!("Skipping one-time price {}: missing metadata.tokens", price_id_str);
                    }
                }
            }
            _ => {
                warn!("Unsupported price type for {}: {:?}", price_id_str, price_type);
            }
        }

        Ok(())
    }

    async fn handle_product_event(&self, event: &serde_json::Value) -> Result<(), ApiError> {
        let product_obj = event
            .get("data")
            .and_then(|d| d.get("object"))
            .ok_or_else(|| ApiError::InvalidRequest("Missing product object".into()))?;

        let product_id = product_obj
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ApiError::InvalidRequest("Missing product id".into()))?;

        let active = product_obj
            .get("active")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let deleted = product_obj.get("deleted").and_then(|v| v.as_bool()).unwrap_or(false);

        if event.get("type").and_then(|v| v.as_str()) == Some("product.deleted") || !active || deleted
        {
            self.billing_repo
                .deactivate_subscription_plans_by_product_id(product_id)
                .await
                .map_err(ApiError::InternalError)?;
            self.billing_repo
                .deactivate_token_packages_by_product_id(product_id)
                .await
                .map_err(ApiError::InternalError)?;
            return Ok(());
        }

        // List all prices for this product and upsert each. This ensures product.updated
        // creates/updates plans and packages even when no price.* webhook was received.
        // Use "data.product" for list endpoints (Stripe rejects plain "product").
        let mut list_params = ListPrices::new();
        list_params.product = Some(IdOrCreate::Id(product_id));
        list_params.expand = &["data.product"];
        list_params.limit = Some(100);

        let mut prices = match stripe_timeout(Price::list(&self.stripe_client, &list_params)).await {
            Ok(list) => list.data,
            Err(e) => {
                warn!("Stripe Price list failed for product {}: {:?}", product_id, e);
                return Ok(());
            }
        };

        while !prices.is_empty() {
            for price in &prices {
                if let Err(e) = self.upsert_or_deactivate_price(price, false).await {
                    warn!("Failed to upsert price {}: {:?}", price.id, e);
                }
            }
            list_params.starting_after = prices.last().map(|p| p.id.clone());
            prices = match stripe_timeout(Price::list(&self.stripe_client, &list_params)).await {
                Ok(list) => list.data,
                Err(e) => {
                    warn!("Stripe Price list pagination failed: {:?}", e);
                    break;
                }
            };
        }

        Ok(())
    }

    fn parse_features_from_metadata(metadata: &std::collections::HashMap<String, String>) -> serde_json::Value {
        metadata
            .get("features")
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_else(|| serde_json::json!([]))
    }
}
