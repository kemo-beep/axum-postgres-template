//! Billing service: Stripe Checkout, Customer Portal, webhook processing,
//! subscription cancel/upgrade/downgrade, grace period and dunning.

use anyhow::Result;
use chrono::TimeZone;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use stripe::{
    CancelSubscription, CheckoutSession, CheckoutSessionMode, Client, CreateBillingPortalSession,
    CreateCheckoutSession, CreateCheckoutSessionLineItems, CreateCustomer, Customer, IdOrCreate,
    ListPrices, Price, PriceId, Product, Subscription, SubscriptionId, UpdateSubscription,
    UpdateSubscriptionItems,
};
use subtle::ConstantTimeEq;
use tracing::{info, warn};

use crate::auth::repository::UserRepository;
use crate::billing::repository::BillingRepository;
use crate::cfg::StripeConfig;
use crate::common::{ApiError, OrgId, UserId};
use crate::org::repository::OrgRepository;

type HmacSha256 = Hmac<Sha256>;

/// Stripe integration: Checkout, Portal, webhooks, subscription management.
#[derive(Clone)]
pub struct BillingService {
    stripe_client: Client,
    stripe_config: StripeConfig,
    billing_repo: BillingRepository,
    user_repo: UserRepository,
    org_repo: OrgRepository,
}

impl BillingService {
    pub async fn list_plans(&self) -> Result<Vec<crate::billing::repository::SubscriptionPlan>> {
        self.billing_repo.list_subscription_plans().await
    }

    pub async fn list_packages(&self) -> Result<Vec<crate::billing::repository::TokenPackage>> {
        self.billing_repo.list_token_packages().await
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
    ) -> Result<(
        Vec<crate::billing::repository::SubscriptionTransaction>,
        Vec<crate::billing::repository::CreditTransaction>,
    )> {
        let sub = self
            .billing_repo
            .list_subscription_transactions(user_id)
            .await?;
        let credit = self.billing_repo.list_credit_transactions(user_id).await?;
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
    ) -> Result<(
        Vec<crate::billing::repository::SubscriptionTransaction>,
        Vec<crate::billing::repository::CreditTransaction>,
    )> {
        let sub = self
            .billing_repo
            .list_subscription_transactions_by_org(org_id)
            .await?;
        let credit = self
            .billing_repo
            .list_credit_transactions_by_org(org_id)
            .await?;
        Ok((sub, credit))
    }

    pub fn new(
        stripe_config: StripeConfig,
        billing_repo: BillingRepository,
        user_repo: UserRepository,
        org_repo: OrgRepository,
    ) -> Self {
        let stripe_client = Client::new(stripe_config.secret_key.clone());
        Self {
            stripe_client,
            stripe_config,
            billing_repo,
            user_repo,
            org_repo,
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
            match Price::retrieve(&self.stripe_client, &price_id_parsed, &[]).await {
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

        let customer_id = if let Some(ref cid) = user.stripe_customer_id {
            Some(
                cid.parse::<stripe::CustomerId>()
                    .map_err(|e| ApiError::InternalError(anyhow::anyhow!("{}", e)))?,
            )
        } else {
            let customer = Customer::create(
                &self.stripe_client,
                CreateCustomer {
                    email: Some(&user.email),
                    metadata: Some(std::collections::HashMap::from([(
                        "user_id".to_string(),
                        user_id.0.to_string(),
                    )])),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| ApiError::InternalError(anyhow::anyhow!("Stripe: {}", e)))?;

            self.user_repo
                .update_stripe_customer_id(user_id, customer.id.as_str())
                .await
                .map_err(ApiError::InternalError)?;

            Some(customer.id)
        };

        params.customer = Some(customer_id.unwrap());

        let session = CheckoutSession::create(&self.stripe_client, params)
            .await
            .map_err(|e| ApiError::InternalError(anyhow::anyhow!("Stripe: {}", e)))?;

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

        let session = stripe::BillingPortalSession::create(&self.stripe_client, params)
            .await
            .map_err(|e| ApiError::InternalError(anyhow::anyhow!("Stripe: {}", e)))?;

        Ok(session.url.to_string())
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

        Subscription::update(&self.stripe_client, &sub_id, params)
            .await
            .map_err(|e| ApiError::InternalError(anyhow::anyhow!("Stripe: {}", e)))?;

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
        Subscription::cancel(&self.stripe_client, &sub_id, params)
            .await
            .map_err(|e| ApiError::InternalError(anyhow::anyhow!("Stripe: {}", e)))?;

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

        let stripe_sub = Subscription::retrieve(&self.stripe_client, &sub_id, &[])
            .await
            .map_err(|e| ApiError::InternalError(anyhow::anyhow!("Stripe: {}", e)))?;

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

        let params = UpdateSubscription {
            items: Some(vec![item]),
            ..Default::default()
        };
        // Stripe prorates by default; upgrade/downgrade applies at next billing cycle or creates proration

        Subscription::update(&self.stripe_client, &sub_id, params)
            .await
            .map_err(|e| ApiError::InternalError(anyhow::anyhow!("Stripe: {}", e)))?;

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

        match event_type.as_str() {
            "checkout.session.completed" => self.handle_checkout_completed(event).await,
            "customer.subscription.updated" => self.handle_subscription_updated(event).await,
            "customer.subscription.deleted" => self.handle_subscription_deleted(event).await,
            "invoice.payment_succeeded" | "invoice.payment_failed" => {
                self.handle_invoice_event(event).await
            }
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
                let customer = Customer::retrieve(&self.stripe_client, &customer_id_parsed, &[])
                    .await
                    .map_err(|e| {
                        ApiError::InternalError(anyhow::anyhow!("Stripe Customer retrieve: {}", e))
                    })?;
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

            let line_items = session.get("line_items");
            let price_id = line_items
                .and_then(|li| li.get("data"))
                .and_then(|d| d.as_array())
                .and_then(|arr| arr.first())
                .and_then(|first| first.get("price"))
                .and_then(|p| {
                    p.as_str()
                        .or_else(|| p.get("id").and_then(|id| id.as_str()))
                })
                .unwrap_or("");
            let plan = self
                .billing_repo
                .get_plan_by_stripe_price_id(price_id)
                .await
                .map_err(ApiError::InternalError)?;
            let plan_id = plan.map(|p| p.id);

            let org_for_create = match org_id {
                Some(o) => o,
                None => {
                    let orgs = self
                        .org_repo
                        .get_user_orgs(user_id)
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
                    self.billing_repo
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
                        .map_err(ApiError::InternalError)?
                }
            };

            let receipt_url = Self::extract_receipt_url(session);
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
                    None,
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

        self.billing_repo
            .update_subscription_status(
                &stripe_id,
                status,
                period_start,
                period_end,
                cancel_at_period_end,
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
                .update_subscription_status(&stripe_id, "canceled", None, None, false)
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
                )
                .await
                .map_err(ApiError::InternalError)?;
        }

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
        let hosted_url = inv
            .get("hosted_invoice_url")
            .and_then(|v| v.as_str())
            .map(String::from);

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
                    )
                    .await
                    .map_err(ApiError::InternalError)?;
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
                    )
                    .await
                    .map_err(ApiError::InternalError)?;

                warn!(
                    subscription_id = %stripe_sub_id,
                    invoice_id = ?stripe_invoice_id,
                    "Invoice payment failed (dunning: Stripe will retry automatically)"
                );
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

        let price = match Price::retrieve(&self.stripe_client, &price_id, &["product"]).await {
            Ok(p) => p,
            Err(e) => {
                warn!("Stripe Price retrieve failed ({}): {}", price_id_str, e);
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
                match Product::retrieve(&self.stripe_client, pid, &[]).await {
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
                        warn!("Stripe Product retrieve failed ({}): {}", pid, e);
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

        let mut prices = match Price::list(&self.stripe_client, &list_params).await {
            Ok(list) => list.data,
            Err(e) => {
                warn!("Stripe Price list failed for product {}: {}", product_id, e);
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
            prices = match Price::list(&self.stripe_client, &list_params).await {
                Ok(list) => list.data,
                Err(e) => {
                    warn!("Stripe Price list pagination failed: {}", e);
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
