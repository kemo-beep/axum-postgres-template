//! Billing routes and Stripe webhook handler.

use axum::{
    body::Bytes,
    extract::rejection::JsonRejection,
    extract::{Query, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use axum::middleware::from_extractor_with_state;

use crate::auth::extractor::{RequireAuth, RequireBillingManage, RequireOrgBillingAccess};
use crate::common::ApiError;
use crate::AppState;

/// Stripe webhook handler. Verifies signature and returns 200 quickly.
/// Process events async in production (spawn task or job queue).
#[utoipa::path(
    post,
    path = "/webhooks/stripe",
    tag = "Webhooks",
    responses(
        (status = 200, description = "Webhook accepted"),
        (status = 400, description = "Invalid signature", body = crate::common::ApiErrorResp),
        (status = 500, description = "Stripe not configured", body = crate::common::ApiErrorResp)
    )
)]
pub async fn stripe_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<axum::http::StatusCode, ApiError> {
    let billing = state
        .billing_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Stripe not configured"
        )))?;

    let sig = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::InvalidRequest("Missing Stripe-Signature".into()))?;

    let event = billing.verify_webhook(&body, sig)?;

    // Spawn task to process async (don't block response)
    let billing = billing.clone();
    tokio::spawn(async move {
        if let Err(e) = billing.process_webhook_event(&event).await {
            tracing::error!("Webhook processing error: {:?}", e);
        }
    });

    Ok(axum::http::StatusCode::OK)
}

pub fn router() -> Router<AppState> {
    Router::new().route("/stripe", post(stripe_webhook))
}

// --- v1/billing routes ---

#[derive(Deserialize, ToSchema)]
pub struct CheckoutRequest {
    pub mode: String, // "subscription" | "payment"
    pub price_id: String,
    pub success_url: String,
    pub cancel_url: String,
}

#[derive(Serialize, ToSchema)]
pub struct UrlResponse {
    pub url: String,
}

#[derive(Serialize)]
pub struct TransactionItem {
    pub id: String,
    pub kind: String,
    pub amount_cents: Option<i64>,
    pub currency: Option<String>,
    pub receipt_url: Option<String>,
    pub occurred_at: String,
}

#[utoipa::path(
    get,
    path = "/v1/billing/plans",
    tag = "Billing",
    responses(
        (status = 200, description = "List of subscription plans"),
        (status = 500, description = "Billing not configured", body = crate::common::ApiErrorResp)
    )
)]
pub async fn list_plans(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let billing = state
        .billing_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Billing not configured"
        )))?;
    let plans = billing
        .list_plans()
        .await
        .map_err(ApiError::InternalError)?;
    Ok(Json(serde_json::json!(plans)))
}

#[utoipa::path(
    get,
    path = "/v1/billing/packages",
    tag = "Billing",
    responses(
        (status = 200, description = "List of token packages"),
        (status = 500, description = "Billing not configured", body = crate::common::ApiErrorResp)
    )
)]
pub async fn list_packages(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let billing = state
        .billing_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Billing not configured"
        )))?;
    let packages = billing
        .list_packages()
        .await
        .map_err(ApiError::InternalError)?;
    Ok(Json(serde_json::json!(packages)))
}

#[utoipa::path(
    post,
    path = "/v1/orgs/{org_id}/billing/checkout",
    tag = "Billing",
    request_body = CheckoutRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Checkout URL", body = UrlResponse),
        (status = 400, description = "Invalid request", body = crate::common::ApiErrorResp),
        (status = 401, description = "Unauthorized", body = crate::common::ApiErrorResp),
        (status = 403, description = "Forbidden", body = crate::common::ApiErrorResp),
        (status = 500, description = "Billing not configured", body = crate::common::ApiErrorResp)
    )
)]
pub async fn checkout(
    State(state): State<AppState>,
    RequireOrgBillingAccess(user, org_id): RequireOrgBillingAccess,
    req: Result<Json<CheckoutRequest>, JsonRejection>,
) -> Result<Json<UrlResponse>, ApiError> {
    let Json(req) = req?;
    let billing = state
        .billing_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Billing not configured"
        )))?;

    let mode = match req.mode.as_str() {
        "subscription" => stripe::CheckoutSessionMode::Subscription,
        "payment" => stripe::CheckoutSessionMode::Payment,
        _ => {
            return Err(ApiError::InvalidRequest(
                "mode must be subscription or payment".into(),
            ))
        }
    };

    let url = billing
        .create_checkout_session(
            user.id,
            org_id,
            mode,
            &req.price_id,
            &req.success_url,
            &req.cancel_url,
        )
        .await?;

    Ok(Json(UrlResponse { url }))
}

#[utoipa::path(
    get,
    path = "/v1/billing/portal",
    tag = "Billing",
    params(("return_url" = Option<String>, Query, description = "Return URL after portal")),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Portal URL", body = UrlResponse),
        (status = 400, description = "No Stripe customer", body = crate::common::ApiErrorResp),
        (status = 401, description = "Unauthorized", body = crate::common::ApiErrorResp),
        (status = 403, description = "Forbidden", body = crate::common::ApiErrorResp),
        (status = 500, description = "Billing not configured", body = crate::common::ApiErrorResp)
    )
)]
pub async fn portal(
    State(state): State<AppState>,
    RequireAuth(user): RequireAuth,
    Query(q): axum::extract::Query<PortalQuery>,
) -> Result<Json<UrlResponse>, ApiError> {
    let return_url = q.return_url.unwrap_or_else(|| state.cfg.base_url.clone());
    let billing = state
        .billing_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Billing not configured"
        )))?;

    let url = billing.create_portal_session(user.id, &return_url).await?;
    Ok(Json(UrlResponse { url }))
}

pub async fn org_portal(
    State(state): State<AppState>,
    RequireOrgBillingAccess(user, _org_id): RequireOrgBillingAccess,
    Query(q): axum::extract::Query<PortalQuery>,
) -> Result<Json<UrlResponse>, ApiError> {
    let return_url = q.return_url.unwrap_or_else(|| state.cfg.base_url.clone());
    let billing = state
        .billing_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Billing not configured"
        )))?;

    let url = billing.create_portal_session(user.id, &return_url).await?;
    Ok(Json(UrlResponse { url }))
}

#[derive(Deserialize)]
pub struct PortalQuery {
    return_url: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct SubscriptionStatusResponse {
    pub plan_name: Option<String>,
}

#[utoipa::path(
    get,
    path = "/v1/billing/subscription-status",
    tag = "Billing",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "User's subscription plan name, if subscribed"),
        (status = 401, description = "Unauthorized", body = crate::common::ApiErrorResp),
        (status = 500, description = "Billing not configured", body = crate::common::ApiErrorResp)
    )
)]
pub async fn subscription_status(
    State(state): State<AppState>,
    RequireAuth(user): RequireAuth,
) -> Result<Json<SubscriptionStatusResponse>, ApiError> {
    let plan_name = match &state.billing_service {
        Some(billing) => {
            billing
                .get_user_subscription_plan_name(user.id)
                .await
                .ok()
                .flatten()
        }
        None => None,
    };
    Ok(Json(SubscriptionStatusResponse { plan_name }))
}

#[derive(Serialize, ToSchema)]
pub struct SubscriptionResponse {
    pub id: String,
    pub status: String,
    pub current_period_end: Option<String>,
    pub cancel_at_period_end: bool,
    pub plan: Option<SubscriptionPlanResponse>,
}

#[derive(Serialize, ToSchema)]
pub struct SubscriptionPlanResponse {
    pub id: String,
    pub name: String,
    pub stripe_price_id: String,
    pub interval: String,
    pub amount_cents: i64,
    pub currency: String,
}

#[utoipa::path(
    get,
    path = "/v1/orgs/{org_id}/billing/subscription",
    tag = "Billing",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Org subscription with plan"),
        (status = 404, description = "No active subscription"),
        (status = 401, description = "Unauthorized", body = crate::common::ApiErrorResp),
        (status = 403, description = "Forbidden", body = crate::common::ApiErrorResp),
        (status = 500, description = "Billing not configured", body = crate::common::ApiErrorResp)
    )
)]
pub async fn get_subscription(
    State(state): State<AppState>,
    RequireOrgBillingAccess(_user, org_id): RequireOrgBillingAccess,
) -> Result<Json<SubscriptionResponse>, ApiError> {
    let billing = state
        .billing_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Billing not configured"
        )))?;

    let Some((sub, plan)) = billing.get_subscription_by_org(org_id).await? else {
        return Err(ApiError::NotFound);
    };

    let plan_resp = plan.map(|p| SubscriptionPlanResponse {
        id: p.id.to_string(),
        name: p.name,
        stripe_price_id: p.stripe_price_id,
        interval: p.interval,
        amount_cents: p.amount_cents,
        currency: p.currency,
    });

    Ok(Json(SubscriptionResponse {
        id: sub.id.to_string(),
        status: sub.status,
        current_period_end: sub
            .current_period_end
            .map(|t| t.to_rfc3339()),
        cancel_at_period_end: sub.cancel_at_period_end,
        plan: plan_resp,
    }))
}

#[utoipa::path(
    get,
    path = "/v1/orgs/{org_id}/billing/transactions",
    tag = "Billing",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Subscription and credit transactions"),
        (status = 401, description = "Unauthorized", body = crate::common::ApiErrorResp),
        (status = 403, description = "Forbidden", body = crate::common::ApiErrorResp),
        (status = 500, description = "Billing not configured", body = crate::common::ApiErrorResp)
    )
)]
pub async fn transactions(
    State(state): State<AppState>,
    RequireOrgBillingAccess(_user, org_id): RequireOrgBillingAccess,
) -> Result<Json<serde_json::Value>, ApiError> {
    let billing = state
        .billing_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Billing not configured"
        )))?;

    let (sub_tx, credit_tx) = billing
        .list_transactions_by_org(org_id)
        .await
        .map_err(ApiError::InternalError)?;

    Ok(Json(serde_json::json!({
        "subscription_transactions": sub_tx,
        "credit_transactions": credit_tx,
    })))
}

#[derive(Deserialize, ToSchema)]
pub struct ChangePlanRequest {
    pub price_id: String,
}

#[utoipa::path(
    post,
    path = "/v1/orgs/{org_id}/billing/subscription/cancel",
    tag = "Billing",
    params(("org_id" = String, description = "Org UUID"), ("immediate" = Option<bool>, Query, description = "Cancel immediately (default: at period end)")),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Subscription cancel scheduled or completed"),
        (status = 400, description = "Invalid request", body = crate::common::ApiErrorResp),
        (status = 401, description = "Unauthorized", body = crate::common::ApiErrorResp),
        (status = 403, description = "Forbidden", body = crate::common::ApiErrorResp),
        (status = 404, description = "No subscription", body = crate::common::ApiErrorResp),
        (status = 500, description = "Billing not configured", body = crate::common::ApiErrorResp)
    )
)]
pub async fn subscription_cancel(
    State(state): State<AppState>,
    RequireOrgBillingAccess(user, org_id): RequireOrgBillingAccess,
    Query(q): Query<CancelQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let billing = state
        .billing_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Billing not configured"
        )))?;

    if q.immediate.unwrap_or(false) {
        billing
            .cancel_subscription_immediately(user.id, org_id)
            .await?;
    } else {
        billing
            .cancel_subscription_at_period_end(user.id, org_id)
            .await?;
    }

    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct CancelQuery {
    immediate: Option<bool>,
}

#[utoipa::path(
    post,
    path = "/v1/orgs/{org_id}/billing/subscription/change-plan",
    tag = "Billing",
    params(("org_id" = String, description = "Org UUID")),
    request_body = ChangePlanRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Plan change scheduled"),
        (status = 400, description = "Invalid request", body = crate::common::ApiErrorResp),
        (status = 401, description = "Unauthorized", body = crate::common::ApiErrorResp),
        (status = 403, description = "Forbidden", body = crate::common::ApiErrorResp),
        (status = 404, description = "No subscription", body = crate::common::ApiErrorResp),
        (status = 500, description = "Billing not configured", body = crate::common::ApiErrorResp)
    )
)]
pub async fn subscription_change_plan(
    State(state): State<AppState>,
    RequireOrgBillingAccess(user, org_id): RequireOrgBillingAccess,
    req: Result<Json<ChangePlanRequest>, JsonRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let Json(req) = req?;
    let billing = state
        .billing_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Billing not configured"
        )))?;

    billing
        .change_subscription_plan(user.id, org_id, &req.price_id)
        .await?;

    Ok(Json(serde_json::json!({ "ok": true })))
}

pub fn billing_router(state: &AppState) -> Router<AppState> {
    let protected = Router::new()
        .route("/portal", get(portal))
        .route_layer(from_extractor_with_state::<RequireBillingManage, _>(
            state.clone(),
        ));
    let auth_only = Router::new()
        .route("/subscription-status", get(subscription_status))
        .route_layer(from_extractor_with_state::<RequireAuth, _>(state.clone()));
    Router::new()
        .route("/plans", get(list_plans))
        .route("/packages", get(list_packages))
        .merge(protected)
        .merge(auth_only)
}

/// Org-scoped billing router: mount at /v1/orgs/:org_id/billing
/// Uses RequireOrgBillingAccess: allows org owners/admins without global billing:manage.
pub fn org_billing_router(_state: &AppState) -> Router<AppState> {
    Router::new()
        .route("/plans", get(list_plans))
        .route("/packages", get(list_packages))
        .route("/checkout", post(checkout))
        .route("/portal", get(org_portal))
        .route("/subscription", get(get_subscription))
        .route("/transactions", get(transactions))
        .route("/subscription/cancel", post(subscription_cancel))
        .route("/subscription/change-plan", post(subscription_change_plan))
}
