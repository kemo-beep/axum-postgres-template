//! Billing routes and Stripe webhook handler.

use axum::{
    body::Bytes,
    extract::{Query, State},
    extract::rejection::JsonRejection,
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::api_error::ApiError;
use crate::auth::extractor::RequireAuth;
use crate::AppState;

/// Stripe webhook handler. Verifies signature and returns 200 quickly.
/// Process events async in production (spawn task or job queue).
#[utoipa::path(
    post,
    path = "/webhooks/stripe",
    tag = "Webhooks",
    responses(
        (status = 200, description = "Webhook accepted"),
        (status = 400, description = "Invalid signature", body = crate::api_error::ApiErrorResp),
        (status = 500, description = "Stripe not configured", body = crate::api_error::ApiErrorResp)
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
        .ok_or(ApiError::InternalError(anyhow::anyhow!("Stripe not configured")))?;

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
        (status = 500, description = "Billing not configured", body = crate::api_error::ApiErrorResp)
    )
)]
pub async fn list_plans(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let billing = state.billing_service.as_ref().ok_or(ApiError::InternalError(
        anyhow::anyhow!("Billing not configured"),
    ))?;
    let plans = billing
        .list_plans()
        .await
        .map_err(|e| ApiError::InternalError(e.into()))?;
    Ok(Json(serde_json::json!(plans)))
}

#[utoipa::path(
    get,
    path = "/v1/billing/packages",
    tag = "Billing",
    responses(
        (status = 200, description = "List of token packages"),
        (status = 500, description = "Billing not configured", body = crate::api_error::ApiErrorResp)
    )
)]
pub async fn list_packages(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let billing = state.billing_service.as_ref().ok_or(ApiError::InternalError(
        anyhow::anyhow!("Billing not configured"),
    ))?;
    let packages = billing
        .list_packages()
        .await
        .map_err(|e| ApiError::InternalError(e.into()))?;
    Ok(Json(serde_json::json!(packages)))
}

#[utoipa::path(
    post,
    path = "/v1/billing/checkout",
    tag = "Billing",
    request_body = CheckoutRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Checkout URL", body = UrlResponse),
        (status = 400, description = "Invalid request", body = crate::api_error::ApiErrorResp),
        (status = 401, description = "Unauthorized", body = crate::api_error::ApiErrorResp),
        (status = 500, description = "Billing not configured", body = crate::api_error::ApiErrorResp)
    )
)]
pub async fn checkout(
    State(state): State<AppState>,
    RequireAuth(user): RequireAuth,
    req: Result<Json<CheckoutRequest>, JsonRejection>,
) -> Result<Json<UrlResponse>, ApiError> {
    let Json(req) = req?;
    let billing = state.billing_service.as_ref().ok_or(ApiError::InternalError(
        anyhow::anyhow!("Billing not configured"),
    ))?;

    let mode = match req.mode.as_str() {
        "subscription" => stripe::CheckoutSessionMode::Subscription,
        "payment" => stripe::CheckoutSessionMode::Payment,
        _ => return Err(ApiError::InvalidRequest("mode must be subscription or payment".into())),
    };

    let url = billing
        .create_checkout_session(
            user.id,
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
        (status = 400, description = "No Stripe customer", body = crate::api_error::ApiErrorResp),
        (status = 401, description = "Unauthorized", body = crate::api_error::ApiErrorResp),
        (status = 500, description = "Billing not configured", body = crate::api_error::ApiErrorResp)
    )
)]
pub async fn portal(
    State(state): State<AppState>,
    RequireAuth(user): RequireAuth,
    Query(q): axum::extract::Query<PortalQuery>,
) -> Result<Json<UrlResponse>, ApiError> {
    let return_url = q.return_url.unwrap_or_else(|| state.cfg.base_url.clone());
    let billing = state.billing_service.as_ref().ok_or(ApiError::InternalError(
        anyhow::anyhow!("Billing not configured"),
    ))?;

    let url = billing.create_portal_session(user.id, &return_url).await?;
    Ok(Json(UrlResponse { url }))
}

#[derive(Deserialize)]
pub struct PortalQuery {
    return_url: Option<String>,
}

#[utoipa::path(
    get,
    path = "/v1/billing/transactions",
    tag = "Billing",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Subscription and credit transactions"),
        (status = 401, description = "Unauthorized", body = crate::api_error::ApiErrorResp),
        (status = 500, description = "Billing not configured", body = crate::api_error::ApiErrorResp)
    )
)]
pub async fn transactions(
    State(state): State<AppState>,
    RequireAuth(user): RequireAuth,
) -> Result<Json<serde_json::Value>, ApiError> {
    let billing = state.billing_service.as_ref().ok_or(ApiError::InternalError(
        anyhow::anyhow!("Billing not configured"),
    ))?;

    let (sub_tx, credit_tx) = billing
        .list_transactions(user.id)
        .await
        .map_err(|e| ApiError::InternalError(e.into()))?;

    Ok(Json(serde_json::json!({
        "subscription_transactions": sub_tx,
        "credit_transactions": credit_tx,
    })))
}

pub fn billing_router() -> Router<AppState> {
    Router::new()
        .route("/plans", get(list_plans))
        .route("/packages", get(list_packages))
        .route("/checkout", post(checkout))
        .route("/portal", get(portal))
        .route("/transactions", get(transactions))
}
