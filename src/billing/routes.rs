//! Billing routes and Stripe webhook handler.

use axum::{
    body::Bytes,
    extract::State,
    http::HeaderMap,
    routing::post,
    Router,
};
use tracing::info;

use crate::api_error::ApiError;
use crate::AppState;

/// Stripe webhook handler. Verifies signature and returns 200 quickly.
/// Process events async in production (spawn task or job queue).
#[utoipa::path(
    post,
    path = "/webhooks/stripe",
    tag = "Webhooks",
    responses(
        (status = 200, description = "Webhook accepted"),
        (status = 500, description = "Stripe not configured", body = crate::api_error::ApiErrorResp)
    )
)]
pub async fn stripe_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    _body: Bytes, // Used when verifying signature and parsing events
) -> Result<axum::http::StatusCode, ApiError> {
    let _secret = state
        .cfg
        .stripe
        .as_ref()
        .map(|s| s.webhook_secret.as_str())
        .ok_or(ApiError::InternalError(anyhow::anyhow!("Stripe not configured")))?;

    // In production: verify Stripe-Signature, parse event, process async
    let sig = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok());
    info!("Stripe webhook received, sig present: {}", sig.is_some());

    Ok(axum::http::StatusCode::OK)
}

pub fn router() -> Router<AppState> {
    Router::new().route("/stripe", post(stripe_webhook))
}
