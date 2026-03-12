//! Contact form route. Public, rate-limited. Sends submission to support email via EmailSender.

use axum::{extract::State, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use utoipa::ToSchema;
use validator::Validate;

use crate::common::{ApiError, ApiErrorResp};
use crate::AppState;

#[derive(Deserialize, ToSchema, Validate)]
pub struct ContactRequest {
    #[validate(length(min = 1, max = 200))]
    pub name: String,
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 1, max = 200))]
    pub subject: String,
    #[validate(length(min = 1, max = 5000))]
    pub message: String,
}

#[derive(Serialize, ToSchema)]
pub struct ContactResponse {
    pub ok: bool,
}

/// POST /v1/contact — submit contact form. Rate limited (3/min per IP). No auth.
#[utoipa::path(
    post,
    path = "/v1/contact",
    request_body = ContactRequest,
    responses(
        (status = 200, description = "Form submitted", body = ContactResponse),
        (status = 400, description = "Validation error", body = ApiErrorResp),
        (status = 503, description = "Email not configured or send failed")
    ),
    tag = "contact"
)]
pub async fn contact_submit(
    State(state): State<AppState>,
    Json(req): Json<ContactRequest>,
) -> Result<Json<ContactResponse>, ApiError> {
    req.validate()
        .map_err(|e| ApiError::UnprocessableEntity(e.to_string()))?;

    let Some(email_sender) = &state.email_sender else {
        return Err(ApiError::InternalError(anyhow::anyhow!(
            "Contact form disabled: SMTP not configured"
        )));
    };

    let to = state.cfg.smtp.as_ref().map(|s| s.from.as_str()).ok_or_else(|| {
        ApiError::InternalError(anyhow::anyhow!(
            "Contact form disabled: no mail recipient configured"
        ))
    })?;

    email_sender
        .send_contact_form(
            to,
            req.name.trim(),
            req.email.trim(),
            req.subject.trim(),
            req.message.trim(),
        )
        .await
        .map_err(|e| {
            tracing::warn!(err = %e, "Contact form email send failed");
            ApiError::InternalError(anyhow::anyhow!("Failed to send message. Please try again later."))
        })?;

    Ok(Json(ContactResponse { ok: true }))
}

pub fn router() -> Router<AppState> {
    let limit_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(20) // 1 per 20 sec = 3/min
            .burst_size(3)
            .finish()
            .unwrap(),
    );

    Router::new()
        .route("/", post(contact_submit))
        .layer(GovernorLayer::new(limit_conf))
}
