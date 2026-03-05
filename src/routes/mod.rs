use axum::{routing::get, Router};

pub mod health_check;
pub mod v1;

use crate::AppState;

/// Root router: /health (probes), /v1/*, /webhooks/*, /swagger-ui.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(health_check::health_check))
        .nest("/v1", v1::router())
        .nest("/webhooks", crate::billing::routes::router())
}
