use axum::{middleware, routing::get, routing::post, routing::put, Router};

pub mod admin_users;
pub mod contact;
pub mod health_check;
pub mod impersonate;
pub mod job_stats;
pub mod v1;

use crate::auth::extractor::RequireAdmin;
use crate::AppState;

/// Internal routes: job-stats, impersonation, feature flags. Auth-protected via RequireAdmin.
fn internal_routes(state: &AppState) -> Router<AppState> {
    Router::new()
        .route("/job-stats", get(job_stats::job_stats))
        .route("/users", get(admin_users::list_users))
        .route("/impersonate", post(impersonate::impersonate))
        .route("/feature-flags", get(crate::feature_flags::routes::list_all))
        .route("/feature-flags/{name}", put(crate::feature_flags::routes::set_flag))
        .route_layer(middleware::from_extractor_with_state::<RequireAdmin, _>(state.clone()))
}

/// Root router: /health (probes), /internal/*, /v1/*, /webhooks/*, /swagger-ui.
pub fn router(state: &AppState) -> Router<AppState> {
    Router::new()
        .route("/health", get(health_check::health_check))
        .nest("/internal", internal_routes(state))
        .nest("/v1", v1::router(state))
        .nest("/webhooks", crate::billing::routes::router())
}
