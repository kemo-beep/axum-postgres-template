//! Versioned API router: /v1/auth/*, /v1/files/*, etc.

use axum::Router;

use crate::AppState;

/// Builds the v1 API router.
pub fn router() -> Router<AppState> {
    Router::new()
        .nest("/auth", crate::auth::routes::router())
        .nest("/files", crate::storage::routes::router())
}
