//! Versioned API router: /v1/auth/*, /v1/files/*, /v1/billing/*, etc.

use axum::{middleware, Router};

use crate::AppState;

/// Builds the v1 API router.
pub fn router(state: &AppState) -> Router<AppState> {
    let api = Router::new()
        .nest("/contact", crate::routes::contact::router())
        .nest("/auth", crate::auth::routes::router())
        .nest("/files", crate::storage::routes::router(state))
        .nest("/billing", crate::billing::routes::billing_router(state))
        .nest(
            "/orgs",
            crate::org::routes::router()
                .nest(
                    "/{org_id}/billing",
                    crate::billing::routes::org_billing_router(state),
                )
                .nest(
                    "/{org_id}/workspaces/{workspace_id}/files",
                    crate::storage::routes::workspace_files_router(state),
                ),
        )
        .nest("/invites", crate::org::routes::invite_router())
        .merge(crate::auth::rbac_routes::router(state));

    api.route_layer(middleware::from_fn(
        crate::middleware::require_idempotency_key,
    ))
}
