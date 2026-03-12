//! Admin-only endpoint to list users for impersonation and support.

use axum::{extract::Query, extract::State, Json};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::extractor::RequireAdmin;
use crate::common::ApiError;
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct ListUsersQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AdminUserItem {
    pub id: String,
    pub email: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ListUsersResponse {
    pub users: Vec<AdminUserItem>,
    pub total: i64,
}

/// List users for admin (impersonation, support). Admin only.
#[utoipa::path(
    get,
    path = "/internal/users",
    tag = "Internal",
    params(("limit" = Option<i64>, Query, description = "Page size (default 50, max 100)"), ("offset" = Option<i64>, Query, description = "Offset for pagination")),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Paginated user list", body = ListUsersResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 500, description = "Internal error")
    )
)]
pub async fn list_users(
    State(state): State<AppState>,
    Query(query): Query<ListUsersQuery>,
    RequireAdmin: RequireAdmin,
) -> Result<Json<ListUsersResponse>, ApiError> {
    let auth = state
        .auth_service
        .as_ref()
        .ok_or(ApiError::InternalError(anyhow::anyhow!(
            "Auth not configured"
        )))?;

    let limit = query.limit.clamp(1, 100);
    let offset = query.offset.max(0);

    let (rows, total) = auth.list_users(limit, offset).await?;

    let users = rows
        .into_iter()
        .map(|(id, email, created_at)| AdminUserItem {
            id: id.0.to_string(),
            email,
            created_at: created_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(ListUsersResponse { users, total }))
}
