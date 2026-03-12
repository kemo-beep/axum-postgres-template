//! WebSocket route handler.

use axum::{
    extract::{
        ws::{WebSocket, WebSocketUpgrade},
        Query, State,
    },
    response::Response,
    routing::get,
    Router,
};
use serde::Deserialize;

use crate::common::ApiError;
use crate::realtime::handle_socket;
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct WsQuery {
    token: Option<String>,
}

/// WebSocket upgrade handler. Requires ?token= with short-lived JWT from GET /v1/auth/ws-token.
pub async fn ws_handler(
    State(state): State<AppState>,
    Query(query): Query<WsQuery>,
    ws: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let token = query
        .token
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or(ApiError::Unauthorized)?;

    let auth = state
        .auth_service
        .as_ref()
        .ok_or_else(|| ApiError::InternalError(anyhow::anyhow!("Auth not configured")))?;

    let token_info = auth.verify_token(token).await?;
    let user_id = token_info.user_id;
    let hub = state
        .realtime_hub
        .as_ref()
        .ok_or_else(|| ApiError::InternalError(anyhow::anyhow!("Realtime not configured")))?
        .clone();

    Ok(ws.on_upgrade(move |socket: WebSocket| {
        handle_socket(socket, user_id, hub)
    }))
}

pub fn router(_state: &AppState) -> Router<AppState> {
    Router::new().route("/ws", get(ws_handler))
}
