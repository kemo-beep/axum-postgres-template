//! WebSocket connection handler.

use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use tokio::time::interval;
use tracing::info;

use crate::common::UserId;
use crate::realtime::message::WsEnvelope;
use crate::realtime::BroadcastHub;

/// Serves a WebSocket connection: forwards hub messages and sends periodic pings.
pub async fn handle_socket(mut socket: WebSocket, user_id: UserId, hub: BroadcastHub) {
    let connected = WsEnvelope::connected();
    if let Ok(json) = serde_json::to_string(&connected) {
        if socket.send(Message::Text(json.into())).await.is_err() {
            return;
        }
    }

    let (mut sender, mut receiver) = socket.split();

    let mut hub_rx = hub.subscribe(user_id).await;
    let mut ping_interval = interval(Duration::from_secs(30));

    let send_task = async move {
        loop {
            tokio::select! {
                result = hub_rx.recv() => {
                    match result {
                        Ok(msg) => {
                            if sender.send(Message::Text(msg.into())).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                _ = ping_interval.tick() => {
                    if sender.send(Message::Ping(bytes::Bytes::new())).await.is_err() {
                        break;
                    }
                }
            }
        }
    };

    let recv_task = async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Close(_) => break,
                Message::Ping(_) | Message::Pong(_) => {}
                Message::Text(_) | Message::Binary(_) => {}
            }
        }
    };

    tokio::select! {
        _ = send_task => {}
        _ = recv_task => {}
    }

    info!("websocket disconnected user_id={}", user_id.0);
}
