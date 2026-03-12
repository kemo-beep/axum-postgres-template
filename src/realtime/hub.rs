//! In-memory broadcast hub for per-user WebSocket messages.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{broadcast, RwLock};

use crate::common::UserId;

/// Per-user broadcast channel. Uses DashMap-like pattern with RwLock + HashMap.
#[derive(Clone, Default)]
pub struct BroadcastHub {
    /// Map of user_id -> broadcast sender. Receivers are created per connection.
    channels: Arc<RwLock<HashMap<UserId, broadcast::Sender<String>>>>,
}

/// Default channel capacity per user.
const CHANNEL_CAPACITY: usize = 64;

impl BroadcastHub {
    pub fn new() -> Self {
        Self {
            channels: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Subscribe to messages for a user. Returns a receiver; messages are sent as JSON strings.
    pub async fn subscribe(&self, user_id: UserId) -> broadcast::Receiver<String> {
        let mut guard = self.channels.write().await;
        let sender = guard
            .entry(user_id)
            .or_insert_with(|| broadcast::channel(CHANNEL_CAPACITY).0)
            .clone();
        sender.subscribe()
    }

    /// Publish a message to a user. Non-blocking; drops if receiver is lagging.
    pub async fn publish(&self, user_id: UserId, message: String) {
        let guard = self.channels.read().await;
        if let Some(sender) = guard.get(&user_id) {
            let _ = sender.send(message);
        }
    }
}
