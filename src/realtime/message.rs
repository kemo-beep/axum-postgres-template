//! WebSocket message envelope for realtime events.

use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Envelope for all WebSocket messages. Extensible for future event types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsEnvelope {
    pub r#type: String,
    pub payload: serde_json::Value,
    #[serde(default = "default_ts")]
    pub ts: String,
}

fn default_ts() -> String {
    Utc::now().to_rfc3339()
}

impl WsEnvelope {
    pub fn connected() -> Self {
        Self {
            r#type: "connected".into(),
            payload: serde_json::json!({}),
            ts: Utc::now().to_rfc3339(),
        }
    }
}
