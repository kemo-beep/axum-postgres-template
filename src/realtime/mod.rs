//! WebSocket realtime infrastructure.

pub mod handler;
pub mod hub;
pub mod message;
pub mod routes;

pub use handler::handle_socket;
pub use hub::BroadcastHub;
pub use message::WsEnvelope;
