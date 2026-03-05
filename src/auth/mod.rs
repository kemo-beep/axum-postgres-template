//! Authentication and authorization modules.

pub mod api_key_repository;
pub mod api_key_routes;
pub mod api_key_service;
pub mod email_sender;
pub mod email_templates;
pub mod extractor;
pub mod permissions;
pub mod rbac_routes;
pub mod rbac_service;
pub mod repository;
pub mod routes;
pub mod service;

pub use api_key_service::ApiKeyScope;
pub use email_sender::{ConsoleEmailSender, EmailSender, SmtpEmailSender};
