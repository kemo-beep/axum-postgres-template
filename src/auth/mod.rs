//! Authentication and authorization modules.

pub mod email_sender;
pub mod extractor;
pub mod permissions;
pub mod rbac_routes;
pub mod repository;
pub mod routes;
pub mod service;

pub use email_sender::{ConsoleEmailSender, EmailSender, SmtpEmailSender};
