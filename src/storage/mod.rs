//! Storage module: R2/S3 file storage, presigned URLs.

pub mod routes;
pub mod service;

pub use service::StorageService;
