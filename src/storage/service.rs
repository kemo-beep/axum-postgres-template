//! R2 / S3 storage service: presigned URLs, upload.
//!
//! Add `aws-config` and `aws-sdk-s3` to Cargo.toml for full R2 support.
//! This stub returns errors when storage is not implemented.

use std::time::Duration;

use anyhow::Result;

use crate::cfg::R2Config;

#[derive(Clone)]
pub struct StorageService;

impl StorageService {
    pub async fn from_config(_config: &R2Config) -> Result<Self> {
        // Stub: requires aws-sdk-s3. Add to Cargo.toml:
        // aws-config = "1.0"
        // aws-sdk-s3 = "1.0"
        Err(anyhow::anyhow!(
            "R2 storage: add aws-config and aws-sdk-s3 to Cargo.toml (requires Rust 1.91+)"
        ))
    }

    pub async fn presigned_get(&self, _key: &str, _expires_in: Duration) -> Result<String> {
        Err(anyhow::anyhow!("Storage not configured"))
    }

    pub async fn presigned_put(&self, _key: &str, _expires_in: Duration) -> Result<String> {
        Err(anyhow::anyhow!("Storage not configured"))
    }
}
