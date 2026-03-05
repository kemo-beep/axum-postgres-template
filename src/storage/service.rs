//! R2 / S3 storage service: presigned URLs, upload.
//!
//! Uses aws-sdk-s3 with custom endpoint for Cloudflare R2.

use std::time::Duration;

use anyhow::Result;
use aws_credential_types::Credentials;
use aws_sdk_s3::config::Config;
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;
use aws_types::region::Region;

use crate::cfg::R2Config;

/// R2/S3-compatible storage: presigned URLs for get/put, direct upload.
#[derive(Clone)]
pub struct StorageService {
    client: Client,
    bucket: String,
}

impl StorageService {
    pub async fn from_config(config: &R2Config) -> Result<Self> {
        let credentials = Credentials::new(
            &config.access_key_id,
            &config.secret_access_key,
            None,
            None,
            "r2",
        );

        let s3_config = Config::builder()
            .credentials_provider(credentials)
            .region(Region::new("auto"))
            .endpoint_url(&config.endpoint)
            .force_path_style(true)
            .build();

        let client = Client::from_conf(s3_config);

        Ok(Self {
            client,
            bucket: config.bucket_name.clone(),
        })
    }

    pub async fn presigned_get(&self, key: &str, expires_in: Duration) -> Result<String> {
        let presigning_config = PresigningConfig::builder().expires_in(expires_in).build()?;

        let presigned = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .presigned(presigning_config)
            .await?;

        Ok(presigned.uri().to_string())
    }

    pub async fn presigned_put(&self, key: &str, expires_in: Duration) -> Result<String> {
        let presigning_config = PresigningConfig::builder().expires_in(expires_in).build()?;

        let presigned = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .presigned(presigning_config)
            .await?;

        Ok(presigned.uri().to_string())
    }

    pub async fn upload(&self, key: &str, body: bytes::Bytes) -> Result<()> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(body))
            .send()
            .await?;

        Ok(())
    }
}
