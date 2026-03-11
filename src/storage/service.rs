//! R2 / S3 storage service: presigned URLs, upload, list, delete.
//!
//! Uses aws-sdk-s3 with custom endpoint for Cloudflare R2.

use std::time::Duration;

const R2_TIMEOUT: Duration = Duration::from_secs(30);

use anyhow::Result;
use aws_sdk_s3::types::ObjectIdentifier;
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

        let presigned = tokio::time::timeout(
            R2_TIMEOUT,
            self.client
                .get_object()
                .bucket(&self.bucket)
                .key(key)
                .presigned(presigning_config),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Storage request timed out"))??;

        Ok(presigned.uri().to_string())
    }

    pub async fn presigned_put(&self, key: &str, expires_in: Duration) -> Result<String> {
        let presigning_config = PresigningConfig::builder().expires_in(expires_in).build()?;

        let presigned = tokio::time::timeout(
            R2_TIMEOUT,
            self.client
                .put_object()
                .bucket(&self.bucket)
                .key(key)
                .presigned(presigning_config),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Storage request timed out"))??;

        Ok(presigned.uri().to_string())
    }

    pub async fn upload(&self, key: &str, body: bytes::Bytes) -> Result<()> {
        tokio::time::timeout(
            R2_TIMEOUT,
            self.client
                .put_object()
                .bucket(&self.bucket)
                .key(key)
                .body(ByteStream::from(body))
                .send(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Storage request timed out"))??;

        Ok(())
    }

    /// List object keys with the given prefix. Paginates through all results.
    pub async fn list_objects_by_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        let mut keys = Vec::new();
        let mut continuation_token: Option<String> = None;

        loop {
            let mut list = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix);

            if let Some(ref token) = continuation_token {
                list = list.continuation_token(token);
            }

            let resp = tokio::time::timeout(R2_TIMEOUT, list.send())
                .await
                .map_err(|_| anyhow::anyhow!("Storage request timed out"))??;
            for obj in resp.contents() {
                if let Some(key) = obj.key() {
                    keys.push(key.to_string());
                }
            }

            continuation_token = resp.next_continuation_token().map(String::from);
            if continuation_token.is_none() {
                break;
            }
        }

        Ok(keys)
    }

    /// Delete all objects under the given prefix. Returns the number of objects deleted.
    pub async fn delete_prefix(&self, prefix: &str) -> Result<u64> {
        let keys = self.list_objects_by_prefix(prefix).await?;
        if keys.is_empty() {
            return Ok(0);
        }

        // S3 DeleteObjects supports up to 1000 keys per request
        const BATCH_SIZE: usize = 1000;
        let mut deleted: u64 = 0;

        for chunk in keys.chunks(BATCH_SIZE) {
            let objects: Vec<ObjectIdentifier> = chunk
                .iter()
                .map(|k| ObjectIdentifier::builder().key(k).build())
                .collect::<Result<Vec<_>, _>>()?;

            tokio::time::timeout(
                R2_TIMEOUT,
                self.client
                    .delete_objects()
                    .bucket(&self.bucket)
                    .delete(
                        aws_sdk_s3::types::Delete::builder()
                            .set_objects(Some(objects))
                            .build()?,
                    )
                    .send(),
            )
            .await
            .map_err(|_| anyhow::anyhow!("Storage request timed out"))??;

            deleted += chunk.len() as u64;
        }

        Ok(deleted)
    }
}
