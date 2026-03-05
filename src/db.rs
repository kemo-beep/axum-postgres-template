use std::time::Duration;

use anyhow::Result;
use sqlx::{postgres::PgPoolOptions, PgPool};
use tracing::{info, warn};

const RETRY_ATTEMPTS: u32 = 5;
const RETRY_BASE_DELAY_MS: u64 = 1000;

#[derive(Clone)]
pub struct Db {
    pub pool: PgPool,
}

impl Db {
    /// Creates a connection pool with retry and exponential backoff on connection failure.
    pub async fn new(dsn: &str, pool_max_size: u32) -> Result<Self> {
        let mut last_err = None;
        for attempt in 1..=RETRY_ATTEMPTS {
            match PgPoolOptions::new()
                .max_connections(pool_max_size)
                .connect(dsn)
                .await
            {
                Ok(pool) => {
                    if attempt > 1 {
                        info!("Database connection established on attempt {}", attempt);
                    }
                    return Ok(Db { pool });
                }
                Err(e) => {
                    last_err = Some(e);
                    if attempt < RETRY_ATTEMPTS {
                        let delay_ms = RETRY_BASE_DELAY_MS * 2u64.pow(attempt - 1);
                        warn!(
                            "Database connection failed (attempt {}/{}), retrying in {}ms: {}",
                            attempt,
                            RETRY_ATTEMPTS,
                            delay_ms,
                            last_err.as_ref().unwrap()
                        );
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    }
                }
            }
        }
        Err(last_err.unwrap().into())
    }

    pub async fn migrate(&self) -> Result<()> {
        // This integrates database migrations into the application binary to ensure the database
        // is properly migrated during startup.
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        Ok(())
    }
}
