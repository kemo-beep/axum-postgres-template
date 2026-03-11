//! Shared service traits.
//!
//! Phase 6.2: Define `JobQueue` trait for background work. Template implements with
//! `tokio::spawn`. Production: use Redis + `background-jobs` or similar.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const RETRY_ATTEMPTS: u32 = 5;
const RETRY_BASE_DELAY_MS: u64 = 1000;

/// Stats snapshot for job queue observability.
#[derive(Clone, Debug, Default)]
pub struct JobStats {
    pub enqueue: u64,
    pub success: u64,
    pub fail: u64,
    pub dead_letter: u64,
    pub last_latency_ms: Option<u64>,
    pub latency_sample_count: u64,
}

/// Trait for enqueueing background jobs.
///
/// Template implementation uses `tokio::spawn` (no persistence).
/// Production upgrade: use Redis-backed `background-jobs` or similar.
pub trait JobQueue: Send + Sync {
    /// Enqueue a job to run in the background.
    fn spawn(&self, f: impl std::future::Future<Output = ()> + Send + 'static);

    /// Enqueue a job that returns Result. Retries with exponential backoff on failure.
    /// After max retries, logs as dead-letter and increments dead_letter count.
    /// The closure is called once per attempt so the job can be retried.
    fn spawn_result<F, Fut>(
        &self,
        job_name: &'static str,
        f: F,
    ) where
        F: Fn() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<(), anyhow::Error>> + Send + 'static;
}

/// Simple in-process job queue using `tokio::spawn`.
#[derive(Clone, Default)]
pub struct SpawnJobQueue;

impl JobQueue for SpawnJobQueue {
    fn spawn(&self, f: impl std::future::Future<Output = ()> + Send + 'static) {
        tokio::spawn(f);
    }

    fn spawn_result<F, Fut>(
        &self,
        job_name: &'static str,
        f: F,
    ) where
        F: Fn() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<(), anyhow::Error>> + Send + 'static,
    {
        tokio::spawn(async move {
            if let Err(e) = f().await {
                tracing::warn!(job = job_name, "Job failed (no retry): {:?}", e);
            }
        });
    }
}

/// Job queue with observability (enqueue/success/fail/dead-letter counts, latency)
/// and retries with exponential backoff for spawn_result jobs.
#[derive(Clone)]
pub struct ObservantJobQueue {
    inner: SpawnJobQueue,
    enqueue_count: std::sync::Arc<AtomicU64>,
    success_count: std::sync::Arc<AtomicU64>,
    fail_count: std::sync::Arc<AtomicU64>,
    dead_letter_count: std::sync::Arc<AtomicU64>,
    last_latency_ms: std::sync::Arc<AtomicU64>,
    latency_sample_count: std::sync::Arc<AtomicU64>,
}

impl Default for ObservantJobQueue {
    fn default() -> Self {
        Self {
            inner: SpawnJobQueue,
            enqueue_count: std::sync::Arc::new(AtomicU64::new(0)),
            success_count: std::sync::Arc::new(AtomicU64::new(0)),
            fail_count: std::sync::Arc::new(AtomicU64::new(0)),
            dead_letter_count: std::sync::Arc::new(AtomicU64::new(0)),
            last_latency_ms: std::sync::Arc::new(AtomicU64::new(0)),
            latency_sample_count: std::sync::Arc::new(AtomicU64::new(0)),
        }
    }
}

impl ObservantJobQueue {
    /// Returns a snapshot of job queue stats.
    pub fn stats(&self) -> JobStats {
        JobStats {
            enqueue: self.enqueue_count.load(Ordering::Relaxed),
            success: self.success_count.load(Ordering::Relaxed),
            fail: self.fail_count.load(Ordering::Relaxed),
            dead_letter: self.dead_letter_count.load(Ordering::Relaxed),
            last_latency_ms: {
                let v = self.last_latency_ms.load(Ordering::Relaxed);
                if v == 0 {
                    None
                } else {
                    Some(v)
                }
            },
            latency_sample_count: self.latency_sample_count.load(Ordering::Relaxed),
        }
    }
}

impl JobQueue for ObservantJobQueue {
    fn spawn(&self, f: impl std::future::Future<Output = ()> + Send + 'static) {
        self.enqueue_count.fetch_add(1, Ordering::Relaxed);
        let success_count = self.success_count.clone();
        let last_latency_ms = self.last_latency_ms.clone();
        let latency_sample_count = self.latency_sample_count.clone();
        self.inner.spawn(async move {
            let start = Instant::now();
            f.await;
            let ms = start.elapsed().as_millis() as u64;
            success_count.fetch_add(1, Ordering::Relaxed);
            last_latency_ms.store(ms, Ordering::Relaxed);
            latency_sample_count.fetch_add(1, Ordering::Relaxed);
        });
    }

    fn spawn_result<F, Fut>(
        &self,
        job_name: &'static str,
        f: F,
    ) where
        F: Fn() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<(), anyhow::Error>> + Send + 'static,
    {
        self.enqueue_count.fetch_add(1, Ordering::Relaxed);
        let success_count = self.success_count.clone();
        let fail_count = self.fail_count.clone();
        let dead_letter_count = self.dead_letter_count.clone();
        let last_latency_ms = self.last_latency_ms.clone();
        let latency_sample_count = self.latency_sample_count.clone();

        self.inner.spawn(async move {
            let start = Instant::now();
            let mut last_err = None;
            for attempt in 1..=RETRY_ATTEMPTS {
                match f().await {
                    Ok(()) => {
                        let ms = start.elapsed().as_millis() as u64;
                        success_count.fetch_add(1, Ordering::Relaxed);
                        last_latency_ms.store(ms, Ordering::Relaxed);
                        latency_sample_count.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    Err(e) => {
                        last_err = Some(e);
                        fail_count.fetch_add(1, Ordering::Relaxed);
                        if attempt < RETRY_ATTEMPTS {
                            let delay_ms = RETRY_BASE_DELAY_MS * 2u64.pow(attempt - 1);
                            tracing::warn!(
                                job = job_name,
                                attempt,
                                "Job failed, retrying in {}ms: {:?}",
                                delay_ms,
                                last_err
                            );
                            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                        }
                    }
                }
            }

            // Final failure: dead-letter
            dead_letter_count.fetch_add(1, Ordering::Relaxed);
            tracing::error!(
                job = job_name,
                "Job failed after {} attempts, dead-lettered: {:?}",
                RETRY_ATTEMPTS,
                last_err
            );
        });
    }
}
