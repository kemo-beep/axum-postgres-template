//! Shared service traits.
//!
//! Phase 6.2: Define `JobQueue` trait for background work. Template implements with
//! `tokio::spawn`. Production: use Redis + `background-jobs` or similar.

/// Trait for enqueueing background jobs.
///
/// Template implementation uses `tokio::spawn` (no persistence).
/// Production upgrade: use Redis-backed `background-jobs` or similar.
pub trait JobQueue: Send + Sync {
    /// Enqueue a job to run in the background.
    fn spawn(&self, f: impl std::future::Future<Output = ()> + Send + 'static);
}

/// Simple in-process job queue using `tokio::spawn`.
#[derive(Clone, Default)]
pub struct SpawnJobQueue;

impl JobQueue for SpawnJobQueue {
    fn spawn(&self, f: impl std::future::Future<Output = ()> + Send + 'static) {
        tokio::spawn(f);
    }
}
