//! Internal job queue observability endpoint.

use axum::{extract::State, Json};
use serde::Serialize;
use utoipa::ToSchema;

use crate::AppState;

#[derive(Serialize, ToSchema)]
pub struct JobStatsResponse {
    pub enqueue: u64,
    pub success: u64,
    pub fail: u64,
    pub dead_letter: u64,
    pub last_latency_ms: Option<u64>,
    pub latency_sample_count: u64,
}

/// Returns job queue stats (enqueue, success, fail, dead-letter counts, latency).
/// Intended for internal monitoring; consider restricting to loopback in production.
#[utoipa::path(
    get,
    path = "/internal/job-stats",
    tag = "Internal",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Job queue stats", body = JobStatsResponse)
    )
)]
pub async fn job_stats(State(state): State<AppState>) -> Json<JobStatsResponse> {
    let stats = state.job_queue.stats();
    Json(JobStatsResponse {
        enqueue: stats.enqueue,
        success: stats.success,
        fail: stats.fail,
        dead_letter: stats.dead_letter,
        last_latency_ms: stats.last_latency_ms,
        latency_sample_count: stats.latency_sample_count,
    })
}
