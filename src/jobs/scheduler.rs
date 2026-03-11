//! Scheduler: spawns tokio tasks for recurring jobs.

use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use tracing::{info, warn};

use crate::auth::api_key_repository::ApiKeyRepository;
use crate::auth::audit::AuditRepository;
use crate::auth::repository::{
    EmailCodeRepository, PasswordResetRepository, TokenBlacklistRepository,
};
use crate::org::repository::OrgRepository;
use crate::AppState;

/// Spawns all scheduled background jobs. Call once at startup.
pub fn spawn_all(state: AppState) {
    // Subscription reconciliation: hourly
    if let Some(billing) = state.billing_service.clone() {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600));
            interval.tick().await; // skip first immediate tick
            loop {
                interval.tick().await;
                match billing.reconcile_stale_cancel_at_period_end().await {
                    Ok(n) if n > 0 => {
                        info!(count = n, "Subscription reconciliation: marked stale subscriptions as canceled");
                    }
                    Ok(_) => {}
                    Err(e) => {
                        warn!("Subscription reconciliation failed: {:?}", e);
                    }
                }
            }
        });
    }

    // Cleanup: daily (expired login codes, password reset tokens, invites, token blacklist)
    {
        let pool = state.db.pool.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(86400));
            interval.tick().await;
            loop {
                interval.tick().await;
                run_cleanup(&pool).await;
            }
        });
    }

    // Trial ending reminder: daily
    if let Some(billing) = state.billing_service.clone() {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(86400));
            interval.tick().await;
            loop {
                interval.tick().await;
                match billing.send_trial_ending_reminders().await {
                    Ok(n) if n > 0 => info!(count = n, "Trial ending reminders sent"),
                    Ok(_) => {}
                    Err(e) => warn!("Trial ending reminders failed: {:?}", e),
                }
            }
        });
    }

    // Past-due reminder: daily
    if let Some(billing) = state.billing_service.clone() {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(86400));
            interval.tick().await;
            loop {
                interval.tick().await;
                match billing.send_past_due_reminders().await {
                    Ok(n) if n > 0 => info!(count = n, "Past-due reminders sent"),
                    Ok(_) => {}
                    Err(e) => warn!("Past-due reminders failed: {:?}", e),
                }
            }
        });
    }
}

async fn run_cleanup(pool: &sqlx::PgPool) {
    let email_code_repo = EmailCodeRepository::new(pool.clone());
    let password_reset_repo = PasswordResetRepository::new(pool.clone());
    let token_blacklist_repo = TokenBlacklistRepository::new(pool.clone());
    let org_repo = OrgRepository::new(pool.clone());

    let mut total: u64 = 0;
    if let Ok(n) = email_code_repo.delete_expired().await {
        if n > 0 {
            info!(count = n, "Cleaned up expired email login codes");
            total += n;
        }
    } else {
        warn!("Failed to delete expired email login codes");
    }
    if let Ok(n) = password_reset_repo.delete_expired().await {
        if n > 0 {
            info!(count = n, "Cleaned up expired password reset tokens");
            total += n;
        }
    } else {
        warn!("Failed to delete expired password reset tokens");
    }
    if let Ok(n) = token_blacklist_repo.delete_expired().await {
        if n > 0 {
            info!(count = n, "Cleaned up expired token blacklist entries");
            total += n;
        }
    } else {
        warn!("Failed to delete expired token blacklist entries");
    }
    if let Ok(n) = org_repo.delete_expired_invites().await {
        if n > 0 {
            info!(count = n, "Cleaned up expired org invites");
            total += n;
        }
    } else {
        warn!("Failed to delete expired org invites");
    }
    if total > 0 {
        info!(total, "Cleanup job completed");
    }

    // Audit retention: delete api_key_usage_log older than 90 days
    let api_key_repo = ApiKeyRepository::new(pool.clone());
    let cutoff = Utc::now() - ChronoDuration::days(90);
    if let Ok(n) = api_key_repo.delete_usage_log_older_than(cutoff).await {
        if n > 0 {
            info!(count = n, "Deleted old api_key_usage_log entries");
        }
    } else {
        warn!("Failed to delete old api_key_usage_log entries");
    }

    // Audit retention: delete audit_log older than 1 year
    let audit_repo = AuditRepository::new(pool.clone());
    let audit_cutoff = Utc::now() - ChronoDuration::days(365);
    if let Ok(n) = audit_repo.delete_older_than(audit_cutoff).await {
        if n > 0 {
            info!(count = n, "Deleted old audit_log entries");
        }
    } else {
        warn!("Failed to delete old audit_log entries");
    }
}
