//! Pagination for list endpoints. Use `?limit=50&offset=0`.

use serde::Deserialize;

/// Default page size for list endpoints.
pub const DEFAULT_LIMIT: u32 = 50;
/// Maximum allowed limit.
pub const MAX_LIMIT: u32 = 100;

/// Query parameters for offset-based pagination.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct PaginationQuery {
    /// Number of items to return. Default 50, max 100.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Number of items to skip.
    #[serde(default)]
    pub offset: Option<u32>,
}

impl PaginationQuery {
    /// Returns validated limit (clamped to 1..=MAX_LIMIT).
    pub fn limit(&self) -> u32 {
        self.limit
            .map(|l| l.clamp(1, MAX_LIMIT))
            .unwrap_or(DEFAULT_LIMIT)
    }

    /// Returns validated offset (>= 0).
    pub fn offset(&self) -> u32 {
        self.offset.unwrap_or(0)
    }
}
