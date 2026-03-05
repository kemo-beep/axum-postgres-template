//! Central module for shared types and errors.
//!
//! All cross-cutting types (ID wrappers, API errors) live here to avoid
//! circular dependencies and keep a single source of truth. Domain modules
//! (auth, billing, org, storage) depend on `common`, never the reverse.

pub mod errors;
pub mod types;

pub use errors::{ApiError, ApiErrorResp};
pub use types::{OrgId, TenantId, UserId, WorkspaceId};
