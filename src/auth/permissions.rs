//! Permission naming convention and constants.
//!
//! Format: `resource:action` (e.g. `users:read`, `billing:manage`, `files:read`).
//! Use these constants when checking permissions or defining RBAC policies.

/// Permission: read user profiles, list users, view roles/permissions.
pub const USERS_READ: &str = "users:read";

/// Permission: create, update, delete users; assign/revoke roles.
pub const USERS_WRITE: &str = "users:write";

/// Permission: manage billing (checkout, portal, view transactions).
pub const BILLING_MANAGE: &str = "billing:manage";

/// Permission: get presigned URLs for reading files.
pub const FILES_READ: &str = "files:read";

/// Permission: upload files, get presigned PUT URLs.
pub const FILES_WRITE: &str = "files:write";

/// Permission: create orgs, invite members, manage org settings.
pub const ORGS_MANAGE: &str = "orgs:manage";

/// Permission: create workspaces, manage workspace settings.
pub const WORKSPACES_MANAGE: &str = "workspaces:manage";

/// Checks that a permission string follows the `resource:action` convention.
/// Returns true if the string contains exactly one `:` and both parts are non-empty.
pub fn is_valid_permission(name: &str) -> bool {
    let mut parts = name.splitn(2, ':');
    matches!((parts.next(), parts.next()), (Some(r), Some(a)) if !r.is_empty() && !a.is_empty())
}
