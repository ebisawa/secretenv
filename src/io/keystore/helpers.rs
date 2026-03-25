// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Helper functions for keystore operations

use crate::io::keystore::active::load_active_kid;
use crate::io::keystore::member::select_most_recent_kid;
use crate::io::keystore::storage::list_kids;
use crate::support::kid::kid_display_lossy;
use crate::support::kid::normalize_kid;
use crate::{Error, Result};
use std::path::Path;

/// Resolves the kid to use for a given member_id
///
/// Resolution order:
/// 1. If `kid_override` is provided, use it
/// 2. If an active kid is set, use it
/// 3. Otherwise, use the latest (most recent) kid
///
/// # Arguments
/// * `keystore_root` - Path to the keystore root directory
/// * `member_id` - The member ID to resolve the kid for
/// * `kid_override` - Optional explicit kid to use (bypasses active/latest selection)
///
/// # Returns
/// The resolved kid as a String
///
/// # Errors
/// - `Error::NotFound` if no keys found for the member_id
/// - `Error::NotFound` if kid_override is provided but doesn't exist
pub fn resolve_kid(
    keystore_root: &Path,
    member_id: &str,
    kid_override: Option<&str>,
) -> Result<String> {
    // If explicit kid provided, validate and use it
    if let Some(kid) = kid_override {
        let normalized_kid = normalize_kid(kid)?;
        let kids = list_kids(keystore_root, member_id)?;
        if !kids.contains(&normalized_kid) {
            return Err(Error::NotFound {
                message: format!(
                    "Specified kid '{}' not found for member '{}'",
                    kid_display_lossy(kid),
                    member_id
                ),
            });
        }
        return Ok(normalized_kid);
    }

    // Try to get active kid
    if let Some(active_kid) = load_active_kid(member_id, keystore_root)? {
        return Ok(active_kid);
    }

    // Fall back to the most recent key by created_at desc, then kid asc.
    select_most_recent_kid(keystore_root, member_id)
}
