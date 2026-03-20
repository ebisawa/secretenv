// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Helper functions for keystore operations

use crate::io::keystore::active::load_active_kid;
use crate::io::keystore::storage::list_kids;
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
        let kids = list_kids(keystore_root, member_id)?;
        if !kids.contains(&kid.to_string()) {
            return Err(Error::NotFound {
                message: format!(
                    "Specified kid '{}' not found for member '{}'",
                    kid, member_id
                ),
            });
        }
        return Ok(kid.to_string());
    }

    // Try to get active kid
    if let Some(active_kid) = load_active_kid(member_id, keystore_root)? {
        return Ok(active_kid);
    }

    // Fall back to latest kid
    let kids = list_kids(keystore_root, member_id)?;
    if kids.is_empty() {
        return Err(Error::NotFound {
            message: format!("No keys found for member: {}", member_id),
        });
    }

    // ULIDs sort chronologically, so the last one is the latest
    // We've checked that kids is not empty above, so last() will return Some
    kids.into_iter().last().ok_or_else(|| Error::Config {
        message: "Internal error: kids list became empty after validation".to_string(),
    })
}
