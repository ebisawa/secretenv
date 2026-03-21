// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Active key management

use crate::support::fs::{atomic, check_permission, load_text};
use crate::Error;
use std::fs;
use std::path::Path;

/// Load the active kid for a member (v3: ULID format)
///
/// Returns the kid (26-character ULID) of the active key, or None if no active key is set
pub fn load_active_kid(member_id: &str, keystore_root: &Path) -> Result<Option<String>, Error> {
    let active_path = keystore_root.join(member_id).join("active");

    if !active_path.exists() {
        return Ok(None);
    }

    if let Some(msg) = check_permission(&active_path) {
        tracing::warn!("{}", msg);
    }

    let content = load_text(&active_path)?;

    // Trim whitespace and newlines
    let kid = content.trim().to_string();

    if kid.is_empty() {
        return Ok(None);
    }

    // Validate ULID format (26 characters, Base32)
    if kid.len() != 26 {
        return Err(Error::InvalidArgument {
            message: format!(
                "Invalid active kid format: expected 26 characters (ULID), got {}",
                kid.len()
            ),
        });
    }

    Ok(Some(kid))
}

/// Set the active kid for a member (v3: ULID format)
///
/// Creates or updates the active file with the specified kid (26-character ULID)
pub fn set_active_kid(member_id: &str, kid: &str, keystore_root: &Path) -> Result<(), Error> {
    // Validate ULID format (26 characters, Base32)
    if kid.len() != 26 {
        return Err(Error::InvalidArgument {
            message: format!(
                "Invalid kid format: expected 26 characters (ULID), got {}",
                kid.len()
            ),
        });
    }

    let active_path = keystore_root.join(member_id).join("active");

    // Write kid to active file atomically (with trailing newline)
    atomic::save_text_restricted(&active_path, &format!("{}\n", kid))
}

/// Clear the active kid for a member
///
/// Removes the active file
pub fn clear_active_kid(member_id: &str, keystore_root: &Path) -> Result<(), Error> {
    let active_path = keystore_root.join(member_id).join("active");

    if active_path.exists() {
        fs::remove_file(&active_path).map_err(|e| Error::Io {
            message: format!("Failed to remove active file: {}", e),
            source: Some(e),
        })?;
    }

    Ok(())
}
