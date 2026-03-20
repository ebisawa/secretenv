// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Keystore member-oriented lookup helpers.

use crate::io::keystore::active;
use crate::io::keystore::paths;
use crate::io::keystore::storage::{list_kids, load_public_key};
use crate::model::public_key::PublicKey;
use crate::support::fs::list_dir;
use crate::support::path::display_path_relative_to_cwd;
use crate::{Error, Result};
use std::path::Path;

/// Active key document lookup result.
pub struct ActiveKeyDocument {
    pub kid: String,
    pub public_key: PublicKey,
}

/// Load member_id from keystore if exactly one exists.
pub fn load_single_member_id_from_keystore(keystore_root: &Path) -> Result<Option<String>> {
    if !keystore_root.exists() {
        return Ok(None);
    }

    let member_dirs: Vec<String> = list_dir(keystore_root)?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            if entry.path().is_dir() {
                entry.file_name().to_str().map(String::from)
            } else {
                None
            }
        })
        .collect();

    match member_dirs.len() {
        1 => Ok(Some(member_dirs[0].clone())),
        _ => Ok(None),
    }
}

/// Load the active public key document for a member when the private key still exists.
pub fn find_active_key_document(
    member_id: &str,
    keystore_root: &Path,
) -> Result<Option<ActiveKeyDocument>> {
    let Some(kid) = active::load_active_kid(member_id, keystore_root)? else {
        return Ok(None);
    };

    let private_key_path =
        paths::get_private_key_file_path_from_root(keystore_root, member_id, &kid);
    if !private_key_path.exists() {
        active::clear_active_kid(member_id, keystore_root)?;
        return Ok(None);
    }

    let public_key = load_public_key(keystore_root, member_id, &kid)?;
    Ok(Some(ActiveKeyDocument { kid, public_key }))
}

/// Select latest valid (non-expired) key for a member.
pub fn select_latest_valid_kid(keystore_root: &Path, member_id: &str) -> Result<String> {
    let kids = list_kids(keystore_root, member_id)?;
    if kids.is_empty() {
        return Err(Error::NotFound {
            message: format!("No keys found for member: {}", member_id),
        });
    }

    let now = time::OffsetDateTime::now_utc();
    for kid in kids.iter().rev() {
        let public_key = load_public_key(keystore_root, member_id, kid)?;
        let expires_at = time::OffsetDateTime::parse(
            &public_key.protected.expires_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|e| Error::Parse {
            message: format!("Invalid expires_at format: {}", e),
            source: Some(Box::new(e)),
        })?;

        if now < expires_at {
            return Ok(kid.clone());
        }
    }

    Err(Error::NotFound {
        message: format!(
            "No valid (non-expired) keys found for member: {}",
            member_id
        ),
    })
}

/// Remove a key directory from the keystore.
pub fn remove_key_directory(keystore_root: &Path, member_id: &str, kid: &str) -> Result<()> {
    let key_dir = keystore_root.join(member_id).join(kid);
    std::fs::remove_dir_all(&key_dir).map_err(|e| Error::Io {
        message: format!(
            "Failed to remove key directory {}: {}",
            display_path_relative_to_cwd(&key_dir),
            e
        ),
        source: Some(e),
    })
}
