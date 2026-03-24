// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key management operations (list, activate, remove, export).

use super::{KeyActivateResult, KeyExportResult, KeyInfo, KeyListResult, KeyRemoveResult};
use crate::feature::context::crypto::validate_private_key_material;
use crate::feature::key::protection::decrypt_private_key;
use crate::io::keystore::active::{clear_active_kid, load_active_kid, set_active_kid};
use crate::io::keystore::member::{remove_key_directory, select_latest_valid_kid};
use crate::io::keystore::paths::get_private_key_file_path_from_root;
use crate::io::keystore::resolver::KeystoreResolver;
use crate::io::keystore::storage::{list_kids, list_member_ids, load_private_key, load_public_key};
use crate::io::ssh::backend::SignatureBackend;
use crate::model::private_key::PrivateKeyPlaintext;
use crate::{Error, Result};
use std::path::PathBuf;

/// List keys in keystore (optionally filtered by member_id).
pub fn list_keys(home: Option<PathBuf>, member_id: Option<String>) -> Result<KeyListResult> {
    let keystore_root = KeystoreResolver::resolve(home.as_ref())?;

    let member_ids = if let Some(mid) = member_id {
        vec![mid]
    } else {
        list_member_ids(&keystore_root)?
    };

    let mut all_key_infos = Vec::new();
    let mut total_keys = 0;

    for member_id in &member_ids {
        let kids = list_kids(&keystore_root, member_id)?;
        let active_kid = load_active_kid(member_id, &keystore_root)?;

        let mut member_key_infos = Vec::new();
        for kid in &kids {
            let public_key = load_public_key(&keystore_root, member_id, kid)?;
            let is_active = active_kid.as_ref() == Some(kid);

            member_key_infos.push(KeyInfo {
                kid: kid.clone(),
                member_id: public_key.protected.member_id.clone(),
                created_at: public_key.protected.created_at.clone().unwrap_or_default(),
                expires_at: public_key.protected.expires_at.clone(),
                active: is_active,
                format: public_key.protected.format.clone(),
            });
        }

        total_keys += member_key_infos.len();
        all_key_infos.push((member_id.clone(), member_key_infos));
    }

    Ok(KeyListResult {
        entries: all_key_infos,
        total_keys,
    })
}

/// Activate a key for a member (or latest valid key if not specified).
pub fn activate_key(
    home: Option<PathBuf>,
    member_id: String,
    kid: Option<String>,
) -> Result<KeyActivateResult> {
    let keystore_root = KeystoreResolver::resolve(home.as_ref())?;

    let kid = match kid {
        Some(k) => k,
        None => select_latest_valid_kid(&keystore_root, &member_id)?,
    };

    let private_key_path = get_private_key_file_path_from_root(&keystore_root, &member_id, &kid);
    if !private_key_path.exists() {
        return Err(Error::NotFound {
            message: format!("Key not found: {}", kid),
        });
    }

    set_active_kid(&member_id, &kid, &keystore_root)?;

    Ok(KeyActivateResult { member_id, kid })
}

/// Remove a key for a member.
pub fn remove_key(
    home: Option<PathBuf>,
    member_id: String,
    kid: String,
    force: bool,
) -> Result<KeyRemoveResult> {
    let keystore_root = KeystoreResolver::resolve(home.as_ref())?;

    let key_dir = keystore_root.join(&member_id).join(&kid);
    if !key_dir.exists() {
        return Err(Error::NotFound {
            message: format!("Key not found: {}", kid),
        });
    }

    let active_kid = load_active_kid(&member_id, &keystore_root)?;
    let was_active = active_kid.as_ref() == Some(&kid);

    if was_active && !force {
        return Err(Error::Config {
            message: format!(
                "Cannot remove active key '{}'. Use --force to remove anyway.",
                kid
            ),
        });
    }

    remove_key_directory(&keystore_root, &member_id, &kid)?;

    if was_active {
        clear_active_kid(&member_id, &keystore_root)?;
    }

    Ok(KeyRemoveResult {
        member_id,
        kid,
        was_active,
    })
}

/// Export a public key for a member.
pub fn export_key(
    home: Option<PathBuf>,
    member_id: String,
    kid: Option<String>,
) -> Result<KeyExportResult> {
    let keystore_root = KeystoreResolver::resolve(home.as_ref())?;

    let kid = resolve_active_kid(&keystore_root, &member_id, kid)?;
    let public_key = load_public_key(&keystore_root, &member_id, &kid)?;

    Ok(KeyExportResult {
        member_id,
        kid,
        public_key,
    })
}

/// Decrypted private key with metadata for portable export.
pub struct LoadedPrivateKey {
    pub plaintext: PrivateKeyPlaintext,
    pub member_id: String,
    pub kid: String,
    pub created_at: String,
    pub expires_at: String,
}

/// Load and decrypt a private key from keystore using SSH backend.
pub fn load_and_decrypt_private_key(
    home: Option<PathBuf>,
    member_id: String,
    kid: Option<String>,
    backend: &dyn SignatureBackend,
    ssh_pubkey: &str,
    debug: bool,
) -> Result<LoadedPrivateKey> {
    let keystore_root = KeystoreResolver::resolve(home.as_ref())?;
    let kid = resolve_active_kid(&keystore_root, &member_id, kid)?;

    let encrypted = load_private_key(&keystore_root, &member_id, &kid)?;
    let plaintext = decrypt_private_key(&encrypted, backend, ssh_pubkey, debug)?;
    validate_private_key_material(&plaintext)?;

    Ok(LoadedPrivateKey {
        plaintext,
        member_id,
        kid,
        created_at: encrypted.protected.created_at.clone(),
        expires_at: encrypted.protected.expires_at.clone(),
    })
}

/// Resolve the key ID, falling back to the active key if not specified.
fn resolve_active_kid(
    keystore_root: &std::path::Path,
    member_id: &str,
    kid: Option<String>,
) -> Result<String> {
    match kid {
        Some(k) => Ok(k),
        None => load_active_kid(member_id, keystore_root)?.ok_or_else(|| Error::NotFound {
            message: format!("No active key for member: {}", member_id),
        }),
    }
}
