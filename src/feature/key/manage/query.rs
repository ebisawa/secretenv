// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::feature::key::manage::common::resolve_keystore_root;
use crate::feature::key::types::{KeyInfo, KeyListResult};
use crate::io::keystore::active::load_active_kid;
use crate::io::keystore::storage::{list_kids, list_member_ids, load_public_key};
use crate::Result;
use std::path::PathBuf;

pub fn list_keys(home: Option<PathBuf>, member_id: Option<String>) -> Result<KeyListResult> {
    let keystore_root = resolve_keystore_root(home)?;
    let member_ids = resolve_member_ids(&keystore_root, member_id)?;
    let entries = load_key_infos(&keystore_root, &member_ids)?;
    let total_keys = entries.iter().map(|(_, keys)| keys.len()).sum();

    Ok(KeyListResult {
        entries,
        total_keys,
    })
}

fn resolve_member_ids(
    keystore_root: &std::path::Path,
    member_id: Option<String>,
) -> Result<Vec<String>> {
    match member_id {
        Some(member_id) => Ok(vec![member_id]),
        None => list_member_ids(keystore_root),
    }
}

fn load_key_infos(
    keystore_root: &std::path::Path,
    member_ids: &[String],
) -> Result<Vec<(String, Vec<KeyInfo>)>> {
    member_ids
        .iter()
        .map(|member_id| load_member_key_infos(keystore_root, member_id))
        .collect()
}

fn load_member_key_infos(
    keystore_root: &std::path::Path,
    member_id: &str,
) -> Result<(String, Vec<KeyInfo>)> {
    let kids = list_kids(keystore_root, member_id)?;
    let active_kid = load_active_kid(member_id, keystore_root)?;
    let key_infos = kids
        .iter()
        .map(|kid| load_key_info(keystore_root, member_id, kid, active_kid.as_ref()))
        .collect::<Result<Vec<_>>>()?;

    Ok((member_id.to_string(), key_infos))
}

fn load_key_info(
    keystore_root: &std::path::Path,
    member_id: &str,
    kid: &str,
    active_kid: Option<&String>,
) -> Result<KeyInfo> {
    let public_key = load_public_key(keystore_root, member_id, kid)?;
    Ok(KeyInfo {
        kid: kid.to_string(),
        member_id: public_key.protected.member_id.clone(),
        created_at: public_key.protected.created_at.clone().unwrap_or_default(),
        expires_at: public_key.protected.expires_at.clone(),
        active: active_kid == Some(&kid.to_string()),
        format: public_key.protected.format.clone(),
    })
}
