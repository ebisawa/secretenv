// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Config feature - configuration operations.

use crate::io::config;
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::path::PathBuf;

// NOTE: Keep in sync with PRD config.toml documentation (global config.toml keys).
pub(crate) const VALID_KEYS: &[&str] = &[
    "member_id",
    "ssh_key",
    "ssh_keygen",
    "ssh_add",
    "ssh_signer",
    "github_user",
];

#[derive(Debug, Clone, Copy)]
pub enum ConfigScope {
    Global,
}

pub(crate) fn normalize_key(key: &str) -> Result<String> {
    // User-facing convenience:
    // historically some users typed `gihub_user` (typo). Normalize to the canonical key.
    if key == "gihub_user" {
        return Ok("github_user".to_string());
    }

    if VALID_KEYS.contains(&key) {
        Ok(key.to_string())
    } else {
        Err(Error::InvalidArgument {
            message: format!(
                "invalid key '{}'. Valid keys: {}",
                key,
                VALID_KEYS.join(", ")
            ),
        })
    }
}

pub fn validate_key(key: &str) -> Result<()> {
    let _ = normalize_key(key)?;
    Ok(())
}

pub fn resolve_config_value(key: &str) -> Result<(Option<String>, Option<String>)> {
    if let Some(value) = load_global_config()?.get(key) {
        return Ok((Some(value.clone()), Some("global".to_string())));
    }

    Ok((None, None))
}

pub fn get_config_path_and_scope() -> Result<(PathBuf, ConfigScope)> {
    Ok((
        config::paths::get_global_config_path()?,
        ConfigScope::Global,
    ))
}

pub fn load_global_config() -> Result<BTreeMap<String, String>> {
    let config_path = config::paths::get_global_config_path()?;
    config::store::load_config_file(&config_path)
}
