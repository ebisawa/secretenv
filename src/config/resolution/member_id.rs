// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Member ID resolution
//!
//! Resolves member_id based on the following priority order:
//! 1. CLI argument (--member-id)
//! 2. Environment variable (SECRETENV_MEMBER_ID)
//! 3. Global config (SECRETENV_HOME/config.toml)
//! 4. Single member_id in keystore

use crate::io::config as io_config;
use crate::io::keystore::paths;
use crate::support::fs::list_dir;
use crate::{Error, Result};
use std::path::Path;

use super::common::resolve_string_with_priority;

/// Resolve member_id based on priority order
///
/// # Priority Order
///
/// 1. `member_id_opt` parameter (CLI argument)
/// 2. `SECRETENV_MEMBER_ID` environment variable
/// 3. Global config (`SECRETENV_HOME/config.toml`)
/// 4. Single member_id in keystore (`SECRETENV_HOME/keys/`)
pub fn resolve_member_id(member_id_opt: Option<String>, base_dir: Option<&Path>) -> Result<String> {
    // Priority 1-3: Use common resolution logic
    if let Some(member_id) = resolve_string_with_priority(
        member_id_opt,
        Some("SECRETENV_MEMBER_ID"),
        "member_id",
        base_dir,
        None,
    )? {
        return Ok(member_id);
    }

    // Priority 4: Single member_id in keystore
    resolve_member_id_from_keystore(base_dir)
}

/// Resolve member_id from keystore (single member_id only)
fn resolve_member_id_from_keystore(base_dir: Option<&Path>) -> Result<String> {
    let keystore_root = match base_dir {
        Some(dir) => paths::get_keystore_root_from_base(dir),
        None => {
            let base = io_config::paths::get_base_dir()?;
            paths::get_keystore_root_from_base(&base)
        }
    };

    if !keystore_root.exists() {
        return Err(missing_member_id_error(
            "member_id not configured and keystore directory does not exist",
        ));
    }

    let member_ids: Vec<String> = list_dir(&keystore_root)?
        .filter_map(|entry| {
            entry.ok().and_then(|e| {
                if e.path().is_dir() {
                    e.file_name().to_str().map(|s| s.to_string())
                } else {
                    None
                }
            })
        })
        .collect();

    match member_ids.len() {
        0 => Err(missing_member_id_error(
            "member_id not configured and no member_ids found in keystore",
        )),
        1 => Ok(member_ids[0].clone()),
        _ => Err(missing_member_id_error(
            "member_id not configured and multiple member_ids found in keystore",
        )),
    }
}

fn missing_member_id_error(detail: &str) -> Error {
    Error::Config {
        message: format!(
            "{detail}.\n\n\
             Specify member_id explicitly using one of:\n\
             1. Specify --member-id <id>\n\
             2. Set environment variable: export SECRETENV_MEMBER_ID=<id>\n\
             3. Set in config: secretenv config set member_id <id>"
        ),
    }
}
