// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-layer identity resolution helpers.

use crate::config::resolution::github_user::resolve_github_user;
use crate::io::config as io_config;
use crate::io::keystore::member;
use crate::support::validation;
use crate::Error;
use std::path::{Path, PathBuf};

/// Resolve member ID from non-interactive sources.
pub fn resolve_member_id_with_fallback(
    member_id: Option<String>,
    workspace: Option<&PathBuf>,
    keystore_root: &Path,
) -> Result<Option<String>, Error> {
    if let Some(id) = resolve_member_id_from_cli(member_id)? {
        return Ok(Some(id));
    }

    if let Some(id) = resolve_member_id_from_env()? {
        return Ok(Some(id));
    }

    if let Some(id) = resolve_member_id_from_config(workspace)? {
        return Ok(Some(id));
    }

    if let Some(id) = resolve_member_id_from_keystore(keystore_root)? {
        return Ok(Some(id));
    }

    Ok(None)
}

/// Resolve GitHub user from config and environment sources.
pub fn resolve_github_user_with_fallback(
    cli_value: Option<String>,
    base_dir: Option<&Path>,
) -> Result<Option<String>, Error> {
    resolve_github_user(cli_value, base_dir)
}

fn resolve_member_id_from_cli(member_id: Option<String>) -> Result<Option<String>, Error> {
    if let Some(id) = member_id {
        validation::validate_member_id(&id)?;
        Ok(Some(id))
    } else {
        Ok(None)
    }
}

fn resolve_member_id_from_env() -> Result<Option<String>, Error> {
    if let Ok(id) = std::env::var("SECRETENV_MEMBER_ID") {
        validation::validate_member_id(&id)?;
        Ok(Some(id))
    } else {
        Ok(None)
    }
}

fn resolve_member_id_from_config(_workspace: Option<&PathBuf>) -> Result<Option<String>, Error> {
    let config_path = io_config::paths::get_global_config_path()?;
    let config = io_config::store::load_config_file(&config_path)?;
    if let Some(id) = config.get("member_id").cloned() {
        validation::validate_member_id(&id)?;
        Ok(Some(id))
    } else {
        Ok(None)
    }
}

fn resolve_member_id_from_keystore(keystore_root: &Path) -> Result<Option<String>, Error> {
    if let Some(id) = member::load_single_member_id_from_keystore(keystore_root)? {
        Ok(Some(id))
    } else {
        Ok(None)
    }
}
