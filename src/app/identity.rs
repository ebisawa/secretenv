// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-layer identity resolution helpers.

use crate::config::resolution::common::load_field_from_global_config;
use crate::config::resolution::github_user::resolve_github_user;
use crate::io::keystore::member;
use crate::support::validation;
use crate::Error;
use std::path::Path;

/// Resolve member ID from non-interactive sources.
pub fn resolve_member_id_with_fallback(
    member_id: Option<String>,
    keystore_root: &Path,
    base_dir: Option<&Path>,
) -> Result<Option<String>, Error> {
    if let Some(id) = resolve_member_id_from_cli(member_id)? {
        return Ok(Some(id));
    }

    if let Some(id) = resolve_member_id_from_env()? {
        return Ok(Some(id));
    }

    if let Some(id) = resolve_member_id_from_config(base_dir)? {
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

fn resolve_member_id_from_config(base_dir: Option<&Path>) -> Result<Option<String>, Error> {
    if let Some(id) = load_field_from_global_config("member_id", base_dir)? {
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
