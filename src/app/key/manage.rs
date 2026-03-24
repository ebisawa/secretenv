// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use crate::app::context::options::CommonCommandOptions;
use crate::app::context::ssh::ResolvedSshSigner;
use crate::app::key::export::{save_exported_public_key, save_portable_private_key};
use crate::app::key::identity::{resolve_member_id_for_removal, resolve_required_key_identity};
use crate::app::key::types::{
    KeyActivateResult, KeyExportPrivateResult, KeyExportResult, KeyListResult, KeyRemoveResult,
};
use crate::feature::key::manage::export::export_key;
use crate::feature::key::manage::mutation::{activate_key, remove_key};
use crate::feature::key::manage::private_load::load_and_decrypt_private_key;
use crate::feature::key::manage::query::list_keys;
use crate::feature::key::portable_export::export_private_key_portable;
use crate::Result;

pub fn list_keys_command(
    options: &CommonCommandOptions,
    member_id: Option<String>,
) -> Result<KeyListResult> {
    list_keys(options.home.clone(), member_id).map(KeyListResult::from)
}

pub fn activate_key_command(
    options: &CommonCommandOptions,
    member_id: Option<String>,
    kid: Option<String>,
) -> Result<KeyActivateResult> {
    let identity = resolve_required_key_identity(options, member_id)?;
    activate_key(options.home.clone(), identity.member_id, kid).map(KeyActivateResult::from)
}

pub fn remove_key_command(
    options: &CommonCommandOptions,
    member_id: Option<String>,
    kid: String,
    force: bool,
) -> Result<KeyRemoveResult> {
    let resolved_member_id = resolve_member_id_for_removal(options, member_id, &kid)?;
    remove_key(options.home.clone(), resolved_member_id, kid, force).map(KeyRemoveResult::from)
}

pub fn export_key_command(
    options: &CommonCommandOptions,
    member_id: Option<String>,
    kid: Option<String>,
    out: &Path,
) -> Result<KeyExportResult> {
    let identity = resolve_required_key_identity(options, member_id)?;
    let result = export_key(options.home.clone(), identity.member_id, kid)?;
    save_exported_public_key(out, &result.public_key)?;
    Ok(result.into())
}

pub fn export_private_key_command(
    options: &CommonCommandOptions,
    member_id: Option<String>,
    kid: Option<String>,
    password: &str,
    ssh_ctx: ResolvedSshSigner,
) -> Result<KeyExportPrivateResult> {
    let identity = resolve_required_key_identity(options, member_id)?;
    let loaded = load_and_decrypt_private_key(
        options.home.clone(),
        identity.member_id,
        kid,
        ssh_ctx.backend.as_ref(),
        &ssh_ctx.public_key,
        options.verbose,
    )?;

    let encoded_key = export_private_key_portable(
        &loaded.plaintext,
        &loaded.member_id,
        &loaded.kid,
        &loaded.created_at,
        &loaded.expires_at,
        password,
        options.verbose,
    )?;

    Ok(crate::feature::key::portable_export::PortableExportOutput {
        member_id: loaded.member_id,
        kid: loaded.kid,
        encoded_key,
    }
    .into())
}

pub fn save_exported_private_key(out: &Path, encoded_key: &str) -> Result<()> {
    save_portable_private_key(out, encoded_key)
}
