// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-layer orchestration for key generation.

mod export;
mod github;
mod timestamp;
mod types;

use crate::app::context::CommonCommandOptions;
use crate::app::identity::{resolve_github_user_with_fallback, resolve_member_id_with_fallback};
use crate::feature::context::ssh::{resolve_ssh_signing_context, SshSigningParams};
use crate::feature::key::generate::{generate_key, KeyGenerationOptions};
use crate::feature::key::manage::{activate_key, export_key, list_keys, remove_key};
use crate::io::keystore::storage;
use crate::{Error, Result};
use export::save_exported_public_key;
pub(crate) use github::{
    resolve_github_account, verify_generated_key_github_binding, verify_preflight_github_binding,
};
use timestamp::resolve_key_timestamps;
pub use types::{
    KeyActivateResult, KeyExportResult, KeyInfo, KeyListResult, KeyNewResult, KeyRemoveResult,
};

/// Resolve GitHub account metadata, verify SSH key on GitHub, then generate a key.
pub fn generate_key_with_github_user(
    mut options: KeyGenerationOptions,
    github_user: Option<String>,
) -> Result<KeyNewResult> {
    let github_account = resolve_github_account(github_user, options.verbose)?;
    options.github_account = github_account.clone();

    let ssh_context = resolve_ssh_signing_context(&SshSigningParams {
        ssh_key: options.ssh_key.clone(),
        signing_method: options.ssh_signer,
        base_dir: options.home.clone(),
        verbose: options.verbose,
    })?;

    let github_verification = if let Some(account) = github_account.as_ref() {
        verify_preflight_github_binding(&ssh_context.public_key, account, options.verbose)?
    } else {
        crate::io::verify_online::VerificationStatus::NotConfigured
    };

    options.ssh_context = Some(ssh_context);
    let result = generate_key(options)?;

    let mut key_result: KeyNewResult = result.into();
    key_result.github_verification = github_verification;
    Ok(key_result)
}

pub fn generate_key_command(
    options: &CommonCommandOptions,
    member_id_arg: Option<String>,
    github_user_arg: Option<String>,
    expires_at_arg: &Option<String>,
    valid_for_arg: &Option<String>,
    no_activate: bool,
) -> Result<KeyNewResult> {
    let keystore_root = options.resolve_keystore_root()?;
    let member_id = require_member_id(resolve_member_id_with_fallback(
        member_id_arg,
        &keystore_root,
        options.home.as_deref(),
    )?)?;
    let github_user = resolve_github_user_with_fallback(github_user_arg, options.home.as_deref())?;
    let (created_at, expires_at) = resolve_key_timestamps(expires_at_arg, valid_for_arg)?;

    generate_key_with_github_user(
        KeyGenerationOptions {
            member_id,
            home: options.home.clone(),
            ssh_key: options.identity.clone(),
            ssh_signer: options.ssh_signer,
            created_at,
            expires_at,
            no_activate,
            debug: options.verbose,
            github_account: None,
            verbose: options.verbose,
            ssh_context: None,
        },
        github_user,
    )
}

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
    let keystore_root = options.resolve_keystore_root()?;
    let member_id = require_member_id(resolve_member_id_with_fallback(
        member_id,
        &keystore_root,
        options.home.as_deref(),
    )?)?;
    activate_key(options.home.clone(), member_id, kid).map(KeyActivateResult::from)
}

pub fn remove_key_command(
    options: &CommonCommandOptions,
    member_id: Option<String>,
    kid: String,
    force: bool,
) -> Result<KeyRemoveResult> {
    let resolved_member_id = match resolve_member_id_with_fallback(
        member_id.clone(),
        &options.resolve_keystore_root()?,
        options.home.as_deref(),
    ) {
        Ok(Some(member_id)) => member_id,
        Ok(None) if member_id.is_none() => {
            let keystore_root = options.resolve_keystore_root()?;
            storage::find_member_by_kid(&keystore_root, &kid)?
        }
        Ok(None) => {
            return Err(missing_member_id_error());
        }
        Err(error) => return Err(error),
    };

    remove_key(options.home.clone(), resolved_member_id, kid, force).map(KeyRemoveResult::from)
}

pub fn export_key_command(
    options: &CommonCommandOptions,
    member_id: Option<String>,
    kid: Option<String>,
    out: &std::path::Path,
) -> Result<KeyExportResult> {
    let keystore_root = options.resolve_keystore_root()?;
    let member_id = require_member_id(resolve_member_id_with_fallback(
        member_id,
        &keystore_root,
        options.home.as_deref(),
    )?)?;
    let result = export_key(options.home.clone(), member_id, kid)?;
    save_exported_public_key(out, &result.public_key)?;
    Ok(result.into())
}

fn require_member_id(member_id: Option<String>) -> Result<String> {
    member_id.ok_or_else(missing_member_id_error)
}

fn missing_member_id_error() -> Error {
    Error::Config {
        message: "member_id is required but could not be determined.\n\
                  Options:\n\
                  1. Specify --member-id <id>\n\
                  2. Set environment variable: export SECRETENV_MEMBER_ID=<id>\n\
                  3. Set in config: secretenv config set member_id <id>"
            .to_string(),
    }
}
