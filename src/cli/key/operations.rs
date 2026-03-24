// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key operations (activate, remove, export) implementation

use crate::app::context::CommonCommandOptions;
use crate::app::key::{activate_key_command, export_key_command, remove_key_command};
use crate::cli::common::ssh::resolve_ssh_context_for_active_key;
use crate::cli::identity_prompt;
use crate::support::path::display_path_relative_to_cwd;
use crate::Result;

use super::{ActivateArgs, ExportArgs, RemoveArgs};

/// Main entry point for key activation
pub fn run_activate(args: ActivateArgs) -> Result<()> {
    let options = CommonCommandOptions::from(&args.common);
    let keystore_root = options.resolve_keystore_root()?;
    let member_id = identity_prompt::resolve_member_id(
        args.member_id.clone(),
        &keystore_root,
        options.home.as_deref(),
    )?;
    let result = activate_key_command(&options, Some(member_id), args.kid.clone())?;
    eprintln!("Activated key for '{}':", result.member_id);
    eprintln!("  Kid: {}", result.kid);
    Ok(())
}

/// Main entry point for key removal
pub fn run_remove(args: RemoveArgs) -> Result<()> {
    let options = CommonCommandOptions::from(&args.common);
    let member_id = if args.member_id.is_some() {
        let keystore_root = options.resolve_keystore_root()?;
        Some(identity_prompt::resolve_member_id(
            args.member_id.clone(),
            &keystore_root,
            options.home.as_deref(),
        )?)
    } else {
        None
    };
    let result = remove_key_command(&options, member_id, args.kid.clone(), args.force)?;
    eprintln!("Removed key for '{}':", result.member_id);
    eprintln!("  Kid: {}", result.kid);
    if result.was_active {
        eprintln!("  Note: This was the active key. No key is now active.");
    }
    Ok(())
}

/// Main entry point for public key export
pub fn run_export(args: ExportArgs) -> Result<()> {
    let out = args
        .out
        .as_ref()
        .ok_or_else(|| crate::Error::InvalidArgument {
            message: "--out is required for public key export".to_string(),
        })?;
    let options = CommonCommandOptions::from(&args.common);
    let keystore_root = options.resolve_keystore_root()?;
    let member_id = identity_prompt::resolve_member_id(
        args.member_id.clone(),
        &keystore_root,
        options.home.as_deref(),
    )?;
    let result = export_key_command(&options, Some(member_id), args.kid.clone(), out)?;
    eprintln!("Exported public key for '{}':", result.member_id);
    eprintln!("  Kid:    {}", result.kid);
    eprintln!("  Output: {}", display_path_relative_to_cwd(out));

    Ok(())
}

/// Main entry point for private key export (password-protected portable format)
pub fn run_export_private(args: ExportArgs) -> Result<()> {
    let options = CommonCommandOptions::from(&args.common);
    let keystore_root = options.resolve_keystore_root()?;
    let member_id = identity_prompt::resolve_member_id(
        args.member_id.clone(),
        &keystore_root,
        options.home.as_deref(),
    )?;

    let password = dialoguer::Password::new()
        .with_prompt("Enter password for key export")
        .with_confirmation("Confirm password", "Passwords do not match")
        .interact()
        .map_err(|e| crate::Error::Io {
            message: format!("Failed to read password: {}", e),
            source: None,
        })?;

    let ssh_ctx = resolve_ssh_context_for_active_key(&options)?;

    let result = crate::app::key::export_private_key_command(
        &options,
        Some(member_id),
        args.kid.clone(),
        &password,
        ssh_ctx,
    )?;

    if let Some(out) = args.out.as_ref() {
        crate::support::fs::atomic::save_text(out, &result.encoded_key)?;
        eprintln!("Exported private key for '{}':", result.member_id);
        eprintln!("  Kid:    {}", result.kid);
        eprintln!("  Output: {}", display_path_relative_to_cwd(out));
    } else {
        println!("{}", result.encoded_key);
        eprintln!("Exported private key for '{}':", result.member_id);
        eprintln!("  Kid: {}", result.kid);
    }

    Ok(())
}
