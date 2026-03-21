// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key operations (activate, remove, export) implementation

use crate::app::context::CommonCommandOptions;
use crate::app::key::{activate_key_command, export_key_command, remove_key_command};
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
    let options = CommonCommandOptions::from(&args.common);
    let keystore_root = options.resolve_keystore_root()?;
    let member_id = identity_prompt::resolve_member_id(
        args.member_id.clone(),
        &keystore_root,
        options.home.as_deref(),
    )?;
    let result = export_key_command(&options, Some(member_id), args.kid.clone(), &args.out)?;
    eprintln!("Exported public key for '{}':", result.member_id);
    eprintln!("  Kid:    {}", result.kid);
    eprintln!("  Output: {}", display_path_relative_to_cwd(&args.out));

    Ok(())
}
