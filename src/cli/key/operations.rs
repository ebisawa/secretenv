// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key operations (activate, remove, export) implementation

use crate::app::context::options::CommonCommandOptions;
use crate::app::key::manage::{
    activate_key_command, export_key_command, export_private_key_command, remove_key_command,
    save_exported_private_key,
};
use crate::cli::common::ssh::resolve_ssh_context_for_active_key;
use crate::support::kid::build_kid_display;
use crate::support::path::display_path_relative_to_cwd;
use crate::Result;
use std::io::IsTerminal;
use std::io::{self, BufRead};
use zeroize::Zeroizing;

use super::{ActivateArgs, ExportArgs, RemoveArgs};

/// Main entry point for key activation
pub fn run_activate(args: ActivateArgs) -> Result<()> {
    let options = CommonCommandOptions::from(&args.common);
    let result = activate_key_command(&options, args.member_id.clone(), args.kid.clone())?;
    let kid_display = build_kid_display(&result.kid).unwrap_or_else(|_| result.kid.clone());
    eprintln!("Activated key for '{}':", result.member_id);
    eprintln!("  Kid: {}", kid_display);
    Ok(())
}

/// Main entry point for key removal
pub fn run_remove(args: RemoveArgs) -> Result<()> {
    let options = CommonCommandOptions::from(&args.common);
    let result = remove_key_command(
        &options,
        args.member_id.clone(),
        args.kid.clone(),
        args.force,
    )?;
    let kid_display = build_kid_display(&result.kid).unwrap_or_else(|_| result.kid.clone());
    eprintln!("Removed key for '{}':", result.member_id);
    eprintln!("  Kid: {}", kid_display);
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
    let result = export_key_command(&options, args.member_id.clone(), args.kid.clone(), out)?;
    let kid_display = build_kid_display(&result.kid).unwrap_or_else(|_| result.kid.clone());
    eprintln!("Exported public key for '{}':", result.member_id);
    eprintln!("  Kid:    {}", kid_display);
    eprintln!("  Output: {}", display_path_relative_to_cwd(out));

    Ok(())
}

/// Main entry point for private key export (password-protected portable format)
pub fn run_export_private(args: ExportArgs) -> Result<()> {
    if args.out.is_none() && !args.stdout {
        return Err(crate::Error::InvalidArgument {
            message: "--private export requires either --out or --stdout".to_string(),
        });
    }

    let options = CommonCommandOptions::from(&args.common);
    let password = prompt_export_password()?;

    let ssh_ctx = resolve_ssh_context_for_active_key(&options, args.member_id.clone())?;

    let result = export_private_key_command(
        &options,
        args.member_id.clone(),
        args.kid.clone(),
        password.as_str(),
        ssh_ctx,
    )?;
    let kid_display = build_kid_display(&result.kid).unwrap_or_else(|_| result.kid.clone());

    if let Some(out) = args.out.as_ref() {
        save_exported_private_key(out, &result.encoded_key)?;
        eprintln!("Exported private key for '{}':", result.member_id);
        eprintln!("  Kid:    {}", kid_display);
        eprintln!("  Output: {}", display_path_relative_to_cwd(out));
    } else if args.stdout {
        eprintln!();
        println!("{}", result.encoded_key);
        eprintln!();
        eprintln!("Exported private key for '{}':", result.member_id);
        eprintln!("  Kid: {}", kid_display);
    }

    Ok(())
}

fn prompt_export_password() -> Result<Zeroizing<String>> {
    if io::stdin().is_terminal() {
        let password = dialoguer::Password::new()
            .with_prompt("Enter password for key export")
            .with_confirmation("Confirm password", "Passwords do not match")
            .interact()
            .map_err(|e| crate::Error::io(format!("Failed to read password: {}", e)))?;
        return Ok(Zeroizing::new(password));
    }

    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut password = Zeroizing::new(String::new());
    let mut confirmation = Zeroizing::new(String::new());

    reader
        .read_line(&mut password)
        .map_err(|e| crate::Error::io(format!("Failed to read password: {}", e)))?;
    reader
        .read_line(&mut confirmation)
        .map_err(|e| crate::Error::io(format!("Failed to read password confirmation: {}", e)))?;

    trim_line_ending(&mut password);
    trim_line_ending(&mut confirmation);

    if password.as_str() != confirmation.as_str() {
        return Err(crate::Error::InvalidArgument {
            message: "Passwords do not match".to_string(),
        });
    }

    Ok(password)
}

fn trim_line_ending(value: &mut String) {
    while matches!(value.chars().last(), Some('\n' | '\r')) {
        value.pop();
    }
}
