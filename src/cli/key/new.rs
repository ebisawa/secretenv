// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key generation (key new) implementation

use crate::app::context::CommonCommandOptions;
use crate::app::key::generate_key_command;
use crate::cli::identity_prompt;
use crate::Result;

use super::common::print_key_generation_binding_info;
use super::NewArgs;

/// Main entry point for key generation
pub fn run(args: NewArgs) -> Result<()> {
    let options = CommonCommandOptions::from(&args.common);
    let keystore_root = options.resolve_keystore_root()?;
    let member_id = identity_prompt::resolve_member_id(
        args.member_id.clone(),
        &keystore_root,
        options.home.as_deref(),
    )?;
    let github_user =
        identity_prompt::resolve_github_user(args.github_user.clone(), options.home.as_deref())?;
    let result = generate_key_command(
        &options,
        Some(member_id),
        github_user,
        &args.expires_at,
        &args.valid_for,
        args.no_activate,
    )?;

    print_key_generation_binding_info(
        &result.ssh_fingerprint,
        &result.ssh_determinism,
        result.github_verification,
    )?;
    eprintln!();
    if result.activated {
        eprintln!("Generated and activated key for '{}':", result.member_id);
    } else {
        eprintln!("Generated key for '{}':", result.member_id);
    }
    eprintln!("  Key ID:  {}", result.kid);
    eprintln!("  Expires: {}", result.expires_at);

    Ok(())
}
