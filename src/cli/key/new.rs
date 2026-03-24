// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key generation (key new) implementation

use crate::app::context::options::CommonCommandOptions;
use crate::app::key::generate::generate_key_command;
use crate::cli::common::ssh::resolve_ssh_context;
use crate::Result;

use super::common::print_key_generation_binding_info;
use super::NewArgs;

/// Main entry point for key generation
pub fn run(args: NewArgs) -> Result<()> {
    let options = CommonCommandOptions::from(&args.common);
    eprintln!();
    let ssh_ctx = resolve_ssh_context(&options)?;
    let result = generate_key_command(
        &options,
        args.member_id.clone(),
        args.github_user.clone(),
        &args.expires_at,
        &args.valid_for,
        args.no_activate,
        ssh_ctx,
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
