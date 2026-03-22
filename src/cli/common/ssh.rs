// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared SSH signing context resolution for CLI commands.

use crate::app::context::{
    build_ssh_signing_context, resolve_ssh_context_by_active_key, resolve_ssh_key_candidates,
    CommonCommandOptions, SshSigningContext,
};
use crate::cli::identity_prompt::select_ssh_key;
use crate::Result;

/// Run the 3-phase SSH signing context resolution.
/// Phase 1: Discover key candidates (via app layer)
/// Phase 2: Select key (auto for 1, interactive for multiple, error for 0)
/// Phase 3: Build signing context (via app layer)
pub fn resolve_ssh_context(options: &CommonCommandOptions) -> Result<SshSigningContext> {
    let candidates = resolve_ssh_key_candidates(options)?;
    let selected = select_ssh_key(&candidates)?;
    build_ssh_signing_context(options, &candidates[selected].public_key)
}

/// Resolve SSH context using the active key's fingerprint.
/// No interactive selection; auto-matches against ssh-agent candidates.
pub fn resolve_ssh_context_for_active_key(
    options: &CommonCommandOptions,
) -> Result<SshSigningContext> {
    let ctx = resolve_ssh_context_by_active_key(options)?;
    if options.verbose {
        eprintln!("Using SSH key: {}", ctx.fingerprint);
    }
    Ok(ctx)
}
