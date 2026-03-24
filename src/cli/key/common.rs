// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Common utilities for key operations.

use crate::app::context::member::resolve_member_context;
use crate::app::context::options::CommonCommandOptions;
use crate::app::verification::OnlineVerificationStatus;
use crate::model::ssh::SshDeterminismStatus;
use crate::support::fs::lock;
use crate::{Error, Result};
use std::path::PathBuf;

/// Context for key operations containing resolved paths and member ID.
pub struct KeyOperationContext {
    pub member_id: String,
    pub keystore_root: PathBuf,
}

/// Setup context for key operations by resolving base_dir, member_id, and keystore_root.
pub fn setup_key_operation_context(
    options: &CommonCommandOptions,
    member_id_opt: Option<String>,
) -> Result<KeyOperationContext> {
    let resolved = resolve_member_context(options, member_id_opt)?;

    Ok(KeyOperationContext {
        member_id: resolved.member_id,
        keystore_root: resolved.paths.keystore_root,
    })
}

/// Execute an operation with file lock on the member's keystore directory.
pub fn with_key_lock<F>(ctx: &KeyOperationContext, operation: F) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    let lock_target = ctx.keystore_root.join(&ctx.member_id);
    lock::with_file_lock(&lock_target, operation)
}

pub(crate) fn print_key_generation_binding_info(
    ssh_fingerprint: &str,
    ssh_determinism: &SshDeterminismStatus,
    github_verification: OnlineVerificationStatus,
) -> Result<()> {
    eprintln!();
    eprintln!("Using SSH key: {}", ssh_fingerprint);
    if ssh_determinism.is_verified() {
        eprintln!("SSH signature determinism: OK");
    } else if let Some(message) = ssh_determinism.message() {
        return Err(Error::Crypto {
            message: message.to_string(),
            source: None,
        });
    }

    if github_verification.is_verified() {
        eprintln!("GitHub verification: OK");
    }

    Ok(())
}
