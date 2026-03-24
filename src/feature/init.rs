// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Init feature - workspace setup and member registration.

use crate::feature::key::generate::{generate_key, KeyGenerationOptions};
use crate::feature::key::ssh_binding::SshBindingContext;
use crate::io::keystore::member::find_active_key_document;
use crate::model::public_key::GithubAccount;
use crate::model::ssh::SshDeterminismStatus;
use crate::support::time as time_util;
use crate::Result;
use std::path::{Path, PathBuf};

/// Result of ensuring key exists.
#[derive(Debug, Clone)]
pub struct EnsureKeyExistsResult {
    /// Key ID
    pub kid: String,
    /// Whether a new key was created (true) or an existing key was reused (false)
    pub created: bool,
    /// Expiration timestamp (RFC 3339)
    pub expires_at: String,
    /// SSH fingerprint (new keys only)
    pub ssh_fingerprint: Option<String>,
    /// SSH determinism check result (new keys only)
    pub ssh_determinism: Option<SshDeterminismStatus>,
}

/// Check if a valid active key already exists for the given member_id.
///
/// Returns `Some(EnsureKeyExistsResult)` if active key with private key exists,
/// `None` if key generation is needed.
pub fn find_active_key(
    member_id: &str,
    keystore_root: &Path,
) -> Result<Option<EnsureKeyExistsResult>> {
    Ok(
        find_active_key_document(member_id, keystore_root)?.map(|active| EnsureKeyExistsResult {
            kid: active.kid,
            created: false,
            expires_at: active.public_key.protected.expires_at,
            ssh_fingerprint: None,
            ssh_determinism: None,
        }),
    )
}

/// Generate a new key for member_id.
pub fn generate_new_key(
    member_id: &str,
    home: Option<PathBuf>,
    verbose: bool,
    github_account: Option<GithubAccount>,
    ssh_binding: SshBindingContext,
) -> Result<EnsureKeyExistsResult> {
    let (created_at, expires_at) = default_key_timestamps()?;
    let result = generate_key(KeyGenerationOptions {
        member_id: member_id.to_string(),
        home,
        created_at,
        expires_at,
        no_activate: false,
        debug: verbose,
        github_account,
        verbose,
        ssh_binding,
    })?;

    Ok(EnsureKeyExistsResult {
        kid: result.kid,
        created: true,
        expires_at: result.expires_at,
        ssh_fingerprint: Some(result.ssh_fingerprint),
        ssh_determinism: Some(result.ssh_determinism),
    })
}

/// Ensure key exists for member_id - generate if missing.
pub fn ensure_key_exists(
    member_id: &str,
    keystore_root: &Path,
    home: Option<PathBuf>,
    verbose: bool,
    github_account: Option<GithubAccount>,
    ssh_binding: SshBindingContext,
) -> Result<EnsureKeyExistsResult> {
    if let Some(result) = find_active_key(member_id, keystore_root)? {
        return Ok(result);
    }
    generate_new_key(member_id, home, verbose, github_account, ssh_binding)
}

fn default_key_timestamps() -> Result<(String, String)> {
    let created_at = time::OffsetDateTime::now_utc();
    let expires_at = created_at + time::Duration::days(365);

    let created_at_str = time_util::build_timestamp_display(created_at)?;
    let expires_at_str = time_util::build_timestamp_display(expires_at)?;

    Ok((created_at_str, expires_at_str))
}
