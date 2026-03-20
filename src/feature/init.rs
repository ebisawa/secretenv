// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Init feature - workspace setup and member registration.

use crate::config::types::SshSigner;
use crate::feature::key::generate::{generate_key, KeyGenerationOptions};
use crate::io::keystore::member::find_active_key_document;
use crate::io::keystore::member::load_single_member_id_from_keystore as load_single_member_id;
use crate::io::keystore::resolver::KeystoreResolver;
use crate::io::keystore::storage::load_public_key;
use crate::io::workspace::setup;
use crate::model::public_key::GithubAccount;
use crate::model::ssh::SshDeterminismStatus;
use crate::support::time as time_util;
use crate::Result;
use std::path::{Path, PathBuf};

/// Resolve keystore root from home override or default.
pub fn resolve_keystore_root(home: &Option<PathBuf>) -> Result<PathBuf> {
    KeystoreResolver::resolve(home.as_ref())
}

/// Load member_id from keystore if exactly one exists.
pub fn load_single_member_id_from_keystore(keystore_root: &Path) -> Result<Option<String>> {
    load_single_member_id(keystore_root)
}

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
    ssh_key: Option<PathBuf>,
    ssh_signer: Option<SshSigner>,
    verbose: bool,
    github_account: Option<GithubAccount>,
) -> Result<EnsureKeyExistsResult> {
    let (created_at, expires_at) = default_key_timestamps()?;
    let result = generate_key(KeyGenerationOptions {
        member_id: member_id.to_string(),
        home,
        ssh_key,
        ssh_signer,
        created_at,
        expires_at,
        no_activate: false,
        debug: verbose,
        github_account,
        verbose,
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
    ssh_key: Option<PathBuf>,
    ssh_signer: Option<SshSigner>,
    verbose: bool,
    github_account: Option<GithubAccount>,
) -> Result<EnsureKeyExistsResult> {
    if let Some(result) = find_active_key(member_id, keystore_root)? {
        return Ok(result);
    }
    generate_new_key(
        member_id,
        home,
        ssh_key,
        ssh_signer,
        verbose,
        github_account,
    )
}

fn default_key_timestamps() -> Result<(String, String)> {
    let created_at = time::OffsetDateTime::now_utc();
    let expires_at = created_at + time::Duration::days(365);

    let created_at_str = time_util::build_timestamp_display(created_at)?;
    let expires_at_str = time_util::build_timestamp_display(expires_at)?;

    Ok((created_at_str, expires_at_str))
}

/// Ensure workspace structure exists - create if missing.
pub fn ensure_workspace_structure(workspace_path: &Path) -> Result<bool> {
    setup::ensure_workspace_structure(workspace_path)
}

/// Save member document to workspace.
pub fn save_member_document(
    member_file: &Path,
    member_id: &str,
    kid: &str,
    keystore_root: &Path,
) -> Result<()> {
    let public_doc = load_public_key(keystore_root, member_id, kid)?;
    setup::save_member_document(member_file, &public_doc)
}

/// Verify that workspace structure already exists (used by join command).
pub fn validate_workspace_exists(workspace_path: &Path) -> Result<()> {
    setup::validate_workspace_exists(workspace_path)
}
