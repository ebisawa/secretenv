// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared CryptoContext builder for tests
//!
//! Uses Ed25519DirectBackend to avoid spawning ssh-keygen subprocesses.

use super::ed25519_backend::Ed25519DirectBackend;
use secretenv::app::context::crypto::load_crypto_context;
use secretenv::feature::context::crypto::CryptoContext;
use secretenv::io::ssh::backend::SignatureBackend;
use std::fs;
use tempfile::TempDir;

/// Build CryptoContext for a member in a test keystore
///
/// Uses Ed25519DirectBackend instead of SshKeygenBackend to avoid
/// spawning ssh-keygen subprocesses.
pub fn setup_member_key_context(
    temp_dir: &TempDir,
    member_id: &str,
    kid: Option<&str>,
) -> CryptoContext {
    let keystore_root = temp_dir.path().join("keys");
    let ssh_pub = fs::read_to_string(temp_dir.path().join(".ssh").join("test_ed25519.pub"))
        .unwrap()
        .trim()
        .to_string();
    let ssh_priv = temp_dir.path().join(".ssh").join("test_ed25519");
    let backend: Box<dyn SignatureBackend> =
        Box::new(Ed25519DirectBackend::new(&ssh_priv).unwrap());

    load_crypto_context(
        member_id,
        backend.as_ref(),
        &ssh_pub,
        kid,
        Some(&keystore_root),
        Some(temp_dir.path().join("workspace")),
        false,
    )
    .unwrap()
}
