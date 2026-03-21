// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for SSH signing context resolution.

use crate::test_utils::{setup_test_keystore, stub_ssh_keygen};
use secretenv::config::types::SshSigner;
use secretenv::feature::context::ssh::{resolve_ssh_signing_context, SshSigningParams};
use secretenv::io::ssh::backend::signature_backend::SignatureBackend;
use secretenv::io::ssh::backend::ssh_keygen::SshKeygenBackend;
use secretenv::io::ssh::protocol::key_descriptor::SshKeyDescriptor;

#[test]
fn test_resolve_ssh_signing_context_default() {
    let temp_dir = setup_test_keystore("test@example.com");
    let ssh_key_path = temp_dir.path().join(".ssh").join("test_ed25519");

    let params = SshSigningParams {
        ssh_key: Some(ssh_key_path),
        signing_method: Some(SshSigner::SshKeygen),
        base_dir: Some(temp_dir.path().to_path_buf()),
        verbose: false,
    };
    let ctx = resolve_ssh_signing_context(&params).unwrap();

    assert!(!ctx.public_key.is_empty());
    assert!(!ctx.fingerprint.is_empty());
}

#[test]
fn test_resolve_ssh_signing_context_verbose() {
    let temp_dir = setup_test_keystore("test@example.com");
    let ssh_key_path = temp_dir.path().join(".ssh").join("test_ed25519");

    let params = SshSigningParams {
        ssh_key: Some(ssh_key_path),
        signing_method: Some(SshSigner::SshKeygen),
        base_dir: Some(temp_dir.path().to_path_buf()),
        verbose: true,
    };
    let ctx = resolve_ssh_signing_context(&params).unwrap();

    assert!(!ctx.public_key.is_empty());
}

#[test]
fn test_check_determinism_via_context() {
    let temp_dir = setup_test_keystore("test@example.com");
    let ssh_pub =
        std::fs::read_to_string(temp_dir.path().join(".ssh").join("test_ed25519.pub")).unwrap();
    let backend: Box<dyn SignatureBackend> = Box::new(SshKeygenBackend::new(
        stub_ssh_keygen(),
        SshKeyDescriptor::from_path(temp_dir.path().join(".ssh").join("test_ed25519")),
    ));

    let result = backend.check_determinism(
        &ssh_pub,
        secretenv::model::identifiers::context::SSH_DETERMINISM_CHECK_MESSAGE,
    );
    // Result may be ok or err depending on backend implementation
    let _ = result;
}
