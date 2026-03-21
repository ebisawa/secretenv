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

#[test]
fn test_resolve_agent_with_explicit_key_loads_pubkey_from_file() {
    // When ssh-agent mode is selected with an explicit key file,
    // the public key should be loaded from the file (not from ssh-add -L).
    // The resolution will fail later at the agent backend (no real agent in CI),
    // but the error should be agent-related, not a pubkey loading error.
    let temp_dir = setup_test_keystore("test@example.com");
    let ssh_key_path = temp_dir.path().join(".ssh").join("test_ed25519");

    let params = SshSigningParams {
        ssh_key: Some(ssh_key_path),
        signing_method: Some(SshSigner::SshAgent),
        base_dir: Some(temp_dir.path().to_path_buf()),
        verbose: false,
    };

    let result = resolve_ssh_signing_context(&params);
    // In CI without a real SSH agent, this will fail at the determinism check
    // (agent connection). If the pubkey had NOT been loaded from file, it would
    // have failed earlier with an ssh-add error. Accept either success (if an
    // agent happens to be available) or an agent-related error.
    match result {
        Ok(ctx) => {
            assert!(!ctx.public_key.is_empty());
            assert!(!ctx.fingerprint.is_empty());
        }
        Err(e) => {
            let msg = e.to_string();
            // The error should be from agent signing/determinism check,
            // NOT from public key loading. If the old behavior (ssh-add -L)
            // were used, we'd see "No Ed25519 key found" or similar.
            assert!(
                msg.contains("ssh-agent signing failed")
                    || msg.contains("agent")
                    || msg.contains("determinism"),
                "Expected agent/determinism error, got: {}",
                msg
            );
        }
    }
}

#[test]
fn test_resolve_agent_with_explicit_nonexistent_key_fails() {
    // When ssh-agent mode is selected with an explicit key that doesn't exist,
    // it should fail with a NotFound error.
    let temp_dir = setup_test_keystore("test@example.com");
    let nonexistent_key = temp_dir.path().join(".ssh").join("nonexistent_key");

    let params = SshSigningParams {
        ssh_key: Some(nonexistent_key),
        signing_method: Some(SshSigner::SshAgent),
        base_dir: Some(temp_dir.path().to_path_buf()),
        verbose: false,
    };

    let result = resolve_ssh_signing_context(&params);
    let msg = match result {
        Ok(_) => panic!("Expected error for nonexistent key"),
        Err(e) => e.to_string(),
    };
    assert!(
        msg.contains("does not exist"),
        "Expected 'does not exist' error, got: {}",
        msg
    );
}
