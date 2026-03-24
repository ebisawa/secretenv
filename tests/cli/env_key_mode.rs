// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! CLI integration tests for env key mode (CI mode)
//!
//! Tests that the CLI binary correctly handles SECRETENV_PRIVATE_KEY and
//! SECRETENV_KEY_PASSWORD environment variables for keyless CI operation.

use crate::cli::common::{cmd, setup_workspace, TEST_MEMBER_ID};
use crate::test_utils::ed25519_backend::Ed25519DirectBackend;
use predicates::prelude::*;
use secretenv::feature::key::portable_export::export_private_key_portable;
use secretenv::feature::key::protection::encryption::decrypt_private_key;
use secretenv::io::keystore::active::load_active_kid;
use secretenv::io::keystore::storage::load_private_key;
use tempfile::TempDir;

const TEST_PASSWORD: &str = "cli-integration-test-password-42";
const ENV_MODE_UNSUPPORTED_MESSAGE: &str =
    "requires a local keystore and SSH signer; run it on a developer machine";

// ============================================================================
// Setup Helper
// ============================================================================

/// Setup a workspace with an exported portable private key for env key mode.
///
/// Returns (workspace_dir, home_dir, exported_key_base64url).
/// The ssh_temp TempDir is also returned to keep it alive during the test.
fn setup_env_key_workspace() -> (TempDir, TempDir, TempDir, String) {
    let (workspace_dir, home_dir, ssh_temp, ssh_priv) = setup_workspace();

    let keystore_root = home_dir.path().join("keys");

    // Read active kid
    let kid = load_active_kid(TEST_MEMBER_ID, &keystore_root)
        .expect("should load active kid")
        .expect("active kid should exist");

    // Load encrypted private key from keystore
    let private_key =
        load_private_key(&keystore_root, TEST_MEMBER_ID, &kid).expect("should load private key");

    // Read SSH public key content
    let ssh_pub_path = ssh_priv.with_extension("pub");
    let ssh_pub_content = std::fs::read_to_string(&ssh_pub_path)
        .expect("should read SSH public key")
        .trim()
        .to_string();

    // Decrypt using Ed25519DirectBackend
    let backend = Ed25519DirectBackend::new(&ssh_priv).expect("should load SSH key");
    let plaintext = decrypt_private_key(&private_key, &backend, &ssh_pub_content, false)
        .expect("should decrypt private key");

    // Export as portable key
    let exported = export_private_key_portable(
        &plaintext,
        &private_key.protected.member_id,
        &private_key.protected.kid,
        &private_key.protected.created_at,
        &private_key.protected.expires_at,
        TEST_PASSWORD,
        false,
    )
    .expect("should export private key");

    (workspace_dir, home_dir, ssh_temp, exported)
}

/// Build a CLI command configured for env key mode.
///
/// Note: `--workspace` is a subcommand option, so it must be added
/// after the subcommand arg by the caller.
fn env_key_cmd(home: &TempDir, exported_key: &str, password: &str) -> assert_cmd::Command {
    let mut c = cmd();
    c.env("SECRETENV_HOME", home.path())
        .env("SECRETENV_PRIVATE_KEY", exported_key)
        .env("SECRETENV_KEY_PASSWORD", password);
    // Remove SSH_AUTH_SOCK to ensure env key mode is used
    c.env_remove("SSH_AUTH_SOCK");
    c.env_remove("SECRETENV_SSH_KEY");
    c
}

// ============================================================================
// Roundtrip Tests
// ============================================================================

#[test]
fn test_env_key_set_and_get_roundtrip() {
    let (workspace_dir, home_dir, _ssh_temp, exported_key) = setup_env_key_workspace();

    // Set a KV pair using env key mode
    env_key_cmd(&home_dir, &exported_key, TEST_PASSWORD)
        .arg("set")
        .arg("DATABASE_URL")
        .arg("postgres://localhost/testdb")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .assert()
        .success();

    // Get it back using env key mode
    env_key_cmd(&home_dir, &exported_key, TEST_PASSWORD)
        .arg("get")
        .arg("DATABASE_URL")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("postgres://localhost/testdb"));
}

#[test]
fn test_env_key_encrypt_decrypt_file_roundtrip() {
    let (workspace_dir, home_dir, _ssh_temp, exported_key) = setup_env_key_workspace();

    // Create a test file to encrypt
    let original_content = b"TOP_SECRET=env_key_mode_works\n";
    let input_file = home_dir.path().join("secret.txt");
    std::fs::write(&input_file, original_content).unwrap();

    let encrypted_file = home_dir.path().join("secret.txt.encrypted");
    let decrypted_file = home_dir.path().join("decrypted.txt");

    // Encrypt using env key mode
    env_key_cmd(&home_dir, &exported_key, TEST_PASSWORD)
        .arg("encrypt")
        .arg(input_file.to_str().unwrap())
        .arg("--out")
        .arg(encrypted_file.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .assert()
        .success();

    assert!(encrypted_file.exists(), "Encrypted file should exist");

    // Decrypt using env key mode
    env_key_cmd(&home_dir, &exported_key, TEST_PASSWORD)
        .arg("decrypt")
        .arg(encrypted_file.to_str().unwrap())
        .arg("--out")
        .arg(decrypted_file.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .assert()
        .success();

    assert!(decrypted_file.exists(), "Decrypted file should exist");
    let decrypted_content = std::fs::read(&decrypted_file).unwrap();
    assert_eq!(
        decrypted_content, original_content,
        "Decrypted content should match original"
    );
}

// ============================================================================
// Error Cases
// ============================================================================

#[test]
fn test_env_key_missing_password_fails() {
    let (workspace_dir, home_dir, _ssh_temp, exported_key) = setup_env_key_workspace();

    // Set SECRETENV_PRIVATE_KEY but NOT SECRETENV_KEY_PASSWORD
    let mut c = cmd();
    c.env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_PRIVATE_KEY", &exported_key)
        .env_remove("SECRETENV_KEY_PASSWORD")
        .env_remove("SSH_AUTH_SOCK")
        .env_remove("SECRETENV_SSH_KEY");

    c.arg("set")
        .arg("SOME_KEY")
        .arg("some_value")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("SECRETENV_KEY_PASSWORD"));
}

#[test]
fn test_env_key_wrong_password_fails() {
    let (workspace_dir, home_dir, _ssh_temp, exported_key) = setup_env_key_workspace();

    // Use wrong password
    env_key_cmd(&home_dir, &exported_key, "wrong-password-99")
        .arg("set")
        .arg("SOME_KEY")
        .arg("some_value")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .assert()
        .failure();
}

#[test]
fn test_env_key_mode_rejects_key_new() {
    let (_workspace_dir, home_dir, _ssh_temp, exported_key) = setup_env_key_workspace();

    env_key_cmd(&home_dir, &exported_key, TEST_PASSWORD)
        .arg("key")
        .arg("new")
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .assert()
        .failure()
        .stderr(predicate::str::contains("environment-variable key mode"))
        .stderr(predicate::str::contains(ENV_MODE_UNSUPPORTED_MESSAGE));
}

#[test]
fn test_env_key_mode_rejects_private_key_export() {
    let (_workspace_dir, home_dir, _ssh_temp, exported_key) = setup_env_key_workspace();

    env_key_cmd(&home_dir, &exported_key, TEST_PASSWORD)
        .arg("key")
        .arg("export")
        .arg("--private")
        .arg("--stdout")
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .assert()
        .failure()
        .stderr(predicate::str::contains("environment-variable key mode"))
        .stderr(predicate::str::contains(ENV_MODE_UNSUPPORTED_MESSAGE));
}

#[test]
fn test_env_key_mode_rejects_init() {
    let (workspace_dir, home_dir, _ssh_temp, exported_key) = setup_env_key_workspace();

    env_key_cmd(&home_dir, &exported_key, TEST_PASSWORD)
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .assert()
        .failure()
        .stderr(predicate::str::contains("environment-variable key mode"))
        .stderr(predicate::str::contains(ENV_MODE_UNSUPPORTED_MESSAGE));
}

#[test]
fn test_env_key_mode_rejects_join() {
    let (workspace_dir, home_dir, _ssh_temp, exported_key) = setup_env_key_workspace();

    env_key_cmd(&home_dir, &exported_key, TEST_PASSWORD)
        .arg("join")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .assert()
        .failure()
        .stderr(predicate::str::contains("environment-variable key mode"))
        .stderr(predicate::str::contains(ENV_MODE_UNSUPPORTED_MESSAGE));
}
