// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for CI key export and environment variable key loading.
//!
//! These tests exercise the full portable export -> env var loading pipeline
//! using properly generated key pairs with SSH attestation.

use secretenv::feature::context::env_key::{load_private_key_from_env, verify_own_public_key};
use secretenv::feature::key::portable_export::export_private_key_portable;
use tempfile::TempDir;

use crate::test_utils::{create_temp_ssh_keypair_in_dir, keygen_test, EnvGuard};

const ENV_PRIVATE_KEY: &str = "SECRETENV_PRIVATE_KEY";
const ENV_KEY_PASSWORD: &str = "SECRETENV_KEY_PASSWORD";

/// Generate a key pair and export it as a portable string.
///
/// Returns (exported_base64url, member_id, kid, plaintext, public_key).
fn generate_and_export(
    member_id: &str,
    password: &str,
) -> (
    String,
    secretenv::model::private_key::PrivateKeyPlaintext,
    secretenv::model::public_key::PublicKey,
) {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub, ssh_pub_content) = create_temp_ssh_keypair_in_dir(&temp_dir);

    let (plaintext, public_key) =
        keygen_test(member_id, &ssh_priv, &ssh_pub_content).expect("keygen should succeed");

    let exported = export_private_key_portable(
        &plaintext,
        &public_key.protected.member_id,
        &public_key.protected.kid,
        public_key
            .protected
            .created_at
            .as_deref()
            .unwrap_or("2026-01-01T00:00:00Z"),
        &public_key.protected.expires_at,
        password,
    )
    .expect("export should succeed");

    (exported, plaintext, public_key)
}

#[test]
fn test_env_key_roundtrip_with_attested_keys() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD]);
    let member_id = "ci-roundtrip@example.com";
    let password = "strong-test-password-42";

    let (exported, plaintext, public_key) = generate_and_export(member_id, password);

    std::env::set_var(ENV_PRIVATE_KEY, &exported);
    std::env::set_var(ENV_KEY_PASSWORD, password);

    let (verified_key, loaded_member_id) =
        load_private_key_from_env().expect("load from env should succeed");

    assert_eq!(loaded_member_id, member_id);
    assert_eq!(verified_key.proof().member_id, member_id);
    assert_eq!(verified_key.proof().kid, public_key.protected.kid);
    assert_eq!(verified_key.proof().ssh_fpr, None);

    // Verify key material matches original
    assert_eq!(verified_key.document().keys.sig.x, plaintext.keys.sig.x);
    assert_eq!(verified_key.document().keys.sig.d, plaintext.keys.sig.d);
    assert_eq!(verified_key.document().keys.kem.x, plaintext.keys.kem.x);
    assert_eq!(verified_key.document().keys.kem.d, plaintext.keys.kem.d);
}

#[test]
fn test_env_key_wrong_password_error() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD]);
    let member_id = "wrong-pass@example.com";
    let password = "strong-test-password-42";

    let (exported, _plaintext, _public_key) = generate_and_export(member_id, password);

    std::env::set_var(ENV_PRIVATE_KEY, &exported);
    std::env::set_var(ENV_KEY_PASSWORD, "different-wrong-password");

    let result = load_private_key_from_env();
    assert!(result.is_err(), "wrong password should fail");
}

#[test]
fn test_verify_own_public_key_with_attested_keys() {
    let member_id = "verify-match@example.com";
    let temp_dir = TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub, ssh_pub_content) = create_temp_ssh_keypair_in_dir(&temp_dir);

    let (plaintext, public_key) =
        keygen_test(member_id, &ssh_priv, &ssh_pub_content).expect("keygen should succeed");

    let result = verify_own_public_key(&plaintext, &public_key);
    assert!(
        result.is_ok(),
        "matching attested keys should verify: {:?}",
        result
    );
}

#[test]
fn test_verify_own_public_key_different_keys_fails() {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub, ssh_pub_content) = create_temp_ssh_keypair_in_dir(&temp_dir);

    // Generate two different key pairs
    let (plaintext_a, _pub_a) = keygen_test("user-a@example.com", &ssh_priv, &ssh_pub_content)
        .expect("keygen a should succeed");
    let (_plaintext_b, pub_b) = keygen_test("user-b@example.com", &ssh_priv, &ssh_pub_content)
        .expect("keygen b should succeed");

    // Verify plaintext_a against pub_b should fail (different key material)
    let result = verify_own_public_key(&plaintext_a, &pub_b);
    assert!(result.is_err(), "mismatched keys should fail");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("mismatch"),
        "error should mention mismatch: {}",
        err
    );
}

#[test]
fn test_env_key_roundtrip_preserves_key_material_for_decryption() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD]);
    let member_id = "ci-decrypt@example.com";
    let password = "strong-test-password-42";

    let (exported, _plaintext, public_key) = generate_and_export(member_id, password);

    // Load from env
    std::env::set_var(ENV_PRIVATE_KEY, &exported);
    std::env::set_var(ENV_KEY_PASSWORD, password);

    let (verified_key, _member_id) =
        load_private_key_from_env().expect("load from env should succeed");

    // Verify the loaded key matches the public key (simulates what CryptoContext does)
    let result = verify_own_public_key(verified_key.document(), &public_key);
    assert!(
        result.is_ok(),
        "env-loaded key should match its own public key: {:?}",
        result
    );
}
