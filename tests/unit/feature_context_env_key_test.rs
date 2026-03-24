// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use secretenv::feature::context::env_key::{is_env_key_mode, load_private_key_from_env};
use secretenv::feature::key::portable_export::export_private_key_portable;
use secretenv::model::private_key::{
    EncryptedData, IdentityKeysPrivate, JwkOkpPrivateKey, PrivateKey, PrivateKeyAlgorithm,
    PrivateKeyPlaintext, PrivateKeyProtected,
};
use secretenv::model::public_key::PublicKey;
use secretenv::model::verified::{DecryptionProof, VerifiedPrivateKey};
use tempfile::TempDir;

use crate::test_utils::{create_temp_ssh_keypair_in_dir, keygen_test, EnvGuard};

const ENV_PRIVATE_KEY: &str = "SECRETENV_PRIVATE_KEY";
const ENV_KEY_PASSWORD: &str = "SECRETENV_KEY_PASSWORD";

fn b64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn build_test_plaintext() -> PrivateKeyPlaintext {
    let kem_sk = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let kem_pk = x25519_dalek::PublicKey::from(&kem_sk);

    let sig_sk = SigningKey::generate(&mut OsRng);
    let sig_pk = ed25519_dalek::VerifyingKey::from(&sig_sk);

    PrivateKeyPlaintext {
        keys: IdentityKeysPrivate {
            kem: JwkOkpPrivateKey {
                kty: "OKP".to_string(),
                crv: "X25519".to_string(),
                x: b64(kem_pk.as_bytes()),
                d: b64(&kem_sk.to_bytes()),
            },
            sig: JwkOkpPrivateKey {
                kty: "OKP".to_string(),
                crv: "Ed25519".to_string(),
                x: b64(&sig_pk.to_bytes()),
                d: b64(&sig_sk.to_bytes()),
            },
        },
    }
}

fn build_exported_key(plaintext: &PrivateKeyPlaintext, password: &str) -> String {
    export_private_key_portable(
        plaintext,
        "alice@example.com",
        "01HN8Z3Q4R5S6T7V8W9X0Y1Z2A",
        "2026-01-01T00:00:00Z",
        "2027-01-01T00:00:00Z",
        password,
        false,
    )
    .expect("export should succeed")
}

fn build_verified_private_key(
    plaintext: PrivateKeyPlaintext,
    member_id: &str,
    kid: &str,
) -> VerifiedPrivateKey {
    VerifiedPrivateKey::new(
        plaintext,
        DecryptionProof {
            member_id: member_id.to_string(),
            kid: kid.to_string(),
            ssh_fpr: None,
        },
    )
}

fn generate_attested_pair(member_id: &str) -> (VerifiedPrivateKey, PublicKey) {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub, ssh_pub_content) = create_temp_ssh_keypair_in_dir(&temp_dir);
    let (plaintext, public_key) = keygen_test(member_id, &ssh_priv, &ssh_pub_content).unwrap();
    let verified_private =
        build_verified_private_key(plaintext, member_id, &public_key.protected.kid);
    (verified_private, public_key)
}

fn resign_public_key(public_key: &mut PublicKey, private_key: &VerifiedPrivateKey) {
    let sig_key_bytes = URL_SAFE_NO_PAD
        .decode(&private_key.document().keys.sig.d)
        .expect("decode signing key");
    let signing_key = ed25519_dalek::SigningKey::from_bytes(
        sig_key_bytes
            .as_slice()
            .try_into()
            .expect("32-byte signing key"),
    );
    let protected_jcs = secretenv::format::jcs::normalize(&public_key.protected).expect("jcs");
    let signature = secretenv::crypto::sign::sign_bytes(
        &protected_jcs,
        &signing_key,
        &public_key.protected.kid,
        None,
        secretenv::model::identifiers::alg::SIGNATURE_ED25519,
    )
    .expect("re-sign public key");
    public_key.signature = signature.sig;
}

fn assert_env_key_vars_cleared() {
    assert!(
        std::env::var(ENV_PRIVATE_KEY).is_err(),
        "SECRETENV_PRIVATE_KEY should be cleared"
    );
    assert!(
        std::env::var(ENV_KEY_PASSWORD).is_err(),
        "SECRETENV_KEY_PASSWORD should be cleared"
    );
}

#[test]
fn test_is_env_key_mode_when_set() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD]);
    std::env::set_var(ENV_PRIVATE_KEY, "dummy-value");

    assert!(is_env_key_mode());
}

#[test]
fn test_is_env_key_mode_when_unset() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD]);
    std::env::remove_var(ENV_PRIVATE_KEY);

    assert!(!is_env_key_mode());
}

#[test]
fn test_decode_env_private_key() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD]);
    let plaintext = build_test_plaintext();
    let password = "strong-password-42";
    let exported = build_exported_key(&plaintext, password);

    std::env::set_var(ENV_PRIVATE_KEY, &exported);
    std::env::set_var(ENV_KEY_PASSWORD, password);

    let (verified_key, member_id) = load_private_key_from_env(false).expect("should succeed");
    assert_eq!(member_id, "alice@example.com");
    assert_eq!(verified_key.proof().kid, "01HN8Z3Q4R5S6T7V8W9X0Y1Z2A");
    assert_eq!(verified_key.proof().ssh_fpr, None);
    assert_eq!(verified_key.document().keys.sig.x, plaintext.keys.sig.x);
    assert_eq!(verified_key.document().keys.kem.x, plaintext.keys.kem.x);
}

#[test]
fn test_env_key_missing_password_error() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD]);
    let plaintext = build_test_plaintext();
    let exported = build_exported_key(&plaintext, "strong-password-42");

    std::env::set_var(ENV_PRIVATE_KEY, &exported);
    std::env::remove_var(ENV_KEY_PASSWORD);

    let result = load_private_key_from_env(false);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("SECRETENV_KEY_PASSWORD"),
        "error should mention SECRETENV_KEY_PASSWORD: {}",
        err
    );
}

#[test]
fn test_env_key_invalid_base64_error() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD]);
    std::env::set_var(ENV_PRIVATE_KEY, "not-valid-base64!!!");
    std::env::set_var(ENV_KEY_PASSWORD, "strong-password-42");

    let result = load_private_key_from_env(false);
    assert!(result.is_err());
    assert_env_key_vars_cleared();
}

#[test]
fn test_verify_own_public_key_match() {
    use secretenv::feature::context::env_key::verify_own_public_key;
    let (verified_private, public_key) = generate_attested_pair("alice@example.com");
    let result = verify_own_public_key(&verified_private, &public_key, false);
    assert!(result.is_ok(), "matching keys should verify: {:?}", result);
    assert!(result.unwrap().warnings.is_empty());
}

#[test]
fn test_verify_own_public_key_sig_mismatch_fails() {
    use secretenv::feature::context::env_key::verify_own_public_key;
    let (verified_private, public_key) = generate_attested_pair("alice@example.com");
    let (other_private, _) = generate_attested_pair("alice@example.com");
    let mut mismatched_plaintext = verified_private.document().clone();
    mismatched_plaintext.keys.sig = other_private.document().keys.sig.clone();
    let mismatched_private = build_verified_private_key(
        mismatched_plaintext,
        &verified_private.proof().member_id,
        &verified_private.proof().kid,
    );

    let result = verify_own_public_key(&mismatched_private, &public_key, false);
    assert!(result.is_err(), "mismatched keys should fail");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Signing key mismatch"),
        "error should mention signing key mismatch: {}",
        err
    );
}

#[test]
fn test_env_vars_cleared_after_successful_load() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD]);
    let plaintext = build_test_plaintext();
    let password = "strong-password-42";
    let exported = build_exported_key(&plaintext, password);

    std::env::set_var(ENV_PRIVATE_KEY, &exported);
    std::env::set_var(ENV_KEY_PASSWORD, password);

    let _result = load_private_key_from_env(false).expect("should succeed");

    assert_env_key_vars_cleared();
}

#[test]
fn test_env_key_rejects_invalid_format() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD]);

    // Build a PrivateKey with wrong format string
    let bad_format_key = PrivateKey {
        protected: PrivateKeyProtected {
            format: "secretenv.private.key@2".to_string(),
            member_id: "alice@example.com".to_string(),
            kid: "01HN8Z3Q4R5S6T7V8W9X0Y1Z2A".to_string(),
            alg: PrivateKeyAlgorithm::Argon2id {
                salt: "AAAAAAAAAAAAAAAAAAAAAA".to_string(),
                aead: "xchacha20-poly1305".to_string(),
            },
            created_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "2027-01-01T00:00:00Z".to_string(),
        },
        encrypted: EncryptedData {
            nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            ct: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
        },
    };

    let json = serde_json::to_vec(&bad_format_key).expect("serialize");
    let encoded = URL_SAFE_NO_PAD.encode(&json);

    std::env::set_var(ENV_PRIVATE_KEY, &encoded);
    std::env::set_var(ENV_KEY_PASSWORD, "test-password");

    let result = load_private_key_from_env(false);
    assert!(result.is_err(), "Wrong format should be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Expected format"),
        "error should mention expected format: {}",
        err
    );
    assert_env_key_vars_cleared();
}

#[test]
fn test_env_key_rejects_sshsig_algorithm() {
    let _guard = EnvGuard::new(&[ENV_PRIVATE_KEY, ENV_KEY_PASSWORD]);

    // Build a PrivateKey with SshSig algorithm and encode it
    let sshsig_key = PrivateKey {
        protected: PrivateKeyProtected {
            format: "secretenv.private.key@3".to_string(),
            member_id: "alice@example.com".to_string(),
            kid: "01HN8Z3Q4R5S6T7V8W9X0Y1Z2A".to_string(),
            alg: PrivateKeyAlgorithm::SshSig {
                fpr: "SHA256:dummy".to_string(),
                salt: "AAAAAAAAAAAAAAAAAAAAAA".to_string(),
                aead: "xchacha20-poly1305".to_string(),
            },
            created_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "2027-01-01T00:00:00Z".to_string(),
        },
        encrypted: EncryptedData {
            nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            ct: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
        },
    };

    let json = serde_json::to_vec(&sshsig_key).expect("serialize");
    let encoded = URL_SAFE_NO_PAD.encode(&json);

    std::env::set_var(ENV_PRIVATE_KEY, &encoded);
    std::env::set_var(ENV_KEY_PASSWORD, "test-password");

    let result = load_private_key_from_env(false);
    assert!(result.is_err(), "SshSig key should be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("password-protected") || err.contains("argon2id"),
        "error should mention password-protected requirement: {}",
        err
    );
    assert_env_key_vars_cleared();
}

#[test]
fn test_verify_own_public_key_kem_mismatch_fails() {
    use secretenv::feature::context::env_key::verify_own_public_key;
    let (verified_private, public_key) = generate_attested_pair("alice@example.com");
    let (other_private, _) = generate_attested_pair("alice@example.com");
    let mut mismatched_plaintext = verified_private.document().clone();
    mismatched_plaintext.keys.kem = other_private.document().keys.kem.clone();
    let mismatched_private = build_verified_private_key(
        mismatched_plaintext,
        &verified_private.proof().member_id,
        &verified_private.proof().kid,
    );

    let result = verify_own_public_key(&mismatched_private, &public_key, false);
    assert!(result.is_err(), "KEM mismatch should fail");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("KEM") && err.contains("mismatch"),
        "error should mention KEM mismatch: {}",
        err
    );
}

#[test]
fn test_verify_own_public_key_expired_returns_warning() {
    use secretenv::feature::context::env_key::verify_own_public_key;

    let (verified_private, mut public_key) = generate_attested_pair("alice@example.com");
    public_key.protected.expires_at = "2020-01-01T00:00:00Z".to_string();
    resign_public_key(&mut public_key, &verified_private);

    let result = verify_own_public_key(&verified_private, &public_key, false)
        .expect("expired verified key should still succeed");
    assert_eq!(result.warnings.len(), 1);
    assert!(result.warnings[0].contains("expired"));
}

#[test]
fn test_verify_own_public_key_rejects_tampered_public_key_document() {
    use secretenv::feature::context::env_key::verify_own_public_key;

    let (verified_private, mut public_key) = generate_attested_pair("alice@example.com");
    public_key.signature = "AAAA".to_string();

    let result = verify_own_public_key(&verified_private, &public_key, false);
    assert!(result.is_err(), "tampered self-signature should fail");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("self-signature") || err.contains("signature"),
        "error should mention self-signature failure: {}",
        err
    );
}
