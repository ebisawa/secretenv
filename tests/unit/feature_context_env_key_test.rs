// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use secretenv::feature::context::env_key::{is_env_key_mode, load_private_key_from_env};
use secretenv::feature::key::portable_export::export_private_key_portable;
use secretenv::model::private_key::{IdentityKeysPrivate, JwkOkpPrivateKey, PrivateKeyPlaintext};

use crate::test_utils::EnvGuard;

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
    )
    .expect("export should succeed")
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

    let (verified_key, member_id) = load_private_key_from_env().expect("should succeed");
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

    let result = load_private_key_from_env();
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

    let result = load_private_key_from_env();
    assert!(result.is_err());
}

#[test]
fn test_verify_own_public_key_match() {
    use secretenv::feature::context::env_key::verify_own_public_key;
    use secretenv::model::public_key::{
        Attestation, Identity, IdentityKeys, JwkOkpPublicKey, PublicKey, PublicKeyProtected,
    };

    let plaintext = build_test_plaintext();

    // Build a PublicKey with matching public components
    let public_key = PublicKey {
        protected: PublicKeyProtected {
            format: "secretenv.public.key@3".to_string(),
            member_id: "alice@example.com".to_string(),
            kid: "01HN8Z3Q4R5S6T7V8W9X0Y1Z2A".to_string(),
            identity: Identity {
                keys: IdentityKeys {
                    sig: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: "Ed25519".to_string(),
                        x: plaintext.keys.sig.x.clone(),
                    },
                    kem: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: "X25519".to_string(),
                        x: plaintext.keys.kem.x.clone(),
                    },
                },
                attestation: Attestation {
                    method: "ssh".to_string(),
                    pub_: "ssh-ed25519 AAAA test".to_string(),
                    sig: "dummy".to_string(),
                },
            },
            binding_claims: None,
            expires_at: "2027-01-01T00:00:00Z".to_string(),
            created_at: Some("2026-01-01T00:00:00Z".to_string()),
        },
        signature: "dummy".to_string(),
    };

    // Should succeed (only checks key component matching, not signature)
    let result = verify_own_public_key(&plaintext, &public_key);
    assert!(result.is_ok(), "matching keys should verify: {:?}", result);
}

#[test]
fn test_verify_own_public_key_mismatch_fails() {
    use secretenv::feature::context::env_key::verify_own_public_key;
    use secretenv::model::public_key::{
        Attestation, Identity, IdentityKeys, JwkOkpPublicKey, PublicKey, PublicKeyProtected,
    };

    let plaintext = build_test_plaintext();

    // Build a PublicKey with DIFFERENT sig public key
    let other_sig_sk = SigningKey::generate(&mut OsRng);
    let other_sig_pk = ed25519_dalek::VerifyingKey::from(&other_sig_sk);

    let public_key = PublicKey {
        protected: PublicKeyProtected {
            format: "secretenv.public.key@3".to_string(),
            member_id: "alice@example.com".to_string(),
            kid: "01HN8Z3Q4R5S6T7V8W9X0Y1Z2A".to_string(),
            identity: Identity {
                keys: IdentityKeys {
                    sig: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: "Ed25519".to_string(),
                        x: b64(&other_sig_pk.to_bytes()),
                    },
                    kem: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: "X25519".to_string(),
                        x: plaintext.keys.kem.x.clone(),
                    },
                },
                attestation: Attestation {
                    method: "ssh".to_string(),
                    pub_: "ssh-ed25519 AAAA test".to_string(),
                    sig: "dummy".to_string(),
                },
            },
            binding_claims: None,
            expires_at: "2027-01-01T00:00:00Z".to_string(),
            created_at: Some("2026-01-01T00:00:00Z".to_string()),
        },
        signature: "dummy".to_string(),
    };

    let result = verify_own_public_key(&plaintext, &public_key);
    assert!(result.is_err(), "mismatched keys should fail");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("mismatch") || err.contains("Mismatch"),
        "error should mention mismatch: {}",
        err
    );
}
