// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use secretenv::feature::key::portable_export::export_private_key_portable;
use secretenv::feature::key::protection::password_encryption::decrypt_private_key_with_password;
use secretenv::model::private_key::{
    IdentityKeysPrivate, JwkOkpPrivateKey, PrivateKey, PrivateKeyAlgorithm, PrivateKeyPlaintext,
};

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

#[test]
fn test_export_produces_valid_base64url() {
    let plaintext = build_test_plaintext();
    let result = export_private_key_portable(
        &plaintext,
        "alice@example.com",
        "01HN8Z3Q4R5S6T7V8W9X0Y1Z2A",
        "2026-01-01T00:00:00Z",
        "2027-01-01T00:00:00Z",
        "strong-password-42",
    )
    .expect("export should succeed");

    // No padding characters
    assert!(!result.contains('='), "should not contain padding");
    // No standard base64 characters
    assert!(!result.contains('+'), "should not contain '+'");
    assert!(!result.contains('/'), "should not contain '/'");
    // Only valid base64url characters
    assert!(
        result
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
        "should only contain base64url characters"
    );
    // Should be non-empty
    assert!(!result.is_empty(), "should not be empty");
}

#[test]
fn test_export_roundtrip() {
    let plaintext = build_test_plaintext();
    let password = "strong-password-42";

    let exported = export_private_key_portable(
        &plaintext,
        "alice@example.com",
        "01HN8Z3Q4R5S6T7V8W9X0Y1Z2A",
        "2026-01-01T00:00:00Z",
        "2027-01-01T00:00:00Z",
        password,
    )
    .expect("export should succeed");

    // Decode base64url
    let json_bytes = URL_SAFE_NO_PAD
        .decode(&exported)
        .expect("should be valid base64url");

    // Deserialize to PrivateKey
    let private_key: PrivateKey =
        serde_json::from_slice(&json_bytes).expect("should be valid JSON");

    // Decrypt with password
    let decrypted = decrypt_private_key_with_password(&private_key, password)
        .expect("decryption should succeed");

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_export_preserves_metadata() {
    let plaintext = build_test_plaintext();
    let member_id = "bob@example.com";
    let kid = "01HN8Z3Q4R5S6T7V8W9X0Y1Z2A";
    let created_at = "2026-03-01T12:00:00Z";
    let expires_at = "2027-03-01T12:00:00Z";

    let exported = export_private_key_portable(
        &plaintext,
        member_id,
        kid,
        created_at,
        expires_at,
        "strong-password-42",
    )
    .expect("export should succeed");

    let json_bytes = URL_SAFE_NO_PAD
        .decode(&exported)
        .expect("should be valid base64url");
    let private_key: PrivateKey =
        serde_json::from_slice(&json_bytes).expect("should be valid JSON");

    assert_eq!(private_key.protected.member_id, member_id);
    assert_eq!(private_key.protected.kid, kid);
    assert_eq!(private_key.protected.created_at, created_at);
    assert_eq!(private_key.protected.expires_at, expires_at);
}

#[test]
fn test_export_uses_argon2id_kdf() {
    let plaintext = build_test_plaintext();

    let exported = export_private_key_portable(
        &plaintext,
        "alice@example.com",
        "01HN8Z3Q4R5S6T7V8W9X0Y1Z2A",
        "2026-01-01T00:00:00Z",
        "2027-01-01T00:00:00Z",
        "strong-password-42",
    )
    .expect("export should succeed");

    let json_bytes = URL_SAFE_NO_PAD
        .decode(&exported)
        .expect("should be valid base64url");
    let private_key: PrivateKey =
        serde_json::from_slice(&json_bytes).expect("should be valid JSON");

    // Verify kdf tag serializes to argon2id-hkdf-sha256
    let json = serde_json::to_value(&private_key.protected.alg).unwrap();
    assert_eq!(json["kdf"], "argon2id-hkdf-sha256");

    match &private_key.protected.alg {
        PrivateKeyAlgorithm::Argon2id { .. } => {}
        _ => panic!("expected Argon2id algorithm variant"),
    }
}

#[test]
fn test_export_password_too_short_fails() {
    let plaintext = build_test_plaintext();

    let result = export_private_key_portable(
        &plaintext,
        "alice@example.com",
        "01HN8Z3Q4R5S6T7V8W9X0Y1Z2A",
        "2026-01-01T00:00:00Z",
        "2027-01-01T00:00:00Z",
        "short",
    );

    assert!(result.is_err(), "password shorter than 8 chars should fail");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("password") || err.contains("Password"),
        "error should mention password: {}",
        err
    );
}
