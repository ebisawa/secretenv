// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use secretenv::feature::key::protection::password_encryption::{
    decrypt_private_key_with_password, encrypt_private_key_with_password,
};
use secretenv::model::private_key::{
    IdentityKeysPrivate, JwkOkpPrivateKey, PrivateKeyAlgorithm, PrivateKeyPlaintext,
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
fn test_password_encrypt_decrypt_roundtrip() {
    let plaintext = build_test_plaintext();
    let password = "test-password-42";

    let encrypted = encrypt_private_key_with_password(
        &plaintext,
        "alice@example.com",
        "01HN8Z3Q4R5S6T7V8W9X0Y1Z2A",
        "2026-01-01T00:00:00Z",
        "2027-01-01T00:00:00Z",
        password,
    )
    .expect("encryption should succeed");

    let decrypted =
        decrypt_private_key_with_password(&encrypted, password).expect("decryption should succeed");

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_password_encrypt_wrong_password_fails() {
    let plaintext = build_test_plaintext();

    let encrypted = encrypt_private_key_with_password(
        &plaintext,
        "alice@example.com",
        "01HN8Z3Q4R5S6T7V8W9X0Y1Z2A",
        "2026-01-01T00:00:00Z",
        "2027-01-01T00:00:00Z",
        "correct-password",
    )
    .expect("encryption should succeed");

    let result = decrypt_private_key_with_password(&encrypted, "wrong-password");
    assert!(
        result.is_err(),
        "decryption with wrong password should fail"
    );
}

#[test]
fn test_password_encrypt_alg_kdf_is_argon2id() {
    let plaintext = build_test_plaintext();

    let encrypted = encrypt_private_key_with_password(
        &plaintext,
        "alice@example.com",
        "01HN8Z3Q4R5S6T7V8W9X0Y1Z2A",
        "2026-01-01T00:00:00Z",
        "2027-01-01T00:00:00Z",
        "test-password",
    )
    .expect("encryption should succeed");

    match &encrypted.protected.alg {
        PrivateKeyAlgorithm::Argon2id { m, t, p, aead, .. } => {
            assert_eq!(*m, 47104);
            assert_eq!(*t, 1);
            assert_eq!(*p, 1);
            assert_eq!(aead, "xchacha20-poly1305");
        }
        _ => panic!("expected Argon2id algorithm variant"),
    }

    // Verify kdf tag serializes correctly
    let json = serde_json::to_value(&encrypted.protected.alg).unwrap();
    assert_eq!(json["kdf"], "argon2id-hkdf-sha256");
}

#[test]
fn test_password_encrypt_preserves_metadata() {
    let plaintext = build_test_plaintext();
    let member_id = "bob@example.com";
    let kid = "01HN8Z3Q4R5S6T7V8W9X0Y1Z2A";
    let created_at = "2026-03-01T12:00:00Z";
    let expires_at = "2027-03-01T12:00:00Z";

    let encrypted =
        encrypt_private_key_with_password(&plaintext, member_id, kid, created_at, expires_at, "pw")
            .expect("encryption should succeed");

    assert_eq!(encrypted.protected.member_id, member_id);
    assert_eq!(encrypted.protected.kid, kid);
    assert_eq!(encrypted.protected.created_at, created_at);
    assert_eq!(encrypted.protected.expires_at, expires_at);
    assert_eq!(encrypted.protected.format, "secretenv.private.key@3");
}
