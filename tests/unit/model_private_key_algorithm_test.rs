// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use secretenv::model::identifiers::alg::AEAD_XCHACHA20_POLY1305;
use secretenv::model::identifiers::private_key::{
    PROTECTION_METHOD_ARGON2ID_HKDF_SHA256, PROTECTION_METHOD_SSHSIG_ED25519_HKDF_SHA256,
};
use secretenv::model::private_key::*;

#[test]
fn test_sshsig_variant_roundtrip() {
    let alg = PrivateKeyAlgorithm::SshSig {
        fpr: "sha256:ABCDEFGH123456789".to_string(),
        salt: "c2FsdA".to_string(),
        aead: AEAD_XCHACHA20_POLY1305.to_string(),
    };

    let json = serde_json::to_value(&alg).expect("serialize");
    assert_eq!(json["kdf"], PROTECTION_METHOD_SSHSIG_ED25519_HKDF_SHA256);
    assert_eq!(json["fpr"], "sha256:ABCDEFGH123456789");
    assert_eq!(json["salt"], "c2FsdA");
    assert_eq!(json["aead"], AEAD_XCHACHA20_POLY1305);

    let deserialized: PrivateKeyAlgorithm = serde_json::from_value(json).expect("deserialize");
    assert_eq!(alg, deserialized);
}

#[test]
fn test_argon2id_variant_roundtrip() {
    let alg = PrivateKeyAlgorithm::Argon2id {
        m: 65536,
        t: 3,
        p: 4,
        salt: "YXJnb24yc2FsdA".to_string(),
        aead: AEAD_XCHACHA20_POLY1305.to_string(),
    };

    let json = serde_json::to_value(&alg).expect("serialize");
    assert_eq!(json["kdf"], PROTECTION_METHOD_ARGON2ID_HKDF_SHA256);
    assert_eq!(json["m"], 65536);
    assert_eq!(json["t"], 3);
    assert_eq!(json["p"], 4);
    assert_eq!(json["salt"], "YXJnb24yc2FsdA");
    assert_eq!(json["aead"], AEAD_XCHACHA20_POLY1305);

    let deserialized: PrivateKeyAlgorithm = serde_json::from_value(json).expect("deserialize");
    assert_eq!(alg, deserialized);
}

#[test]
fn test_unknown_kdf_fails() {
    let json = serde_json::json!({
        "kdf": "unknown-kdf-method",
        "salt": "c2FsdA",
        "aead": AEAD_XCHACHA20_POLY1305
    });

    let result = serde_json::from_value::<PrivateKeyAlgorithm>(json);
    assert!(result.is_err());
}

#[test]
fn test_existing_private_key_document_roundtrip() {
    let doc = PrivateKey {
        protected: PrivateKeyProtected {
            format: secretenv::model::identifiers::format::PRIVATE_KEY_V3.to_string(),
            member_id: "alice@example.com".to_string(),
            kid: "01HN8Z3Q4R5S6T7V8W9X0Y1Z2A".to_string(),
            alg: PrivateKeyAlgorithm::SshSig {
                fpr: "sha256:ABCDEFGH123456789".to_string(),
                salt: "c2FsdA".to_string(),
                aead: AEAD_XCHACHA20_POLY1305.to_string(),
            },
            created_at: "2024-01-15T00:00:00Z".to_string(),
            expires_at: "2025-01-15T00:00:00Z".to_string(),
        },
        encrypted: EncryptedData {
            nonce: "bm9uY2U".to_string(),
            ct: "Y3QNCg".to_string(),
        },
    };

    let json_str = serde_json::to_string(&doc).expect("serialize");
    let deserialized: PrivateKey = serde_json::from_str(&json_str).expect("deserialize");

    assert_eq!(doc, deserialized);

    // Verify wire format has "kdf" field for backward compatibility
    let json_value: serde_json::Value = serde_json::from_str(&json_str).expect("parse json");
    assert_eq!(
        json_value["protected"]["alg"]["kdf"],
        PROTECTION_METHOD_SSHSIG_ED25519_HKDF_SHA256
    );
}
