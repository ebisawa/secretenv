// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for Signature model

use secretenv::model::signature::Signature;

#[test]
fn test_signature_serialization() {
    let sig = Signature {
        alg: secretenv::model::identifiers::alg::SIGNATURE_ED25519.to_string(),
        kid: "01HY0G8N3P5X7QRSTV0WXYZ123".to_string(),
        signer_pub: None,
        sig: "SGVsbG8gV29ybGQ".to_string(),
    };

    let json = serde_json::to_string(&sig).unwrap();
    assert!(json.contains(&format!(
        "\"alg\":\"{}\"",
        secretenv::model::identifiers::alg::SIGNATURE_ED25519
    )));
    assert!(!json.contains("\"signer\""));
    assert!(json.contains("\"kid\":\"01HY0G8N3P5X7QRSTV0WXYZ123\""));
    assert!(json.contains("\"sig\":\"SGVsbG8gV29ybGQ\""));
}

#[test]
fn test_signature_deserialization() {
    let json = r#"{
        "alg": "eddsa-ed25519",
        "kid": "01HXYZ1234ABCDEFGHJKMNPQRS",
        "sig": "YWJjZGVmZ2hp"
    }"#;

    let sig: Signature = serde_json::from_str(json).unwrap();
    assert_eq!(
        sig.alg,
        secretenv::model::identifiers::alg::SIGNATURE_ED25519
    );
    assert_eq!(sig.kid, "01HXYZ1234ABCDEFGHJKMNPQRS");
    assert_eq!(sig.sig, "YWJjZGVmZ2hp");
    assert!(sig.signer_pub.is_none());
}

#[test]
fn test_signature_roundtrip() {
    let original = Signature {
        alg: secretenv::model::identifiers::alg::SIGNATURE_ED25519.to_string(),
        kid: "01HTEST123456789ABCDEFGHIJK".to_string(),
        signer_pub: None,
        sig: "dGVzdHNpZ25hdHVyZQ".to_string(),
    };

    let json = serde_json::to_string(&original).unwrap();
    let deserialized: Signature = serde_json::from_str(&json).unwrap();

    assert_eq!(original, deserialized);
}
