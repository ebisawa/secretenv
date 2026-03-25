// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for Signature model

use secretenv::model::signature::Signature;

#[test]
fn test_signature_serialization() {
    let sig = Signature {
        alg: secretenv::model::identifiers::alg::SIGNATURE_ED25519.to_string(),
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
        signer_pub: None,
        sig: "SGVsbG8gV29ybGQ".to_string(),
    };

    let json = serde_json::to_string(&sig).unwrap();
    assert!(json.contains(&format!(
        "\"alg\":\"{}\"",
        secretenv::model::identifiers::alg::SIGNATURE_ED25519
    )));
    assert!(!json.contains("\"signer\""));
    assert!(json.contains("\"kid\":\"7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD\""));
    assert!(json.contains("\"sig\":\"SGVsbG8gV29ybGQ\""));
}

#[test]
fn test_signature_deserialization() {
    let json = r#"{
        "alg": "eddsa-ed25519",
        "kid": "4Z8N6K1W3Q7RT5YH9M2PC4XV8D1B6FJA",
        "sig": "YWJjZGVmZ2hp"
    }"#;

    let sig: Signature = serde_json::from_str(json).unwrap();
    assert_eq!(
        sig.alg,
        secretenv::model::identifiers::alg::SIGNATURE_ED25519
    );
    assert_eq!(sig.kid, "4Z8N6K1W3Q7RT5YH9M2PC4XV8D1B6FJA");
    assert_eq!(sig.sig, "YWJjZGVmZ2hp");
    assert!(sig.signer_pub.is_none());
}

#[test]
fn test_signature_roundtrip() {
    let original = Signature {
        alg: secretenv::model::identifiers::alg::SIGNATURE_ED25519.to_string(),
        kid: "RDKJ8YHMPPJHW7QC3446GPNXHNRTX61N".to_string(),
        signer_pub: None,
        sig: "dGVzdHNpZ25hdHVyZQ".to_string(),
    };

    let json = serde_json::to_string(&original).unwrap();
    let deserialized: Signature = serde_json::from_str(&json).unwrap();

    assert_eq!(original, deserialized);
}
