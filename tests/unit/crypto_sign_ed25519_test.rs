// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for Ed25519 signature primitives

use ed25519_dalek::SigningKey;
use secretenv::crypto::sign::{sign_bytes, verify_bytes};
use secretenv::model::identifiers::alg::SIGNATURE_ED25519;
use secretenv::model::signature::Signature;

#[test]
fn test_sign_bytes_returns_valid_structure() {
    let seed = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);

    let canonical_bytes = b"test canonical bytes";

    let sig = sign_bytes(
        canonical_bytes,
        &sk,
        "01HY0G8N3P5X7QRSTV0WXYZ123",
        None,
        SIGNATURE_ED25519,
    )
    .unwrap();

    assert_eq!(sig.alg, SIGNATURE_ED25519);
    assert_eq!(sig.kid, "01HY0G8N3P5X7QRSTV0WXYZ123");
    assert!(sig.signer_pub.is_none());
    assert!(!sig.sig.is_empty());
}

#[test]
fn test_verify_bytes_accepts_valid_signature() {
    let seed = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();

    let canonical_bytes = b"test canonical bytes";

    let sig = sign_bytes(
        canonical_bytes,
        &sk,
        "01HY0G8N3P5X7QRSTV0WXYZ123",
        None,
        SIGNATURE_ED25519,
    )
    .unwrap();
    verify_bytes(canonical_bytes, &vk, &sig, SIGNATURE_ED25519).unwrap();
}

#[test]
fn test_verify_bytes_rejects_wrong_algorithm() {
    let seed = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();

    let canonical_bytes = b"test canonical bytes";

    let bad_sig = Signature {
        alg: "rsa-2048".to_string(),
        kid: "01HY0G8N3P5X7QRSTV0WXYZ123".to_string(),
        signer_pub: None,
        sig: "AAAA".to_string(),
    };

    let result = verify_bytes(canonical_bytes, &vk, &bad_sig, SIGNATURE_ED25519);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Unsupported signature algorithm"));
}

#[test]
fn test_verify_bytes_rejects_tampered_bytes() {
    let seed = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();

    let original = b"test canonical bytes";
    let tampered = b"tampered canonical bytes";

    let sig = sign_bytes(
        original,
        &sk,
        "01HY0G8N3P5X7QRSTV0WXYZ123",
        None,
        SIGNATURE_ED25519,
    )
    .unwrap();

    let result = verify_bytes(tampered, &vk, &sig, SIGNATURE_ED25519);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Signature verification failed"));
}

#[test]
fn test_sign_bytes_deterministic() {
    let seed = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);

    let canonical_bytes = b"deterministic test bytes";

    let sig1 = sign_bytes(
        canonical_bytes,
        &sk,
        "01HY0G8N3P5X7QRSTV0WXYZ123",
        None,
        SIGNATURE_ED25519,
    )
    .unwrap();
    let sig2 = sign_bytes(
        canonical_bytes,
        &sk,
        "01HY0G8N3P5X7QRSTV0WXYZ123",
        None,
        SIGNATURE_ED25519,
    )
    .unwrap();

    // Ed25519 signatures are deterministic per RFC 8032
    assert_eq!(sig1.sig, sig2.sig);
}

#[test]
fn test_sign_kv_returns_valid_structure() {
    let seed = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);

    let canonical_bytes = b":SECRETENV_KV 3\n:WRAP {...}\nKEY {...}\n";

    let sig = sign_bytes(
        canonical_bytes,
        &sk,
        "01HY0G8N3P5X7QRSTV0WXYZ123",
        None,
        SIGNATURE_ED25519,
    )
    .unwrap();

    assert_eq!(sig.alg, SIGNATURE_ED25519);
    assert_eq!(sig.kid, "01HY0G8N3P5X7QRSTV0WXYZ123");
    assert!(sig.signer_pub.is_none());
    assert!(!sig.sig.is_empty());
}

#[test]
fn test_verify_kv_accepts_valid_signature() {
    let seed = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();

    let canonical_bytes = b":SECRETENV_KV 3\n:WRAP {...}\nKEY {...}\n";

    let sig = sign_bytes(
        canonical_bytes,
        &sk,
        "01HY0G8N3P5X7QRSTV0WXYZ123",
        None,
        SIGNATURE_ED25519,
    )
    .unwrap();
    verify_bytes(canonical_bytes, &vk, &sig, SIGNATURE_ED25519).unwrap();
}

#[test]
fn test_verify_kv_rejects_tampered_content() {
    let seed = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();

    let original = b":SECRETENV_KV 3\n:WRAP {...}\nKEY {...}\n";
    let tampered = b":SECRETENV_KV 3\n:WRAP {...}\nKEY {!!!}\n";

    let sig = sign_bytes(
        original,
        &sk,
        "01HY0G8N3P5X7QRSTV0WXYZ123",
        None,
        SIGNATURE_ED25519,
    )
    .unwrap();
    let result = verify_bytes(tampered, &vk, &sig, SIGNATURE_ED25519);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Signature verification failed"));
}

#[test]
fn test_kv_lf_normalization_matters() {
    let seed = [42u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();

    let lf_version = b":SECRETENV_KV 3\nKEY {...}\n";
    let crlf_version = b":SECRETENV_KV 3\r\nKEY {...}\r\n";

    // Sign LF version
    let sig = sign_bytes(
        lf_version,
        &sk,
        "01HY0G8N3P5X7QRSTV0WXYZ123",
        None,
        SIGNATURE_ED25519,
    )
    .unwrap();

    // Verify with CRLF should fail (caller must normalize)
    let result = verify_bytes(crlf_version, &vk, &sig, SIGNATURE_ED25519);
    assert!(result.is_err());
}
