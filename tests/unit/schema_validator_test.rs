// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for JSON Schema validator

use secretenv::io::schema::validator::Validator;
use secretenv::model::identifiers::hpke;

#[test]
fn test_validator_creation() {
    let validator = Validator::new();
    assert!(
        validator.is_ok(),
        "Validator v3 should be created successfully"
    );
}

#[test]
fn test_validate_public_key_basic() {
    let validator = Validator::new().unwrap();
    // v3 schema requires: protected (format, member_id, kid, identity, attestation, expires_at), signature
    let valid_public_key = serde_json::json!({
        "protected": {
            "format": secretenv::model::identifiers::format::PUBLIC_KEY_V3,
            "member_id": "alice@example.com",
            "kid": "01HY0G8N3P5X7QRSTV0WXYZ123",
            "identity": {
                "keys": {
                    "kem": {
                        "kty": "OKP",
                        "crv": secretenv::model::identifiers::jwk::CRV_X25519,
                        "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    },
                    "sig": {
                        "kty": "OKP",
                        "crv": secretenv::model::identifiers::jwk::CRV_ED25519,
                        "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    }
                },
                "attestation": {
                    "method": "ssh-sign",
                    "pub": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "sig": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ"
                }
            },
            "expires_at": "2027-01-01T00:00:00Z"
        },
        "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    });

    let result = validator.validate_public_key(&valid_public_key);
    assert!(
        result.is_ok(),
        "Valid public key v3 should pass validation: {:?}",
        result
    );
}

#[test]
fn test_validate_private_key_basic() {
    let validator = Validator::new().unwrap();
    // v3 schema (Rev11): external format with protection and encrypted fields
    let valid_private_key = serde_json::json!({
        "protected": {
            "format": secretenv::model::identifiers::format::PRIVATE_KEY_V3,
            "member_id": "alice@example.com",
            "kid": "01HY0G8N3P5X7QRSTV0WXYZ123",
            "alg": {
                "kdf": secretenv::model::identifiers::private_key::PROTECTION_METHOD_SSHSIG_ED25519_HKDF_SHA256,
                "fpr": "sha256:abcdef1234567890",
                "salt": "AAAAAAAAAAAAAAAAAAAAAA",
                "aead": secretenv::model::identifiers::alg::AEAD_XCHACHA20_POLY1305
            },
            "created_at": "2026-01-14T00:00:00Z",
            "expires_at": "2027-01-14T00:00:00Z"
        },
        "encrypted": {
            "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "ct": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        }
    });

    let result = validator.validate_private_key(&valid_private_key);
    assert!(
        result.is_ok(),
        "Valid private key v3 should pass validation: {:?}",
        result
    );
}

#[test]
fn test_validate_file_enc_document_basic() {
    let validator = Validator::new().unwrap();
    // v3 schema requires: protected { format, sid, payload, wrap, created_at, updated_at }, signature
    // payload is envelope: { protected { format, sid, alg }, encrypted { nonce, ct } }
    // wrap_item v3 requires: rid, kid, alg, enc, ct
    let sid = "123e4567-e89b-12d3-a456-426614174000";
    let valid_file_enc_doc = serde_json::json!({
        "protected": {
            "format": secretenv::model::identifiers::format::FILE_ENC_V3,
            "sid": sid,
            "payload": {
                "protected": {
                    "format": secretenv::model::identifiers::format::FILE_PAYLOAD_V3,
                    "sid": sid,
                    "alg": {
                        "aead": secretenv::model::identifiers::alg::AEAD_XCHACHA20_POLY1305
                    }
                },
                "encrypted": {
                    "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "ct": "AAAAAAAAAAAAAAAA"
                }
            },
            "wrap": [{
                "rid": "alice@example.com",
                "kid": "01HY0G8N3P5X7QRSTV0WXYZ123",
                "alg": hpke::ALG_HPKE_32_1_3,
                "enc": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "ct": "AAAAAAAAAAAAAAAA"
            }],
            "created_at": "2026-01-14T00:00:00Z",
            "updated_at": "2026-01-14T00:00:00Z"
        },
        "signature": {
            "alg": secretenv::model::identifiers::alg::SIGNATURE_ED25519,
            "kid": "01HY0G8N3P5X7QRSTV0WXYZ123",
            "sig": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ"
        }
    });

    let result = validator.validate_file_enc_document(&valid_file_enc_doc);
    assert!(
        result.is_ok(),
        "Valid file secret v3 should pass validation: {:?}",
        result
    );
}

#[test]
fn test_validator_allows_member_id_without_at_in_wrap_rid() {
    let validator = Validator::new().unwrap();

    // Regression test:
    // - CLI validation allows member_id without '@' (e.g. GitHub login like "ebisawa")
    // - v3 JSON schema should accept the same to avoid runtime validation failures
    let sid = "123e4567-e89b-12d3-a456-426614174000";
    let valid_file_enc_doc = serde_json::json!({
        "protected": {
            "format": secretenv::model::identifiers::format::FILE_ENC_V3,
            "sid": sid,
            "payload": {
                "protected": {
                    "format": secretenv::model::identifiers::format::FILE_PAYLOAD_V3,
                    "sid": sid,
                    "alg": {
                        "aead": secretenv::model::identifiers::alg::AEAD_XCHACHA20_POLY1305
                    }
                },
                "encrypted": {
                    "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "ct": "AAAAAAAAAAAAAAAA"
                }
            },
            "wrap": [{
                "rid": "ebisawa",
                "kid": "01HY0G8N3P5X7QRSTV0WXYZ123",
                "alg": hpke::ALG_HPKE_32_1_3,
                "enc": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "ct": "AAAAAAAAAAAAAAAA"
            }],
            "created_at": "2026-01-14T00:00:00Z",
            "updated_at": "2026-01-14T00:00:00Z"
        },
        "signature": {
            "alg": secretenv::model::identifiers::alg::SIGNATURE_ED25519,
            "kid": "01HY0G8N3P5X7QRSTV0WXYZ123",
            "sig": "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ"
        }
    });

    let result = validator.validate_file_enc_document(&valid_file_enc_doc);
    assert!(
        result.is_ok(),
        "Schema should allow member_id without '@' in wrap.rid: {:?}",
        result
    );
}
