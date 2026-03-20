// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for FileEncDocument model

use secretenv::model::file_enc::{
    FileEncAlgorithm, FileEncDocument, FileEncDocumentProtected, FilePayload,
    FilePayloadCiphertext, FilePayloadHeader,
};
use secretenv::model::identifiers::hpke;
use secretenv::model::signature::Signature;
use uuid::Uuid;

fn create_test_payload_envelope() -> FilePayload {
    let sid = Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").unwrap();
    FilePayload {
        protected: FilePayloadHeader {
            format: secretenv::model::identifiers::format::FILE_PAYLOAD_V3.to_string(),
            sid,
            alg: FileEncAlgorithm {
                aead: secretenv::model::identifiers::alg::AEAD_XCHACHA20_POLY1305.to_string(),
            },
        },
        encrypted: FilePayloadCiphertext {
            nonce: "nonce_base64url".to_string(),
            ct: "ciphertext_base64url".to_string(),
        },
    }
}

#[test]
fn test_file_enc_document_basic() {
    let sid = Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").unwrap();
    let doc = FileEncDocument {
        protected: FileEncDocumentProtected {
            format: secretenv::model::identifiers::format::FILE_ENC_V3.to_string(),
            sid,
            wrap: vec![secretenv::model::common::WrapItem {
                rid: "alice@example.com".to_string(),
                kid: "01HY0G8N3P5X7QRSTV0WXYZ123".to_string(),
                alg: hpke::ALG_HPKE_32_1_3.to_string(),
                enc: "enc_base64url".to_string(),
                ct: "ct_base64url".to_string(),
            }],
            removed_recipients: None,
            payload: create_test_payload_envelope(),
            created_at: "2025-01-01T00:00:00Z".to_string(),
            updated_at: "2025-01-01T00:00:00Z".to_string(),
        },
        signature: Signature {
            alg: secretenv::model::identifiers::alg::SIGNATURE_ED25519.to_string(),
            kid: "01HY0G8N3P5X7QRSTV0WXYZ123".to_string(),
            signer_pub: None,
            sig: "signature_base64url".to_string(),
        },
    };

    let json = serde_json::to_string(&doc).unwrap();
    let deserialized: FileEncDocument = serde_json::from_str(&json).unwrap();
    assert_eq!(doc, deserialized);
}

#[test]
fn test_recipients_derived_from_wrap() {
    let sid = Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").unwrap();
    let doc = FileEncDocument {
        protected: FileEncDocumentProtected {
            format: secretenv::model::identifiers::format::FILE_ENC_V3.to_string(),
            sid,
            wrap: vec![
                secretenv::model::common::WrapItem {
                    rid: "alice@example.com".to_string(),
                    kid: "01HY0G8N3P5X7QRSTV0WXYZ123".to_string(),
                    alg: hpke::ALG_HPKE_32_1_3.to_string(),
                    enc: "enc1".to_string(),
                    ct: "ct1".to_string(),
                },
                secretenv::model::common::WrapItem {
                    rid: "bob@example.com".to_string(),
                    kid: "01HY0G8N3P5X7QRSTV0WXYZ456".to_string(),
                    alg: hpke::ALG_HPKE_32_1_3.to_string(),
                    enc: "enc2".to_string(),
                    ct: "ct2".to_string(),
                },
            ],
            removed_recipients: None,
            payload: create_test_payload_envelope(),
            created_at: "2025-01-01T00:00:00Z".to_string(),
            updated_at: "2025-01-01T00:00:00Z".to_string(),
        },
        signature: Signature {
            alg: secretenv::model::identifiers::alg::SIGNATURE_ED25519.to_string(),
            kid: "01HY0G8N3P5X7QRSTV0WXYZ123".to_string(),
            signer_pub: None,
            sig: "sig".to_string(),
        },
    };

    let recipients = doc.recipients();
    assert_eq!(recipients.len(), 2);
    assert_eq!(recipients[0], "alice@example.com");
    assert_eq!(recipients[1], "bob@example.com");
}

#[test]
fn test_payload_serialization() {
    // Test that payload.protected correctly serializes without sid field
    let sid = Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").unwrap();
    let doc = FileEncDocument {
        protected: FileEncDocumentProtected {
            format: secretenv::model::identifiers::format::FILE_ENC_V3.to_string(),
            sid,
            wrap: vec![],
            removed_recipients: None,
            payload: create_test_payload_envelope(),
            created_at: "2025-01-01T00:00:00Z".to_string(),
            updated_at: "2025-01-01T00:00:00Z".to_string(),
        },
        signature: Signature {
            alg: secretenv::model::identifiers::alg::SIGNATURE_ED25519.to_string(),
            kid: "01HY0G8N3P5X7QRSTV0WXYZ123".to_string(),
            signer_pub: None,
            sig: "sig".to_string(),
        },
    };

    let json = serde_json::to_string_pretty(&doc).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    // Verify outer protected has sid
    assert_eq!(parsed["protected"]["sid"], sid.to_string());

    // Verify payload.protected has sid (must match outer sid)
    assert_eq!(
        parsed["protected"]["payload"]["protected"]["sid"],
        sid.to_string()
    );

    // Verify payload.protected has format and alg
    assert_eq!(
        parsed["protected"]["payload"]["protected"]["format"],
        "secretenv.file.payload@3"
    );
    assert_eq!(
        parsed["protected"]["payload"]["protected"]["alg"]["aead"],
        "xchacha20-poly1305"
    );
}
