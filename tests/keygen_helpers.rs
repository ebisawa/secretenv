// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key generation helpers for v3 testing (without SSH attestation)
//!
//! This module provides test-only functions for generating key pairs and private keys
//! without requiring SSH key attestation. These functions are intended for use in
//! test code only and should NOT be used in production code.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use secretenv::model::{
    private_key::{
        EncryptedData, IdentityKeysPrivate, JwkOkpPrivateKey, PrivateKey, PrivateKeyAlgorithm,
        PrivateKeyPlaintext, PrivateKeyProtected,
    },
    public_key::{
        Attestation, Identity, IdentityKeys, JwkOkpPublicKey, PublicKey, PublicKeyProtected,
    },
    public_key::{AttestationProof, AttestedIdentity, VerifiedPublicKeyAttested},
    verification::SelfSignatureProof,
    verified::{DecryptionProof, VerifiedPrivateKey},
};
use secretenv::{Error, Result};
use time::OffsetDateTime;
use ulid::Ulid;

// ============================================================================
// Constants
// ============================================================================

const PUBLIC_KEY_FORMAT: &str = secretenv::model::identifiers::format::PUBLIC_KEY_V3;

/// Test-only protection method identifier (bypass SSH key validation).
pub const PROTECTION_METHOD_TEST: &str = "test";

// ============================================================================
// Helpers
// ============================================================================

/// Encode bytes to base64url (no padding)
fn b64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

// ============================================================================
// Key Pair Generation
// ============================================================================

/// Generate X25519 KEM key pair
fn generate_kem_keypair() -> (JwkOkpPrivateKey, String) {
    let sk = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let pk = x25519_dalek::PublicKey::from(&sk);

    let pub_key = b64(pk.as_bytes());
    let keypair = JwkOkpPrivateKey {
        kty: "OKP".to_string(),
        crv: secretenv::model::identifiers::jwk::CRV_X25519.to_string(),
        x: pub_key.clone(),
        d: b64(&sk.to_bytes()),
    };

    (keypair, pub_key)
}

/// Generate Ed25519 signing key pair
fn generate_sig_keypair() -> (JwkOkpPrivateKey, String) {
    let sk = SigningKey::generate(&mut OsRng);
    let pk: VerifyingKey = (&sk).into();

    let pub_key = b64(&pk.to_bytes());
    let keypair = JwkOkpPrivateKey {
        kty: "OKP".to_string(),
        crv: secretenv::model::identifiers::jwk::CRV_ED25519.to_string(),
        x: pub_key.clone(),
        d: b64(&sk.to_bytes()),
    };

    (keypair, pub_key)
}

// ============================================================================
// Public API
// ============================================================================

/// Generate a test key pair (without SSH attestation)
///
/// This function is for testing purposes only and does NOT create
/// proper attestation or binding_claims.github_account. For production use, use the CLI
/// command which properly integrates SSH signatures.
pub fn keygen_test(member_id: &str) -> Result<(PrivateKeyPlaintext, PublicKey)> {
    let (kem_keypair, kem_pub) = generate_kem_keypair();
    let (sig_keypair, sig_pub) = generate_sig_keypair();

    let kid = Ulid::new().to_string();

    let now = OffsetDateTime::now_utc();
    let created_at = secretenv::support::time::build_timestamp_display(now)?;
    let expires_at =
        secretenv::support::time::build_timestamp_display(now + time::Duration::days(365))?;

    // Extract signing key from keypair before moving it
    let sig_key_bytes = URL_SAFE_NO_PAD
        .decode(&sig_keypair.d)
        .map_err(|e| Error::Crypto {
            message: format!("Failed to decode signing key: {}", e),
            source: Some(Box::new(e)),
        })?;
    let signing_key =
        ed25519_dalek::SigningKey::from_bytes(sig_key_bytes.as_slice().try_into().map_err(
            |_| Error::Crypto {
                message: "Invalid signing key length".to_string(),
                source: None,
            },
        )?);

    let private_key = PrivateKeyPlaintext {
        keys: IdentityKeysPrivate {
            kem: kem_keypair,
            sig: sig_keypair,
        },
    };

    let protected = PublicKeyProtected {
        format: PUBLIC_KEY_FORMAT.to_string(),
        member_id: member_id.to_string(),
        kid: kid.clone(),
        identity: Identity {
            keys: IdentityKeys {
                kem: JwkOkpPublicKey {
                    kty: "OKP".to_string(),
                    crv: secretenv::model::identifiers::jwk::CRV_X25519.to_string(),
                    x: kem_pub,
                },
                sig: JwkOkpPublicKey {
                    kty: "OKP".to_string(),
                    crv: secretenv::model::identifiers::jwk::CRV_ED25519.to_string(),
                    x: sig_pub,
                },
            },
            attestation: Attestation {
                method: "test".to_string(),
                pub_: "test-key".to_string(),
                sig: b64(b"test-sig"),
            },
        },
        binding_claims: None,
        expires_at,
        created_at: Some(created_at),
    };

    // Generate actual signature for PublicKey
    let protected_jcs =
        secretenv::format::jcs::normalize(&protected).map_err(|e| Error::Crypto {
            message: format!("Failed to normalize PublicKey protected: {}", e),
            source: Some(Box::new(e)),
        })?;
    let signature_obj = secretenv::crypto::sign::sign_bytes(
        &protected_jcs,
        &signing_key,
        &kid,
        None,
        secretenv::model::identifiers::alg::SIGNATURE_ED25519,
    )?;

    let public_key = PublicKey {
        protected,
        signature: signature_obj.sig,
    };

    Ok((private_key, public_key))
}

/// Create a test PrivateKey (for testing only).
///
/// This function creates a PrivateKey with protection.method="test",
/// which allows tests to bypass SSH key requirements during decryption.
/// The plaintext is Base64-encoded (not encrypted) in the ct field.
///
/// **IMPORTANT**: This is for testing only. Do NOT use in production.
pub fn create_test_private_key(
    plaintext: &PrivateKeyPlaintext,
    member_id: &str,
    kid: &str,
) -> Result<PrivateKey> {
    let now = OffsetDateTime::now_utc();
    let created_at = secretenv::support::time::build_timestamp_display(now)?;
    let expires_at =
        secretenv::support::time::build_timestamp_display(now + time::Duration::days(365))?;

    // Serialize plaintext to JSON
    let plaintext_json = serde_json::to_string(plaintext).map_err(|e| Error::Crypto {
        message: format!("Failed to serialize plaintext: {}", e),
        source: Some(Box::new(e)),
    })?;

    Ok(PrivateKey {
        protected: PrivateKeyProtected {
            format: secretenv::model::identifiers::format::PRIVATE_KEY_V3.to_string(),
            member_id: member_id.to_string(),
            kid: kid.to_string(),
            alg: PrivateKeyAlgorithm {
                kdf: PROTECTION_METHOD_TEST.to_string(),
                fpr: "sha256:test".to_string(),
                salt: b64(&[0u8; 16]),
                aead: "none".to_string(),
            },
            created_at,
            expires_at,
        },
        encrypted: EncryptedData {
            nonce: b64(&[0u8; 24]),
            ct: b64(plaintext_json.as_bytes()), // Plaintext as Base64
        },
    })
}

/// Create a Decrypted wrapper for PrivateKeyPlaintext (for testing only)
///
/// This function wraps a PrivateKeyPlaintext in a Decrypted type without
/// performing full validation. It's intended for test code only.
#[allow(dead_code)] // Used in unit tests via tests/unit.rs
pub fn make_decrypted_private_key_plaintext(
    plaintext: PrivateKeyPlaintext,
    member_id: &str,
    kid: &str,
    ssh_fpr: &str,
) -> VerifiedPrivateKey {
    let proof = DecryptionProof {
        member_id: member_id.to_string(),
        kid: kid.to_string(),
        ssh_fpr: ssh_fpr.to_string(),
    };
    VerifiedPrivateKey::new(plaintext, proof)
}

/// Convert a slice of PublicKeys to VerifiedPublicKeyAttested (for testing only).
///
/// Used by tests that call encrypt_kv_document or similar with a list of keys.
#[allow(dead_code)]
pub fn make_verified_members(members: &[PublicKey]) -> Vec<VerifiedPublicKeyAttested> {
    members
        .iter()
        .map(|pk| make_attested_public_key(pk.clone()))
        .collect()
}

/// Create a VerifiedPublicKeyAttested wrapper for PublicKey (for testing only)
///
/// This function wraps a PublicKey in a VerifiedPublicKeyAttested type without
/// performing full verification. It's intended for test code only.
/// The PublicKey should have method="test" attestation to skip verification.
#[allow(dead_code)] // Used in unit tests via tests/unit.rs
pub fn make_attested_public_key(public_key: PublicKey) -> VerifiedPublicKeyAttested {
    let proof = AttestationProof {
        method: public_key.protected.identity.attestation.method.clone(),
        ssh_pub: public_key.protected.identity.attestation.pub_.clone(),
        verified_at: None,
    };
    let attested_identity = AttestedIdentity::new(public_key.protected.identity.clone(), proof);
    let self_sig_proof = SelfSignatureProof::new();
    VerifiedPublicKeyAttested::new(public_key, self_sig_proof, attested_identity)
}
