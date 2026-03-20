// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public key verification.

use crate::format::jcs;
use crate::io::ssh::verify::verify_attestation;
use crate::model::public_key::{
    AttestationProof, AttestedIdentity, PublicKey, VerifiedPublicKey, VerifiedPublicKeyAttested,
};
use crate::model::verification::SelfSignatureProof;
use crate::support::base64url::{b64_decode, b64_decode_array};
use crate::{Error, Result};
use ed25519_dalek::{Verifier, VerifyingKey};
use tracing::debug;

/// Verify PublicKey document self-signature only and return VerifiedPublicKey
///
/// # Arguments
/// * `public_key` - PublicKey document to verify
/// * `debug` - Enable debug logging
///
/// # Returns
/// `VerifiedPublicKey` if self-signature is valid, error otherwise
pub fn verify_public_key(public_key: &PublicKey, debug: bool) -> Result<VerifiedPublicKey> {
    let protected_jcs = jcs::normalize(&public_key.protected).map_err(|e| Error::Crypto {
        message: format!("Failed to normalize PublicKey protected: {}", e),
        source: Some(Box::new(e)),
    })?;
    let verifying_key_bytes: [u8; 32] = b64_decode_array(
        &public_key.protected.identity.keys.sig.x,
        "Ed25519 public key",
    )?;
    let verifying_key =
        VerifyingKey::from_bytes(&verifying_key_bytes).map_err(|e| Error::Crypto {
            message: format!("Invalid Ed25519 public key: {}", e),
            source: Some(Box::new(e)),
        })?;

    let sig_bytes = b64_decode(&public_key.signature, "signature").map_err(|e| Error::Crypto {
        message: format!("Failed to decode PublicKey signature: {}", e),
        source: Some(Box::new(e)),
    })?;
    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).map_err(|e| Error::Crypto {
        message: format!("Invalid signature format: {}", e),
        source: Some(Box::new(e)),
    })?;

    verifying_key
        .verify(&protected_jcs, &sig)
        .map_err(|e| Error::Crypto {
            message: format!("PublicKey self-signature verification failed: {}", e),
            source: Some(Box::new(e)),
        })?;

    if debug {
        debug!("[VERIFY] PublicKey self-signature verified");
    }

    let proof = SelfSignatureProof::new();
    Ok(VerifiedPublicKey::new(public_key.clone(), proof))
}

/// Verify PublicKey document (self-signature and attestation) and return VerifiedPublicKeyAttested
///
/// # Arguments
/// * `public_key` - PublicKey document to verify
/// * `debug` - Enable debug logging
///
/// # Returns
/// `VerifiedPublicKeyAttested` if verification succeeds, error otherwise
pub fn verify_public_key_with_attestation(
    public_key: &PublicKey,
    debug: bool,
) -> Result<VerifiedPublicKeyAttested> {
    let verified = verify_public_key(public_key, debug)?;

    // Verify attestation.
    //
    // Important: `attestation.method == "test"` must never be a verification bypass
    // for production/release builds. We only allow skipping in debug builds to keep
    // existing test fixtures working.
    let method = public_key.protected.identity.attestation.method.as_str();
    if method == "test" {
        if cfg!(debug_assertions) {
            if debug {
                debug!("[VERIFY] PublicKey attestation skipped (test mode)");
            }
        } else {
            return Err(Error::Crypto {
                message: "Refusing PublicKey verification with attestation.method == \"test\" in non-debug build"
                    .to_string(),
                source: None,
            });
        }
    } else {
        verify_attestation(
            &public_key.protected.identity.keys,
            &public_key.protected.identity.attestation.pub_,
            &public_key.protected.identity.attestation.sig,
        )?;

        if debug {
            debug!("[VERIFY] PublicKey attestation verified");
        }
    }

    let proof = AttestationProof {
        method: public_key.protected.identity.attestation.method.clone(),
        ssh_pub: public_key.protected.identity.attestation.pub_.clone(),
        verified_at: None,
    };
    let attested_identity = AttestedIdentity::new(public_key.protected.identity.clone(), proof);

    Ok(VerifiedPublicKeyAttested::new(
        public_key.clone(),
        verified.self_signature_proof().clone(),
        attested_identity,
    ))
}

/// Verify multiple recipient public keys and return VerifiedPublicKeyAttested wrappers
pub fn verify_recipient_public_keys(
    keys: &[PublicKey],
    debug: bool,
) -> Result<Vec<VerifiedPublicKeyAttested>> {
    keys.iter()
        .map(|key| verify_public_key_with_attestation(key, debug))
        .collect()
}
