// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key loading for signature verification.

use crate::io::workspace::members::find_active_member_by_kid;
use crate::model::public_key::PublicKey;
use crate::model::signature::Signature;
use crate::model::verification::VerifyingKeySource;
use crate::support::base64url::b64_decode_array;
use crate::support::kid::kid_display_lossy;
use crate::{Error, Result};
use ed25519_dalek::VerifyingKey;

use super::public_key::{public_key_expiry_warning, verify_public_key_for_verification};

/// Check if a PublicKey has expired. Returns a warning message if expired.
/// Used for verification where expired keys are allowed but warned about.
#[cfg_attr(not(test), allow(dead_code))]
fn check_key_expiry_for_verification(doc: &PublicKey) -> Result<Option<String>> {
    public_key_expiry_warning(doc)
}

#[cfg(test)]
fn check_key_expiry_for_signing(doc: &PublicKey) -> Result<()> {
    if let Some(expired_msg) = check_key_expiry_for_verification(doc)? {
        return Err(Error::Crypto {
            message: expired_msg,
            source: None,
        });
    }
    Ok(())
}

/// Find PublicKey by kid, searching workspace active members.
///
/// Incoming members are excluded to prevent untrusted keys from being used
/// for signature verification.
///
/// Returns `(member_id, PublicKey, VerifyingKeySource)`.
pub fn find_public_key_by_kid(
    workspace_path: Option<&std::path::Path>,
    kid: &str,
) -> Result<(String, PublicKey, VerifyingKeySource)> {
    if let Some(ws_path) = workspace_path {
        if let Some(public_key) = find_active_member_by_kid(ws_path, kid)? {
            return Ok((
                public_key.protected.member_id.clone(),
                public_key,
                VerifyingKeySource::ActiveMemberByKid {
                    kid: kid.to_string(),
                },
            ));
        }
    }

    Err(Error::Crypto {
        message: format!(
            "Cannot find public key with kid '{}' in workspace",
            kid_display_lossy(kid)
        ),
        source: None,
    })
}

/// Result of loading a verifying key from a signature
#[derive(Debug)]
pub struct LoadedVerifyingKey {
    pub verifying_key: VerifyingKey,
    pub member_id: String,
    pub source: VerifyingKeySource,
    pub warnings: Vec<String>,
    pub public_key: PublicKey,
}

/// Load verifying key from signature (signer_pub or workspace search)
///
/// Expired keys are allowed for verification but generate a warning.
pub fn load_verifying_key_from_signature(
    signature: &Signature,
    workspace_path: Option<&std::path::Path>,
    debug: bool,
) -> Result<LoadedVerifyingKey> {
    if let Some(ref signer_pub) = signature.signer_pub {
        load_from_signer_pub(signature, signer_pub, workspace_path, debug)
    } else {
        load_from_kid_lookup(signature, workspace_path, debug)
    }
}

/// Load verifying key from embedded signer_pub.
///
/// The embedded key is used for cryptographic verification, but membership
/// is also confirmed by checking that the kid exists in workspace active members.
fn load_from_signer_pub(
    signature: &Signature,
    signer_pub: &PublicKey,
    workspace_path: Option<&std::path::Path>,
    debug: bool,
) -> Result<LoadedVerifyingKey> {
    verify_kid_in_active_members(workspace_path, &signature.kid)?;
    build_loaded_verifying_key(
        signer_pub,
        &signature.kid,
        VerifyingKeySource::SignerPubEmbedded,
        "signer_pub embedded",
        debug,
    )
}

/// Verify that a kid exists in workspace active members.
fn verify_kid_in_active_members(workspace_path: Option<&std::path::Path>, kid: &str) -> Result<()> {
    let ws_path = workspace_path.ok_or_else(|| Error::Crypto {
        message: "Workspace is required to verify signer membership".to_string(),
        source: None,
    })?;
    let found = find_active_member_by_kid(ws_path, kid)?;
    if found.is_none() {
        return Err(Error::Crypto {
            message: format!(
                "Signer key '{}' not found in active members",
                kid_display_lossy(kid)
            ),
            source: None,
        });
    }
    Ok(())
}

/// Load verifying key by kid lookup in workspace active members.
fn load_from_kid_lookup(
    signature: &Signature,
    workspace_path: Option<&std::path::Path>,
    debug: bool,
) -> Result<LoadedVerifyingKey> {
    let (_member_id, public_key, source) = find_public_key_by_kid(workspace_path, &signature.kid)?;
    build_loaded_verifying_key(&public_key, &signature.kid, source, "workspace", debug)
}

fn build_loaded_verifying_key(
    public_key: &PublicKey,
    expected_kid: &str,
    source: VerifyingKeySource,
    source_label: &str,
    debug: bool,
) -> Result<LoadedVerifyingKey> {
    let verified =
        verify_public_key_for_verification(public_key, debug).map_err(|e| Error::Crypto {
            message: format!(
                "PublicKey document verification failed ({}): {}",
                source_label, e
            ),
            source: Some(Box::new(e)),
        })?;

    let doc = verified.verified_public_key.document();
    if expected_kid != doc.protected.kid {
        return Err(Error::Crypto {
            message: format!(
                "kid mismatch: signature.kid '{}' != signer_pub.protected.kid '{}'",
                kid_display_lossy(expected_kid),
                kid_display_lossy(&doc.protected.kid)
            ),
            source: None,
        });
    }

    Ok(LoadedVerifyingKey {
        verifying_key: extract_verifying_key(doc)?,
        member_id: doc.protected.member_id.clone(),
        source,
        warnings: verified.warnings,
        public_key: public_key.clone(),
    })
}

/// Extract Ed25519 verifying key from a PublicKey document.
fn extract_verifying_key(doc: &PublicKey) -> Result<VerifyingKey> {
    let verifying_key_bytes: [u8; 32] =
        b64_decode_array(&doc.protected.identity.keys.sig.x, "Ed25519 public key")?;
    VerifyingKey::from_bytes(&verifying_key_bytes).map_err(|e| Error::Crypto {
        message: format!("Invalid Ed25519 public key: {}", e),
        source: Some(Box::new(e)),
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/feature_verify_key_loader_internal_test.rs"]
mod tests;
