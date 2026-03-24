// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Environment variable key loading for CI environments
//!
//! Loads private keys from SECRETENV_PRIVATE_KEY environment variable,
//! decrypts using SECRETENV_KEY_PASSWORD, and validates the key material.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use zeroize::Zeroizing;

use crate::feature::context::crypto::validate_and_wrap_private_key_password;
use crate::feature::key::protection::password_encryption::decrypt_private_key_with_password;
use crate::feature::verify::public_key::{
    verify_public_key_for_verification, VerifiedPublicKeyForVerification,
};
use crate::format::schema::document::parse_private_key_bytes;
use crate::model::private_key::{PrivateKey, PrivateKeyAlgorithm};
use crate::model::public_key::{PublicKey, VerifiedPublicKeyAttested};
use crate::model::verified::VerifiedPrivateKey;
use crate::{Error, Result};

const ENV_PRIVATE_KEY: &str = "SECRETENV_PRIVATE_KEY";
const ENV_KEY_PASSWORD: &str = "SECRETENV_KEY_PASSWORD";

struct EnvKeyCleanupGuard;

impl Drop for EnvKeyCleanupGuard {
    fn drop(&mut self) {
        std::env::remove_var(ENV_PRIVATE_KEY);
        std::env::remove_var(ENV_KEY_PASSWORD);
    }
}

/// Check if environment variable key mode is active
pub fn is_env_key_mode() -> bool {
    std::env::var_os(ENV_PRIVATE_KEY).is_some()
}

/// Load private key from environment variables
///
/// Reads SECRETENV_PRIVATE_KEY (Base64url-encoded PrivateKey JSON),
/// decrypts it using SECRETENV_KEY_PASSWORD, and validates the key material.
///
/// Returns the verified private key and the member_id from the protected header.
pub fn load_private_key_from_env(
    debug: bool,
) -> Result<(crate::model::verified::VerifiedPrivateKey, String)> {
    // Safety: clear sensitive env vars on every exit path.
    // This is intentional security hygiene to minimize secret exposure.
    // Note: std::env::remove_var is not thread-safe; this function must
    // be called from the main thread only. The env vars cannot be
    // recovered after removal, so retries require re-setting them.
    let _cleanup = EnvKeyCleanupGuard;

    let encoded = Zeroizing::new(std::env::var(ENV_PRIVATE_KEY).map_err(|e| match e {
        std::env::VarError::NotPresent => Error::Config {
            message: format!("{} environment variable is not set", ENV_PRIVATE_KEY),
        },
        std::env::VarError::NotUnicode(_) => Error::Config {
            message: format!(
                "{} environment variable contains invalid UTF-8",
                ENV_PRIVATE_KEY
            ),
        },
    })?);

    let password = Zeroizing::new(std::env::var(ENV_KEY_PASSWORD).map_err(|e| match e {
        std::env::VarError::NotPresent => Error::Config {
            message: format!(
                "{} environment variable is required when {} is set",
                ENV_KEY_PASSWORD, ENV_PRIVATE_KEY
            ),
        },
        std::env::VarError::NotUnicode(_) => Error::Config {
            message: format!(
                "{} environment variable contains invalid UTF-8",
                ENV_KEY_PASSWORD
            ),
        },
    })?);

    let json_bytes =
        Zeroizing::new(URL_SAFE_NO_PAD.decode(&encoded).map_err(|e| Error::Parse {
            message: format!("Failed to decode {} as Base64url: {}", ENV_PRIVATE_KEY, e),
            source: Some(Box::new(e)),
        })?);

    let private_key: PrivateKey = parse_private_key_bytes(&json_bytes, ENV_PRIVATE_KEY)?;

    // Verify algorithm is Argon2id (password-based)
    match &private_key.protected.alg {
        PrivateKeyAlgorithm::Argon2id { .. } => {}
        _ => {
            return Err(Error::Config {
                message: format!(
                    "{} must contain a password-protected key (argon2id-hkdf-sha256)",
                    ENV_PRIVATE_KEY
                ),
            });
        }
    }

    let member_id = private_key.protected.member_id.clone();
    let kid = private_key.protected.kid.clone();

    let plaintext = decrypt_private_key_with_password(&private_key, &password, debug)?;
    let verified_key = validate_and_wrap_private_key_password(plaintext, &member_id, &kid)?;

    Ok((verified_key, member_id))
}

/// Verify that a public key's components match the private key plaintext
///
/// Reuses the standard PublicKey verification path (self-signature + attestation),
/// then confirms that the verified PublicKey matches the env-loaded private key.
#[derive(Debug, Clone)]
pub struct OwnPublicKeyVerification {
    pub verified_public_key: VerifiedPublicKeyAttested,
    pub warnings: Vec<String>,
}

pub fn verify_own_public_key(
    private_key: &VerifiedPrivateKey,
    public_key: &PublicKey,
    debug: bool,
) -> Result<OwnPublicKeyVerification> {
    let verified = verify_public_key_for_verification(public_key, debug)?;
    ensure_verified_public_key_matches_private_key(private_key, &verified)?;
    Ok(OwnPublicKeyVerification {
        verified_public_key: verified.verified_public_key,
        warnings: verified.warnings,
    })
}

fn ensure_verified_public_key_matches_private_key(
    private_key: &VerifiedPrivateKey,
    verified: &VerifiedPublicKeyForVerification,
) -> Result<()> {
    let doc = verified.verified_public_key.document();
    let proof = private_key.proof();
    let plaintext = private_key.document();

    if doc.protected.member_id != proof.member_id {
        return Err(Error::Verify {
            rule: "public-key-match".to_string(),
            message: format!(
                "Member ID mismatch: private key member_id '{}' does not match public key member_id '{}'",
                proof.member_id, doc.protected.member_id
            ),
        });
    }

    if doc.protected.kid != proof.kid {
        return Err(Error::Verify {
            rule: "public-key-match".to_string(),
            message: format!(
                "Key ID mismatch: private key kid '{}' does not match public key kid '{}'",
                proof.kid, doc.protected.kid
            ),
        });
    }

    if plaintext.keys.sig.x != doc.protected.identity.keys.sig.x {
        return Err(Error::Verify {
            rule: "public-key-match".to_string(),
            message: "Signing key mismatch: private key sig.x does not match public key sig.x"
                .to_string(),
        });
    }

    if plaintext.keys.kem.x != doc.protected.identity.keys.kem.x {
        return Err(Error::Verify {
            rule: "public-key-match".to_string(),
            message: "KEM key mismatch: private key kem.x does not match public key kem.x"
                .to_string(),
        });
    }

    Ok(())
}
