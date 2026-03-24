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
use crate::model::private_key::{PrivateKey, PrivateKeyAlgorithm, PrivateKeyPlaintext};
use crate::model::public_key::PublicKey;
use crate::{Error, Result};

const ENV_PRIVATE_KEY: &str = "SECRETENV_PRIVATE_KEY";
const ENV_KEY_PASSWORD: &str = "SECRETENV_KEY_PASSWORD";

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
    // Clear sensitive environment variable after reading
    std::env::remove_var(ENV_PRIVATE_KEY);

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
    // Clear sensitive environment variable after reading
    std::env::remove_var(ENV_KEY_PASSWORD);

    let json_bytes =
        Zeroizing::new(URL_SAFE_NO_PAD.decode(&encoded).map_err(|e| Error::Parse {
            message: format!("Failed to decode {} as Base64url: {}", ENV_PRIVATE_KEY, e),
            source: Some(Box::new(e)),
        })?);

    let private_key: PrivateKey =
        serde_json::from_slice(&json_bytes).map_err(|e| Error::Parse {
            message: format!(
                "Failed to parse {} as PrivateKey JSON: {}",
                ENV_PRIVATE_KEY, e
            ),
            source: Some(Box::new(e)),
        })?;

    // Validate format field
    if private_key.protected.format != crate::model::identifiers::format::PRIVATE_KEY_V3 {
        return Err(Error::Parse {
            message: format!(
                "Unsupported PrivateKey format: expected '{}', got '{}'",
                crate::model::identifiers::format::PRIVATE_KEY_V3,
                private_key.protected.format
            ),
            source: None,
        });
    }

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
/// Compares sig.x and kem.x between the private key plaintext and the public key.
/// This ensures the workspace public key belongs to the same identity as the
/// environment-loaded private key.
pub fn verify_own_public_key(
    plaintext: &PrivateKeyPlaintext,
    public_key: &PublicKey,
) -> Result<()> {
    let pub_sig_x = &public_key.protected.identity.keys.sig.x;
    let pub_kem_x = &public_key.protected.identity.keys.kem.x;

    if plaintext.keys.sig.x != *pub_sig_x {
        return Err(Error::Verify {
            rule: "public-key-match".to_string(),
            message: "Signing key mismatch: private key sig.x does not match public key sig.x"
                .to_string(),
        });
    }

    if plaintext.keys.kem.x != *pub_kem_x {
        return Err(Error::Verify {
            rule: "public-key-match".to_string(),
            message: "KEM key mismatch: private key kem.x does not match public key kem.x"
                .to_string(),
        });
    }

    Ok(())
}
