// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Crypto context construction for use cases
//!
//! Provides context for cryptographic operations requiring member keys.
//! This module handles IO operations (keystore access, SSH key decryption)
//! and should be used at the usecase layer.

use ed25519_dalek::SigningKey;
use std::path::PathBuf;
use tracing::debug;
use zeroize::Zeroizing;

use crate::feature::key::protection::decrypt_private_key;
use crate::io::config::paths::get_base_dir;
use crate::io::keystore::helpers::resolve_kid;
use crate::io::keystore::paths::get_keystore_root_from_base;
use crate::io::keystore::storage::load_private_key;
use crate::io::ssh::backend::SignatureBackend;
use crate::model::identifiers::jwk;
use crate::model::private_key::PrivateKeyAlgorithm;
use crate::model::private_key::PrivateKeyPlaintext;
use crate::model::verified::{DecryptionProof, VerifiedPrivateKey};
use crate::support::base64url::{b64_decode, b64_decode_array};
use crate::{Error, Result};

/// Context for cryptographic operations requiring member keys
#[derive(Clone)]
pub struct CryptoContext {
    pub member_id: String,
    pub kid: String,
    pub keystore_root: PathBuf,
    pub workspace_path: Option<PathBuf>,
    pub private_key: VerifiedPrivateKey,
    pub signing_key: SigningKey,
}

impl CryptoContext {
    /// Load member keys from keystore with SSH key decryption
    ///
    /// # Arguments
    /// * `member_id` - Member ID to load keys for
    /// * `backend` - SSH signature backend for private key decryption
    /// * `ssh_pubkey` - SSH public key string
    /// * `explicit_kid` - Optional explicit key ID (if None, uses active key)
    /// * `keystore_root` - Optional keystore root path (if None, uses default)
    /// * `workspace_path` - Optional workspace path for key lookup
    /// * `debug` - Enable debug logging
    ///
    /// # Returns
    /// CryptoContext with loaded keys
    pub fn load(
        member_id: &str,
        backend: &dyn SignatureBackend,
        ssh_pubkey: &str,
        explicit_kid: Option<&str>,
        keystore_root: Option<&PathBuf>,
        workspace_path: Option<PathBuf>,
        debug: bool,
    ) -> Result<Self> {
        if debug {
            debug!(
                "[CRYPTO] CryptoContext::load: member_id={}, explicit_kid={}",
                member_id,
                explicit_kid.unwrap_or("(none)")
            );
        }
        let keystore_root = match keystore_root {
            Some(path) => path.clone(),
            None => {
                let base_dir = get_base_dir()?;
                get_keystore_root_from_base(&base_dir)
            }
        };
        let kid = resolve_kid(&keystore_root, member_id, explicit_kid)?;
        if debug {
            debug!("[CRYPTO] CryptoContext::load: resolved kid={}", kid);
        }
        let encrypted_private_key = load_private_key(&keystore_root, member_id, &kid)?;
        let private_key_plaintext =
            decrypt_private_key(&encrypted_private_key, backend, ssh_pubkey, debug)?;

        // Extract SSH fingerprint from SshSig algorithm variant
        let ssh_fpr = match &encrypted_private_key.protected.alg {
            PrivateKeyAlgorithm::SshSig { fpr, .. } => fpr.as_str(),
            _ => {
                return Err(Error::Crypto {
                    message: "Expected SshSig algorithm for SSH-based decryption".to_string(),
                    source: None,
                });
            }
        };

        // Validate and create Decrypted wrapper
        let decrypted_key = validate_and_wrap_private_key(
            private_key_plaintext,
            &encrypted_private_key.protected.member_id,
            &encrypted_private_key.protected.kid,
            ssh_fpr,
        )?;

        let sig_key_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(b64_decode_array(
            &decrypted_key.document().keys.sig.d,
            "Ed25519 private key",
        )?);
        let signing_key = SigningKey::from_bytes(&sig_key_bytes);

        Ok(Self {
            member_id: member_id.to_string(),
            kid,
            keystore_root,
            workspace_path,
            private_key: decrypted_key,
            signing_key,
        })
    }
}

/// Validate an OKP key (kty, crv, d/x length).
pub fn validate_okp_key(
    kty: &str,
    crv: &str,
    expected_crv: &str,
    d: &str,
    x: &str,
    label: &str,
) -> Result<(Vec<u8>, Vec<u8>)> {
    if kty != "OKP" {
        return Err(Error::Crypto {
            message: format!("Invalid {} key type: expected 'OKP', got '{}'", label, kty),
            source: None,
        });
    }
    if crv != expected_crv {
        return Err(Error::Crypto {
            message: format!(
                "Invalid {} curve: expected '{}', got '{}'",
                label, expected_crv, crv
            ),
            source: None,
        });
    }
    let d_bytes = b64_decode(d, &format!("{} private key", label))?;
    let x_bytes = b64_decode(x, &format!("{} public key", label))?;
    if d_bytes.len() != 32 {
        return Err(Error::Crypto {
            message: format!(
                "Invalid {} private key length: expected 32 bytes, got {}",
                label,
                d_bytes.len()
            ),
            source: None,
        });
    }
    if x_bytes.len() != 32 {
        return Err(Error::Crypto {
            message: format!(
                "Invalid {} public key length: expected 32 bytes, got {}",
                label,
                x_bytes.len()
            ),
            source: None,
        });
    }
    Ok((d_bytes, x_bytes))
}

/// Verify Ed25519 key pair consistency: private key must derive to the given public key.
pub fn validate_ed25519_consistency(sig_d_bytes: &[u8], sig_x_bytes: &[u8]) -> Result<()> {
    let sig_d_array: [u8; 32] = sig_d_bytes.try_into().map_err(|_| Error::Crypto {
        message: "Failed to convert Sig private key to array".to_string(),
        source: None,
    })?;
    let signing_key = SigningKey::from_bytes(&sig_d_array);
    let derived_vk = signing_key.verifying_key();
    let derived_x_bytes = derived_vk.as_bytes();
    if derived_x_bytes != sig_x_bytes {
        return Err(Error::Crypto {
            message: "Ed25519 key pair inconsistency: private key does not derive to public key"
                .to_string(),
            source: None,
        });
    }
    Ok(())
}

/// Validate private key plaintext and wrap in Decrypted type
fn validate_and_wrap_private_key(
    plaintext: PrivateKeyPlaintext,
    member_id: &str,
    kid: &str,
    ssh_fpr: &str,
) -> Result<VerifiedPrivateKey> {
    let kem = &plaintext.keys.kem;
    validate_okp_key(&kem.kty, &kem.crv, jwk::CRV_X25519, &kem.d, &kem.x, "KEM")?;

    let sig = &plaintext.keys.sig;
    let (sig_d_bytes, sig_x_bytes) =
        validate_okp_key(&sig.kty, &sig.crv, jwk::CRV_ED25519, &sig.d, &sig.x, "Sig")?;
    validate_ed25519_consistency(&sig_d_bytes, &sig_x_bytes)?;

    let proof = DecryptionProof {
        member_id: member_id.to_string(),
        kid: kid.to_string(),
        ssh_fpr: Some(ssh_fpr.to_string()),
    };
    Ok(VerifiedPrivateKey::new(plaintext, proof))
}
