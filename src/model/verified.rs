// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Verified private key types for functional domain modeling
//!
//! This module provides type-level guarantees that encrypted documents have been
//! successfully decrypted and validated. The `VerifiedPrivateKey` wrapper ensures that
//! decryption and validation must occur before using the plaintext in operations.

use super::private_key::PrivateKeyPlaintext;

/// Proof of successful decryption and validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptionProof {
    /// Member ID from the encrypted document
    pub member_id: String,
    /// Key statement ID from the encrypted document
    pub kid: String,
    /// SSH fingerprint used for decryption (None for non-SSH key protection)
    pub ssh_fpr: Option<String>,
}

/// A PrivateKeyPlaintext that has been successfully decrypted and validated
///
/// This type ensures that decryption and validation must occur before the plaintext
/// can be used in operations that require trust (e.g., unwrapping master keys).
/// The validation process checks:
/// - Key material structure (crv, kty, key lengths)
/// - Cryptographic consistency (e.g., private/public key pairs match)
/// - SSH fingerprint matches the decryption key
///
/// # Example
///
/// ```rust,no_run
/// use secretenv::app::context::crypto::load_crypto_context;
/// use secretenv::model::verified::VerifiedPrivateKey;
/// use secretenv::model::private_key::PrivateKeyPlaintext;
/// use secretenv::io::ssh::backend::SignatureBackend;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Load member key context (returns CryptoContext with VerifiedPrivateKey)
/// # let member_id = "alice@example.com";
/// # let backend: &dyn SignatureBackend = todo!();
/// # let ssh_pubkey = "";
/// # let keystore_root = std::path::PathBuf::from("/tmp");
/// # let debug = false;
/// let key_ctx = load_crypto_context(
///     member_id,
///     backend,
///     ssh_pubkey,
///     None,
///     Some(&keystore_root),
///     None,
///     debug,
/// )?;
///
/// // Access decrypted document and proof information
/// let plaintext = key_ctx.private_key.document();
/// let proof = key_ctx.private_key.proof();
/// assert_eq!(proof.member_id, "alice@example.com");
///
/// // The VerifiedPrivateKey wrapper ensures type-level guarantees that decryption
/// // and validation have occurred before the plaintext can be used in trusted operations.
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct VerifiedPrivateKey {
    /// The decrypted document
    pub document: PrivateKeyPlaintext,
    /// Proof of decryption and validation
    pub proof: DecryptionProof,
}
impl VerifiedPrivateKey {
    /// Create a new VerifiedPrivateKey wrapper
    pub fn new(document: PrivateKeyPlaintext, proof: DecryptionProof) -> Self {
        Self { document, proof }
    }

    /// Get a reference to the decrypted document
    pub fn document(&self) -> &PrivateKeyPlaintext {
        &self.document
    }

    /// Get a reference to the decryption proof
    pub fn proof(&self) -> &DecryptionProof {
        &self.proof
    }

    /// Extract the inner document and proof (consumes self)
    pub fn into_inner(self) -> (PrivateKeyPlaintext, DecryptionProof) {
        (self.document, self.proof)
    }

    /// Map the inner document while preserving decryption status
    pub fn map<F>(self, f: F) -> VerifiedPrivateKey
    where
        F: FnOnce(PrivateKeyPlaintext) -> PrivateKeyPlaintext,
    {
        VerifiedPrivateKey {
            document: f(self.document),
            proof: self.proof,
        }
    }
}
