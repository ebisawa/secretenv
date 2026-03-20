// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! PrivateKey v3 model.
//!
//! SSH Ed25519 encrypted private key storage for secretenv.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// PrivateKey v3 document (SSH encrypted).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PrivateKey {
    /// Protected header (used for AAD construction)
    pub protected: PrivateKeyProtected,

    /// Encrypted key material
    pub encrypted: EncryptedData,
}

/// Protected header (AAD source)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PrivateKeyProtected {
    /// Format identifier: "secretenv.private.key@3"
    pub format: String,

    /// Member ID (RFC 5322 email format)
    pub member_id: String,

    /// Key ID (ULID, 26 characters)
    pub kid: String,

    /// Algorithm configuration
    pub alg: PrivateKeyAlgorithm,

    /// Creation timestamp (RFC 3339)
    pub created_at: String,

    /// Expiration timestamp (RFC 3339)
    pub expires_at: String,
}

/// Algorithm configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PrivateKeyAlgorithm {
    /// Key derivation function: "sshsig-ed25519-hkdf-sha256"
    pub kdf: String,

    /// SSH public key fingerprint (sha256:...; prefix is case-insensitive)
    pub fpr: String,

    /// Salt for key derivation (base64url, 16 bytes)
    pub salt: String,

    /// AEAD algorithm: "xchacha20-poly1305"
    pub aead: String,
}

/// Encrypted key material
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EncryptedData {
    /// Nonce (base64url, 24 bytes)
    pub nonce: String,

    /// Ciphertext (base64url)
    pub ct: String,
}

/// Plaintext key material (inside encrypted.ct).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Zeroize)]
#[zeroize(drop)]
#[serde(deny_unknown_fields)]
pub struct PrivateKeyPlaintext {
    /// Keys (KEM + Sig key pairs)
    pub keys: IdentityKeysPrivate,
}

/// Identity Keys Private (KEM + Sig with private components)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Zeroize)]
#[zeroize(drop)]
#[serde(deny_unknown_fields)]
pub struct IdentityKeysPrivate {
    /// KEM key pair (X25519).
    pub kem: JwkOkpPrivateKey,
    /// Sig key pair (Ed25519).
    pub sig: JwkOkpPrivateKey,
}

/// JWK/OKP private key (RFC 7517 / RFC 8037).
///
/// SecretEnv v3 plaintext key material uses:
/// - `crv = "X25519"` for KEM
/// - `crv = "Ed25519"` for signatures
///
/// It also includes public component `x` for PublicKey reconstruction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Zeroize)]
#[zeroize(drop)]
#[serde(deny_unknown_fields)]
pub struct JwkOkpPrivateKey {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub d: String,
}
impl PrivateKey {
    /// Create a new PrivateKey with the given parameters
    pub fn new(protected: PrivateKeyProtected, encrypted: EncryptedData) -> Self {
        Self {
            protected,
            encrypted,
        }
    }
}
