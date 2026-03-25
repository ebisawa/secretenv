// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Common signature structure for signed document formats
//!
//! Unified signature format used by both file-enc and kv-enc.
//!
//! # Security
//!
//! The signature format does not include msg_hash field for security reasons:
//! verifiers must compute the hash themselves rather than trusting
//! a provided hash value.

use serde::{Deserialize, Serialize};

use crate::model::public_key::PublicKey;

/// Unified signature structure
///
/// Used by both file-enc `signature` field and kv-enc `SIG` line.
/// Simplified format without msg_hash or version fields.
///
/// # Format
///
/// - `alg`: Signature algorithm, always "eddsa-ed25519"
/// - `kid`: signer key statement ID in canonical Crockford Base32 form
/// - `signer_pub`: Optional PublicKey document for self-contained verification
/// - `sig`: Ed25519 signature in base64url encoding (no padding)
///
/// # Example JSON
///
/// ```json
/// {
///   "alg": "eddsa-ed25519",
///   "kid": "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
///   "signer_pub": { /* PublicKey: secretenv.public.key@4 */ },
///   "sig": "SGVsbG8gV29ybGQ..."
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    /// Signature algorithm: "eddsa-ed25519"
    pub alg: String,

    /// Signer key statement ID in canonical Crockford Base32 form
    pub kid: String,

    /// Signer's PublicKey document (optional, for self-contained verification)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_pub: Option<PublicKey>,

    /// Signature bytes (base64url, no padding)
    pub sig: String,
}
