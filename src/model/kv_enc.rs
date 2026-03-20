// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV v3 models
//!
//! kv-enc v3 format with file-level HEAD and WRAP lines.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

use super::common::{RemovedRecipient, WrapItem};
use super::signature::Signature;
use super::verification::SignatureVerificationProof;

/// KV-enc format version (type-safe wrapper).
///
/// Model layer is intentionally free from fallible parsing and error types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KvEncVersion(u32);

impl KvEncVersion {
    /// Version 3 (current and only supported version)
    pub const V3: KvEncVersion = KvEncVersion(3);

    /// Get the version number as u32
    pub fn as_u32(self) -> u32 {
        self.0
    }

    /// Create a KvEncVersion from a raw u32 (only v3 is accepted).
    pub fn from_u32(value: u32) -> Option<Self> {
        (value == 3).then_some(KvEncVersion::V3)
    }
}

impl fmt::Display for KvEncVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Parsed line types in kv-enc format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KvEncLine {
    /// Header line: ":SECRETENV_KV {version}"
    Header { version: KvEncVersion },

    /// HEAD line: ":HEAD {token}"
    Head { token: String },

    /// WRAP line: ":WRAP {token}"
    Wrap { token: String },

    /// Key-value line: "{key} {token}" (space separator)
    KV { key: String, token: String },

    /// Signature line: ":SIG {token}"
    Sig { token: String },

    /// Empty line
    Empty,
}

/// KvHeader - HEAD line token for kv-enc v3
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KvHeader {
    /// File identifier (UUID v4)
    pub sid: Uuid,

    /// Creation timestamp (RFC 3339)
    pub created_at: String,

    /// Update timestamp (RFC 3339)
    pub updated_at: String,
}

/// KvWrap - WRAP line token for kv-enc v3
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KvWrap {
    /// Master key wrapped for each recipient
    pub wrap: Vec<WrapItem>,

    /// Removed recipients history
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed_recipients: Option<Vec<RemovedRecipient>>,
}

/// Helper for serde skip_serializing_if on bool fields
fn is_false(value: &bool) -> bool {
    !value
}

/// KvEntryValue - Entry line token (no wrap field)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KvEntryValue {
    /// Salt for key derivation (base64url, no padding, 16 bytes)
    pub salt: String,

    /// Key name
    pub k: String,

    /// AEAD algorithm
    pub aead: String,

    /// AEAD nonce (base64url)
    pub nonce: String,

    /// AEAD ciphertext (base64url, includes authentication tag)
    #[serde(rename = "ct")]
    pub ct: String,

    /// Disclosure flag: true if this entry was potentially disclosed to a removed recipient
    #[serde(default, skip_serializing_if = "is_false")]
    pub disclosed: bool,
}

/// KvFileSignature is an alias for the unified Signature.
///
/// This maintains backward compatibility while using the common structure.
/// The v3 format removes the version and msg_hash fields.
pub type KvFileSignature = Signature;

/// Parsed kv-enc document (unverified)
///
/// This structure holds the parsed components of a kv-enc v3 file
/// before signature verification. It contains all information needed
/// for verification and decryption.
#[derive(Debug, Clone)]
pub struct KvEncDocument {
    /// Original content (for re-serialization if needed)
    pub original_content: String,
    /// Parsed lines
    pub lines: Vec<KvEncLine>,
    /// HEAD token (parsed)
    pub head: KvHeader,
    /// WRAP token (parsed)
    pub wrap: KvWrap,
    /// Signature token (raw, for parsing)
    pub signature_token: String,
}

impl KvEncDocument {
    /// Create a new KvEncDocument
    pub fn new(
        original_content: String,
        lines: Vec<KvEncLine>,
        head: KvHeader,
        wrap: KvWrap,
        signature_token: String,
    ) -> Self {
        Self {
            original_content,
            lines,
            head,
            wrap,
            signature_token,
        }
    }

    /// Get a reference to the original content
    pub fn content(&self) -> &str {
        &self.original_content
    }

    /// Get a reference to the parsed lines
    pub fn lines(&self) -> &[KvEncLine] {
        &self.lines
    }

    /// Get a reference to the HEAD data
    pub fn head(&self) -> &KvHeader {
        &self.head
    }

    /// Get a reference to the WRAP data
    pub fn wrap(&self) -> &KvWrap {
        &self.wrap
    }

    /// Get the signature token
    pub fn signature_token(&self) -> &str {
        &self.signature_token
    }
}

/// A KvEncDocument that has been verified to have a valid signature
///
/// This type ensures that signature verification must occur before the document
/// can be used in operations that require trust (e.g., decryption).
/// The verification process validates:
/// - The signature is cryptographically valid
/// - The signer's public key is trusted (either embedded and verified,
///   or found in keystore)
/// - For embedded signer_pub, the PublicKey document itself is verified
///
/// # Example
///
/// ```rust,no_run
/// use secretenv::model::kv_enc::{KvEncDocument, VerifiedKvEncDocument};
/// use secretenv::feature::verify::kv::verify_kv_document;
/// use secretenv::format::kv::parse_kv_document;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Parse unverified document
/// # let content = ":SECRETENV_KV 3\n:HEAD ...";
/// # let debug = false;
/// let doc = parse_kv_document(content)?;
///
/// // Verify signature (returns VerifiedKvEncDocument)
/// let verified = verify_kv_document(&doc, None, debug)?;
///
/// // Access verified document and proof information
/// let document = verified.document();
/// let proof = verified.proof();
/// assert_eq!(proof.member_id, "alice");
///
/// // The VerifiedKvEncDocument wrapper ensures type-level guarantees that verification
/// // has occurred before the document can be used in trusted operations.
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct VerifiedKvEncDocument {
    /// The verified document
    pub document: KvEncDocument,
    /// Proof of signature verification
    pub proof: SignatureVerificationProof,
}

impl VerifiedKvEncDocument {
    /// Create a new VerifiedKvEncDocument wrapper
    pub fn new(document: KvEncDocument, proof: SignatureVerificationProof) -> Self {
        Self { document, proof }
    }

    /// Get a reference to the verified document
    pub fn document(&self) -> &KvEncDocument {
        &self.document
    }

    /// Get a reference to the verification proof
    pub fn proof(&self) -> &SignatureVerificationProof {
        &self.proof
    }

    /// Extract the inner document and proof (consumes self)
    pub fn into_inner(self) -> (KvEncDocument, SignatureVerificationProof) {
        (self.document, self.proof)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/model_kv_enc_internal_test.rs"]
mod tests;
