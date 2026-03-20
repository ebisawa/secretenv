// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Common structures
//!
//! Shared structures used by file-enc and kv-enc formats

use serde::{Deserialize, Serialize};

/// Wrapped key item (HPKE-encrypted content key)
///
/// Used in both FileEncDocument and EncryptedKVValue
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct WrapItem {
    /// Recipient member_id
    pub rid: String,

    /// Key ID (ULID, 26 characters) of the recipient's key used for wrapping
    pub kid: String,

    /// HPKE algorithm identifier (e.g., "hpke-32-1-2")
    pub alg: String,

    /// Encapsulated key (base64url)
    pub enc: String,

    /// Wrapped content key ciphertext (base64url)
    pub ct: String,
}

/// Removed recipient record
///
/// Tracks disclosure history for removed recipients
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RemovedRecipient {
    /// Recipient member_id that was removed
    pub rid: String,

    /// Key ID (ULID) of the recipient's key used for wrapping (wrap_item.kid)
    pub kid: String,

    /// Timestamp when the recipient was removed (RFC 3339)
    pub removed_at: String,
}

/// Normalizes a list of recipients by sorting and removing duplicates
///
/// This ensures consistent ordering for HPKE info generation and deduplication.
/// Recipients are sorted lexicographically (case-sensitive).
///
/// # Arguments
/// * `recipients` - Slice of recipient member_id strings
///
/// # Returns
/// A new Vec with sorted, deduplicated recipients
///
/// # Example
/// ```
/// use secretenv::model::common::normalize_recipients;
///
/// let recipients = vec!["bob@example.com".to_string(), "alice@example.com".to_string(), "bob@example.com".to_string()];
/// let normalized = normalize_recipients(&recipients);
/// assert_eq!(normalized, vec!["alice@example.com", "bob@example.com"]);
/// ```
pub fn normalize_recipients(recipients: &[String]) -> Vec<String> {
    let mut sorted = recipients.to_vec();
    sorted.sort();
    sorted.dedup();
    sorted
}
