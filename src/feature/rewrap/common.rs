// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Common helpers for rewrap operations.
//!
//! Provides shared utilities for recipient operations and rewrap operations
//! used by both file-enc and kv-enc rewrap operations.

use crate::feature::context::crypto::CryptoContext;
use crate::feature::verify::public_key::verify_recipient_public_keys;
use crate::model::common::RemovedRecipient;
use crate::model::public_key::{PublicKey, VerifiedRecipientKey};
use crate::support::time::current_timestamp;
use crate::{Error, Result};
use tracing::warn;

/// Check if a recipient exists in the current recipients list.
pub fn check_recipient_exists(current_recipients: &[String], rid: &str) -> bool {
    current_recipients.iter().any(|r| r == rid)
}

/// Validate that recipients list is not empty.
///
/// # Returns
/// `Ok(())` if not empty, `Err(Error::Config)` if empty
pub fn validate_not_empty_recipients(recipients: &[String]) -> Result<()> {
    if recipients.is_empty() {
        return Err(Error::Config {
            message: "Cannot remove all recipients. At least one recipient must remain."
                .to_string(),
        });
    }
    Ok(())
}

/// Warn that a recipient already exists.
pub fn warn_recipient_already_exists(rid: &str) {
    warn!("[CRYPTO] Warning: {} is already a recipient, skipping", rid);
}

/// Warn that a recipient is not found.
pub fn warn_recipient_not_found(rid: &str) {
    warn!("[CRYPTO] Warning: {} is not a recipient, skipping", rid);
}

/// Add a recipient to the removed_recipients history list
pub fn add_to_removed_history(
    removed_recipients: &mut Option<Vec<RemovedRecipient>>,
    rid: &str,
    kid: &str,
) -> Result<()> {
    let timestamp = current_timestamp()?;
    let removed = RemovedRecipient {
        rid: rid.to_string(),
        kid: kid.to_string(),
        removed_at: timestamp,
    };

    match removed_recipients {
        Some(list) => list.push(removed),
        None => *removed_recipients = Some(vec![removed]),
    }
    Ok(())
}

/// Merge old removed_recipients history into new list
pub fn merge_removed_history(
    target: &mut Option<Vec<RemovedRecipient>>,
    source: Option<&Vec<RemovedRecipient>>,
) {
    if let Some(old_removed) = source {
        match target {
            Some(new_list) => new_list.extend(old_removed.clone()),
            None => *target = Some(old_removed.clone()),
        }
    }
}

/// Resolve and verify new recipients, returning attested public keys.
///
/// Combines `build_new_recipients` and `verify_recipient_public_keys` into a single step
/// used by both file-enc and kv-enc add-recipient operations.
pub fn resolve_attested_recipients(
    key_ctx: &CryptoContext,
    new_recipients: &[String],
    current_recipients: &[String],
    debug: bool,
) -> Result<Vec<VerifiedRecipientKey>> {
    let (new_pubkeys, _) = build_new_recipients(key_ctx, new_recipients, current_recipients)?;
    verify_recipient_public_keys(&new_pubkeys, debug)
}

/// Process new recipients for addition: load public keys and filter out duplicates.
///
/// This is a common helper used by both file-enc and kv-enc recipient addition operations.
/// It loads public keys for new recipients and returns them along with the filtered list.
///
/// # Arguments
/// * `key_ctx` - Member key context containing keystore root
/// * `new_recipients` - List of new recipient member IDs to add
/// * `current_recipients` - List of current recipient member IDs (for duplicate checking)
///
/// # Returns
/// Tuple of (public keys, filtered recipient IDs that are not duplicates)
pub fn build_new_recipients(
    key_ctx: &CryptoContext,
    new_recipients: &[String],
    current_recipients: &[String],
) -> Result<(Vec<PublicKey>, Vec<String>)> {
    let new_pubkeys = key_ctx
        .pub_key_source
        .load_public_keys_for_member_ids(new_recipients)?;

    // Filter out duplicates
    let mut filtered_recipients = Vec::new();
    let mut filtered_pubkeys = Vec::new();

    for (rid, pubkey) in new_recipients.iter().zip(new_pubkeys.iter()) {
        if check_recipient_exists(current_recipients, rid) {
            warn_recipient_already_exists(rid);
            continue;
        }
        filtered_recipients.push(rid.clone());
        filtered_pubkeys.push(pubkey.clone());
    }

    Ok((filtered_pubkeys, filtered_recipients))
}
