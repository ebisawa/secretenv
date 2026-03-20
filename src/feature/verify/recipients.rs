// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Recipient public key verification.

use crate::io::keystore::public_keys::load_public_keys_for_member_ids;
use crate::model::public_key::VerifiedPublicKeyAttested;
use crate::Result;
use std::path::Path;

pub use super::public_key::verify_recipient_public_keys;

/// Load and verify recipient public keys in one step.
pub fn load_and_verify_recipient_public_keys(
    keystore_root: &Path,
    member_ids: &[String],
    debug: bool,
) -> Result<Vec<VerifiedPublicKeyAttested>> {
    let pubkeys = load_public_keys_for_member_ids(keystore_root, member_ids)?;
    verify_recipient_public_keys(&pubkeys, debug)
}
