// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Recipient public key verification.

use super::public_key::verify_recipient_public_keys;
use crate::io::keystore::public_key_source::PublicKeySource;
use crate::model::public_key::VerifiedPublicKeyAttested;
use crate::Result;

/// Load and verify recipient public keys in one step.
pub fn load_and_verify_recipient_public_keys(
    pub_key_source: &dyn PublicKeySource,
    member_ids: &[String],
    debug: bool,
) -> Result<Vec<VerifiedPublicKeyAttested>> {
    let pubkeys = pub_key_source.load_public_keys_for_member_ids(member_ids)?;
    verify_recipient_public_keys(&pubkeys, debug)
}
