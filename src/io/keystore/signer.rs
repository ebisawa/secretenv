// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Signer public key loading utilities.

use crate::io::keystore::public_key_source::PublicKeySource;
use crate::model::public_key::PublicKey;
use crate::Result;

/// Load signer's public key unless no_signer_pub flag is set.
///
/// # Arguments
/// * `pub_key_source` - Source for loading public keys
/// * `member_id` - Member ID of the signer
/// * `no_signer_pub` - If true, skip loading the public key
///
/// # Returns
/// `Some(PublicKey)` if `no_signer_pub` is false, `None` otherwise
pub fn load_signer_public_key_if_needed(
    pub_key_source: &dyn PublicKeySource,
    member_id: &str,
    no_signer_pub: bool,
) -> Result<Option<PublicKey>> {
    if no_signer_pub {
        Ok(None)
    } else {
        Ok(Some(pub_key_source.load_public_key(member_id)?))
    }
}
