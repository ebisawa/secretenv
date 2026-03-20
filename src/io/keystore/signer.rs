// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Signer public key loading utilities.

use crate::io::keystore::storage::load_public_key;
use crate::model::public_key::PublicKey;
use crate::Result;

/// Load signer's public key unless no_signer_pub flag is set.
///
/// # Arguments
/// * `keystore_root` - Path to keystore root directory
/// * `member_id` - Member ID of the signer
/// * `kid` - Key ID of the signer
/// * `no_signer_pub` - If true, skip loading the public key
///
/// # Returns
/// `Some(PublicKey)` if `no_signer_pub` is false, `None` otherwise
pub fn load_signer_public_key_if_needed(
    keystore_root: &std::path::Path,
    member_id: &str,
    kid: &str,
    no_signer_pub: bool,
) -> Result<Option<PublicKey>> {
    if no_signer_pub {
        Ok(None)
    } else {
        Ok(Some(load_public_key(keystore_root, member_id, kid)?))
    }
}
