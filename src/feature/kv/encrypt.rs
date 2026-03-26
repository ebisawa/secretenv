// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV encryption operations

use crate::crypto::types::keys::MasterKey;
use crate::feature::envelope::entry::encrypt_entry;
use crate::feature::envelope::signature::SigningContext;
use crate::feature::envelope::wrap::{build_wraps_for_recipients, WrapFormat};
use crate::format::token::TokenCodec;
use crate::model::kv_enc::entry::KvEntryValue;
use crate::model::kv_enc::header::{KvHeader, KvWrap};
use crate::model::public_key::VerifiedPublicKeyAttested;
use crate::Result;
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Build KV encryption context: generate master key, create HEAD/WRAP structures
pub(crate) fn build_kv_encryption(
    members: &[VerifiedPublicKeyAttested],
    sid: &Uuid,
    timestamp: &str,
) -> Result<(MasterKey, KvHeader, KvWrap)> {
    // Generate master key
    let mut master_key_bytes = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(master_key_bytes.as_mut());
    let master_key = MasterKey::new(*master_key_bytes);

    // Create HEAD token
    let head_data = KvHeader {
        sid: *sid,
        created_at: timestamp.to_string(),
        updated_at: timestamp.to_string(),
    };

    // Create WRAP items for all recipients
    let wrap_items = build_wraps_for_recipients(members, sid, &master_key, WrapFormat::Kv, false)?;

    let wrap_data = KvWrap {
        wrap: wrap_items,
        removed_recipients: None,
    };

    Ok((master_key, head_data, wrap_data))
}

/// Encrypt all KV entries
pub(crate) fn encrypt_kv_entries(
    kv_map: &HashMap<String, String>,
    master_key: &MasterKey,
    sid: &Uuid,
    debug: bool,
    disclosed: bool,
) -> Result<Vec<(String, KvEntryValue)>> {
    let mut entries: Vec<_> = kv_map
        .iter()
        .map(|(key, value)| {
            encrypt_entry(
                key,
                value,
                master_key,
                sid,
                debug,
                "encrypt_kv_entries",
                disclosed,
            )
            .map(|entry| (key.clone(), entry))
        })
        .collect::<Result<Vec<_>>>()?;

    // Sort for deterministic output
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    Ok(entries)
}

/// Encrypt KV map to kv-enc v3 format
///
/// # Arguments
/// * `kv_map` - Key-value map to encrypt
/// * `recipients` - List of recipient member_ids
/// * `members` - Verified public keys with attested identity for recipients
/// * `signing` - Signing context (signing_key, signer_kid, signer_pub, debug)
/// * `token_codec` - Token codec to use (JSON/JCS or CBOR)
///
/// # Returns
/// kv-enc v3 format string with SIG line
pub fn encrypt_kv_document(
    kv_map: &HashMap<String, String>,
    _recipients: &[String],
    members: &[VerifiedPublicKeyAttested],
    signing: &SigningContext<'_>,
    token_codec: TokenCodec,
) -> Result<String> {
    encrypt_kv_document_with_disclosed(kv_map, _recipients, members, signing, token_codec, false)
}

/// Encrypt KV map to kv-enc v3 format with disclosed flag control
pub fn encrypt_kv_document_with_disclosed(
    kv_map: &HashMap<String, String>,
    _recipients: &[String],
    members: &[VerifiedPublicKeyAttested],
    signing: &SigningContext<'_>,
    token_codec: TokenCodec,
    disclosed: bool,
) -> Result<String> {
    super::rewrite_session::encrypt_and_sign_kv_map(
        kv_map,
        members,
        signing,
        token_codec,
        disclosed,
        |_| Ok(()),
    )
}
