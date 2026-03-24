// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Rotate content key for file-enc content.

use crate::crypto::types::data::Plaintext;
use crate::crypto::types::keys::{MasterKey, XChaChaKey};
use crate::feature::context::crypto::CryptoContext;
use crate::feature::decrypt::file::decrypt_file_payload;
use crate::feature::envelope::payload::encrypt_file_payload_content;
use crate::feature::envelope::unwrap::unwrap_master_key_for_file;
use crate::feature::envelope::wrap::{build_wraps_for_recipients, WrapFormat};
use crate::feature::verify::recipients::load_and_verify_recipient_public_keys;
use crate::model::file_enc::FileEncDocumentProtected;
use crate::model::file_enc::VerifiedFileEncDocument;
use crate::Result;
use rand::rngs::OsRng;
use rand::RngCore;

/// Rotate content key for file-enc content.
pub fn rotate_file_key(
    protected: &mut FileEncDocumentProtected,
    verified: &VerifiedFileEncDocument,
    key_ctx: &CryptoContext,
    debug: bool,
) -> Result<()> {
    let old_content_key = unwrap_master_key_for_file(
        verified,
        &key_ctx.member_id,
        &key_ctx.kid,
        &key_ctx.private_key,
        debug,
    )?;

    // Decrypt payload using shared helper
    let plaintext_bytes =
        decrypt_file_payload(verified, &old_content_key, debug, "rotate_file_key")?;
    let plaintext_obj = Plaintext::from(plaintext_bytes.as_slice());

    // Generate new content key and re-encrypt
    let mut new_content_key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut new_content_key_bytes);
    let new_content_key = MasterKey::new(new_content_key_bytes);
    let new_xchacha_key = XChaChaKey::from_slice(new_content_key.as_bytes())?;
    protected.payload.encrypted = encrypt_file_payload_content(
        &plaintext_obj,
        &new_xchacha_key,
        &protected.payload.protected,
        debug,
        "rotate_file_key",
    )?;

    let current_recipients = protected.recipients();
    let attested_pubkeys = load_and_verify_recipient_public_keys(
        key_ctx.pub_key_source.as_ref(),
        &current_recipients,
        debug,
    )?;
    protected.wrap = build_wraps_for_recipients(
        &attested_pubkeys,
        &protected.sid,
        &new_content_key,
        WrapFormat::File,
        debug,
    )?;

    Ok(())
}
