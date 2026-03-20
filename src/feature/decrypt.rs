// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Decrypt feature - file-enc decryption.

pub mod file;

use crate::feature::context::crypto::CryptoContext;
use crate::feature::decrypt::file::decrypt_file_document;
use crate::feature::verify::file::verify_file_content;
use crate::format::content::FileEncContent;
use crate::Result;
use zeroize::Zeroizing;

/// Decrypt file-enc content.
///
/// This is the main entry point called by the CLI after format detection.
pub fn decrypt_document(
    content: &FileEncContent,
    member_id: &str,
    key_ctx: &CryptoContext,
    debug: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    let verified_doc = verify_file_content(content, key_ctx.workspace_path.as_deref(), debug)?;
    decrypt_file_document(
        &verified_doc,
        member_id,
        &key_ctx.kid,
        &key_ctx.private_key,
        debug,
    )
}
