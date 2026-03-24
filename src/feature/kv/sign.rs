// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Signing helpers for unsigned kv-enc documents.

use crate::feature::envelope::signature::{sign_kv_document, SigningContext};
use crate::Result;

use super::document::UnsignedKvDocument;

/// Serialize and sign an unsigned KV document.
pub(crate) fn sign_unsigned_kv_document(
    unsigned: UnsignedKvDocument,
    signing: &SigningContext<'_>,
) -> Result<String> {
    let token_codec = unsigned.token_codec();
    let content = unsigned.serialize_unsigned()?;
    sign_kv_document(&content, signing, token_codec, "sign_unsigned_kv_document")
}

impl UnsignedKvDocument {
    /// Serialize and sign the document.
    pub fn sign(self, signing: &SigningContext<'_>) -> Result<String> {
        sign_unsigned_kv_document(self, signing)
    }
}
