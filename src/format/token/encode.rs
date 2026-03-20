// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Token encoding implementation

use crate::format::jcs;
use crate::format::token::TokenCodec;
use crate::format::FormatError;
use crate::support::base64url::b64_encode;
use crate::Result;

/// Serialize value to token.
pub fn to_token_with_codec_impl<T: serde::Serialize>(
    value: &T,
    codec: TokenCodec,
    _debug: bool,
    _label: Option<&str>,
    _caller: Option<&str>,
) -> Result<String> {
    // v3 Rev9: token encoding is JSON/JCS only
    let _ = codec;
    let json_value = serde_json::to_value(value).map_err(|e| {
        crate::Error::from(FormatError::parse_failed_with_source(
            format!("JSON serialization failed: {}", e),
            e,
        ))
    })?;
    let jcs_bytes = jcs::normalize_to_string(&json_value)?;
    let original_bytes = jcs_bytes.as_bytes().to_vec();

    Ok(b64_encode(&original_bytes))
}
