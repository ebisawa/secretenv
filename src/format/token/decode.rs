// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Token decoding implementation

use crate::format::token::TokenCodec;
use crate::format::FormatError;
use crate::support::base64url::b64_decode_token;
use crate::Result;

/// Decode a token's raw bytes.
/// Returns (bytes, codec).
pub fn decode_token_bytes(
    token: &str,
    _debug: bool,
    _caller: Option<&str>,
) -> Result<(Vec<u8>, TokenCodec)> {
    // CBOR tokens were supported in earlier versions but are removed in the current spec.
    if token.starts_with("cb:") || token.starts_with("cz:") {
        return Err(FormatError::parse_failed(
            "CBOR tokens are not supported (use JSON/JCS tokens)",
        )
        .into());
    }

    let data = b64_decode_token(token, "token")?;
    Ok((data, TokenCodec::JsonJcs))
}

/// Deserialize value from token.
pub fn from_token_impl<T: serde::de::DeserializeOwned + serde::Serialize>(
    codec: TokenCodec,
    token: &str,
    debug: bool,
    label: Option<&str>,
    caller: Option<&str>,
) -> Result<T> {
    let (bytes, detected_codec) = decode_token_bytes(token, debug, caller)?;

    if codec != detected_codec {
        return Err(FormatError::parse_failed(format!(
            "Token codec mismatch: expected {:?}, detected {:?}",
            codec, detected_codec
        ))
        .into());
    }

    let _ = label;

    crate::support::json_limits::validate_json_limits(&bytes)?;

    serde_json::from_slice(&bytes).map_err(|e| {
        crate::Error::from(FormatError::parse_failed_with_source(
            format!("Failed to deserialize token: {}", e),
            e,
        ))
    })
}
