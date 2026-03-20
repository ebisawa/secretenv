// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Token codec implementation
//!
//! Provides encode/decode implementations for TokenCodec.

use super::{decode, encode, TokenCodec};
use crate::Result;

impl TokenCodec {
    /// Serialize value to base64url token.
    pub fn encode<T: serde::Serialize>(codec: TokenCodec, value: &T) -> Result<String> {
        encode::to_token_with_codec_impl(value, codec, false, None, None)
    }

    /// Serialize value to token with debug logging.
    pub fn encode_debug<T: serde::Serialize>(
        codec: TokenCodec,
        value: &T,
        debug: bool,
        label: Option<&str>,
        caller: Option<&str>,
    ) -> Result<String> {
        encode::to_token_with_codec_impl(value, codec, debug, label, caller)
    }

    /// Deserialize value from token.
    pub fn decode<T: serde::de::DeserializeOwned + serde::Serialize>(
        codec: TokenCodec,
        token: &str,
    ) -> Result<T> {
        Self::decode_debug(codec, token, false, None, None)
    }

    /// Deserialize value from token with debug logging.
    pub fn decode_debug<T: serde::de::DeserializeOwned + serde::Serialize>(
        codec: TokenCodec,
        token: &str,
        debug: bool,
        label: Option<&str>,
        caller: Option<&str>,
    ) -> Result<T> {
        decode::from_token_impl(codec, token, debug, label, caller)
    }

    /// Deserialize value from token with auto-detected codec.
    pub fn decode_auto<T: serde::de::DeserializeOwned + serde::Serialize>(
        token: &str,
    ) -> Result<T> {
        let codec = TokenCodec::detect(token);
        Self::decode(codec, token)
    }

    /// Deserialize value from token with auto-detected codec and debug logging.
    pub fn decode_auto_debug<T: serde::de::DeserializeOwned + serde::Serialize>(
        token: &str,
        debug: bool,
        label: Option<&str>,
        caller: Option<&str>,
    ) -> Result<T> {
        let codec = TokenCodec::detect(token);
        Self::decode_debug(codec, token, debug, label, caller)
    }
}
