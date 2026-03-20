// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV format modules
//!
//! This module provides:
//! - dotenv: Dotenv format parser
//! - enc: KV-enc format parser/writer

mod document;

pub mod dotenv;
pub mod enc;

pub use document::{parse_kv_document, validate_kv_file_structure};

/// Header line prefix with colon: `:SECRETENV_KV `.
pub const HEADER_LINE_PREFIX: &str = ":SECRETENV_KV ";
/// Header line for v3: `:SECRETENV_KV 3`.
pub const HEADER_LINE_V3: &str = ":SECRETENV_KV 3";

/// File extension for kv-enc files.
pub const KV_ENC_EXTENSION: &str = ".kvenc";
/// Default base name for kv-enc files.
pub const DEFAULT_KV_ENC_BASENAME: &str = "default";
/// Default kv-enc file name: `default.kvenc`.
pub const DEFAULT_KV_ENC_FILE_NAME: &str = "default.kvenc";

use crate::format::kv::enc::parser::{KvEncLine, KvEncParser};
use crate::format::token::TokenCodec;

/// Detect token codec from kv-enc content by parsing WRAP line.
///
/// # Arguments
/// * `content` - kv-enc format content string
///
/// # Returns
/// Detected TokenCodec, or JsonJcs as default if not found
pub fn detect_token_codec_from_kv_content(content: &str) -> TokenCodec {
    let parser = KvEncParser::new(content);
    if let Ok(lines) = parser.parse_all() {
        for line in &lines {
            if let KvEncLine::Wrap { token } = line {
                return TokenCodec::detect(token);
            }
        }
    }
    TokenCodec::JsonJcs // Default
}
