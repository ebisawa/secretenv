// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! kv-enc format rewrap operations (CLI wrapper)

use crate::app::rewrap::rewrap_kv_content;
use crate::format::content::KvEncContent;
use crate::format::token::TokenCodec;
use crate::Result;

use super::{run_rewrap, RewrapArgs};

/// Rewrap a kv-enc v3 file (returns updated content).
pub fn rewrap_kv(args: &RewrapArgs, content: &KvEncContent) -> Result<String> {
    run_rewrap(args, content, Some(TokenCodec::JsonJcs), rewrap_kv_content)
}
