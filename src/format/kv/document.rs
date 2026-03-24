// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV-enc document parsing and validation.

mod parse;
mod schema;
mod structure;

use crate::model::kv_enc::document::KvEncDocument;
use crate::model::kv_enc::line::KvEncLine;
use crate::Result;

pub fn parse_kv_document(content: &str) -> Result<KvEncDocument> {
    parse::parse_kv_document(content)
}

pub fn validate_kv_file_structure(lines: &[KvEncLine]) -> Result<()> {
    structure::validate_kv_file_structure(lines)
}
