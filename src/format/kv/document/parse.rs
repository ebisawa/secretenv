// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::format::kv::document::schema::validate_kv_document_schema;
use crate::format::kv::document::structure::{
    parse_kv_signature_token, validate_kv_file_structure, validate_kv_tokens,
};
use crate::format::kv::enc::canonical::extract_head_and_wrap_tokens;
use crate::format::kv::enc::parser::KvEncParser;
use crate::format::token::TokenCodec;
use crate::model::kv_enc::document::KvEncDocument;
use crate::model::kv_enc::header::{KvHeader, KvWrap};
use crate::{Error, Result};

pub(super) fn parse_kv_document(content: &str) -> Result<KvEncDocument> {
    let lines = KvEncParser::new(content).parse_all()?;
    validate_kv_file_structure(&lines)?;
    validate_kv_tokens(&lines)?;

    let (head_token, wrap_token) = extract_head_and_wrap_tokens(&lines)?;
    let signature_token = parse_kv_signature_token(&lines)?;
    let head = decode_head_token(&head_token)?;
    let wrap = decode_wrap_token(&wrap_token)?;
    validate_kv_document_schema(&head, &wrap)?;

    Ok(KvEncDocument::new(
        content.to_string(),
        lines,
        head,
        wrap,
        signature_token,
    ))
}

fn decode_head_token(token: &str) -> Result<KvHeader> {
    TokenCodec::decode_auto(token).map_err(|e| Error::Parse {
        message: format!("Failed to parse HEAD token: {}", e),
        source: Some(Box::new(e)),
    })
}

fn decode_wrap_token(token: &str) -> Result<KvWrap> {
    TokenCodec::decode_auto(token).map_err(|e| Error::Parse {
        message: format!("Failed to parse WRAP token: {}", e),
        source: Some(Box::new(e)),
    })
}
