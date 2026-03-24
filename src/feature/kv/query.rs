// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Read/query operations for kv-enc documents.

use super::decrypt::{decrypt_kv_document, decrypt_kv_single_entry};
use crate::feature::context::crypto::CryptoContext;
use crate::feature::verify::kv::signature::verify_kv_content;
use crate::format::content::KvEncContent;
use crate::format::kv::enc::parser::KvEncParser;
use crate::format::schema::document::parse_kv_entry_token;
use crate::model::kv_enc::line::KvEncLine;
use crate::{Error, Result};
use std::collections::HashMap;

/// Check if a KV entry is marked as disclosed.
pub fn check_kv_entry_disclosed(content: &KvEncContent, key: &str) -> Result<bool> {
    let doc = content.parse()?;
    for line in doc.lines() {
        if let KvEncLine::KV { key: k, token } = line {
            if k == key {
                let entry = parse_kv_entry_token(token)?;
                return Ok(entry.disclosed);
            }
        }
    }
    Ok(false)
}

/// List all KV keys with their disclosed status.
pub fn list_kv_keys_with_disclosed(content: &KvEncContent) -> Result<Vec<(String, bool)>> {
    let doc = content.parse()?;
    let mut keys = Vec::new();
    for line in doc.lines() {
        if let KvEncLine::KV { key, token } = line {
            let entry = parse_kv_entry_token(token)?;
            keys.push((key.clone(), entry.disclosed));
        }
    }
    keys.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(keys)
}

/// List keys in kv-enc content.
pub fn list_kv_keys(content: &KvEncContent) -> Result<Vec<String>> {
    let parser = KvEncParser::new(content.as_str());
    let lines = parser.parse_all()?;

    Ok(lines
        .iter()
        .filter_map(|line| match line {
            KvEncLine::KV { key, .. } => Some(key.clone()),
            _ => None,
        })
        .collect())
}

/// Decrypt a single key from kv-enc content.
pub fn decrypt_kv_value(
    content: &KvEncContent,
    member_id: &str,
    key_ctx: &CryptoContext,
    key: &str,
    verbose: bool,
) -> Result<String> {
    let verified_doc = verify_kv_content(content, key_ctx.workspace_path.as_deref(), verbose)?;
    let value = decrypt_kv_single_entry(
        &verified_doc,
        member_id,
        &key_ctx.kid,
        &key_ctx.private_key,
        key,
        verbose,
    )?;
    String::from_utf8(value.to_vec()).map_err(|e| Error::Parse {
        message: format!("Invalid UTF-8 in decrypted value: {}", e),
        source: Some(Box::new(e)),
    })
}

/// Decrypt all KV entries and return as a HashMap.
pub fn decrypt_all_kv_values(
    content: &KvEncContent,
    member_id: &str,
    key_ctx: &CryptoContext,
    verbose: bool,
) -> Result<HashMap<String, String>> {
    let verified_doc = verify_kv_content(content, key_ctx.workspace_path.as_deref(), verbose)?;
    let kv_map = decrypt_kv_document(
        &verified_doc,
        member_id,
        &key_ctx.kid,
        &key_ctx.private_key,
        verbose,
    )?;
    kv_map
        .into_iter()
        .map(|(k, v)| {
            let s = String::from_utf8(v.to_vec()).map_err(|e| Error::Parse {
                message: format!("Invalid UTF-8 in decrypted value for '{}': {}", k, e),
                source: Some(Box::new(e)),
            })?;
            Ok((k, s))
        })
        .collect()
}
