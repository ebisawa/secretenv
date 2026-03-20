// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Mutating operations for kv-enc documents.

use crate::crypto::types::keys::MasterKey;
use crate::feature::context::crypto::CryptoContext;
use crate::feature::envelope::entry::encrypt_entry;
use crate::feature::verify::recipients::load_and_verify_recipient_public_keys;
use crate::format::content::KvEncContent;
use crate::format::kv::enc::{extract_recipients_from_wrap, KvEncLine};
use crate::format::token::TokenCodec;
use crate::io::workspace::members::list_active_member_ids;
use crate::model::kv_enc::KvHeader;
use crate::support::time::current_timestamp;
use crate::{Error, Result};
use std::collections::HashMap;
use std::path::Path;
use uuid::Uuid;

/// Result of kv set operation.
pub struct KvSetResult {
    pub encrypted: KvEncContent,
    pub recipients: Vec<String>,
}

/// Context for kv write operations (set/unset).
pub struct KvWriteContext {
    pub member_id: String,
    pub key_ctx: CryptoContext,
    pub token_codec: Option<TokenCodec>,
    pub no_signer_pub: bool,
    pub verbose: bool,
}

impl KvWriteContext {
    /// Build a new KvWriteContext.
    pub fn new(
        member_id: &str,
        key_ctx: CryptoContext,
        no_signer_pub: bool,
        verbose: bool,
    ) -> Self {
        Self {
            member_id: member_id.to_string(),
            key_ctx,
            token_codec: None,
            no_signer_pub,
            verbose,
        }
    }
}

/// Set or update one or more key-value pairs.
pub fn set_kv_entry(
    existing_content: Option<&KvEncContent>,
    entries: &[(String, String)],
    workspace_root: &Path,
    ctx: &KvWriteContext,
) -> Result<KvSetResult> {
    match existing_content {
        None => set_kv_new_file(entries, workspace_root, ctx),
        Some(content) => set_kv_existing_file(content, entries, ctx),
    }
}

/// Remove a key from kv-enc content without decrypting any entries.
pub fn unset_kv_entry(content: &KvEncContent, key: &str, ctx: &KvWriteContext) -> Result<String> {
    let session = super::rewrite::VerifiedKvRewriteSession::load(
        content,
        &ctx.member_id,
        &ctx.key_ctx,
        ctx.token_codec,
        ctx.no_signer_pub,
        ctx.verbose,
    )?;
    let doc = session.document();
    if !contains_key(doc.lines(), key) {
        return Err(Error::InvalidOperation {
            message: format!("Key '{}' not found", key),
        });
    }

    let mut unsigned = session.build_unsigned(build_updated_head(doc)?)?;
    unsigned.unset_entry(key);
    session.sign(unsigned)
}

fn set_kv_new_file(
    entries: &[(String, String)],
    workspace_root: &Path,
    ctx: &KvWriteContext,
) -> Result<KvSetResult> {
    let recipients = list_active_member_ids(workspace_root)?;
    let verified_members = load_and_verify_recipient_public_keys(
        &ctx.key_ctx.keystore_root,
        &recipients,
        ctx.verbose,
    )?;
    let signing = crate::feature::envelope::signature::build_signing_context(
        &ctx.key_ctx,
        ctx.no_signer_pub,
        ctx.verbose,
    )?;
    let codec = ctx.token_codec.unwrap_or(TokenCodec::JsonJcs);
    let kv_map: HashMap<String, String> = entries.iter().cloned().collect();
    let encrypted = super::encrypt::encrypt_kv_document(
        &kv_map,
        &recipients,
        &verified_members,
        &signing,
        codec,
    )?;
    Ok(KvSetResult {
        encrypted: KvEncContent::new_unchecked(encrypted),
        recipients,
    })
}

fn set_kv_existing_file(
    content: &KvEncContent,
    entries: &[(String, String)],
    ctx: &KvWriteContext,
) -> Result<KvSetResult> {
    let session = super::rewrite::VerifiedKvRewriteSession::load(
        content,
        &ctx.member_id,
        &ctx.key_ctx,
        ctx.token_codec,
        ctx.no_signer_pub,
        ctx.verbose,
    )?;
    let doc = session.document();
    let recipients = extract_recipients_from_wrap(&doc.wrap);
    let codec = session.token_codec();
    let master_key = session.unwrap_master_key()?;
    let new_entry_tokens = build_entry_tokens(entries, &master_key, &doc.head.sid, codec, ctx)?;
    let new_entries: HashMap<&str, &str> = new_entry_tokens
        .iter()
        .map(|(key, value)| (*key, value.as_str()))
        .collect();
    let mut unsigned = session.build_unsigned(build_updated_head(doc)?)?;
    unsigned.set_entries(&new_entries);
    let encrypted = session.sign(unsigned)?;
    Ok(KvSetResult {
        encrypted: KvEncContent::new_unchecked(encrypted),
        recipients,
    })
}

fn contains_key(lines: &[KvEncLine], key: &str) -> bool {
    lines
        .iter()
        .any(|line| matches!(line, KvEncLine::KV { key: existing, .. } if existing == key))
}

fn build_entry_tokens<'a>(
    entries: &'a [(String, String)],
    master_key: &MasterKey,
    sid: &Uuid,
    codec: TokenCodec,
    ctx: &KvWriteContext,
) -> Result<HashMap<&'a str, String>> {
    entries
        .iter()
        .map(|(key, value)| {
            let token = encrypt_and_encode_entry(key, value, master_key, sid, codec, ctx)?;
            Ok((key.as_str(), token))
        })
        .collect()
}

fn encrypt_and_encode_entry(
    key: &str,
    value: &str,
    master_key: &MasterKey,
    sid: &Uuid,
    codec: TokenCodec,
    ctx: &KvWriteContext,
) -> Result<String> {
    let new_entry = encrypt_entry(
        key,
        value,
        master_key,
        sid,
        ctx.verbose,
        "set_kv_entry",
        false,
    )?;
    crate::format::token::TokenCodec::encode_debug(
        codec,
        &new_entry,
        ctx.verbose,
        Some(key),
        Some("set_kv_entry"),
    )
}

fn build_updated_head(doc: &crate::model::kv_enc::KvEncDocument) -> Result<KvHeader> {
    Ok(KvHeader {
        sid: doc.head.sid,
        created_at: doc.head.created_at.clone(),
        updated_at: current_timestamp()?,
    })
}
