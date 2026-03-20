// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared helpers for verified KV rewrites and re-signing.

use crate::crypto::types::keys::MasterKey;
use crate::feature::context::crypto::CryptoContext;
use crate::feature::envelope::signature::build_signing_context;
use crate::feature::envelope::signature::SigningContext;
use crate::feature::kv::builder::UnsignedKvDocument;
use crate::feature::kv::encrypt::{build_kv_encryption, encrypt_kv_entries};
use crate::feature::verify::kv::verify_kv_content;
use crate::format::content::KvEncContent;
use crate::format::kv::detect_token_codec_from_kv_content;
use crate::format::kv::enc::{parse_kv_wrap, KvEncLine};
use crate::format::token::TokenCodec;
use crate::model::kv_enc::{KvEntryValue, KvHeader, KvWrap, VerifiedKvEncDocument};
use crate::model::public_key::VerifiedPublicKeyAttested;
use crate::Result;
use std::collections::HashMap;
use uuid::Uuid;

pub(crate) struct VerifiedKvRewriteSession<'a> {
    verified: VerifiedKvEncDocument,
    member_id: &'a str,
    key_ctx: &'a CryptoContext,
    token_codec: Option<TokenCodec>,
    no_signer_pub: bool,
    debug: bool,
}

impl<'a> VerifiedKvRewriteSession<'a> {
    pub(crate) fn load(
        content: &KvEncContent,
        member_id: &'a str,
        key_ctx: &'a CryptoContext,
        token_codec: Option<TokenCodec>,
        no_signer_pub: bool,
        debug: bool,
    ) -> Result<Self> {
        let verified = verify_kv_content(content, key_ctx.workspace_path.as_deref(), debug)?;
        Ok(Self::from_verified(
            verified,
            member_id,
            key_ctx,
            token_codec,
            no_signer_pub,
            debug,
        ))
    }

    pub(crate) fn from_verified(
        verified: VerifiedKvEncDocument,
        member_id: &'a str,
        key_ctx: &'a CryptoContext,
        token_codec: Option<TokenCodec>,
        no_signer_pub: bool,
        debug: bool,
    ) -> Self {
        Self {
            verified,
            member_id,
            key_ctx,
            token_codec,
            no_signer_pub,
            debug,
        }
    }

    pub(crate) fn document(&self) -> &crate::model::kv_enc::KvEncDocument {
        self.verified.document()
    }

    pub(crate) fn token_codec(&self) -> TokenCodec {
        let doc = self.document();
        detect_token_codec(doc.content(), doc.lines(), self.token_codec)
    }

    pub(crate) fn build_unsigned(&self, head: KvHeader) -> Result<UnsignedKvDocument> {
        build_unsigned_from_verified(&self.verified, head, self.token_codec, self.debug)
    }

    pub(crate) fn rebuild_unsigned_from_content(
        &self,
        content: &str,
    ) -> Result<UnsignedKvDocument> {
        rebuild_unsigned_from_content(content, self.token_codec, self.debug)
    }

    pub(crate) fn sign(&self, unsigned: UnsignedKvDocument) -> Result<String> {
        sign_unsigned_with_key_context(unsigned, self.key_ctx, self.no_signer_pub, self.debug)
    }

    pub(crate) fn unwrap_master_key(&self) -> Result<MasterKey> {
        unwrap_master_key_from_verified(&self.verified, self.member_id, self.key_ctx, self.debug)
    }
}

/// Encode encrypted KV entries to token strings.
pub(crate) fn encode_kv_entries_to_tokens(
    entries: &[(String, KvEntryValue)],
    token_codec: TokenCodec,
    debug: bool,
    caller: &'static str,
) -> Result<Vec<(String, String)>> {
    entries
        .iter()
        .map(|(key, entry)| {
            let token =
                TokenCodec::encode_debug(token_codec, entry, debug, Some(&entry.k), Some(caller))?;
            Ok((key.clone(), token))
        })
        .collect()
}

/// Detect the token codec for a verified or parsed KV document.
pub(crate) fn detect_token_codec(
    content: &str,
    lines: &[KvEncLine],
    override_codec: Option<TokenCodec>,
) -> TokenCodec {
    override_codec.unwrap_or_else(|| {
        lines
            .iter()
            .find_map(|line| match line {
                KvEncLine::Wrap { token } => Some(TokenCodec::detect(token)),
                _ => None,
            })
            .unwrap_or_else(|| detect_token_codec_from_kv_content(content))
    })
}

/// Build an unsigned KV document from a verified document and replacement head.
pub(crate) fn build_unsigned_from_verified(
    verified: &VerifiedKvEncDocument,
    head: KvHeader,
    override_codec: Option<TokenCodec>,
    debug: bool,
) -> Result<super::builder::UnsignedKvDocument> {
    let doc = verified.document();
    let token_codec = detect_token_codec(doc.content(), doc.lines(), override_codec);
    super::builder::KvDocumentBuilder::from_lines(head, None, doc.lines(), token_codec, debug)
        .map(|builder| builder.build())
}

/// Rebuild an unsigned KV document from signed content produced by rewrap flows.
pub(crate) fn rebuild_unsigned_from_content(
    content: &str,
    override_codec: Option<TokenCodec>,
    debug: bool,
) -> Result<super::builder::UnsignedKvDocument> {
    let (lines, head, wrap) = parse_kv_wrap(content)?;
    let token_codec = detect_token_codec(content, &lines, override_codec);
    super::builder::KvDocumentBuilder::from_lines(head, Some(wrap), &lines, token_codec, debug)
        .map(|builder| builder.build())
}

/// Sign an unsigned KV document using the given crypto context.
pub(crate) fn sign_unsigned_with_key_context(
    unsigned: super::builder::UnsignedKvDocument,
    key_ctx: &CryptoContext,
    no_signer_pub: bool,
    debug: bool,
) -> Result<String> {
    let signing = build_signing_context(key_ctx, no_signer_pub, debug)?;
    super::sign::sign_unsigned_kv_document(unsigned, &signing)
}

/// Unwrap the master key from a verified KV document for rewrite operations.
pub(crate) fn unwrap_master_key_from_verified(
    verified: &VerifiedKvEncDocument,
    member_id: &str,
    key_ctx: &CryptoContext,
    debug: bool,
) -> Result<MasterKey> {
    let doc = verified.document();
    crate::feature::envelope::unwrap::unwrap_master_key_for_kv(
        &doc.head.sid,
        &doc.wrap.wrap,
        member_id,
        &key_ctx.kid,
        &key_ctx.private_key,
        debug,
    )
}

/// Encrypt a plaintext KV map for the given recipients and sign the result.
pub(crate) fn encrypt_and_sign_kv_map<F>(
    kv_map: &HashMap<String, String>,
    members: &[VerifiedPublicKeyAttested],
    signing: &SigningContext<'_>,
    token_codec: TokenCodec,
    disclosed: bool,
    mutate_wrap: F,
) -> Result<String>
where
    F: FnOnce(&mut KvWrap) -> Result<()>,
{
    let timestamp = crate::support::time::current_timestamp()?;
    let sid = Uuid::new_v4();
    let (master_key, head_data, mut wrap_data) = build_kv_encryption(members, &sid, &timestamp)?;
    mutate_wrap(&mut wrap_data)?;

    let entries = encrypt_kv_entries(kv_map, &master_key, &sid, signing.debug, disclosed)?;
    let encoded = encode_kv_entries_to_tokens(
        &entries,
        token_codec,
        signing.debug,
        "encrypt_and_sign_kv_map",
    )?;

    let unsigned =
        super::builder::KvDocumentBuilder::new(head_data, wrap_data, token_codec, signing.debug)
            .with_entries(encoded)
            .build();
    super::sign::sign_unsigned_kv_document(unsigned, signing)
}
