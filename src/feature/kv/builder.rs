// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV document builder - unified builder for KV-enc document assembly and signing.

use crate::format::kv::enc::writer::build_unsigned_kv_document;
use crate::format::kv::enc::KvEncLine;
use crate::format::token::TokenCodec;
use crate::model::kv_enc::{KvEntryValue, KvHeader, KvWrap};
use crate::support::time::current_timestamp;
use crate::{Error, Result};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single entry in a KV document under construction.
#[derive(Debug, Clone)]
pub(crate) enum KvDocumentEntry {
    /// Preserved from the original document (token kept as-is).
    Preserved { key: String, token: String },
    /// Newly encoded (token freshly produced by TokenCodec).
    Encoded { key: String, token: String },
}

impl KvDocumentEntry {
    /// Entry key name.
    pub fn key(&self) -> &str {
        match self {
            Self::Preserved { key, .. } | Self::Encoded { key, .. } => key,
        }
    }

    /// Encoded token string.
    pub fn token(&self) -> &str {
        match self {
            Self::Preserved { token, .. } | Self::Encoded { token, .. } => token,
        }
    }
}

/// Source of the WRAP data — either decoded or raw (passthrough).
#[derive(Debug, Clone)]
pub(crate) enum WrapSource {
    /// Decoded (deserialized) WRAP data.
    Decoded(KvWrap),
    /// Raw passthrough: data is present alongside the original token string.
    Raw { data: KvWrap, token: String },
}

impl WrapSource {
    /// Borrow the decoded WRAP data.
    pub fn data(&self) -> &KvWrap {
        match self {
            Self::Decoded(d) => d,
            Self::Raw { data, .. } => data,
        }
    }

    /// Mutably borrow the WRAP data, promoting Raw to Decoded.
    pub fn data_mut(&mut self) -> &mut KvWrap {
        if let Self::Raw { data, .. } = self {
            let owned = data.clone();
            *self = Self::Decoded(owned);
        }
        match self {
            Self::Decoded(d) => d,
            Self::Raw { .. } => unreachable!(),
        }
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for assembling a KV-enc document prior to signing.
pub struct KvDocumentBuilder {
    head: KvHeader,
    wrap: WrapSource,
    entries: Vec<KvDocumentEntry>,
    token_codec: TokenCodec,
    debug: bool,
}

impl KvDocumentBuilder {
    /// Create a new builder with decoded wrap data.
    pub fn new(head: KvHeader, wrap: KvWrap, token_codec: TokenCodec, debug: bool) -> Self {
        Self {
            head,
            wrap: WrapSource::Decoded(wrap),
            entries: Vec::new(),
            token_codec,
            debug,
        }
    }

    /// Build from parsed KV-enc lines.
    ///
    /// * `wrap` — if `Some`, the WRAP line is stored as `Decoded`; if `None`,
    ///   the WRAP token is decoded from the raw line and stored as `Raw`.
    pub fn from_lines(
        head: KvHeader,
        wrap: Option<KvWrap>,
        lines: &[KvEncLine],
        token_codec: TokenCodec,
        debug: bool,
    ) -> Result<Self> {
        let mut entries = Vec::new();
        let mut wrap_source: Option<WrapSource> = None;

        for line in lines {
            match line {
                KvEncLine::KV { key, token } => {
                    entries.push(KvDocumentEntry::Preserved {
                        key: key.clone(),
                        token: token.clone(),
                    });
                }
                KvEncLine::Wrap { token } => {
                    wrap_source = Some(Self::resolve_wrap_source(wrap.as_ref(), token)?);
                }
                _ => {}
            }
        }

        let wrap = match wrap_source {
            Some(ws) => ws,
            None => {
                return Err(Error::Parse {
                    message: "WRAP line not found in document".to_string(),
                    source: None,
                });
            }
        };

        Ok(Self {
            head,
            wrap,
            entries,
            token_codec,
            debug,
        })
    }

    /// Resolve WRAP source from optional decoded data and raw token.
    fn resolve_wrap_source(wrap: Option<&KvWrap>, token: &str) -> Result<WrapSource> {
        match wrap {
            Some(w) => Ok(WrapSource::Decoded(w.clone())),
            None => {
                let data: KvWrap = TokenCodec::decode_auto(token)?;
                Ok(WrapSource::Raw {
                    data,
                    token: token.to_string(),
                })
            }
        }
    }

    /// Append entries as Encoded.
    pub fn with_entries(mut self, entries: Vec<(String, String)>) -> Self {
        for (key, token) in entries {
            self.entries.push(KvDocumentEntry::Encoded { key, token });
        }
        self
    }

    /// Consume the builder and produce an unsigned document.
    pub fn build(self) -> UnsignedKvDocument {
        UnsignedKvDocument {
            head: self.head,
            wrap: self.wrap,
            entries: self.entries,
            token_codec: self.token_codec,
            debug: self.debug,
        }
    }
}

// ---------------------------------------------------------------------------
// UnsignedKvDocument
// ---------------------------------------------------------------------------

/// An assembled but unsigned KV-enc document.
pub struct UnsignedKvDocument {
    head: KvHeader,
    wrap: WrapSource,
    entries: Vec<KvDocumentEntry>,
    token_codec: TokenCodec,
    debug: bool,
}

impl UnsignedKvDocument {
    /// Borrow the HEAD header.
    pub fn head(&self) -> &KvHeader {
        &self.head
    }

    /// Borrow the decoded WRAP data.
    pub fn wrap(&self) -> &KvWrap {
        self.wrap.data()
    }

    /// List entry keys in document order.
    pub fn entry_keys(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.key()).collect()
    }

    /// Check whether a key exists.
    pub fn has_entry(&self, key: &str) -> bool {
        self.entries.iter().any(|e| e.key() == key)
    }

    /// Replace existing keys in place; append new keys sorted.
    pub fn set_entries(&mut self, entries: &HashMap<&str, &str>) {
        let mut found: std::collections::HashSet<&str> = std::collections::HashSet::new();

        // Replace in place
        for entry in &mut self.entries {
            if let Some((&matched_key, &new_token)) = entries.get_key_value(entry.key()) {
                found.insert(matched_key);
                *entry = KvDocumentEntry::Encoded {
                    key: entry.key().to_string(),
                    token: new_token.to_string(),
                };
            }
        }

        // Append new keys sorted
        let mut new_keys: Vec<_> = entries
            .iter()
            .filter(|(k, _)| !found.contains(**k))
            .collect();
        new_keys.sort_by_key(|(k, _)| **k);
        for (key, token) in new_keys {
            self.entries.push(KvDocumentEntry::Encoded {
                key: key.to_string(),
                token: token.to_string(),
            });
        }
    }

    /// Remove entry by key.
    pub fn unset_entry(&mut self, key: &str) {
        self.entries.retain(|e| e.key() != key);
    }

    /// Update the HEAD timestamp to current UTC time.
    pub fn update_timestamp(&mut self) -> Result<()> {
        self.head.updated_at = current_timestamp()?;
        Ok(())
    }

    /// Replace wrap data with a decoded value.
    pub fn set_wrap(&mut self, wrap: KvWrap) {
        self.wrap = WrapSource::Decoded(wrap);
    }

    /// Mutably borrow wrap data (promotes Raw to Decoded).
    pub fn wrap_mut(&mut self) -> &mut KvWrap {
        self.wrap.data_mut()
    }

    /// Return the token codec used for serialization.
    pub(crate) fn token_codec(&self) -> TokenCodec {
        self.token_codec
    }
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

impl UnsignedKvDocument {
    /// Clear disclosed flags on preserved entries.
    ///
    /// For each `Preserved` entry whose `KvEntryValue.disclosed` is `true`,
    /// decode the token, set `disclosed = false`, re-encode, and convert to
    /// `Encoded`.
    pub fn clear_disclosed_flags(&mut self) -> Result<()> {
        for entry in &mut self.entries {
            if let KvDocumentEntry::Preserved { key, token } = entry {
                let mut val: KvEntryValue = TokenCodec::decode_auto(token)?;
                if val.disclosed {
                    val.disclosed = false;
                    let new_token = TokenCodec::encode(self.token_codec, &val)?;
                    *entry = KvDocumentEntry::Encoded {
                        key: key.clone(),
                        token: new_token,
                    };
                }
            }
        }
        Ok(())
    }

    /// Serialize the document to unsigned kv-enc format string.
    pub fn serialize_unsigned(&self) -> Result<String> {
        let head_token = self.encode_head()?;
        let wrap_token = self.resolve_wrap_token()?;
        let entries: Vec<(&str, &str)> =
            self.entries.iter().map(|e| (e.key(), e.token())).collect();
        Ok(build_unsigned_kv_document(
            &head_token,
            &wrap_token,
            &entries,
        ))
    }

    /// Encode the HEAD to a token string.
    fn encode_head(&self) -> Result<String> {
        TokenCodec::encode_debug(
            self.token_codec,
            &self.head,
            self.debug,
            Some("HEAD"),
            Some("serialize_unsigned"),
        )
    }

    /// Resolve WRAP token: re-encode if Decoded, passthrough if Raw.
    fn resolve_wrap_token(&self) -> Result<String> {
        match &self.wrap {
            WrapSource::Decoded(data) => TokenCodec::encode_debug(
                self.token_codec,
                data,
                self.debug,
                Some("WRAP"),
                Some("serialize_unsigned"),
            ),
            WrapSource::Raw { token, .. } => Ok(token.clone()),
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/feature_kv_builder_test.rs"]
mod tests;
