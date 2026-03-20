// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV-enc format parser/writer
//!
//! Line-oriented format:
//! ```text
//! :SECRETENV_KV 3
//! :HEAD <base64url(jcs(KVFileHeader@3))>
//! :WRAP <base64url(jcs(KVFileWrap@3))>
//! KEY1 <base64url(jcs(EncryptedKVValue@3))>
//! KEY2 <base64url(jcs(EncryptedKVValue@3))>
//! :SIG <base64url(jcs(KVFileSignature@3))>
//! ```
//!
//! Diff-friendly: Unchanged lines preserve exact byte representation
//! Control lines start with `:` prefix, separator is space (0x20)

pub mod canonical;
pub mod parser;
pub mod writer;

pub use crate::model::kv_enc::{KvEncLine, KvEncVersion};
pub use canonical::{extract_head_and_wrap_tokens, extract_recipients_from_wrap, parse_kv_wrap};
pub use parser::KvEncParser;
