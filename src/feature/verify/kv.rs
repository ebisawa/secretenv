// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV-enc signature verification.

mod signature;

pub use signature::{
    verify_kv_content, verify_kv_content_report, verify_kv_document, verify_kv_document_report,
};
