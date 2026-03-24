// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! DoS protection limits (per PRD)

use crate::{Error, Result};

/// Maximum number of WRAP items per document
pub const MAX_WRAP_ITEMS: usize = 1_000;

/// Maximum kv-enc file size in bytes (16 MiB)
pub const MAX_KV_ENC_FILE_SIZE: usize = 16 * 1024 * 1024;

/// Maximum number of KEY lines in a kv-enc document
pub const MAX_KV_KEY_LINES: usize = 10_000;

/// Maximum length of a single base64url token in bytes
pub const MAX_BASE64_TOKEN_LENGTH: usize = 1024 * 1024;

/// Maximum length of base64url ciphertext in bytes (16 MiB)
pub const MAX_BASE64_CIPHERTEXT_LENGTH: usize = 16 * 1024 * 1024;

/// Maximum JSON nesting depth
pub const MAX_JSON_DEPTH: usize = 32;

/// Maximum number of JSON elements (objects + arrays + values)
pub const MAX_JSON_ELEMENTS: usize = 10_000;

/// Validate WRAP item count against the global DoS limit.
pub fn validate_wrap_count(count: usize, context: &str) -> Result<()> {
    if count <= MAX_WRAP_ITEMS {
        return Ok(());
    }

    Err(Error::Parse {
        message: format!(
            "{} exceeds maximum wrap count ({} > {})",
            context, count, MAX_WRAP_ITEMS
        ),
        source: None,
    })
}
