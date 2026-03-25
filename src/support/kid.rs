// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared helpers for canonical `kid` handling.

use crate::{Error, Result};

const KID_LENGTH: usize = 32;
const DISPLAY_GROUP_SIZE: usize = 4;

/// Normalize user-provided `kid` input to canonical serialized form.
pub fn normalize_kid(input: &str) -> Result<String> {
    let normalized = input
        .bytes()
        .filter(|byte| *byte != b'-')
        .map(|byte| byte.to_ascii_uppercase())
        .collect::<Vec<u8>>();

    if normalized.len() != KID_LENGTH {
        return Err(Error::invalid_argument(format!(
            "kid must be {KID_LENGTH} Crockford Base32 characters after normalization"
        )));
    }

    let canonical = String::from_utf8(normalized)
        .map_err(|_| Error::invalid_argument("kid must be valid ASCII"))?;

    if !canonical.bytes().all(is_crockford_base32_byte) {
        return Err(Error::invalid_argument(
            "kid must use Crockford Base32 characters only",
        ));
    }

    Ok(canonical)
}

/// Build the human-friendly dashed display form of a canonical `kid`.
pub fn build_kid_display(canonical_kid: &str) -> Result<String> {
    let canonical = normalize_kid(canonical_kid)?;
    let mut output = String::with_capacity(KID_LENGTH + (KID_LENGTH / DISPLAY_GROUP_SIZE - 1));

    for (index, chunk) in canonical.as_bytes().chunks(DISPLAY_GROUP_SIZE).enumerate() {
        if index > 0 {
            output.push('-');
        }
        output.push_str(std::str::from_utf8(chunk).expect("canonical kid must stay ASCII"));
    }

    Ok(output)
}

/// Build dashed display form for human-facing output.
///
/// This function is **lossy**: if `kid` is not a valid canonical `kid`, it returns the input as-is.
pub fn kid_display_lossy(kid: &str) -> String {
    build_kid_display(kid).unwrap_or_else(|_| kid.to_string())
}

fn is_crockford_base32_byte(byte: u8) -> bool {
    matches!(byte, b'0'..=b'9' | b'A'..=b'H' | b'J'..=b'K' | b'M'..=b'N' | b'P'..=b'T' | b'V'..=b'Z')
}
