// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for support/base64url module
//!
//! Tests for base64url encoding/decoding utilities.

use secretenv::support::base64url::{
    b64_decode, b64_decode_array, b64_decode_ciphertext, b64_decode_token, b64_encode,
};
use secretenv::support::limits::{MAX_BASE64_CIPHERTEXT_LENGTH, MAX_BASE64_TOKEN_LENGTH};

#[test]
fn test_b64_roundtrip() {
    let data = b"hello world";
    let encoded = b64_encode(data);
    let decoded = b64_decode(&encoded, "test").unwrap();
    assert_eq!(decoded, data);
}

#[test]
fn test_b64_decode_array() {
    let data = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let encoded = b64_encode(&data);
    let decoded: [u8; 8] = b64_decode_array(&encoded, "test").unwrap();
    assert_eq!(decoded, data);
}

#[test]
fn test_b64_decode_array_wrong_size() {
    let data = [1u8, 2, 3, 4];
    let encoded = b64_encode(&data);
    let result: Result<[u8; 8], _> = b64_decode_array(&encoded, "test");
    assert!(result.is_err());
}

#[test]
fn test_b64_decode_token_rejects_input_over_limit() {
    let oversized = "A".repeat(MAX_BASE64_TOKEN_LENGTH + 1);
    let result = b64_decode_token(&oversized, "token");
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("maximum token length"));
}

#[test]
fn test_b64_decode_ciphertext_rejects_input_over_limit() {
    let oversized = "A".repeat(MAX_BASE64_CIPHERTEXT_LENGTH + 1);
    let result = b64_decode_ciphertext(&oversized, "ct");
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("maximum base64url length"));
}
