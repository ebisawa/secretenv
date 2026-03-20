// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for format/token/decode module
//!
//! Tests for token decoding and error handling.

use secretenv::format::token::TokenCodec;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TestData {
    message: String,
    count: u32,
}

#[test]
fn test_token_decode() {
    // Create a valid token
    let data = TestData {
        message: "test".to_string(),
        count: 42,
    };
    let token = TokenCodec::encode(TokenCodec::JsonJcs, &data).unwrap();

    let decoded: TestData = TokenCodec::decode(TokenCodec::JsonJcs, &token).unwrap();

    assert_eq!(decoded, data);
}

#[test]
fn test_token_decode_large_data() {
    // Create a token with large data
    let data = TestData {
        message: "A".repeat(1000),
        count: 42,
    };
    let token = TokenCodec::encode(TokenCodec::JsonJcs, &data).unwrap();

    let decoded: TestData = TokenCodec::decode(TokenCodec::JsonJcs, &token).unwrap();

    assert_eq!(decoded, data);
}

#[test]
fn test_token_decode_auto() {
    let data = TestData {
        message: "test".to_string(),
        count: 42,
    };
    let token = TokenCodec::encode(TokenCodec::JsonJcs, &data).unwrap();

    let decoded: TestData = TokenCodec::decode_auto(&token).unwrap();

    assert_eq!(decoded, data);
}

#[test]
fn test_token_decode_invalid_base64() {
    let result: Result<TestData, _> =
        TokenCodec::decode(TokenCodec::JsonJcs, "invalid!base64@token");

    assert!(result.is_err());
}

#[test]
fn test_token_decode_invalid_json() {
    // Create a token with invalid JSON content
    let invalid_json = secretenv::support::base64url::b64_encode(b"{invalid json}");
    let result: Result<TestData, _> = TokenCodec::decode(TokenCodec::JsonJcs, &invalid_json);

    assert!(result.is_err());
}
