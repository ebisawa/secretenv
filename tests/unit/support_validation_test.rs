// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for support/validation module
//!
//! Tests for validation utilities (edge cases).

use secretenv::support::validation::validate_member_id;

#[test]
fn test_validate_member_id_valid() {
    assert!(validate_member_id("alice@example.com").is_ok());
    assert!(validate_member_id("user.name@example.com").is_ok());
    assert!(validate_member_id("user+tag@example.com").is_ok());
    assert!(validate_member_id("user_name@example.com").is_ok());
    assert!(validate_member_id("user-name@example.com").is_ok());
}

#[test]
fn test_validate_member_id_empty() {
    assert!(validate_member_id("").is_err());
}

#[test]
fn test_validate_member_id_too_long() {
    let long_id = "a".repeat(255);
    assert!(validate_member_id(&long_id).is_err());
}

#[test]
fn test_validate_member_id_max_length() {
    let max_id = "a".repeat(254);
    assert!(validate_member_id(&max_id).is_ok());
}

#[test]
fn test_validate_member_id_starts_with_non_alphanumeric() {
    assert!(validate_member_id("@example.com").is_err());
    assert!(validate_member_id(".example.com").is_err());
    assert!(validate_member_id("_example.com").is_err());
}

#[test]
fn test_validate_member_id_invalid_characters() {
    assert!(validate_member_id("user#example.com").is_err());
    assert!(validate_member_id("user$example.com").is_err());
    assert!(validate_member_id("user example.com").is_err());
}
