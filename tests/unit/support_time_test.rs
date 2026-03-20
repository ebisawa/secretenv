// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for support/time module
//!
//! Tests for time-related helpers.

use secretenv::support::time::{build_timestamp_display, current_timestamp};
use time::OffsetDateTime;

#[test]
fn test_build_timestamp_display() {
    let dt = OffsetDateTime::from_unix_timestamp(1609459200).unwrap(); // 2021-01-01T00:00:00Z
    let formatted = build_timestamp_display(dt).unwrap();

    assert!(formatted.contains("2021-01-01"));
    assert!(formatted.contains("00:00:00"));
}

#[test]
fn test_current_timestamp() {
    let timestamp = current_timestamp().unwrap();

    // Verify it's a valid RFC 3339 timestamp
    assert!(timestamp.contains("T"));
    assert!(timestamp.contains("Z") || timestamp.contains("+") || timestamp.contains("-"));
}

#[test]
fn test_build_timestamp_display_no_subseconds() {
    let dt = OffsetDateTime::from_unix_timestamp(1609459200).unwrap();
    let formatted = build_timestamp_display(dt).unwrap();

    // Should not contain subseconds
    assert!(!formatted.contains("."));
}
