// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for inspect/verification online verification display.

use secretenv::feature::inspect::verification::{
    build_online_verification_display, OnlineVerificationDisplay,
};
use secretenv::io::verify_online::{VerificationResult, VerificationStatus};

fn make_verified_result() -> VerificationResult {
    VerificationResult {
        member_id: "alice@example.com".to_string(),
        status: VerificationStatus::Verified,
        message: "OK".to_string(),
        fingerprint: Some("SHA256:abcdef1234567890".to_string()),
        matched_key_id: Some(67890),
        verified_bindings: None,
    }
}

fn make_failed_result() -> VerificationResult {
    VerificationResult {
        member_id: "bob@example.com".to_string(),
        status: VerificationStatus::Failed,
        message: "SSH key not found in GitHub account keys".to_string(),
        fingerprint: None,
        matched_key_id: None,
        verified_bindings: None,
    }
}

#[test]
fn test_online_verification_display_github_verified() {
    let result = make_verified_result();
    let display = OnlineVerificationDisplay::GithubResult(result);
    let mut out = String::new();
    build_online_verification_display(&display, Some("alice"), Some(12345), &mut out);

    assert!(out.contains("Online Verification (GitHub):"));
    assert!(out.contains("Status:   OK"));
    assert!(out.contains("Account:  alice (id: 12345)"));
    assert!(out.contains("SSH key fingerprint: SHA256:abcdef1234567890"));
    assert!(out.contains("Matched key ID: 67890"));
}

#[test]
fn test_online_verification_display_github_failed() {
    let result = make_failed_result();
    let display = OnlineVerificationDisplay::GithubResult(result);
    let mut out = String::new();
    build_online_verification_display(&display, Some("bob"), Some(54321), &mut out);

    assert!(out.contains("Online Verification (GitHub):"));
    assert!(out.contains("Status:   FAILED"));
    assert!(out.contains("Reason:   SSH key not found in GitHub account keys"));
    assert!(!out.contains("Account:"));
}

#[test]
fn test_online_verification_display_no_supported_binding() {
    let display = OnlineVerificationDisplay::NoSupportedBinding;
    let mut out = String::new();
    build_online_verification_display(&display, None, None, &mut out);

    assert!(out.contains("Online Verification:"));
    assert!(!out.contains("(GitHub)"));
    assert!(out.contains("Not available (no supported binding configured)"));
}
