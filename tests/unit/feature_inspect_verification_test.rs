// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for inspect/verification online verification display.

use secretenv::feature::inspect::verification::{
    build_online_verification_section, OnlineVerificationDisplay,
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
    let section = build_online_verification_section(&display, Some("alice"), Some(12345));

    assert_eq!(section.title, "Online Verification (GitHub)");
    assert!(section.lines.iter().any(|line| line == "Status:   OK"));
    assert!(section
        .lines
        .iter()
        .any(|line| line == "Account:  alice (id: 12345)"));
    assert!(section
        .lines
        .iter()
        .any(|line| line == "SSH key fingerprint: SHA256:abcdef1234567890"));
    assert!(section
        .lines
        .iter()
        .any(|line| line == "Matched key ID: 67890"));
}

#[test]
fn test_online_verification_display_github_failed() {
    let result = make_failed_result();
    let display = OnlineVerificationDisplay::GithubResult(result);
    let section = build_online_verification_section(&display, Some("bob"), Some(54321));

    assert_eq!(section.title, "Online Verification (GitHub)");
    assert!(section.lines.iter().any(|line| line == "Status:   FAILED"));
    assert!(section
        .lines
        .iter()
        .any(|line| line == "Reason:   SSH key not found in GitHub account keys"));
    assert!(!section
        .lines
        .iter()
        .any(|line| line.starts_with("Account:")));
}

#[test]
fn test_online_verification_display_no_supported_binding() {
    let display = OnlineVerificationDisplay::NoSupportedBinding;
    let section = build_online_verification_section(&display, None, None);

    assert_eq!(section.title, "Online Verification");
    assert!(!section.title.contains("(GitHub)"));
    assert!(section
        .lines
        .iter()
        .any(|line| line == "Status:   Not available (no supported binding configured)"));
}
