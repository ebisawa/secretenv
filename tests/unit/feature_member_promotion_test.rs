// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::io::verify_online::VerificationResult;
use crate::model::public_key::{BindingClaims, VerifiedBindingClaims};
use crate::model::verification::BindingVerificationProof;

fn dummy_bindings() -> VerifiedBindingClaims {
    VerifiedBindingClaims::new(
        BindingClaims {
            github_account: None,
        },
        BindingVerificationProof::new("github".to_string(), None, None),
    )
}

#[test]
fn test_report_all_member_ids_returns_all_categories() {
    let report = IncomingVerificationReport {
        verified: vec![VerificationResult::verified(
            "alice",
            "OK".to_string(),
            "SHA256:abc".to_string(),
            42,
            dummy_bindings(),
        )],
        failed: vec![VerificationResult::failed(
            "bob",
            "Failed".to_string(),
            None,
        )],
        not_configured: vec![VerificationResult::not_configured(
            "carol",
            "No binding",
            None,
        )],
    };
    let mut ids = report.all_member_ids();
    ids.sort();
    assert_eq!(ids, vec!["alice", "bob", "carol"]);
}

#[test]
fn test_report_verified_member_ids() {
    let report = IncomingVerificationReport {
        verified: vec![VerificationResult::verified(
            "alice",
            "OK".to_string(),
            "SHA256:abc".to_string(),
            42,
            dummy_bindings(),
        )],
        failed: vec![],
        not_configured: vec![],
    };
    let ids = report.verified_member_ids();
    assert_eq!(ids, vec!["alice"]);
}

#[test]
fn test_report_non_failed_member_ids_excludes_failed() {
    let report = IncomingVerificationReport {
        verified: vec![VerificationResult::verified(
            "alice",
            "OK".to_string(),
            "SHA256:abc".to_string(),
            42,
            dummy_bindings(),
        )],
        failed: vec![VerificationResult::failed(
            "bob",
            "Failed".to_string(),
            None,
        )],
        not_configured: vec![VerificationResult::not_configured(
            "carol",
            "No binding",
            None,
        )],
    };
    let mut ids = report.non_failed_member_ids();
    ids.sort();
    assert_eq!(ids, vec!["alice", "carol"]);
}
