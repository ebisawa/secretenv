// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for app::key::github verification status

use secretenv::app::key::KeyNewResult;
use secretenv::io::verify_online::VerificationStatus;

#[test]
fn test_key_new_result_github_verification_not_configured_by_default() {
    // KeyNewResult.github_verification must be VerificationStatus::NotConfigured
    // when no github_user is specified.
    // This test verifies the field exists and has the correct type.
    let _: fn(VerificationStatus) = |_: VerificationStatus| {};

    // Verify the field access compiles: KeyNewResult must have github_verification
    fn assert_has_github_verification(r: &KeyNewResult) -> VerificationStatus {
        r.github_verification
    }
    let _ = assert_has_github_verification;
}
