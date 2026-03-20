// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Member verification - online verification of member binding claims.

use crate::io::verify_online::github::verify_github_account;
use crate::io::verify_online::{VerificationResult, VerificationStatus};
use crate::io::workspace::members::{list_member_file_paths, load_member_file_from_path};
use crate::model::public_key::PublicKey;
use crate::Result;
use std::path::Path;

/// Verify binding_claims.github_account for members (GitHub).
pub async fn verify_member(
    workspace_path: &Path,
    member_ids: &[String],
    verbose: bool,
) -> Result<Vec<VerificationResult>> {
    let member_files = list_member_file_paths(workspace_path, member_ids)?;

    let mut results = Vec::new();
    for member_file in member_files {
        let public_key = load_member_file_from_path(&member_file)?;
        let result = verify_github_account(&public_key, verbose, None).await?;
        results.push(result);
    }

    Ok(results)
}

/// Classify verification results into verified, failed, and not_configured.
pub fn classify_verification_results(
    results: &[VerificationResult],
) -> (
    Vec<&VerificationResult>,
    Vec<&VerificationResult>,
    Vec<&VerificationResult>,
) {
    let mut verified = Vec::new();
    let mut failed = Vec::new();
    let mut not_configured = Vec::new();
    for result in results {
        match result.status {
            VerificationStatus::Verified => verified.push(result),
            VerificationStatus::Failed => failed.push(result),
            VerificationStatus::NotConfigured => not_configured.push(result),
        }
    }
    (verified, failed, not_configured)
}

/// Verify incoming members' binding_claims via GitHub online verification.
///
/// Network errors and API failures are converted to `VerificationResult::failed`
/// rather than propagated as `Err`.
pub async fn verify_incoming_members(
    incoming_members: &[PublicKey],
    verbose: bool,
) -> Vec<VerificationResult> {
    let mut results = Vec::new();
    for public_key in incoming_members {
        let result = match verify_github_account(public_key, verbose, None).await {
            Ok(r) => r,
            Err(e) => VerificationResult::failed(
                &public_key.protected.member_id,
                format!("Online verification error: {e}"),
                None,
            ),
        };
        results.push(result);
    }
    results
}

#[cfg(test)]
#[path = "../../../tests/unit/feature_member_verification_test.rs"]
mod tests;
