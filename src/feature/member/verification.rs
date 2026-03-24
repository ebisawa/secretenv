// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Member verification - online verification of member binding claims.

use crate::feature::verify::public_key::verify_public_key_for_verification;
use crate::io::verify_online::github::verify_github_account;
use crate::io::verify_online::{VerificationResult, VerificationStatus};
use crate::io::workspace::members::{list_member_file_paths, load_member_file_from_path};
use crate::model::public_key::PublicKey;
use crate::support::path::display_path_relative_to_cwd;
use crate::{Error, Result};
use std::ffi::OsStr;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct VerifiedMemberFile {
    pub member_id: String,
    pub public_key: PublicKey,
    pub warnings: Vec<String>,
}

pub fn load_and_verify_member_file(
    member_file: &Path,
    expected_member_id: Option<&str>,
    debug: bool,
) -> Result<VerifiedMemberFile> {
    let fallback_member_id = expected_member_id
        .map(str::to_string)
        .unwrap_or_else(|| member_id_from_path(member_file));
    let public_key = load_member_file_from_path(member_file)?;

    if public_key.protected.member_id != fallback_member_id {
        return Err(Error::InvalidArgument {
            message: format!(
                "Member ID mismatch in {}: expected '{}', found '{}'",
                display_path_relative_to_cwd(member_file),
                fallback_member_id,
                public_key.protected.member_id
            ),
        });
    }

    let verified = verify_public_key_for_verification(&public_key, debug)?;
    Ok(VerifiedMemberFile {
        member_id: verified
            .verified_public_key
            .document
            .protected
            .member_id
            .clone(),
        public_key,
        warnings: verified.warnings,
    })
}

pub fn member_id_from_path(member_file: &Path) -> String {
    member_file
        .file_stem()
        .and_then(OsStr::to_str)
        .map(str::to_string)
        .unwrap_or_else(|| display_path_relative_to_cwd(member_file))
}

/// Verify binding_claims.github_account for members (GitHub).
pub async fn verify_member(
    workspace_path: &Path,
    member_ids: &[String],
    verbose: bool,
) -> Result<Vec<VerificationResult>> {
    let member_files = list_member_file_paths(workspace_path, member_ids)?;

    let mut results = Vec::new();
    for member_file in member_files {
        let result = verify_member_file_online(&member_file, verbose).await;
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

/// Verify member files' binding_claims via GitHub online verification.
///
/// Offline verification failures, network errors, and API failures are converted
/// to `VerificationResult::failed` rather than propagated as `Err`.
pub async fn verify_member_files(
    member_files: &[std::path::PathBuf],
    verbose: bool,
) -> Vec<VerificationResult> {
    let mut results = Vec::new();
    for member_file in member_files {
        let result = verify_member_file_online(member_file, verbose).await;
        results.push(result);
    }
    results
}

async fn verify_member_file_online(member_file: &Path, verbose: bool) -> VerificationResult {
    let fallback_member_id = member_id_from_path(member_file);
    let verified =
        match load_and_verify_member_file(member_file, Some(&fallback_member_id), verbose) {
            Ok(verified) => verified,
            Err(e) => {
                return VerificationResult::failed(
                    &fallback_member_id,
                    format!("Offline verification failed: {e}"),
                    None,
                );
            }
        };

    let result = match verify_github_account(&verified.public_key, verbose, None).await {
        Ok(result) => result,
        Err(e) => VerificationResult::failed(
            &verified.member_id,
            format!("Online verification error: {e}"),
            None,
        ),
    };

    append_verification_warnings(result, &verified.warnings)
}

fn append_verification_warnings(
    mut result: VerificationResult,
    warnings: &[String],
) -> VerificationResult {
    if warnings.is_empty() {
        return result;
    }

    result.message = format!("{} [{}]", result.message, warnings.join("; "));
    result
}

#[cfg(test)]
#[path = "../../../tests/unit/feature_member_verification_test.rs"]
mod tests;
