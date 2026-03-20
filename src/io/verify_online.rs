// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Online verification for binding_claims.github_account
//!
//! Implements GitHub API integration for verifying SSH key ownership

pub mod github;

use crate::model::public_key::VerifiedBindingClaims;

/// Status of online verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum VerificationStatus {
    /// Verification succeeded — key matched on external service.
    Verified,
    /// Verification failed — key did not match or API error.
    Failed,
    /// Verification not configured — no binding_claims or invalid attestation.
    NotConfigured,
}

/// Verification result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerificationResult {
    pub member_id: String,
    pub status: VerificationStatus,
    pub message: String,
    pub fingerprint: Option<String>,
    pub matched_key_id: Option<i64>,
    /// When verification succeeded, the verified binding claims (not serialized)
    #[serde(skip)]
    pub verified_bindings: Option<VerifiedBindingClaims>,
}

impl VerificationResult {
    /// Create a result for when verification is not configured / skipped.
    pub(crate) fn not_configured(
        member_id: &str,
        message: &str,
        fingerprint: Option<String>,
    ) -> Self {
        Self {
            member_id: member_id.to_string(),
            status: VerificationStatus::NotConfigured,
            message: message.to_string(),
            fingerprint,
            matched_key_id: None,
            verified_bindings: None,
        }
    }

    /// Create a failed verification result.
    pub(crate) fn failed(member_id: &str, message: String, fingerprint: Option<String>) -> Self {
        Self {
            member_id: member_id.to_string(),
            status: VerificationStatus::Failed,
            message,
            fingerprint,
            matched_key_id: None,
            verified_bindings: None,
        }
    }

    /// Create a successful verification result.
    pub(crate) fn verified(
        member_id: &str,
        message: String,
        fingerprint: String,
        matched_key_id: i64,
        verified_bindings: VerifiedBindingClaims,
    ) -> Self {
        Self {
            member_id: member_id.to_string(),
            status: VerificationStatus::Verified,
            message,
            fingerprint: Some(fingerprint),
            matched_key_id: Some(matched_key_id),
            verified_bindings: Some(verified_bindings),
        }
    }

    /// Returns `true` if verification succeeded.
    pub fn is_verified(&self) -> bool {
        self.status == VerificationStatus::Verified
    }
}
