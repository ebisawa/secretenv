// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Signature verification report generation

use super::SignatureVerificationReport;
use crate::model::public_key::PublicKey;
use crate::model::verification::VerifyingKeySource;

/// Build an error verification report.
pub(crate) fn build_error_report(message: String) -> SignatureVerificationReport {
    SignatureVerificationReport {
        verified: false,
        signer_member_id: None,
        source: None,
        warnings: Vec::new(),
        message,
        signer_public_key: None,
    }
}

/// Build a success verification report.
pub(crate) fn build_success_report(
    member_id: String,
    source: VerifyingKeySource,
    warnings: Vec<String>,
    signer_public_key: PublicKey,
) -> SignatureVerificationReport {
    SignatureVerificationReport {
        verified: true,
        signer_member_id: Some(member_id),
        source: Some(source),
        warnings,
        message: "OK".to_string(),
        signer_public_key: Some(signer_public_key),
    }
}
