// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Signature verification display for inspection.

use crate::feature::verify::SignatureVerificationReport;
use crate::io::verify_online::{VerificationResult, VerificationStatus};
use crate::model::verification::VerifyingKeySource;

use super::formatter::push_line;

/// Online verification display variants
pub enum OnlineVerificationDisplay {
    /// GitHub verification result available
    GithubResult(VerificationResult),
    /// binding_claims exist but no supported binding is configured
    NoSupportedBinding,
}

/// Build signature verification report display string.
pub(crate) fn build_signature_verification_report_display(
    report: &SignatureVerificationReport,
    out: &mut String,
) {
    push_line(out, "");
    push_line(out, "Signature Verification:");
    push_line(
        out,
        format!(
            "  Status:   {}",
            if report.verified { "OK" } else { "FAILED" }
        ),
    );

    if report.verified {
        if let Some(ref member_id) = report.signer_member_id {
            push_line(out, format!("  Signer:   {} (verified)", member_id));
        }
        if let Some(ref source) = report.source {
            let source_str = match source {
                VerifyingKeySource::SignerPubEmbedded => "signer_pub embedded",
                VerifyingKeySource::ActiveMemberByKid { kid } => {
                    &format!("workspace active (kid: {})", kid)
                }
            };
            push_line(out, format!("  Source:   {}", source_str));
        }
        for warning in &report.warnings {
            push_line(out, format!("  Warning:  {}", warning));
        }
    } else {
        push_line(out, format!("  Reason:   {}", report.message));
    }
}

/// Build online verification display string.
pub fn build_online_verification_display(
    display: &OnlineVerificationDisplay,
    github_login: Option<&str>,
    github_id: Option<u64>,
    out: &mut String,
) {
    match display {
        OnlineVerificationDisplay::GithubResult(result) => {
            push_line(out, "");
            push_line(out, "Online Verification (GitHub):");
            match result.status {
                VerificationStatus::Verified => {
                    push_line(out, "  Status:   OK");
                    if let (Some(login), Some(id)) = (github_login, github_id) {
                        push_line(out, format!("  Account:  {} (id: {})", login, id));
                    }
                    if let Some(ref fp) = result.fingerprint {
                        push_line(out, format!("  SSH key fingerprint: {}", fp));
                    }
                    if let Some(key_id) = result.matched_key_id {
                        push_line(out, format!("  Matched key ID: {}", key_id));
                    }
                }
                VerificationStatus::Failed | VerificationStatus::NotConfigured => {
                    push_line(out, "  Status:   FAILED");
                    push_line(out, format!("  Reason:   {}", result.message));
                }
            }
        }
        OnlineVerificationDisplay::NoSupportedBinding => {
            push_line(out, "");
            push_line(out, "Online Verification:");
            push_line(
                out,
                "  Status:   Not available (no supported binding configured)",
            );
        }
    }
}
