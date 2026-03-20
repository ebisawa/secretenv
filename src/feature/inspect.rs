// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Inspect feature - format metadata display.

pub mod file;
pub mod kv;

mod formatter;
pub mod verification;

use crate::feature::verify::file::verify_file_document_report;
use crate::feature::verify::kv::verify_kv_document_report;
use crate::feature::verify::SignatureVerificationReport;
use crate::format::content::EncryptedContent;
use crate::Result;
use std::path::Path;

/// Output of inspect with verification
pub struct InspectOutput {
    pub formatted: String,
    pub signature_report: SignatureVerificationReport,
}

/// Inspect and return formatted output with signature verification.
pub fn inspect_document_with_verification(
    content: &EncryptedContent,
    _source_label: &str,
    workspace_path: Option<&Path>,
    debug: bool,
) -> Result<InspectOutput> {
    let mut output = String::new();
    let report = match content {
        EncryptedContent::FileEnc(file_content) => {
            let doc = file_content.parse()?;
            file::inspect_file_enc(&doc, &mut output);
            let report = verify_file_document_report(&doc, workspace_path, debug);
            verification::build_signature_verification_report_display(&report, &mut output);
            report
        }
        EncryptedContent::KvEnc(kv_content) => {
            let doc = kv_content.parse()?;
            kv::inspect_kv_enc(&doc, &mut output)?;
            let report = verify_kv_document_report(kv_content.as_str(), workspace_path, debug);
            verification::build_signature_verification_report_display(&report, &mut output);
            report
        }
    };
    Ok(InspectOutput {
        formatted: output,
        signature_report: report,
    })
}
