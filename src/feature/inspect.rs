// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Inspect feature - format metadata display.

pub(crate) mod file;
pub(crate) mod kv;

mod formatter;
pub mod verification;

use crate::feature::verify::file::verify_file_document_report;
use crate::feature::verify::kv::verify_kv_document_report;
use crate::feature::verify::SignatureVerificationReport;
use crate::format::content::EncryptedContent;
use crate::Result;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct InspectSection {
    pub title: String,
    pub lines: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct InspectView {
    pub title: String,
    pub sections: Vec<InspectSection>,
}

/// Output of inspect with verification.
#[derive(Debug, Clone)]
pub struct InspectOutput {
    pub title: String,
    pub sections: Vec<InspectSection>,
    pub signature_report: SignatureVerificationReport,
}

pub(crate) fn build_section(title: impl Into<String>, lines: Vec<String>) -> InspectSection {
    InspectSection {
        title: title.into(),
        lines,
    }
}

/// Inspect and return structured sections with signature verification.
pub fn inspect_document_with_verification(
    content: &EncryptedContent,
    _source_label: &str,
    workspace_path: Option<&Path>,
    debug: bool,
) -> Result<InspectOutput> {
    let (view, report) = match content {
        EncryptedContent::FileEnc(file_content) => {
            let doc = file_content.parse()?;
            let view = file::inspect_file_enc(&doc);
            let report = verify_file_document_report(&doc, workspace_path, debug);
            (view, report)
        }
        EncryptedContent::KvEnc(kv_content) => {
            let doc = kv_content.parse()?;
            let view = kv::inspect_kv_enc(&doc)?;
            let report = verify_kv_document_report(kv_content.as_str(), workspace_path, debug);
            (view, report)
        }
    };
    Ok(InspectOutput {
        title: view.title,
        sections: view.sections,
        signature_report: report,
    })
}
