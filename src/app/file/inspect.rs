// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::load_optional_workspace;
use crate::feature::inspect::verification::{
    build_online_verification_section, build_signature_verification_section,
    OnlineVerificationDisplay,
};
use crate::feature::inspect::{build_inspect_view, InspectSection as FeatureInspectSection};
use crate::feature::verify::file::verify_file_document_report;
use crate::feature::verify::kv::signature::verify_kv_document_report;
use crate::feature::verify::SignatureVerificationReport;
use crate::format::content::EncryptedContent;
use crate::io::verify_online::github::verify_github_account;
use crate::io::verify_online::VerificationResult as OnlineVerificationResult;
use crate::io::workspace::detection::WorkspaceRoot;
use crate::support::fs::load_text;
use crate::support::path::display_path_relative_to_cwd;
use crate::support::runtime::run_blocking_result;
use crate::Result;

/// Inspect command inputs resolved at the application layer.
struct InspectFileSession {
    content: EncryptedContent,
    input_display: String,
    workspace_root: Option<WorkspaceRoot>,
}

impl InspectFileSession {
    fn load(options: &CommonCommandOptions, input_path: &Path) -> Result<Self> {
        let content = EncryptedContent::detect(load_text(input_path)?)?;
        let workspace_root = load_optional_workspace(options)?;

        Ok(Self {
            content,
            input_display: display_path_relative_to_cwd(input_path),
            workspace_root,
        })
    }
}

pub(crate) struct InspectCommandOutput {
    pub input_display: String,
    pub title: String,
    pub sections: Vec<InspectSection>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct InspectSection {
    pub title: String,
    pub lines: Vec<String>,
}

impl From<FeatureInspectSection> for InspectSection {
    fn from(value: FeatureInspectSection) -> Self {
        Self {
            title: value.title,
            lines: value.lines,
        }
    }
}

pub(crate) fn inspect_file_command(
    options: &CommonCommandOptions,
    input_path: &Path,
) -> Result<InspectCommandOutput> {
    let session = InspectFileSession::load(options, input_path)?;
    let inspect_output = build_inspect_view(&session.content)?;
    let signature_report = build_signature_report(
        &session.content,
        session
            .workspace_root
            .as_ref()
            .map(|w| w.root_path.as_path()),
        options.verbose,
    )?;
    let mut sections = inspect_output.sections;
    sections.push(build_signature_verification_section(&signature_report));
    let report = &signature_report;

    if report.verified {
        if let Some(ref public_key) = report.signer_public_key {
            if let Some(ref binding_claims) = public_key.protected.binding_claims {
                if let Some(github) = binding_claims.github_account.as_ref() {
                    let result = match run_blocking_result(verify_github_account(
                        public_key,
                        options.verbose,
                        None,
                    )) {
                        Ok(r) => r,
                        Err(e) => OnlineVerificationResult::failed(
                            &public_key.protected.member_id,
                            e.user_message().to_string(),
                            None,
                        ),
                    };
                    sections.push(build_online_verification_section(
                        &OnlineVerificationDisplay::GithubResult(result),
                        Some(&github.login),
                        Some(github.id),
                    ));
                } else {
                    sections.push(build_online_verification_section(
                        &OnlineVerificationDisplay::NoSupportedBinding,
                        None,
                        None,
                    ));
                }
            }
        }
    }

    Ok(InspectCommandOutput {
        input_display: session.input_display,
        title: inspect_output.title,
        sections: sections.into_iter().map(InspectSection::from).collect(),
    })
}

fn build_signature_report(
    content: &EncryptedContent,
    workspace_path: Option<&Path>,
    debug: bool,
) -> Result<SignatureVerificationReport> {
    Ok(match content {
        EncryptedContent::FileEnc(file_content) => {
            let doc = file_content.parse()?;
            verify_file_document_report(&doc, workspace_path, debug)
        }
        EncryptedContent::KvEnc(kv_content) => {
            verify_kv_document_report(kv_content.as_str(), workspace_path, debug)
        }
    })
}
