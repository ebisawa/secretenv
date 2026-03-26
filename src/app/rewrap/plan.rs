// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::require_workspace;
use crate::app::member::verification::verify_incoming_members_for_promotion;
use crate::feature::member::promotion::IncomingVerificationReport as FeatureIncomingVerificationReport;
use crate::format::kv::KV_ENC_EXTENSION;
use crate::support::fs::list_dir;
use crate::{Error, Result};
use std::path::{Path, PathBuf};

use super::types::{
    IncomingGithubAccount, IncomingVerificationCategory, IncomingVerificationItem,
    IncomingVerificationReport, RewrapBatchPlan,
};

/// Resolve workspace inputs, incoming promotion candidates, and target files.
pub fn build_rewrap_batch_plan(options: &CommonCommandOptions) -> Result<RewrapBatchPlan> {
    let workspace = require_workspace(options, "rewrap")?;
    let incoming_report =
        verify_incoming_members_for_promotion(&workspace.root_path, options.verbose)?;
    let file_paths = find_encrypted_files_in_workspace(&workspace.root_path)?;
    if file_paths.is_empty() {
        return Err(Error::NotFound {
            message: "No encrypted files found in workspace secrets/".to_string(),
        });
    }

    Ok(RewrapBatchPlan {
        workspace_root: workspace.root_path,
        incoming_report: incoming_report.map(map_incoming_report),
        file_paths,
    })
}

fn find_encrypted_files_in_workspace(workspace_root: &Path) -> Result<Vec<PathBuf>> {
    let secrets_dir = workspace_root.join("secrets");
    let entries = list_dir(&secrets_dir)
        .map_err(|e| Error::io(format!("Failed to read secrets directory: {}", e)))?;

    let mut files: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| is_encrypted_file(path))
        .collect();
    files.sort();
    Ok(files)
}

fn is_encrypted_file(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.ends_with(KV_ENC_EXTENSION) || name.ends_with(".json") || name.ends_with(".encrypted")
}

fn map_incoming_report(report: FeatureIncomingVerificationReport) -> IncomingVerificationReport {
    IncomingVerificationReport {
        verified: report
            .verified
            .into_iter()
            .map(|result| map_incoming_item(result, IncomingVerificationCategory::Verified))
            .collect(),
        failed: report
            .failed
            .into_iter()
            .map(|result| map_incoming_item(result, IncomingVerificationCategory::Failed))
            .collect(),
        not_configured: report
            .not_configured
            .into_iter()
            .map(|result| map_incoming_item(result, IncomingVerificationCategory::NotConfigured))
            .collect(),
    }
}

fn map_incoming_item(
    result: crate::io::verify_online::VerificationResult,
    category: IncomingVerificationCategory,
) -> IncomingVerificationItem {
    let github_account = result
        .verified_bindings
        .as_ref()
        .and_then(|bindings| bindings.claims.github_account.as_ref())
        .map(|account| IncomingGithubAccount {
            id: account.id,
            login: account.login.clone(),
        });

    IncomingVerificationItem {
        member_id: result.member_id,
        category,
        message: result.message,
        fingerprint: result.fingerprint,
        github_account,
    }
}
