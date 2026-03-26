// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::require_workspace;
use crate::feature::member::promotion::{
    build_incoming_verification_report, IncomingVerificationReport,
};
use crate::feature::member::verification::{verify_member, verify_member_files};
use crate::io::workspace::members::list_incoming_member_paths;
use crate::support::runtime::{block_on, block_on_result};
use crate::Result;

use super::types::MemberVerificationResult;
use super::view::build_member_verification_result;

pub fn verify_members(
    options: &CommonCommandOptions,
    member_ids: &[String],
    verbose: bool,
) -> Result<Vec<MemberVerificationResult>> {
    let workspace = require_workspace(options, "member verify")?;
    let results = block_on_result(verify_member(&workspace.root_path, member_ids, verbose))?;
    Ok(results
        .into_iter()
        .map(build_member_verification_result)
        .collect())
}

pub fn verify_incoming_members_for_promotion(
    workspace_path: &Path,
    verbose: bool,
) -> Result<Option<IncomingVerificationReport>> {
    let incoming_member_files = list_incoming_member_paths(workspace_path)?;
    if incoming_member_files.is_empty() {
        return Ok(None);
    }

    let results = block_on(verify_member_files(&incoming_member_files, verbose))?;
    Ok(Some(build_incoming_verification_report(&results)))
}
