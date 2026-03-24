// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::require_workspace;
use crate::feature::member::promotion::{
    build_incoming_verification_report, IncomingVerificationReport,
};
use crate::feature::member::verification::{verify_incoming_members, verify_member};
use crate::io::workspace::members::load_incoming_member_files;
use crate::support::runtime::{run_blocking, run_blocking_result};
use crate::Result;

use super::types::MemberVerificationResult;
use super::view::build_member_verification_result;

pub fn verify_members(
    options: &CommonCommandOptions,
    member_ids: &[String],
    verbose: bool,
) -> Result<Vec<MemberVerificationResult>> {
    let workspace = require_workspace(options, "member verify")?;
    let results = run_blocking_result(verify_member(&workspace.root_path, member_ids, verbose))?;
    Ok(results
        .into_iter()
        .map(build_member_verification_result)
        .collect())
}

pub fn verify_incoming_members_for_promotion(
    workspace_path: &Path,
    verbose: bool,
) -> Result<Option<IncomingVerificationReport>> {
    let incoming_members = load_incoming_member_files(workspace_path)?;
    if incoming_members.is_empty() {
        return Ok(None);
    }

    let results = run_blocking(verify_incoming_members(&incoming_members, verbose))?;
    Ok(Some(build_incoming_verification_report(&results)))
}
