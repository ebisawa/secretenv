// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-layer orchestration for member verification and promotion.

use crate::app::context::{require_workspace, CommonCommandOptions};
use crate::app::errors::serialize_to_json_value;
use crate::feature::member::add::add_member_from_file;
use crate::feature::member::promotion::{
    build_incoming_verification_report, promote_verified_members, IncomingVerificationReport,
};
use crate::feature::member::verification::{verify_incoming_members, verify_member};
use crate::io::workspace::members::{
    delete_member, load_active_member_files, load_incoming_member_files, load_member_file,
};
use crate::support::runtime::{run_blocking, run_blocking_result};
use crate::{Error, Result};
use std::path::Path;

pub use crate::io::workspace::members::MemberStatus;

#[derive(Debug)]
pub struct MemberListEntry {
    pub member_id: String,
    pub document: serde_json::Value,
}

#[derive(Debug)]
pub struct MemberListResult {
    pub active: Vec<MemberListEntry>,
    pub incoming: Vec<MemberListEntry>,
}

#[derive(Debug, Clone)]
pub struct MemberGithubAccount {
    pub id: u64,
    pub login: String,
}

#[derive(Debug)]
pub struct MemberDocumentView {
    pub member_id: String,
    pub kid: String,
    pub format: String,
    pub expires_at: String,
    pub created_at: Option<String>,
    pub kem_key_type: String,
    pub kem_curve: String,
    pub sig_key_type: String,
    pub sig_curve: String,
    pub ssh_attestation_method: String,
    pub ssh_attestation_pubkey: String,
    pub github_account: Option<MemberGithubAccount>,
    pub document: serde_json::Value,
}

#[derive(Debug)]
pub struct MemberShowResult {
    pub member: MemberDocumentView,
    pub status: MemberStatus,
}

#[derive(Debug)]
pub struct MemberRemoveResult {
    pub member_id: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MemberVerificationResult {
    pub member_id: String,
    pub verified: bool,
    pub message: String,
    pub fingerprint: Option<String>,
    pub matched_key_id: Option<i64>,
}

pub fn add_member(options: &CommonCommandOptions, filename: &Path, force: bool) -> Result<String> {
    let workspace = require_workspace(options, "member add")?;
    add_member_from_file(&workspace.root_path, filename, force)
}

pub fn list_members(options: &CommonCommandOptions) -> Result<MemberListResult> {
    let workspace = require_workspace(options, "member list")?;
    Ok(MemberListResult {
        active: load_active_member_files(&workspace.root_path)?
            .into_iter()
            .map(map_member_list_entry)
            .collect::<Result<Vec<_>>>()?,
        incoming: load_incoming_member_files(&workspace.root_path)?
            .into_iter()
            .map(map_member_list_entry)
            .collect::<Result<Vec<_>>>()?,
    })
}

pub fn show_member(options: &CommonCommandOptions, member_id: &str) -> Result<MemberShowResult> {
    let workspace = require_workspace(options, "member show")?;
    let (member, status) = load_member_file(&workspace.root_path, member_id)?;
    Ok(MemberShowResult {
        member: map_member_document_view(member)?,
        status,
    })
}

pub fn remove_member(
    options: &CommonCommandOptions,
    member_id: &str,
    force: bool,
) -> Result<MemberRemoveResult> {
    if !force {
        return Err(Error::Config {
            message: format!(
                "Removing member '{}' requires --force flag. This will affect secrets shared with this member.",
                member_id
            ),
        });
    }

    let workspace = require_workspace(options, "member remove")?;
    delete_member(&workspace.root_path, member_id)?;
    Ok(MemberRemoveResult {
        member_id: member_id.to_string(),
    })
}

/// Verify member bindings online using a blocking runtime.
pub fn verify_members(
    options: &CommonCommandOptions,
    member_ids: &[String],
    verbose: bool,
) -> Result<Vec<MemberVerificationResult>> {
    let workspace = require_workspace(options, "member verify")?;
    let results = run_blocking_result(verify_member(&workspace.root_path, member_ids, verbose))?;
    Ok(results.into_iter().map(map_verification_result).collect())
}

/// Verify incoming members online and classify the results for promotion.
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

/// Promote the accepted incoming members.
pub fn promote_members(workspace_path: &Path, member_ids: &[String]) -> Result<()> {
    promote_verified_members(workspace_path, member_ids)
}

fn map_member_list_entry(
    public_key: crate::model::public_key::PublicKey,
) -> Result<MemberListEntry> {
    Ok(MemberListEntry {
        member_id: public_key.protected.member_id.clone(),
        document: serialize_to_json_value(&public_key)?,
    })
}

fn map_member_document_view(
    public_key: crate::model::public_key::PublicKey,
) -> Result<MemberDocumentView> {
    Ok(MemberDocumentView {
        member_id: public_key.protected.member_id.clone(),
        kid: public_key.protected.kid.clone(),
        format: public_key.protected.format.clone(),
        expires_at: public_key.protected.expires_at.clone(),
        created_at: public_key.protected.created_at.clone(),
        kem_key_type: public_key.protected.identity.keys.kem.kty.clone(),
        kem_curve: public_key.protected.identity.keys.kem.crv.clone(),
        sig_key_type: public_key.protected.identity.keys.sig.kty.clone(),
        sig_curve: public_key.protected.identity.keys.sig.crv.clone(),
        ssh_attestation_method: public_key.protected.identity.attestation.method.clone(),
        ssh_attestation_pubkey: public_key.protected.identity.attestation.pub_.clone(),
        github_account: public_key
            .protected
            .binding_claims
            .as_ref()
            .and_then(|claims| claims.github_account.as_ref())
            .map(|account| MemberGithubAccount {
                id: account.id,
                login: account.login.clone(),
            }),
        document: serialize_to_json_value(&public_key)?,
    })
}

fn map_verification_result(
    result: crate::io::verify_online::VerificationResult,
) -> MemberVerificationResult {
    let verified = result.is_verified();
    MemberVerificationResult {
        member_id: result.member_id,
        verified,
        message: result.message,
        fingerprint: result.fingerprint,
        matched_key_id: result.matched_key_id,
    }
}
