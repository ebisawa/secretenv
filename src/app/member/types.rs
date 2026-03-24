// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::io::workspace::members::MemberStatus;

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
