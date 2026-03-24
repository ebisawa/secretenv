// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use crate::app::verification::OnlineVerificationStatus;
use crate::io::workspace::members::MemberStatus;
use crate::model::ssh::SshDeterminismStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationResult {
    NewMember,
    Updated,
    AlreadyExists,
    Skipped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationMode {
    Init,
    Join,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationKeyPlan {
    UseExisting { kid: String, expires_at: String },
    GenerateNew,
}

impl RegistrationKeyPlan {
    pub fn requires_github_user(&self) -> bool {
        matches!(self, Self::GenerateNew)
    }
}

#[derive(Debug, Clone)]
pub struct MemberSetupResult {
    pub member_id: String,
    pub key_result: MemberKeySetupResult,
}

impl MemberSetupResult {
    pub fn kid(&self) -> &str {
        &self.key_result.kid
    }
}

#[derive(Debug, Clone)]
pub struct MemberKeySetupResult {
    pub kid: String,
    pub created: bool,
    pub expires_at: String,
    pub ssh_fingerprint: Option<String>,
    pub ssh_determinism: Option<SshDeterminismStatus>,
    pub github_verification: OnlineVerificationStatus,
}

#[derive(Debug, Clone)]
pub struct PreparedRegistration {
    pub mode: RegistrationMode,
    pub workspace_path: PathBuf,
    pub keystore_root: PathBuf,
    pub setup: MemberSetupResult,
    pub target: MemberStatus,
    pub is_new_workspace: bool,
    pub conflict_exists: bool,
    pub already_active: bool,
}

#[derive(Debug, Clone)]
pub struct RegistrationOutcome {
    pub mode: RegistrationMode,
    pub workspace_path: PathBuf,
    pub target: MemberStatus,
    pub is_new_workspace: bool,
    pub member_id: String,
    pub key_result: MemberKeySetupResult,
    pub result: RegistrationResult,
}
