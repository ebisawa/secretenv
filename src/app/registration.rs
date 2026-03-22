// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-layer member registration helpers for init/join flows.

use std::path::{Path, PathBuf};

use crate::app::context::CommonCommandOptions;
use crate::app::key::{resolve_github_account, verify_generated_key_github_binding};
use crate::feature::init::generate_new_key;
use crate::io::keystore::member::find_active_key_document;
use crate::io::keystore::resolver::KeystoreResolver;
use crate::io::keystore::storage::load_public_key;
use crate::io::verify_online::VerificationStatus;
use crate::io::workspace::detection::resolve_workspace_creation_path;
use crate::io::workspace::members::{active_member_file_path, incoming_member_file_path};
use crate::io::workspace::setup;
use crate::model::ssh::SshDeterminismStatus;
use crate::Result;

pub use crate::io::workspace::members::MemberStatus;

/// Registration outcome for workspace member documents.
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

/// Result of ensuring a member key for init/join flows.
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
    pub github_verification: VerificationStatus,
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

pub fn resolve_registration_key_plan(
    member_id: &str,
    keystore_root: &Path,
) -> Result<RegistrationKeyPlan> {
    let Some(active) = find_active_key_document(member_id, keystore_root)? else {
        return Ok(RegistrationKeyPlan::GenerateNew);
    };

    Ok(RegistrationKeyPlan::UseExisting {
        kid: active.kid,
        expires_at: active.public_key.protected.expires_at,
    })
}

pub fn build_init_registration(
    common: &CommonCommandOptions,
    member_id: String,
    github_user: Option<String>,
    key_plan: RegistrationKeyPlan,
) -> Result<PreparedRegistration> {
    build_registration(
        common,
        member_id,
        github_user,
        key_plan,
        RegistrationMode::Init,
    )
}

pub fn build_join_registration(
    common: &CommonCommandOptions,
    member_id: String,
    github_user: Option<String>,
    key_plan: RegistrationKeyPlan,
) -> Result<PreparedRegistration> {
    build_registration(
        common,
        member_id,
        github_user,
        key_plan,
        RegistrationMode::Join,
    )
}

pub fn apply_registration(
    prepared: &PreparedRegistration,
    overwrite: bool,
) -> Result<RegistrationOutcome> {
    let result = register_member(
        &prepared.workspace_path,
        &prepared.setup.member_id,
        prepared.setup.kid(),
        overwrite,
        &prepared.keystore_root,
        prepared.target,
    )?;

    Ok(build_registration_outcome(prepared, result))
}

pub fn build_registration_outcome(
    prepared: &PreparedRegistration,
    result: RegistrationResult,
) -> RegistrationOutcome {
    RegistrationOutcome {
        mode: prepared.mode,
        workspace_path: prepared.workspace_path.clone(),
        target: prepared.target,
        is_new_workspace: prepared.is_new_workspace,
        member_id: prepared.setup.member_id.clone(),
        key_result: prepared.setup.key_result.clone(),
        result,
    }
}

pub fn target_directory_name(target: MemberStatus) -> &'static str {
    match target {
        MemberStatus::Active => "members/active",
        MemberStatus::Incoming => "members/incoming",
    }
}

/// Register a member document in the workspace.
pub fn register_member(
    workspace_path: &Path,
    member_id: &str,
    kid: &str,
    overwrite: bool,
    keystore_root: &Path,
    target: MemberStatus,
) -> Result<RegistrationResult> {
    let member_file = member_file_path(workspace_path, member_id, target);

    if !member_file.exists() {
        save_member_document(&member_file, member_id, kid, keystore_root)?;
        return Ok(RegistrationResult::NewMember);
    }

    if overwrite {
        save_member_document(&member_file, member_id, kid, keystore_root)?;
        return Ok(RegistrationResult::Updated);
    }

    Ok(RegistrationResult::AlreadyExists)
}

fn member_file_path(workspace_path: &Path, member_id: &str, target: MemberStatus) -> PathBuf {
    match target {
        MemberStatus::Active => active_member_file_path(workspace_path, member_id),
        MemberStatus::Incoming => incoming_member_file_path(workspace_path, member_id),
    }
}

fn save_member_document(
    member_file: &Path,
    member_id: &str,
    kid: &str,
    keystore_root: &Path,
) -> Result<()> {
    let public_key = load_public_key(keystore_root, member_id, kid)?;
    setup::save_member_document(member_file, &public_key)
}

fn build_registration(
    common: &CommonCommandOptions,
    member_id: String,
    github_user: Option<String>,
    key_plan: RegistrationKeyPlan,
    mode: RegistrationMode,
) -> Result<PreparedRegistration> {
    let setup = resolve_member_setup(common, member_id, github_user, key_plan)?;
    let workspace_path = resolve_workspace_creation_path(common.workspace.clone())?;
    let is_new_workspace = resolve_workspace_for_registration(mode, &workspace_path)?;
    let keystore_root = KeystoreResolver::resolve(common.home.as_ref())?;
    let target = registration_target(mode);
    let conflict_exists = member_file_path(&workspace_path, &setup.member_id, target).exists();
    let already_active = resolve_already_active(mode, &workspace_path, &setup.member_id);

    Ok(PreparedRegistration {
        mode,
        workspace_path,
        keystore_root,
        setup,
        target,
        is_new_workspace,
        conflict_exists,
        already_active,
    })
}

impl From<crate::feature::init::EnsureKeyExistsResult> for MemberKeySetupResult {
    fn from(r: crate::feature::init::EnsureKeyExistsResult) -> Self {
        Self {
            kid: r.kid,
            created: r.created,
            expires_at: r.expires_at,
            ssh_fingerprint: r.ssh_fingerprint,
            ssh_determinism: r.ssh_determinism,
            github_verification: VerificationStatus::NotConfigured,
        }
    }
}

fn resolve_member_setup(
    common: &CommonCommandOptions,
    member_id: String,
    github_user: Option<String>,
    key_plan: RegistrationKeyPlan,
) -> Result<MemberSetupResult> {
    match key_plan {
        RegistrationKeyPlan::UseExisting { kid, expires_at } => {
            Ok(build_existing_member_setup(member_id, kid, expires_at))
        }
        RegistrationKeyPlan::GenerateNew => {
            resolve_generated_member_setup(common, &member_id, github_user)
        }
    }
}

fn resolve_generated_member_setup(
    common: &CommonCommandOptions,
    member_id: &str,
    github_user: Option<String>,
) -> Result<MemberSetupResult> {
    let keystore_root = KeystoreResolver::resolve(common.home.as_ref())?;
    let github_account = resolve_github_account(github_user, common.verbose)?;
    let mut key_result = MemberKeySetupResult::from(generate_new_key(
        member_id,
        common.home.clone(),
        common.identity.clone(),
        common.ssh_signer,
        common.verbose,
        github_account.clone(),
        None,
    )?);

    let github_verification = verify_member_key_binding(
        &keystore_root,
        member_id,
        &key_result.kid,
        github_account.as_ref(),
        common.verbose,
    )?;
    key_result.github_verification = github_verification;

    Ok(MemberSetupResult {
        member_id: member_id.to_string(),
        key_result,
    })
}

fn verify_member_key_binding(
    keystore_root: &Path,
    member_id: &str,
    kid: &str,
    github_account: Option<&crate::model::public_key::GithubAccount>,
    verbose: bool,
) -> Result<VerificationStatus> {
    let Some(account) = github_account else {
        return Ok(VerificationStatus::NotConfigured);
    };

    let public_key = load_public_key(keystore_root, member_id, kid)?;
    verify_generated_key_github_binding(&public_key, Some(account), verbose)
}

fn build_existing_member_setup(
    member_id: String,
    kid: String,
    expires_at: String,
) -> MemberSetupResult {
    let key_result = MemberKeySetupResult {
        kid,
        created: false,
        expires_at,
        ssh_fingerprint: None,
        ssh_determinism: None,
        github_verification: VerificationStatus::NotConfigured,
    };

    MemberSetupResult {
        member_id,
        key_result,
    }
}

fn resolve_workspace_for_registration(
    mode: RegistrationMode,
    workspace_path: &Path,
) -> Result<bool> {
    match mode {
        RegistrationMode::Init => setup::ensure_workspace_structure(workspace_path),
        RegistrationMode::Join => {
            setup::validate_workspace_exists(workspace_path)?;
            Ok(false)
        }
    }
}

fn registration_target(mode: RegistrationMode) -> MemberStatus {
    match mode {
        RegistrationMode::Init => MemberStatus::Active,
        RegistrationMode::Join => MemberStatus::Incoming,
    }
}

fn resolve_already_active(mode: RegistrationMode, workspace_path: &Path, member_id: &str) -> bool {
    if mode != RegistrationMode::Join {
        return false;
    }
    active_member_file_path(workspace_path, member_id).exists()
}
