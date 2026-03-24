// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::options::CommonCommandOptions;
use crate::app::context::ssh::ResolvedSshSigner;
use crate::app::key::github::{resolve_github_account, verify_preflight_github_binding};
use crate::app::verification::OnlineVerificationStatus;
use crate::feature::init::generate_new_key;
use crate::model::public_key::GithubAccount;
use crate::Result;

use super::types::{
    MemberKeySetupResult, MemberSetupResult, PreparedRegistration, RegistrationKeyPlan,
    RegistrationMode, RegistrationOutcome, RegistrationResult,
};
use super::workspace::{register_member, resolve_registration_paths};

pub fn build_init_registration(
    common: &CommonCommandOptions,
    member_id: String,
    github_user: Option<String>,
    key_plan: RegistrationKeyPlan,
    ssh_ctx: Option<ResolvedSshSigner>,
) -> Result<PreparedRegistration> {
    build_registration(
        common,
        member_id,
        github_user,
        key_plan,
        RegistrationMode::Init,
        ssh_ctx,
    )
}

pub fn build_join_registration(
    common: &CommonCommandOptions,
    member_id: String,
    github_user: Option<String>,
    key_plan: RegistrationKeyPlan,
    ssh_ctx: Option<ResolvedSshSigner>,
) -> Result<PreparedRegistration> {
    build_registration(
        common,
        member_id,
        github_user,
        key_plan,
        RegistrationMode::Join,
        ssh_ctx,
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

impl From<crate::feature::init::EnsureKeyExistsResult> for MemberKeySetupResult {
    fn from(r: crate::feature::init::EnsureKeyExistsResult) -> Self {
        Self {
            kid: r.kid,
            created: r.created,
            expires_at: r.expires_at,
            ssh_fingerprint: r.ssh_fingerprint,
            ssh_determinism: r.ssh_determinism,
            github_verification: OnlineVerificationStatus::NotConfigured,
        }
    }
}

fn build_registration(
    common: &CommonCommandOptions,
    member_id: String,
    github_user: Option<String>,
    key_plan: RegistrationKeyPlan,
    mode: RegistrationMode,
    ssh_ctx: Option<ResolvedSshSigner>,
) -> Result<PreparedRegistration> {
    let setup = resolve_member_setup(common, member_id, github_user, key_plan, ssh_ctx)?;
    build_prepared_registration(common, mode, setup)
}

fn resolve_member_setup(
    common: &CommonCommandOptions,
    member_id: String,
    github_user: Option<String>,
    key_plan: RegistrationKeyPlan,
    ssh_ctx: Option<ResolvedSshSigner>,
) -> Result<MemberSetupResult> {
    match key_plan {
        RegistrationKeyPlan::UseExisting { kid, expires_at } => {
            Ok(build_existing_member_setup(member_id, kid, expires_at))
        }
        RegistrationKeyPlan::GenerateNew => resolve_generated_member_setup(
            common,
            &member_id,
            github_user,
            require_generation_ssh_context(ssh_ctx)?,
        ),
    }
}

fn resolve_generated_member_setup(
    common: &CommonCommandOptions,
    member_id: &str,
    github_user: Option<String>,
    ssh_ctx: ResolvedSshSigner,
) -> Result<MemberSetupResult> {
    let github_account = resolve_github_account(github_user, common.verbose)?;
    let github_verification =
        resolve_github_verification(&ssh_ctx.public_key, github_account.as_ref(), common.verbose)?;
    let mut key_result = generate_member_key_result(common, member_id, github_account, ssh_ctx)?;
    key_result.github_verification = github_verification;

    Ok(build_generated_member_setup(member_id, key_result))
}

fn build_existing_member_setup(
    member_id: String,
    kid: String,
    expires_at: String,
) -> MemberSetupResult {
    MemberSetupResult {
        member_id,
        key_result: build_existing_member_key_result(kid, expires_at),
    }
}

fn build_prepared_registration(
    common: &CommonCommandOptions,
    mode: RegistrationMode,
    setup: MemberSetupResult,
) -> Result<PreparedRegistration> {
    let paths = resolve_registration_paths(common, mode, &setup.member_id)?;
    Ok(PreparedRegistration {
        mode,
        workspace_path: paths.workspace_path,
        keystore_root: paths.keystore_root,
        setup,
        target: paths.target,
        is_new_workspace: paths.is_new_workspace,
        conflict_exists: paths.conflict_exists,
        already_active: paths.already_active,
    })
}

fn resolve_github_verification(
    ssh_public_key: &str,
    github_account: Option<&GithubAccount>,
    verbose: bool,
) -> Result<OnlineVerificationStatus> {
    match github_account {
        Some(account) => {
            verify_preflight_github_binding(ssh_public_key, account, verbose).map(Into::into)
        }
        None => Ok(OnlineVerificationStatus::NotConfigured),
    }
}

fn generate_member_key_result(
    common: &CommonCommandOptions,
    member_id: &str,
    github_account: Option<GithubAccount>,
    ssh_ctx: ResolvedSshSigner,
) -> Result<MemberKeySetupResult> {
    let result = generate_new_key(
        member_id,
        common.home.clone(),
        common.verbose,
        github_account,
        ssh_ctx.into_ssh_binding(),
    )?;
    Ok(MemberKeySetupResult::from(result))
}

fn build_generated_member_setup(
    member_id: &str,
    key_result: MemberKeySetupResult,
) -> MemberSetupResult {
    MemberSetupResult {
        member_id: member_id.to_string(),
        key_result,
    }
}

fn build_existing_member_key_result(kid: String, expires_at: String) -> MemberKeySetupResult {
    MemberKeySetupResult {
        kid,
        created: false,
        expires_at,
        ssh_fingerprint: None,
        ssh_determinism: None,
        github_verification: OnlineVerificationStatus::NotConfigured,
    }
}

fn require_generation_ssh_context(ssh_ctx: Option<ResolvedSshSigner>) -> Result<ResolvedSshSigner> {
    ssh_ctx.ok_or_else(|| crate::Error::InvalidOperation {
        message: "SSH signing context is required for key generation".to_string(),
    })
}
