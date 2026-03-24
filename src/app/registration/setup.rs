// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::options::CommonCommandOptions;
use crate::app::key::github::{resolve_github_account, verify_preflight_github_binding};
use crate::app::verification::OnlineVerificationStatus;
use crate::feature::context::ssh::SshSigningContext;
use crate::feature::init::generate_new_key;
use crate::io::keystore::member::find_active_key_document;
use crate::Result;

use super::types::{
    MemberKeySetupResult, MemberSetupResult, PreparedRegistration, RegistrationKeyPlan,
    RegistrationMode, RegistrationOutcome, RegistrationResult,
};
use super::workspace::{register_member, resolve_registration_paths};

pub fn resolve_registration_key_plan(
    member_id: &str,
    keystore_root: &std::path::Path,
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
    ssh_ctx: Option<SshSigningContext>,
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
    ssh_ctx: Option<SshSigningContext>,
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
    ssh_ctx: Option<SshSigningContext>,
) -> Result<PreparedRegistration> {
    let setup = resolve_member_setup(common, member_id, github_user, key_plan, ssh_ctx)?;
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

fn resolve_member_setup(
    common: &CommonCommandOptions,
    member_id: String,
    github_user: Option<String>,
    key_plan: RegistrationKeyPlan,
    ssh_ctx: Option<SshSigningContext>,
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
    ssh_ctx: SshSigningContext,
) -> Result<MemberSetupResult> {
    let github_account = resolve_github_account(github_user, common.verbose)?;

    let github_verification = if let Some(account) = github_account.as_ref() {
        verify_preflight_github_binding(&ssh_ctx.public_key, account, common.verbose)?.into()
    } else {
        OnlineVerificationStatus::NotConfigured
    };

    let mut key_result = MemberKeySetupResult::from(generate_new_key(
        member_id,
        common.home.clone(),
        common.verbose,
        github_account,
        ssh_ctx,
    )?);
    key_result.github_verification = github_verification;

    Ok(MemberSetupResult {
        member_id: member_id.to_string(),
        key_result,
    })
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
        github_verification: OnlineVerificationStatus::NotConfigured,
    };

    MemberSetupResult {
        member_id,
        key_result,
    }
}

fn require_generation_ssh_context(ssh_ctx: Option<SshSigningContext>) -> Result<SshSigningContext> {
    ssh_ctx.ok_or_else(|| crate::Error::InvalidOperation {
        message: "SSH signing context is required for key generation".to_string(),
    })
}
