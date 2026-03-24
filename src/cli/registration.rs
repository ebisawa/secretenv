// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::options::CommonCommandOptions;
use crate::app::registration::{
    apply_registration, build_init_registration, build_join_registration,
    build_registration_outcome, resolve_registration_key_plan, MemberKeySetupResult, MemberStatus,
    PreparedRegistration, RegistrationMode, RegistrationOutcome, RegistrationResult,
};
use crate::cli::common::options::CommonOptions;
use crate::cli::common::ssh::resolve_ssh_context;
use crate::cli::identity_prompt;
use crate::cli::key::common::print_key_generation_binding_info;
use crate::support::path::display_path_relative_to_cwd;
use crate::Error;
use std::path::Path;

pub(crate) fn execute_registration_command(
    common: CommonOptions,
    force: bool,
    github_user: Option<String>,
    member_id: Option<String>,
    mode: RegistrationMode,
) -> Result<(), Error> {
    let options = CommonCommandOptions::from(&common);
    let keystore_root = options.resolve_keystore_root()?;
    let member_id =
        identity_prompt::resolve_member_id(member_id, &keystore_root, options.home.as_deref())?;
    let key_plan = resolve_registration_key_plan(&member_id, &keystore_root)?;
    if key_plan.requires_github_user() {
        print_missing_key_notice(&member_id);
    }
    let github_user = if key_plan.requires_github_user() {
        identity_prompt::resolve_github_user(github_user, options.home.as_deref())?
    } else {
        None
    };

    eprintln!();
    let ssh_ctx = if key_plan.requires_github_user() {
        Some(resolve_ssh_context(&options)?)
    } else {
        None
    };
    let prepared = match mode {
        RegistrationMode::Init => {
            build_init_registration(&options, member_id, github_user, key_plan, ssh_ctx)?
        }
        RegistrationMode::Join => {
            build_join_registration(&options, member_id, github_user, key_plan, ssh_ctx)?
        }
    };
    let outcome = resolve_registration_outcome(&prepared, force)?;
    print_registration_outcome(&outcome)?;
    Ok(())
}

fn resolve_registration_outcome(
    prepared: &PreparedRegistration,
    force: bool,
) -> Result<RegistrationOutcome, Error> {
    if prepared.already_active {
        return Ok(build_registration_outcome(
            prepared,
            RegistrationResult::AlreadyExists,
        ));
    }

    if !prepared.conflict_exists {
        return apply_registration(prepared, force);
    }

    if force {
        return apply_registration(prepared, true);
    }

    if identity_prompt::is_prompt_available() {
        if identity_prompt::confirm_member_overwrite(&prepared.setup.member_id)? {
            return apply_registration(prepared, true);
        }
        return Ok(build_registration_outcome(
            prepared,
            RegistrationResult::AlreadyExists,
        ));
    }

    match prepared.mode {
        RegistrationMode::Init => Ok(build_registration_outcome(
            prepared,
            RegistrationResult::Skipped,
        )),
        RegistrationMode::Join => Err(Error::InvalidOperation {
            message: format!(
                "Member '{}' already exists. Use --force to overwrite.",
                prepared.setup.member_id
            ),
        }),
    }
}

fn print_registration_outcome(outcome: &RegistrationOutcome) -> Result<(), Error> {
    match outcome.result {
        RegistrationResult::NewMember | RegistrationResult::Updated => {
            print_key_info(&outcome.member_id, &outcome.key_result)?;
            if outcome.is_new_workspace {
                print_new_workspace_created(&outcome.workspace_path);
            }
            eprintln!(
                "Added '{}' to {}/",
                outcome.member_id,
                target_directory_name(outcome.target)
            );
            eprintln!();
            match outcome.mode {
                RegistrationMode::Init if outcome.is_new_workspace => {
                    eprintln!("Ready! Commit .secretenv/ to your repository.");
                }
                RegistrationMode::Init => {
                    eprintln!("Ready! Create a PR to share your public key with the team.");
                }
                RegistrationMode::Join => {
                    eprintln!("Ready! Create a PR to share your public key with the team.");
                    eprintln!(
                        "An existing member needs to run 'secretenv rewrap' to approve your membership."
                    );
                }
            }
        }
        RegistrationResult::AlreadyExists => {
            eprintln!();
            eprintln!("Already a member of this workspace.");
            eprintln!(
                "Current key: {} (active, expires {})",
                outcome.key_result.kid,
                build_expiry_date_display(&outcome.key_result.expires_at)
            );
        }
        RegistrationResult::Skipped => {
            eprintln!(
                "Warning: Member '{}' already exists in workspace (use --force to overwrite)",
                outcome.member_id
            );
        }
    }
    Ok(())
}

fn print_new_workspace_created(workspace_path: &Path) {
    eprintln!(
        "Creating workspace {}",
        build_workspace_display(workspace_path)
    );
    eprintln!("  Created members/active/");
    eprintln!("  Created members/incoming/");
    eprintln!("  Created secrets/");
}

fn print_key_info(member_id: &str, key_result: &MemberKeySetupResult) -> Result<(), Error> {
    if key_result.created {
        print_generated_key_binding_info(key_result)?;
        eprintln!();
        eprintln!("Generated key for '{}':", member_id);
        eprintln!("  Key ID:  {}", key_result.kid);
        eprintln!(
            "  Expires: {}",
            build_expiry_date_display(&key_result.expires_at)
        );
    } else {
        eprintln!(
            "Using existing key for '{}' ({})",
            member_id, key_result.kid
        );
    }
    Ok(())
}

fn print_generated_key_binding_info(key_result: &MemberKeySetupResult) -> Result<(), Error> {
    let ssh_fingerprint =
        key_result
            .ssh_fingerprint
            .as_deref()
            .ok_or_else(|| Error::InvalidOperation {
                message: "Registration output requires an SSH fingerprint for generated keys"
                    .to_string(),
            })?;
    let ssh_determinism =
        key_result
            .ssh_determinism
            .as_ref()
            .ok_or_else(|| Error::InvalidOperation {
                message: "Registration output requires SSH determinism for generated keys"
                    .to_string(),
            })?;

    print_key_generation_binding_info(
        ssh_fingerprint,
        ssh_determinism,
        key_result.github_verification,
    )
}

fn print_missing_key_notice(member_id: &str) {
    eprintln!(
        "No local key found for '{}'. Generating a new key...",
        member_id
    );
}

fn target_directory_name(target: MemberStatus) -> &'static str {
    match target {
        MemberStatus::Active => "members/active",
        MemberStatus::Incoming => "members/incoming",
    }
}

fn build_workspace_display(path: &Path) -> String {
    format!("{}/", display_path_relative_to_cwd(path))
}

fn build_expiry_date_display(expires_at: &str) -> &str {
    expires_at.split('T').next().unwrap_or(expires_at)
}
