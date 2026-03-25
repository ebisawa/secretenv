// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use crate::app::registration::types::{
    MemberKeySetupResult, RegistrationMode, RegistrationOutcome, RegistrationResult,
    RegistrationTarget,
};
use crate::cli::key::common::print_key_generation_binding_info;
use crate::support::kid::build_kid_display;
use crate::support::path::display_path_relative_to_cwd;
use crate::Error;

pub(super) fn print_registration_outcome(outcome: &RegistrationOutcome) -> Result<(), Error> {
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
            print_next_steps(outcome.mode, outcome.is_new_workspace);
        }
        RegistrationResult::AlreadyExists => print_existing_member_message(outcome),
        RegistrationResult::Skipped => print_skipped_message(&outcome.member_id),
    }
    Ok(())
}

pub(super) fn print_missing_key_notice(member_id: &str) {
    eprintln!(
        "No local key found for '{}'. Generating a new key...",
        member_id
    );
}

fn print_next_steps(mode: RegistrationMode, is_new_workspace: bool) {
    match mode {
        RegistrationMode::Init if is_new_workspace => {
            eprintln!("Ready! Commit .secretenv/ to your repository.");
        }
        RegistrationMode::Init | RegistrationMode::Join => {
            eprintln!("Ready! Create a PR to share your public key with the team.");
            if mode == RegistrationMode::Join {
                eprintln!(
                    "An existing member needs to run 'secretenv rewrap' to approve your membership."
                );
            }
        }
    }
}

fn print_existing_member_message(outcome: &RegistrationOutcome) {
    eprintln!();
    eprintln!("Already a member of this workspace.");
    let kid_display = build_kid_display(&outcome.key_result.kid)
        .unwrap_or_else(|_| outcome.key_result.kid.clone());
    eprintln!(
        "Current key: {} (active, expires {})",
        kid_display,
        build_expiry_date_display(&outcome.key_result.expires_at)
    );
}

fn print_skipped_message(member_id: &str) {
    eprintln!(
        "Warning: Member '{}' already exists in workspace (use --force to overwrite)",
        member_id
    );
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
    let kid_display = build_kid_display(&key_result.kid).unwrap_or_else(|_| key_result.kid.clone());
    if key_result.created {
        print_generated_key_binding_info(key_result)?;
        eprintln!();
        eprintln!("Generated key for '{}':", member_id);
        eprintln!("  Key ID:  {}", kid_display);
        eprintln!(
            "  Expires: {}",
            build_expiry_date_display(&key_result.expires_at)
        );
        return Ok(());
    }

    eprintln!("Using existing key for '{}' ({})", member_id, kid_display);
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

fn target_directory_name(target: RegistrationTarget) -> &'static str {
    target.directory_name()
}

fn build_workspace_display(path: &Path) -> String {
    format!("{}/", display_path_relative_to_cwd(path))
}

fn build_expiry_date_display(expires_at: &str) -> &str {
    expires_at.split('T').next().unwrap_or(expires_at)
}
