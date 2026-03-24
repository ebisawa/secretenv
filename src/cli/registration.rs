// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

mod output;

use crate::app::context::options::CommonCommandOptions;
use crate::app::registration::command::{
    apply_registration, build_init_registration, build_join_registration,
    build_registration_outcome,
};
use crate::app::registration::key_plan::resolve_registration_key_plan;
use crate::app::registration::types::{
    PreparedRegistration, RegistrationMode, RegistrationOutcome, RegistrationResult,
};
use crate::cli::common::options::CommonOptions;
use crate::cli::common::ssh::resolve_ssh_context;
use crate::cli::identity_prompt;
use crate::Error;
use output::{print_missing_key_notice, print_registration_outcome};

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
    resolve_conflicting_registration(prepared, force)
}

fn resolve_conflicting_registration(
    prepared: &PreparedRegistration,
    force: bool,
) -> Result<RegistrationOutcome, Error> {
    if force {
        return overwrite_registration(prepared);
    }
    if identity_prompt::is_prompt_available() {
        return resolve_interactive_registration(prepared);
    }
    resolve_non_interactive_registration(prepared)
}

fn resolve_interactive_registration(
    prepared: &PreparedRegistration,
) -> Result<RegistrationOutcome, Error> {
    if identity_prompt::confirm_member_overwrite(&prepared.setup.member_id)? {
        return overwrite_registration(prepared);
    }
    Ok(build_registration_outcome(
        prepared,
        RegistrationResult::AlreadyExists,
    ))
}

fn resolve_non_interactive_registration(
    prepared: &PreparedRegistration,
) -> Result<RegistrationOutcome, Error> {
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

fn overwrite_registration(prepared: &PreparedRegistration) -> Result<RegistrationOutcome, Error> {
    apply_registration(prepared, true)
}
