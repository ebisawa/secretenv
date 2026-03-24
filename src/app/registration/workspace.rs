// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use crate::app::context::options::CommonCommandOptions;
use crate::io::keystore::resolver::KeystoreResolver;
use crate::io::keystore::storage::load_public_key;
use crate::io::workspace::detection::resolve_workspace_creation_path;
use crate::io::workspace::members::{
    active_member_file_path, ensure_member_document_kid_is_unique, incoming_member_file_path,
    MemberStatus,
};
use crate::io::workspace::setup;
use crate::Result;

use super::types::{RegistrationMode, RegistrationResult, RegistrationTarget};

pub(crate) struct RegistrationPaths {
    pub workspace_path: PathBuf,
    pub keystore_root: PathBuf,
    pub target: RegistrationTarget,
    pub is_new_workspace: bool,
    pub conflict_exists: bool,
    pub already_active: bool,
}

pub(crate) fn register_member(
    workspace_path: &Path,
    member_id: &str,
    kid: &str,
    overwrite: bool,
    keystore_root: &Path,
    target: RegistrationTarget,
) -> Result<RegistrationResult> {
    let member_file = member_file_path(workspace_path, member_id, target);

    if !member_file.exists() {
        save_member_document(
            &member_file,
            workspace_path,
            member_id,
            kid,
            false,
            keystore_root,
            target,
        )?;
        return Ok(RegistrationResult::NewMember);
    }

    if overwrite {
        save_member_document(
            &member_file,
            workspace_path,
            member_id,
            kid,
            true,
            keystore_root,
            target,
        )?;
        return Ok(RegistrationResult::Updated);
    }

    Ok(RegistrationResult::AlreadyExists)
}

pub(crate) fn resolve_registration_paths(
    common: &CommonCommandOptions,
    mode: RegistrationMode,
    member_id: &str,
) -> Result<RegistrationPaths> {
    let workspace_path = resolve_workspace_creation_path(common.workspace.clone())?;
    let is_new_workspace = resolve_workspace_for_registration(mode, &workspace_path)?;
    let keystore_root = KeystoreResolver::resolve(common.home.as_ref())?;
    let target = registration_target(mode);
    let conflict_exists =
        member_file_path(&workspace_path, member_id, RegistrationTarget::from(target)).exists();
    let already_active = resolve_already_active(mode, &workspace_path, member_id);
    Ok(RegistrationPaths {
        workspace_path,
        keystore_root,
        target: RegistrationTarget::from(target),
        is_new_workspace,
        conflict_exists,
        already_active,
    })
}

fn member_file_path(workspace_path: &Path, member_id: &str, target: RegistrationTarget) -> PathBuf {
    match target {
        RegistrationTarget::Active => active_member_file_path(workspace_path, member_id),
        RegistrationTarget::Incoming => incoming_member_file_path(workspace_path, member_id),
    }
}

fn save_member_document(
    member_file: &Path,
    workspace_path: &Path,
    member_id: &str,
    kid: &str,
    overwrite: bool,
    keystore_root: &Path,
    target: RegistrationTarget,
) -> Result<()> {
    let public_key = load_public_key(keystore_root, member_id, kid)?;
    let status = match target {
        RegistrationTarget::Active => MemberStatus::Active,
        RegistrationTarget::Incoming => MemberStatus::Incoming,
    };
    ensure_member_document_kid_is_unique(
        workspace_path,
        status,
        member_id,
        &public_key.protected.kid,
        overwrite && member_file.exists(),
    )?;
    setup::save_member_document(member_file, &public_key)
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
