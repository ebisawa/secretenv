// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::test_utils::setup_test_keystore_from_fixtures;
use secretenv::app::context::options::CommonCommandOptions;
use secretenv::app::registration::command::{apply_registration, build_join_registration};
use secretenv::app::registration::key_plan::resolve_registration_key_plan;
use secretenv::app::registration::types::{RegistrationKeyPlan, RegistrationMode};
use secretenv::io::keystore::storage::load_public_key;
use tempfile::TempDir;

fn build_common_options(home: &TempDir, workspace: &TempDir) -> CommonCommandOptions {
    CommonCommandOptions {
        home: Some(home.path().to_path_buf()),
        identity: None,
        quiet: false,
        verbose: false,
        workspace: Some(workspace.path().to_path_buf()),
        ssh_signer: None,
    }
}

#[test]
fn test_resolve_registration_key_plan_existing_active_key() {
    let home_dir = setup_test_keystore_from_fixtures("alice@example.com");
    let keystore_root = home_dir.path().join("keys");

    let plan = resolve_registration_key_plan("alice@example.com", &keystore_root).unwrap();

    assert!(matches!(plan, RegistrationKeyPlan::UseExisting { .. }));
    assert!(!plan.needs_new_key());
}

#[test]
fn test_resolve_registration_key_plan_missing_active_key() {
    let home_dir = TempDir::new().unwrap();
    let keystore_root = home_dir.path().join("keys");
    std::fs::create_dir_all(&keystore_root).unwrap();

    let plan = resolve_registration_key_plan("alice@example.com", &keystore_root).unwrap();

    assert_eq!(plan, RegistrationKeyPlan::GenerateNew);
    assert!(plan.needs_new_key());
}

#[test]
fn test_build_join_registration_reuses_existing_key_without_github_user() {
    let home_dir = setup_test_keystore_from_fixtures("alice@example.com");
    let workspace_dir = TempDir::new().unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/active")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/incoming")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();
    let common = build_common_options(&home_dir, &workspace_dir);
    let keystore_root = home_dir.path().join("keys");
    let key_plan = resolve_registration_key_plan("alice@example.com", &keystore_root).unwrap();

    let prepared = build_join_registration(
        &common,
        "alice@example.com".to_string(),
        None,
        key_plan,
        None,
    )
    .unwrap();

    assert_eq!(prepared.mode, RegistrationMode::Join);
    assert!(!prepared.setup.key_result.created);
    assert_eq!(prepared.setup.member_id, "alice@example.com");
}

#[test]
fn test_build_join_registration_requires_ssh_context_for_generated_key() {
    let home_dir = TempDir::new().unwrap();
    std::fs::create_dir_all(home_dir.path().join("keys")).unwrap();
    let workspace_dir = TempDir::new().unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/active")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/incoming")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();
    let common = build_common_options(&home_dir, &workspace_dir);

    let error = build_join_registration(
        &common,
        "alice@example.com".to_string(),
        None,
        RegistrationKeyPlan::GenerateNew,
        None,
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("SSH signing context is required for key generation"),
        "unexpected error: {error}"
    );
}

#[test]
fn test_apply_join_registration_rejects_duplicate_kid_in_workspace() {
    let home_dir = setup_test_keystore_from_fixtures("alice@example.com");
    let workspace_dir = TempDir::new().unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/active")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/incoming")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();
    let common = build_common_options(&home_dir, &workspace_dir);
    let keystore_root = home_dir.path().join("keys");
    let key_plan = resolve_registration_key_plan("alice@example.com", &keystore_root).unwrap();
    let kid = match &key_plan {
        RegistrationKeyPlan::UseExisting { kid, .. } => kid.clone(),
        other => panic!("expected existing key plan, got {other:?}"),
    };
    let public_key = load_public_key(&keystore_root, "alice@example.com", &kid).unwrap();
    let existing = serde_json::to_string_pretty(&public_key).unwrap();
    std::fs::write(
        workspace_dir
            .path()
            .join("members/active")
            .join("duplicate-owner.json"),
        existing,
    )
    .unwrap();

    let prepared = build_join_registration(
        &common,
        "alice@example.com".to_string(),
        None,
        key_plan,
        None,
    )
    .unwrap();

    let error = apply_registration(&prepared, false).unwrap_err();
    assert!(
        error.to_string().contains("kid"),
        "unexpected error: {error}"
    );
}
