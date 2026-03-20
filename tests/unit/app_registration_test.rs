// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::test_utils::setup_test_keystore;
use secretenv::app::context::CommonCommandOptions;
use secretenv::app::registration::{
    build_join_registration, resolve_registration_key_plan, RegistrationKeyPlan, RegistrationMode,
};
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
    let home_dir = setup_test_keystore("alice@example.com");
    let keystore_root = home_dir.path().join("keys");

    let plan = resolve_registration_key_plan("alice@example.com", &keystore_root).unwrap();

    assert!(matches!(plan, RegistrationKeyPlan::UseExisting { .. }));
    assert!(!plan.requires_github_user());
}

#[test]
fn test_resolve_registration_key_plan_missing_active_key() {
    let home_dir = TempDir::new().unwrap();
    let keystore_root = home_dir.path().join("keys");
    std::fs::create_dir_all(&keystore_root).unwrap();

    let plan = resolve_registration_key_plan("alice@example.com", &keystore_root).unwrap();

    assert_eq!(plan, RegistrationKeyPlan::GenerateNew);
    assert!(plan.requires_github_user());
}

#[test]
fn test_build_join_registration_reuses_existing_key_without_github_user() {
    let home_dir = setup_test_keystore("alice@example.com");
    let workspace_dir = TempDir::new().unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/active")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("members/incoming")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();
    let common = build_common_options(&home_dir, &workspace_dir);
    let keystore_root = home_dir.path().join("keys");
    let key_plan = resolve_registration_key_plan("alice@example.com", &keystore_root).unwrap();

    let prepared =
        build_join_registration(&common, "alice@example.com".to_string(), None, key_plan).unwrap();

    assert_eq!(prepared.mode, RegistrationMode::Join);
    assert!(!prepared.setup.key_result.created);
    assert_eq!(prepared.setup.member_id, "alice@example.com");
}
