// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for member list/show/remove/add commands

use crate::cli::common::{cmd, setup_workspace, TEST_MEMBER_ID};
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

// ============================================================================
// member list
// ============================================================================

#[test]
fn test_member_list_shows_initialized_member() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    cmd()
        .arg("member")
        .arg("list")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains(TEST_MEMBER_ID));
}

#[test]
fn test_member_list_json_output() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    let assert = cmd()
        .arg("member")
        .arg("list")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--json")
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("member list --json should output valid JSON");

    assert!(
        parsed.get("active").is_some(),
        "JSON should have 'active' key"
    );
    let active = parsed["active"]
        .as_array()
        .expect("active should be an array");
    assert!(
        !active.is_empty(),
        "active array should contain the initialized member"
    );
}

#[test]
fn test_member_list_empty_workspace() {
    let workspace_dir = TempDir::new().unwrap();
    let home_dir = TempDir::new().unwrap();

    // Create workspace directory structure without running init
    // Workspace validation requires members/active/ subdirectory
    fs::create_dir_all(workspace_dir.path().join("members").join("active")).unwrap();
    fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();

    cmd()
        .arg("member")
        .arg("list")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("No members found"));
}

// ============================================================================
// member show
// ============================================================================

#[test]
fn test_member_show_displays_public_key() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    cmd()
        .arg("member")
        .arg("show")
        .arg(TEST_MEMBER_ID)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("Member:"))
        .stdout(predicate::str::contains(TEST_MEMBER_ID))
        .stdout(predicate::str::contains("Key ID:"))
        .stdout(predicate::str::contains("Format:"));
}

#[test]
fn test_member_show_unknown_member_fails() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    cmd()
        .arg("member")
        .arg("show")
        .arg("nonexistent@example.com")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .assert()
        .failure();
}

// ============================================================================
// member remove
// ============================================================================

#[test]
fn test_member_remove_removes_from_workspace() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Confirm the member exists before removal
    cmd()
        .arg("member")
        .arg("list")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains(TEST_MEMBER_ID));

    // Remove the member with --force
    cmd()
        .arg("member")
        .arg("remove")
        .arg(TEST_MEMBER_ID)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--force")
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    // Verify the member no longer appears in the active list
    let assert = cmd()
        .arg("member")
        .arg("list")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    // After removing the only member, the list should show no members or not list
    // the removed member under Active
    assert!(
        !stdout.contains(&format!("  {}", TEST_MEMBER_ID)) || stdout.contains("No members found"),
        "Removed member should not appear in active member list, got: {}",
        stdout
    );
}

#[test]
fn test_member_remove_nonexistent_fails() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    cmd()
        .arg("member")
        .arg("remove")
        .arg("nonexistent@example.com")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--force")
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .assert()
        .failure();
}

// ============================================================================
// member add
// ============================================================================

#[test]
fn test_member_add_places_in_incoming() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Copy the active member's public key JSON to a temp file
    let active_key_path = workspace_dir
        .path()
        .join("members")
        .join("active")
        .join(format!("{}.json", TEST_MEMBER_ID));
    let temp_dir = TempDir::new().unwrap();
    let temp_key_file = temp_dir.path().join("pubkey.json");
    fs::copy(&active_key_path, &temp_key_file).unwrap();

    cmd()
        .arg("member")
        .arg("add")
        .arg(&temp_key_file)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stderr(predicate::str::contains("Added member"));
}

#[test]
fn test_member_add_invalid_file_fails() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    let temp_dir = TempDir::new().unwrap();
    let temp_key_file = temp_dir.path().join("invalid.json");
    fs::write(&temp_key_file, "not json").unwrap();

    cmd()
        .arg("member")
        .arg("add")
        .arg(&temp_key_file)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .assert()
        .failure();
}

#[test]
fn test_member_add_duplicate_without_force_fails() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Copy the active member's public key JSON to a temp file
    let active_key_path = workspace_dir
        .path()
        .join("members")
        .join("active")
        .join(format!("{}.json", TEST_MEMBER_ID));
    let temp_dir = TempDir::new().unwrap();
    let temp_key_file = temp_dir.path().join("pubkey.json");
    fs::copy(&active_key_path, &temp_key_file).unwrap();

    // First add succeeds
    cmd()
        .arg("member")
        .arg("add")
        .arg(&temp_key_file)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    // Second add without --force fails
    cmd()
        .arg("member")
        .arg("add")
        .arg(&temp_key_file)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .assert()
        .failure();
}
