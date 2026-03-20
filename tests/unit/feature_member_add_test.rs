// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for feature/member_add module

use crate::test_utils::setup_test_workspace;
use secretenv::feature::member::add::add_member_from_file;
use secretenv::io::workspace::members::load_incoming_member_files;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_add_member_valid_file() {
    // Create workspace with alice as active member
    let (_temp_dir, workspace_dir) = setup_test_workspace(&["alice@example.com"]);

    // Export alice's public key to a temp file
    let alice_key_path = workspace_dir.join("members/active/alice@example.com.json");
    let key_content = fs::read_to_string(&alice_key_path).unwrap();

    let export_dir = TempDir::new().unwrap();
    let export_file = export_dir.path().join("alice.json");
    fs::write(&export_file, &key_content).unwrap();

    // Create a fresh workspace with no members
    let temp_dir2 = TempDir::new().unwrap();
    let workspace_dir2 = temp_dir2.path().join("workspace");
    fs::create_dir_all(workspace_dir2.join("members/active")).unwrap();
    fs::create_dir_all(workspace_dir2.join("members/incoming")).unwrap();

    let member_id = add_member_from_file(&workspace_dir2, &export_file, false).unwrap();
    assert_eq!(member_id, "alice@example.com");

    let incoming = load_incoming_member_files(&workspace_dir2).unwrap();
    assert_eq!(incoming.len(), 1);
    assert_eq!(incoming[0].protected.member_id, "alice@example.com");
}

#[test]
fn test_add_member_invalid_json() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_dir = temp_dir.path().join("workspace");
    fs::create_dir_all(workspace_dir.join("members/active")).unwrap();
    fs::create_dir_all(workspace_dir.join("members/incoming")).unwrap();

    let export_dir = TempDir::new().unwrap();
    let export_file = export_dir.path().join("bad.json");
    fs::write(&export_file, "not json").unwrap();

    let result = add_member_from_file(&workspace_dir, &export_file, false);
    assert!(result.is_err());
}

#[test]
fn test_add_member_file_not_found() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_dir = temp_dir.path().join("workspace");
    fs::create_dir_all(workspace_dir.join("members/active")).unwrap();
    fs::create_dir_all(workspace_dir.join("members/incoming")).unwrap();

    let result = add_member_from_file(
        &workspace_dir,
        std::path::Path::new("/nonexistent/file.json"),
        false,
    );
    assert!(result.is_err());
}

#[test]
fn test_add_member_duplicate_without_force() {
    let (_temp_dir, workspace_dir) = setup_test_workspace(&["alice@example.com"]);

    let alice_key_path = workspace_dir.join("members/active/alice@example.com.json");
    let key_content = fs::read_to_string(&alice_key_path).unwrap();

    let export_dir = TempDir::new().unwrap();
    let export_file = export_dir.path().join("alice.json");
    fs::write(&export_file, &key_content).unwrap();

    // First add succeeds
    let temp_dir2 = TempDir::new().unwrap();
    let workspace_dir2 = temp_dir2.path().join("workspace");
    fs::create_dir_all(workspace_dir2.join("members/active")).unwrap();
    fs::create_dir_all(workspace_dir2.join("members/incoming")).unwrap();

    add_member_from_file(&workspace_dir2, &export_file, false).unwrap();

    // Second add without force fails
    let result = add_member_from_file(&workspace_dir2, &export_file, false);
    assert!(result.is_err());
}

#[test]
fn test_add_member_duplicate_with_force() {
    let (_temp_dir, workspace_dir) = setup_test_workspace(&["alice@example.com"]);

    let alice_key_path = workspace_dir.join("members/active/alice@example.com.json");
    let key_content = fs::read_to_string(&alice_key_path).unwrap();

    let export_dir = TempDir::new().unwrap();
    let export_file = export_dir.path().join("alice.json");
    fs::write(&export_file, &key_content).unwrap();

    let temp_dir2 = TempDir::new().unwrap();
    let workspace_dir2 = temp_dir2.path().join("workspace");
    fs::create_dir_all(workspace_dir2.join("members/active")).unwrap();
    fs::create_dir_all(workspace_dir2.join("members/incoming")).unwrap();

    add_member_from_file(&workspace_dir2, &export_file, false).unwrap();

    // Second add with force succeeds
    let result = add_member_from_file(&workspace_dir2, &export_file, true);
    assert!(result.is_ok());
}
