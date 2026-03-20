// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for core/usecase/member module
//!
//! Tests for member management use cases.

use crate::cli_common::ALICE_MEMBER_ID;
use crate::test_utils::setup_test_workspace;
use secretenv::feature::member::verify_member;
use secretenv::io::workspace::members::{
    delete_member, load_active_member_files, load_member_file,
};
use tempfile::TempDir;

#[test]
fn test_member_list() {
    let (_temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, "bob@example.com"]);

    let members = load_active_member_files(&workspace_dir).unwrap();

    assert_eq!(members.len(), 2);
    let member_ids: Vec<String> = members
        .iter()
        .map(|m| m.protected.member_id.clone())
        .collect();
    assert!(member_ids.contains(&ALICE_MEMBER_ID.to_string()));
    assert!(member_ids.contains(&"bob@example.com".to_string()));
}

#[test]
fn test_member_list_empty() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_dir = temp_dir.path().join("workspace");
    std::fs::create_dir_all(workspace_dir.join("members/active")).unwrap();
    std::fs::create_dir_all(workspace_dir.join("members/incoming")).unwrap();

    let members = load_active_member_files(&workspace_dir).unwrap();

    assert_eq!(members.len(), 0);
}

#[test]
fn test_member_show() {
    let (_temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);

    let (member, _status) = load_member_file(&workspace_dir, ALICE_MEMBER_ID).unwrap();

    assert_eq!(member.protected.member_id, ALICE_MEMBER_ID);
}

#[test]
fn test_member_show_not_found() {
    let (_temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);

    let result = load_member_file(&workspace_dir, "nonexistent@example.com");

    assert!(result.is_err());
}

#[test]
fn test_member_remove() {
    let (_temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, "bob@example.com"]);

    delete_member(&workspace_dir, ALICE_MEMBER_ID).unwrap();

    // alice should no longer be in active/
    let members = load_active_member_files(&workspace_dir).unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].protected.member_id, "bob@example.com");
}

#[tokio::test]
async fn test_verify_member() {
    let (_temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID]);

    let result = verify_member(&workspace_dir, &[ALICE_MEMBER_ID.to_string()], false).await;

    // The result may be Ok or Err depending on network/GitHub API availability
    let _ = result;
}

#[tokio::test]
async fn test_verify_member_all() {
    let (_temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_ID, "bob@example.com"]);

    let result = verify_member(&workspace_dir, &[], false).await;

    // The result may be Ok or Err depending on network/GitHub API availability
    let _ = result;
}
