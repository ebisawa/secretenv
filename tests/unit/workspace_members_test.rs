// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for workspace members

use secretenv::io::workspace::members::list_active_member_ids;
use tempfile::TempDir;

#[test]
fn test_list_member_ids() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_root = temp_dir.path();
    std::fs::create_dir_all(workspace_root.join("members/active")).unwrap();
    std::fs::create_dir_all(workspace_root.join("members/incoming")).unwrap();
    let active_dir = workspace_root.join("members/active");

    // Create member files
    std::fs::write(active_dir.join("alice@example.com.json"), "{}").unwrap();
    std::fs::write(active_dir.join("bob@example.com.json"), "{}").unwrap();
    std::fs::write(active_dir.join("charlie@example.com.json"), "{}").unwrap();

    let result = list_active_member_ids(workspace_root).unwrap();
    assert_eq!(
        result,
        vec![
            "alice@example.com".to_string(),
            "bob@example.com".to_string(),
            "charlie@example.com".to_string()
        ]
    );
}

#[test]
fn test_list_member_ids_empty() {
    let temp_dir = TempDir::new().unwrap();
    let workspace_root = temp_dir.path();
    std::fs::create_dir_all(workspace_root.join("members/active")).unwrap();
    std::fs::create_dir_all(workspace_root.join("members/incoming")).unwrap();

    let result = list_active_member_ids(workspace_root);
    assert!(result.is_err());
}
