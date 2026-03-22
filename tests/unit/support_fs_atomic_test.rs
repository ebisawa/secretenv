// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for support/fs/atomic module
//!
//! Tests for atomic file operations.

use secretenv::support::fs::atomic::{
    save_bytes, save_json, save_json_restricted, save_text, save_text_restricted,
};
use serde::{Deserialize, Serialize};
use std::fs;
use tempfile::TempDir;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct TestData {
    name: String,
    value: i32,
}

#[test]
fn test_save_json() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.json");

    let data = TestData {
        name: "test".to_string(),
        value: 42,
    };

    save_json(&file_path, &data).unwrap();

    assert!(file_path.exists());
    let content = fs::read_to_string(&file_path).unwrap();
    let loaded: TestData = serde_json::from_str(&content).unwrap();
    assert_eq!(loaded, data);
}

#[test]
fn test_save_text() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.txt");

    save_text(&file_path, "Hello, World!").unwrap();

    assert!(file_path.exists());
    let content = fs::read_to_string(&file_path).unwrap();
    assert_eq!(content, "Hello, World!");
}

#[test]
fn test_save_bytes() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.bin");

    let data = b"Binary data";
    save_bytes(&file_path, data).unwrap();

    assert!(file_path.exists());
    let content = fs::read(&file_path).unwrap();
    assert_eq!(content, data);
}

#[test]
fn test_save_json_creates_parent_dir() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("subdir").join("test.json");

    let data = TestData {
        name: "test".to_string(),
        value: 42,
    };

    save_json(&file_path, &data).unwrap();

    assert!(file_path.exists());
    assert!(file_path.parent().unwrap().exists());
}

#[cfg(unix)]
#[test]
fn test_save_text_restricted_creates_parent_with_0700() {
    use std::os::unix::fs::PermissionsExt;
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("restricted_dir").join("test.txt");
    save_text_restricted(&file_path, "content").unwrap();
    assert!(file_path.exists());
    let parent_mode = fs::metadata(file_path.parent().unwrap())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(parent_mode, 0o700);
}

#[cfg(unix)]
#[test]
fn test_save_text_restricted_creates_file_with_0600() {
    use std::os::unix::fs::PermissionsExt;
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("restricted_dir").join("test.txt");
    save_text_restricted(&file_path, "content").unwrap();
    let file_mode = fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(file_mode, 0o600);
}

#[cfg(unix)]
#[test]
fn test_save_json_restricted_creates_parent_with_0700() {
    use std::os::unix::fs::PermissionsExt;
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("restricted_dir").join("test.json");
    let data = TestData {
        name: "test".to_string(),
        value: 42,
    };
    save_json_restricted(&file_path, &data).unwrap();
    assert!(file_path.exists());
    let parent_mode = fs::metadata(file_path.parent().unwrap())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(parent_mode, 0o700);
}

#[cfg(unix)]
#[test]
fn test_save_json_restricted_creates_file_with_0600() {
    use std::os::unix::fs::PermissionsExt;
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("restricted_dir").join("test.json");
    let data = TestData {
        name: "test".to_string(),
        value: 42,
    };
    save_json_restricted(&file_path, &data).unwrap();
    let file_mode = fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(file_mode, 0o600);
}
