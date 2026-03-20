// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for support/fs/atomic module
//!
//! Tests for atomic file operations.

use secretenv::support::fs::atomic::{save_bytes, save_json, save_text};
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
