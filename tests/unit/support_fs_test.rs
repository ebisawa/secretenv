// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for support/fs module.

use secretenv::support::fs::{ensure_dir, list_dir, load_text};
use std::fs;
use tempfile::TempDir;

#[test]
fn test_load_text() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.txt");
    fs::write(&file_path, "hello").unwrap();

    let content = load_text(&file_path).unwrap();

    assert_eq!(content, "hello");
}

#[test]
fn test_load_text_missing_file_error() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("missing.txt");

    let error = load_text(&file_path).unwrap_err();

    let message = error.to_string();
    assert!(message.contains("Failed to read file"));
    assert!(message.contains("missing.txt"));
}

#[test]
fn test_list_dir() {
    let temp_dir = TempDir::new().unwrap();
    fs::write(temp_dir.path().join("a.txt"), "a").unwrap();
    fs::create_dir(temp_dir.path().join("subdir")).unwrap();

    let entries = list_dir(temp_dir.path()).unwrap();
    let names: Vec<String> = entries
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();

    assert!(names.contains(&"a.txt".to_string()));
    assert!(names.contains(&"subdir".to_string()));
}

#[test]
fn test_list_dir_missing_directory_error() {
    let temp_dir = TempDir::new().unwrap();
    let dir_path = temp_dir.path().join("missing");

    let error = list_dir(&dir_path).unwrap_err();

    let message = error.to_string();
    assert!(message.contains("Failed to read directory"));
    assert!(message.contains("missing"));
}

#[test]
fn test_ensure_dir() {
    let temp_dir = TempDir::new().unwrap();
    let dir_path = temp_dir.path().join("a/b/c");

    ensure_dir(&dir_path).unwrap();

    assert!(dir_path.exists());
    assert!(dir_path.is_dir());
}
