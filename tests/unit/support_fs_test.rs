// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for support/fs module.

use secretenv::support::fs::{
    check_permission, ensure_dir, ensure_dir_restricted, list_dir, load_text,
};
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

#[cfg(unix)]
#[test]
fn test_ensure_dir_restricted_sets_mode_0700() {
    use std::os::unix::fs::PermissionsExt;
    let temp_dir = TempDir::new().unwrap();
    let dir_path = temp_dir.path().join("a/b/c");
    ensure_dir_restricted(&dir_path).unwrap();
    assert!(dir_path.exists());
    let mode = fs::metadata(&dir_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
}

#[cfg(unix)]
#[test]
fn test_ensure_dir_restricted_fixes_existing_dir_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let temp_dir = TempDir::new().unwrap();
    let dir_path = temp_dir.path().join("existing");
    fs::create_dir(&dir_path).unwrap();
    fs::set_permissions(&dir_path, fs::Permissions::from_mode(0o755)).unwrap();
    ensure_dir_restricted(&dir_path).unwrap();
    let mode = fs::metadata(&dir_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
}

#[cfg(unix)]
#[test]
fn test_check_permission_detects_insecure_file() {
    use std::os::unix::fs::PermissionsExt;
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.txt");
    fs::write(&file_path, "secret").unwrap();
    fs::set_permissions(&file_path, fs::Permissions::from_mode(0o644)).unwrap();
    let result = check_permission(&file_path);
    assert!(result.is_some());
    let msg = result.unwrap();
    assert!(msg.contains("0644"));
    assert!(msg.contains("expected 0600"));
}

#[cfg(unix)]
#[test]
fn test_check_permission_accepts_secure_file() {
    use std::os::unix::fs::PermissionsExt;
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.txt");
    fs::write(&file_path, "secret").unwrap();
    fs::set_permissions(&file_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(check_permission(&file_path).is_none());
}

#[cfg(unix)]
#[test]
fn test_check_permission_detects_insecure_directory() {
    use std::os::unix::fs::PermissionsExt;
    let temp_dir = TempDir::new().unwrap();
    let dir_path = temp_dir.path().join("testdir");
    fs::create_dir(&dir_path).unwrap();
    fs::set_permissions(&dir_path, fs::Permissions::from_mode(0o755)).unwrap();
    let result = check_permission(&dir_path);
    assert!(result.is_some());
    assert!(result.unwrap().contains("expected 0700"));
}

#[cfg(unix)]
#[test]
fn test_check_permission_nonexistent_path_returns_warning() {
    let temp_dir = TempDir::new().unwrap();
    let missing = temp_dir.path().join("nonexistent");
    let result = check_permission(&missing);
    assert!(result.is_some());
    assert!(result.unwrap().contains("Cannot check permissions"));
}
