// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for keystore active key management

use secretenv::io::keystore::active::{clear_active_kid, load_active_kid, set_active_kid};
use tempfile::TempDir;

#[test]
fn test_set_and_load_active_kid() {
    let temp = TempDir::new().unwrap();
    let keystore_root = temp.path();
    let member_id = "alice@example.com";
    let test_kid = "01HY0G8N3P5X7QRSTV0WXYZ123";

    set_active_kid(member_id, test_kid, keystore_root).unwrap();
    let active = load_active_kid(member_id, keystore_root).unwrap();

    assert_eq!(active, Some(test_kid.to_string()));
}

#[test]
fn test_clear_active_kid() {
    let temp = TempDir::new().unwrap();
    let keystore_root = temp.path();
    let member_id = "alice@example.com";
    let test_kid = "01HY0G8N3P5X7QRSTV0WXYZ123";

    set_active_kid(member_id, test_kid, keystore_root).unwrap();
    clear_active_kid(member_id, keystore_root).unwrap();

    let active = load_active_kid(member_id, keystore_root).unwrap();
    assert_eq!(active, None);
}

#[test]
fn test_set_active_kid_invalid_length() {
    let temp = TempDir::new().unwrap();
    let keystore_root = temp.path();
    let member_id = "alice@example.com";
    let invalid_kid = "too-short";

    let err = set_active_kid(member_id, invalid_kid, keystore_root).unwrap_err();
    assert!(err.to_string().contains("Invalid kid format"));
}

#[test]
fn test_load_active_kid_invalid_format() {
    let temp = TempDir::new().unwrap();
    let keystore_root = temp.path();
    let member_id = "alice@example.com";
    let invalid_kid = "invalid\n";

    let active_path = keystore_root.join(member_id).join("active");
    std::fs::create_dir_all(active_path.parent().unwrap()).unwrap();
    std::fs::write(&active_path, invalid_kid).unwrap();

    let err = load_active_kid(member_id, keystore_root).unwrap_err();
    assert!(err.to_string().contains("Invalid active kid format"));
}
