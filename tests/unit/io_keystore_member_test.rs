// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::cli_common::ALICE_MEMBER_ID;
use crate::test_utils::setup_test_keystore;
use secretenv::io::keystore::member::{
    find_active_key_document, load_single_member_id_from_keystore,
};
use tempfile::TempDir;

#[test]
fn test_load_single_member_id_from_keystore_returns_single_member() {
    let temp_dir = TempDir::new().unwrap();
    let keystore_root = temp_dir.path().join("keys");
    std::fs::create_dir_all(keystore_root.join(ALICE_MEMBER_ID)).unwrap();

    let member_id = load_single_member_id_from_keystore(&keystore_root).unwrap();

    assert_eq!(member_id, Some(ALICE_MEMBER_ID.to_string()));
}

#[test]
fn test_find_active_key_document_returns_active_key() {
    let temp_dir = setup_test_keystore(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    let active = find_active_key_document(ALICE_MEMBER_ID, &keystore_root)
        .unwrap()
        .expect("expected active key");

    assert_eq!(active.public_key.protected.member_id, ALICE_MEMBER_ID);
    assert_eq!(active.kid, active.public_key.protected.kid);
}
