// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `key export` command

use crate::cli::common::{cmd, create_temp_ssh_keypair, TEST_MEMBER_ID};
use crate::cli::key::find_kid_in_member_dir;
use secretenv::model::identifiers::format;
use secretenv::model::public_key::PublicKey;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_key_export_explicit_kid() {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = create_temp_ssh_keypair();

    let member_id = TEST_MEMBER_ID;

    // Generate a key
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-id")
        .arg(member_id)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    // Get the kid
    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(member_id);
    let kid = find_kid_in_member_dir(&member_dir);

    // Export to a temp file
    let export_file = temp_dir.path().join("exported.json");

    cmd()
        .arg("key")
        .arg("export")
        .arg(&kid)
        .arg("--member-id")
        .arg(member_id)
        .arg("--out")
        .arg(export_file.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    // Verify exported file exists and is valid JSON
    assert!(export_file.exists(), "Exported file should exist");

    let exported_json = fs::read_to_string(&export_file).expect("Should read exported file");
    let exported: PublicKey =
        serde_json::from_str(&exported_json).expect("Exported file should be valid PublicKey JSON");

    // Verify fields
    assert_eq!(exported.protected.kid, kid, "Exported kid should match");
    assert_eq!(
        exported.protected.member_id, member_id,
        "Exported member_id should match"
    );
    assert_eq!(
        exported.protected.format,
        format::PUBLIC_KEY_V3,
        "Exported format should be v3"
    );

    // Keep temp directories alive
    drop(ssh_temp);
}

#[test]
fn test_key_export_active() {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = create_temp_ssh_keypair();

    let member_id = TEST_MEMBER_ID;

    // Generate a key
    cmd()
        .arg("key")
        .arg("new")
        .arg("--member-id")
        .arg(member_id)
        .arg("-i")
        .arg(ssh_priv.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    // Export active key to a temp file
    let export_file = temp_dir.path().join("exported.json");

    cmd()
        .arg("key")
        .arg("export")
        .arg("--member-id")
        .arg(member_id)
        .arg("--out")
        .arg(export_file.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .success();

    // Verify exported file exists and is valid
    assert!(export_file.exists(), "Exported file should exist");

    let exported_json = fs::read_to_string(&export_file).expect("Should read exported file");
    let exported: PublicKey =
        serde_json::from_str(&exported_json).expect("Exported file should be valid PublicKey JSON");

    assert_eq!(
        exported.protected.format,
        format::PUBLIC_KEY_V3,
        "Exported format should be v3"
    );

    // Keep temp directories alive
    drop(ssh_temp);
}
