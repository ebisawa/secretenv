// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::keygen_helpers::{create_test_private_key, keygen_test};
use secretenv::io::keystore::active::set_active_kid;
use secretenv::io::keystore::storage::save_key_pair_atomic;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Save PublicKey only to keystore (test helper)
///
/// For saving both keys, use `save_key_pair_atomic` from production code instead.
pub fn save_public_key(
    keystore_root: &Path,
    member_id: &str,
    kid: &str,
    public_key: &secretenv::model::public_key::PublicKey,
) -> secretenv::Result<()> {
    let dir = keystore_root.join(member_id).join(kid);
    fs::create_dir_all(&dir).unwrap();
    secretenv::support::fs::atomic::save_json(&dir.join("public.json"), public_key)
}

/// Helper to create a temporary SSH Ed25519 keypair for testing
///
/// Returns: (private_key_path, public_key_path, public_key_content)
pub fn create_temp_ssh_keypair_in_dir(temp_dir: &TempDir) -> (PathBuf, PathBuf, String) {
    let ssh_dir = temp_dir.path().join(".ssh");
    fs::create_dir_all(&ssh_dir).unwrap();

    let private_key_path = ssh_dir.join("test_ed25519");
    let public_key_path = ssh_dir.join("test_ed25519.pub");

    std::process::Command::new("ssh-keygen")
        .arg("-t")
        .arg(secretenv::io::ssh::protocol::constants::KEYGEN_TYPE_ED25519)
        .arg("-f")
        .arg(&private_key_path)
        .arg("-N")
        .arg("")
        .arg("-C")
        .arg("test@example.com")
        .output()
        .expect("Failed to generate SSH keypair with ssh-keygen");

    let public_key_content = fs::read_to_string(&public_key_path)
        .expect("Failed to read public key")
        .trim()
        .to_string();

    (private_key_path, public_key_path, public_key_content)
}

/// Setup test workspace with members directory and public keys
pub fn setup_test_workspace(member_ids: &[&str]) -> (TempDir, PathBuf) {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub, ssh_pub_content) = create_temp_ssh_keypair_in_dir(&temp_dir);

    let workspace_dir = temp_dir.path().join("workspace");
    let workspace_keystore = workspace_dir.join("keystore");
    let members_dir = workspace_dir.join("members/active");
    let secrets_dir = workspace_dir.join("secrets");
    fs::create_dir_all(&workspace_keystore).unwrap();
    fs::create_dir_all(&members_dir).unwrap();
    fs::create_dir_all(workspace_dir.join("members/incoming")).unwrap();
    fs::create_dir_all(&secrets_dir).unwrap();

    let base_keystore = temp_dir.path().join("keys");
    fs::create_dir_all(&base_keystore).unwrap();

    for member_id in member_ids {
        let (private_key, public_key) =
            keygen_test(member_id, &ssh_priv, &ssh_pub_content).unwrap();
        let private_key_doc = create_test_private_key(
            &private_key,
            &public_key.protected.member_id,
            &public_key.protected.kid,
            &ssh_priv,
            &ssh_pub_content,
        )
        .unwrap();

        save_key_pair_atomic(
            &base_keystore,
            &public_key.protected.member_id,
            &public_key.protected.kid,
            &private_key_doc,
            &public_key,
        )
        .unwrap();

        save_public_key(
            &workspace_keystore,
            &public_key.protected.member_id,
            &public_key.protected.kid,
            &public_key,
        )
        .unwrap();

        let member_file = members_dir.join(format!("{}.json", member_id));
        fs::write(
            &member_file,
            serde_json::to_string_pretty(&public_key).unwrap(),
        )
        .unwrap();
    }

    (temp_dir, workspace_dir)
}

/// Setup test environment with keystore and test keys
pub fn setup_test_keystore(member_id: &str) -> TempDir {
    let temp_dir = TempDir::new().unwrap();
    let (ssh_priv, _ssh_pub, ssh_pub_content) = create_temp_ssh_keypair_in_dir(&temp_dir);

    let keystore_root = temp_dir.path().join("keys");
    fs::create_dir_all(&keystore_root).unwrap();

    let (private_key, public_key) = keygen_test(member_id, &ssh_priv, &ssh_pub_content).unwrap();
    let private_key_doc = create_test_private_key(
        &private_key,
        &public_key.protected.member_id,
        &public_key.protected.kid,
        &ssh_priv,
        &ssh_pub_content,
    )
    .unwrap();

    save_key_pair_atomic(
        &keystore_root,
        &public_key.protected.member_id,
        &public_key.protected.kid,
        &private_key_doc,
        &public_key,
    )
    .unwrap();

    set_active_kid(
        &public_key.protected.member_id,
        &public_key.protected.kid,
        &keystore_root,
    )
    .unwrap();

    let workspace_dir = temp_dir.path().join("workspace");
    let members_dir = workspace_dir.join("members/active");
    fs::create_dir_all(&members_dir).unwrap();
    fs::create_dir_all(workspace_dir.join("members/incoming")).unwrap();
    fs::create_dir_all(workspace_dir.join("secrets")).unwrap();
    let member_file = members_dir.join(format!("{}.json", member_id));
    fs::write(
        &member_file,
        serde_json::to_string_pretty(&public_key).unwrap(),
    )
    .unwrap();

    temp_dir
}
