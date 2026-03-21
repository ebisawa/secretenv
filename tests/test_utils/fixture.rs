// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::keygen_helpers::{create_test_private_key, keygen_test};
use secretenv::io::keystore::active::set_active_kid;
use secretenv::io::keystore::storage::save_key_pair_atomic;
use secretenv::model::public_key::PublicKey;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

// ============================================================================
// Fixture constants
// ============================================================================

const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
pub const FIXTURE_ALICE_KID: &str = "01KM8R41Y7J9VXGE6VM8AHR452";
pub const FIXTURE_BOB_KID: &str = "01KM8R41YW44AVEP1NBSG2VQFC";

// ============================================================================
// Fixture loaders
// ============================================================================

/// Resolve the absolute path to a fixture file
fn fixture_path(relative: &str) -> PathBuf {
    Path::new(FIXTURES_DIR).join(relative)
}

/// Load the fixture SSH public key content
pub fn load_fixture_ssh_pubkey() -> String {
    fs::read_to_string(fixture_path("test_ed25519.pub"))
        .expect("Failed to read fixture SSH public key")
        .trim()
        .to_string()
}

/// Load a fixture PublicKey document
fn load_fixture_public_key(member_id: &str) -> PublicKey {
    let path = fixture_path(&format!("{}/public_key.json", member_id));
    let content = fs::read_to_string(&path).unwrap();
    serde_json::from_str(&content).unwrap()
}

/// Load a fixture PrivateKey document
fn load_fixture_private_key(member_id: &str) -> secretenv::model::private_key::PrivateKey {
    let path = fixture_path(&format!("{}/private_key.json", member_id));
    let content = fs::read_to_string(&path).unwrap();
    serde_json::from_str(&content).unwrap()
}

/// Copy fixture SSH keypair to TempDir
fn copy_fixture_ssh_keys(temp_dir: &TempDir) -> (PathBuf, String) {
    let ssh_dir = temp_dir.path().join(".ssh");
    fs::create_dir_all(&ssh_dir).unwrap();

    let dst_priv = ssh_dir.join("test_ed25519");
    let dst_pub = ssh_dir.join("test_ed25519.pub");
    fs::copy(fixture_path("test_ed25519"), &dst_priv).unwrap();
    fs::copy(fixture_path("test_ed25519.pub"), &dst_pub).unwrap();

    // Ensure private key has correct permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dst_priv, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let ssh_pub_content = load_fixture_ssh_pubkey();
    (dst_priv, ssh_pub_content)
}

/// Install a fixture member into keystore and workspace
fn install_fixture_member(
    member_id: &str,
    keystore_root: &Path,
    workspace_keystore: Option<&Path>,
    members_dir: &Path,
) {
    let public_key = load_fixture_public_key(member_id);
    let private_key = load_fixture_private_key(member_id);

    save_key_pair_atomic(
        keystore_root,
        &public_key.protected.member_id,
        &public_key.protected.kid,
        &private_key,
        &public_key,
    )
    .unwrap();

    if let Some(ws_keystore) = workspace_keystore {
        save_public_key(
            ws_keystore,
            &public_key.protected.member_id,
            &public_key.protected.kid,
            &public_key,
        )
        .unwrap();
    }

    let member_file = members_dir.join(format!("{}.json", member_id));
    fs::write(
        &member_file,
        serde_json::to_string_pretty(&public_key).unwrap(),
    )
    .unwrap();
}

/// Setup test keystore from pre-generated fixtures (no ssh-keygen calls)
pub fn setup_test_keystore_from_fixtures(member_id: &str) -> TempDir {
    let temp_dir = TempDir::new().unwrap();
    copy_fixture_ssh_keys(&temp_dir);

    let keystore_root = temp_dir.path().join("keys");
    fs::create_dir_all(&keystore_root).unwrap();

    let public_key = load_fixture_public_key(member_id);
    let kid = &public_key.protected.kid;

    install_fixture_member(member_id, &keystore_root, None, temp_dir.path());

    set_active_kid(member_id, kid, &keystore_root).unwrap();

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

/// Setup test workspace from pre-generated fixtures (no ssh-keygen calls)
pub fn setup_test_workspace_from_fixtures(member_ids: &[&str]) -> (TempDir, PathBuf) {
    let temp_dir = TempDir::new().unwrap();
    copy_fixture_ssh_keys(&temp_dir);

    let workspace_dir = temp_dir.path().join("workspace");
    let workspace_keystore = workspace_dir.join("keystore");
    let members_dir = workspace_dir.join("members/active");
    fs::create_dir_all(&workspace_keystore).unwrap();
    fs::create_dir_all(&members_dir).unwrap();
    fs::create_dir_all(workspace_dir.join("members/incoming")).unwrap();
    fs::create_dir_all(workspace_dir.join("secrets")).unwrap();

    let base_keystore = temp_dir.path().join("keys");
    fs::create_dir_all(&base_keystore).unwrap();

    for member_id in member_ids {
        install_fixture_member(
            member_id,
            &base_keystore,
            Some(&workspace_keystore),
            &members_dir,
        );
    }

    (temp_dir, workspace_dir)
}

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

    let output = std::process::Command::new("ssh-keygen")
        .arg("-t")
        .arg(secretenv::io::ssh::protocol::constants::KEYGEN_TYPE_ED25519)
        .arg("-f")
        .arg(&private_key_path)
        .arg("-N")
        .arg("")
        .arg("-C")
        .arg("test@example.com")
        .output()
        .expect("Failed to spawn ssh-keygen");
    assert!(
        output.status.success(),
        "ssh-keygen failed with status {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

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
