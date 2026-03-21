// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! One-time fixture generator for pre-generated test data
//!
//! Run with: cargo test --test unit generate_fixtures -- --ignored --nocapture
//!
//! Generates SSH keypair and member key documents (alice, bob) using real
//! ssh-keygen and production code paths.

use super::create_temp_ssh_keypair_in_dir;
use super::keygen_helpers::{create_test_private_key, keygen_test};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

const FIXTURES_DIR: &str = "tests/fixtures";

fn save_fixture(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, content).unwrap();
    eprintln!("  wrote: {}", path.display());
}

fn generate_member_fixtures(
    member_id: &str,
    ssh_priv: &Path,
    ssh_pub_content: &str,
    fixtures: &Path,
) {
    let (private_key_plaintext, public_key) =
        keygen_test(member_id, ssh_priv, ssh_pub_content).unwrap();

    let private_key_doc = create_test_private_key(
        &private_key_plaintext,
        &public_key.protected.member_id,
        &public_key.protected.kid,
        ssh_priv,
        ssh_pub_content,
    )
    .unwrap();

    let member_dir = fixtures.join(member_id);
    save_fixture(
        &member_dir.join("public_key.json"),
        &serde_json::to_string_pretty(&public_key).unwrap(),
    );
    save_fixture(
        &member_dir.join("private_key.json"),
        &serde_json::to_string_pretty(&private_key_doc).unwrap(),
    );

    eprintln!("  {} kid: {}", member_id, public_key.protected.kid);
}

#[test]
#[ignore]
fn generate_fixtures() {
    let fixtures = Path::new(FIXTURES_DIR);

    eprintln!("Generating test fixtures...");

    // Generate SSH keypair
    let temp_dir = TempDir::new().unwrap();
    let (ssh_priv, ssh_pub, ssh_pub_content) = create_temp_ssh_keypair_in_dir(&temp_dir);

    // Copy SSH keys to fixtures
    fs::copy(&ssh_priv, fixtures.join("test_ed25519")).unwrap();
    fs::copy(&ssh_pub, fixtures.join("test_ed25519.pub")).unwrap();
    eprintln!("  wrote: {}/test_ed25519", FIXTURES_DIR);
    eprintln!("  wrote: {}/test_ed25519.pub", FIXTURES_DIR);

    // Generate alice and bob with email-style member IDs
    generate_member_fixtures("alice@example.com", &ssh_priv, &ssh_pub_content, fixtures);
    generate_member_fixtures("bob@example.com", &ssh_priv, &ssh_pub_content, fixtures);

    eprintln!("Fixture generation complete.");
    eprintln!("SSH pubkey: {}", ssh_pub_content);
}
