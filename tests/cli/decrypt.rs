// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for decrypt command
//!
//! Tests the decrypt command with CommonOptions, member_id resolution, and file-enc format

use crate::cli::common::{
    cmd, setup_workspace, ALICE_MEMBER_ID, BOB_MEMBER_ID, CAROL_MEMBER_ID, DAVE_MEMBER_ID,
    EVE_MEMBER_ID, FRANK_MEMBER_ID, TEST_MEMBER_ID,
};
use predicates::prelude::*;
use secretenv::model::identifiers::private_key::PROTECTION_METHOD_SSHSIG_ED25519_HKDF_SHA256;
use std::fs;
use tempfile::TempDir;

/// Create a test keystore with a private key
fn create_test_keystore(temp_dir: &TempDir, member_id: &str, kid: &str) -> std::path::PathBuf {
    let keystore_root = temp_dir.path().join("keys");
    let member_dir = keystore_root.join(member_id);
    let kid_dir = member_dir.join(kid);
    fs::create_dir_all(&kid_dir).unwrap();

    // Create active file
    fs::write(member_dir.join("active"), kid).unwrap();

    // Create a dummy private.json (minimal structure for testing)
    let private_json = format!(
        r#"{{
    "format": "secretenv.private.key@3",
    "member_id": "{}",
    "kid": "{}",
    "protection": {{
        "method": "{}",
        "fpr": "SHA256:dummy",
        "salt": "AAAAAAAAAAAAAAAAAAAAAA"
    }},
    "encrypted": {{
        "aead": "xchacha20-poly1305",
        "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "ct": "dGVzdA"
    }},
    "created_at": "2026-01-16T00:00:00Z",
    "expires_at": "2027-01-16T00:00:00Z"
}}"#,
        member_id, kid, PROTECTION_METHOD_SSHSIG_ED25519_HKDF_SHA256
    );
    fs::write(kid_dir.join("private.json"), private_json).unwrap();

    keystore_root
}

/// Create a minimal test file-enc v3 file
fn create_test_encrypted_file(path: &std::path::Path) {
    let content = r#"{
  "protected": {
    "format": "secretenv.file@3",
    "sid": "550e8400-e29b-41d4-a716-446655440000",
    "wrap": [],
    "payload": {
      "protected": {
        "format": "secretenv.file.payload@3",
        "sid": "550e8400-e29b-41d4-a716-446655440000",
        "alg": {
          "aead": "xchacha20-poly1305"
        }
      },
      "encrypted": {
        "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "ct": "dGVzdA"
      }
    },
    "created_at": "2026-01-19T10:00:00Z",
    "updated_at": "2026-01-19T10:00:00Z"
  },
  "signature": {
    "alg": "eddsa-ed25519",
    "kid": "01HTEST0000000000000000000",
    "sig": "dGVzdA"
  }
}"#;
    fs::write(path, content).unwrap();
}

#[test]
fn test_decrypt_help() {
    cmd()
        .arg("decrypt")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Decrypt"));
}

#[test]
fn test_decrypt_missing_input() {
    cmd()
        .arg("decrypt")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "required arguments were not provided",
        ));
}

#[test]
fn test_decrypt_with_explicit_member_id() {
    let temp_dir = TempDir::new().unwrap();
    create_test_keystore(&temp_dir, ALICE_MEMBER_ID, "01HTEST0000000000000000000");
    let input_file = temp_dir.path().join("test.enc");
    create_test_encrypted_file(&input_file);
    let output_file = temp_dir.path().join("output.dat");

    cmd()
        .arg("decrypt")
        .arg(input_file.to_str().unwrap())
        .arg("--out")
        .arg(output_file.to_str().unwrap())
        .arg("--member-id")
        .arg(ALICE_MEMBER_ID)
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .failure(); // Will fail due to invalid test data, but should parse args correctly
}

#[test]
fn test_decrypt_with_member_id_from_env() {
    let temp_dir = TempDir::new().unwrap();
    let _keystore_root =
        create_test_keystore(&temp_dir, BOB_MEMBER_ID, "01HTEST00000000000000000002");
    let input_file = temp_dir.path().join("test.enc");
    create_test_encrypted_file(&input_file);
    let output_file = temp_dir.path().join("output.dat");

    cmd()
        .arg("decrypt")
        .arg(input_file.to_str().unwrap())
        .arg("--out")
        .arg(output_file.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .env("SECRETENV_MEMBER_ID", BOB_MEMBER_ID)
        .assert()
        .failure(); // Will fail due to invalid test data, but should parse args correctly
}

#[test]
fn test_decrypt_with_workspace_option() {
    let temp_dir = TempDir::new().unwrap();
    let workspace = temp_dir.path().join("workspace");
    fs::create_dir_all(workspace.join("members")).unwrap();
    fs::create_dir_all(workspace.join("secrets")).unwrap();

    let _keystore_root =
        create_test_keystore(&temp_dir, CAROL_MEMBER_ID, "01HTEST00000000000000000003");
    let input_file = temp_dir.path().join("test.enc");
    create_test_encrypted_file(&input_file);
    let output_file = temp_dir.path().join("output.dat");

    cmd()
        .arg("decrypt")
        .arg(input_file.to_str().unwrap())
        .arg("--out")
        .arg(output_file.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace.to_str().unwrap())
        .arg("--member-id")
        .arg(CAROL_MEMBER_ID)
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .failure(); // Will fail due to invalid test data, but should parse args correctly
}

#[test]
fn test_decrypt_accepts_out_option_parsing() {
    let temp_dir = TempDir::new().unwrap();
    let _keystore_root =
        create_test_keystore(&temp_dir, DAVE_MEMBER_ID, "01HTEST00000000000000000004");
    let input_file = temp_dir.path().join("test.enc");
    let output_file = temp_dir.path().join("output.env");
    create_test_encrypted_file(&input_file);

    cmd()
        .arg("decrypt")
        .arg(input_file.to_str().unwrap())
        .arg("--out")
        .arg(output_file.to_str().unwrap())
        .arg("--member-id")
        .arg(DAVE_MEMBER_ID)
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .failure(); // Will fail due to invalid test data, but should parse args correctly
}

#[test]
fn test_decrypt_with_kid_option() {
    let temp_dir = TempDir::new().unwrap();
    let _keystore_root =
        create_test_keystore(&temp_dir, EVE_MEMBER_ID, "01HTEST00000000000000000005");
    let input_file = temp_dir.path().join("test.enc");
    create_test_encrypted_file(&input_file);
    let output_file = temp_dir.path().join("output.dat");

    cmd()
        .arg("decrypt")
        .arg(input_file.to_str().unwrap())
        .arg("--out")
        .arg(output_file.to_str().unwrap())
        .arg("--member-id")
        .arg(EVE_MEMBER_ID)
        .arg("--kid")
        .arg("01HTEST00000000000000000005")
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .failure(); // Will fail due to invalid test data, but should parse args correctly
}

#[test]
fn test_decrypt_with_ssh_key_option() {
    let temp_dir = TempDir::new().unwrap();
    let _keystore_root =
        create_test_keystore(&temp_dir, FRANK_MEMBER_ID, "01HTEST00000000000000000006");
    let input_file = temp_dir.path().join("test.enc");
    let ssh_key_file = temp_dir.path().join("test_key");
    fs::write(&ssh_key_file, "dummy ssh key").unwrap();
    create_test_encrypted_file(&input_file);
    let output_file = temp_dir.path().join("output.dat");

    cmd()
        .arg("decrypt")
        .arg(input_file.to_str().unwrap())
        .arg("--out")
        .arg(output_file.to_str().unwrap())
        .arg("--member-id")
        .arg(FRANK_MEMBER_ID)
        .arg("-i")
        .arg(ssh_key_file.to_str().unwrap())
        .env("SECRETENV_HOME", temp_dir.path())
        .assert()
        .failure(); // Will fail due to invalid test data, but should parse args correctly
}

#[test]
fn test_decrypt_command_exists() {
    // Test that the command is named "decrypt" not "decrypt-v3"
    cmd().arg("decrypt").arg("--help").assert().success();
}

#[test]
fn test_decrypt_legacy_command_removed() {
    // Test that the old "decrypt-v3" command no longer exists
    cmd()
        .arg("decrypt-v3")
        .arg("--help")
        .assert()
        .failure()
        .stderr(predicate::str::contains("unrecognized subcommand"));
}

// ============================================================================
// Format detection tests
// ============================================================================

#[test]
fn test_decrypt_rejects_kv_enc_format() {
    // kv-enc format should be rejected with guidance to use `get` command
    let temp_dir = TempDir::new().unwrap();
    let test_dir = temp_dir.path();

    let encrypted_path = test_dir.join("test.kv");
    let content = r#":SECRETENV_KV 3
:HEAD eyJzaWQiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDAiLCJjcmVhdGVkX2F0IjoiMjAyNC0wMS0wMVQwMDowMDowMFoiLCJ1cGRhdGVkX2F0IjoiMjAyNC0wMS0wMVQwMDowMDowMFoifQ
:WRAP eyJ3cmFwIjpbeyJtX2lkIjoiYWxpY2VAZXhhbXBsZS5jb20iLCJraWQiOiIwMUhURVNUIiwiZW5jX2NrIjoiZHVtbXkifV19
DATABASE_URL eyJ2IjozLCJrIjoiREFUQUJBU0VfVVJMIiwiZSI6ImR1bW15In0
"#;
    fs::write(&encrypted_path, content).unwrap();

    create_test_keystore(&temp_dir, ALICE_MEMBER_ID, "01HTEST0000000000000000000");

    cmd()
        .arg("decrypt")
        .arg(encrypted_path.to_str().unwrap())
        .arg("--out")
        .arg(test_dir.join("out.dat").to_str().unwrap())
        .arg("--member-id")
        .arg(ALICE_MEMBER_ID)
        .env("SECRETENV_HOME", test_dir.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains("Expected file-enc format"));
}

#[test]
fn test_decrypt_detects_file_enc_format_version3() {
    // Test that decrypt detects file-enc v3 format
    let temp_dir = TempDir::new().unwrap();
    let test_dir = temp_dir.path();

    // Create a minimal file-enc v3 file
    let encrypted_path = test_dir.join("test.json");
    create_test_encrypted_file(&encrypted_path);

    create_test_keystore(&temp_dir, ALICE_MEMBER_ID, "01HTEST0000000000000000000");

    // Try to decrypt without --out - should fail with specific error
    cmd()
        .arg("decrypt")
        .arg(encrypted_path.to_str().unwrap())
        .arg("--member-id")
        .arg(ALICE_MEMBER_ID)
        .env("SECRETENV_HOME", test_dir.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains("requires --out option"));
}

#[test]
fn test_decrypt_rejects_plain_kv_format() {
    // Test that decrypt rejects plain (unencrypted) kv format
    let temp_dir = TempDir::new().unwrap();
    let test_dir = temp_dir.path();

    // Create a plain dotenv file
    let plain_path = test_dir.join("plain.env");
    let content = "DATABASE_URL=postgres://localhost\nAPI_KEY=secret123\n";
    fs::write(&plain_path, content).unwrap();

    create_test_keystore(&temp_dir, ALICE_MEMBER_ID, "01HTEST0000000000000000000");

    // Try to decrypt plain file - should fail with specific error
    cmd()
        .arg("decrypt")
        .arg(plain_path.to_str().unwrap())
        .arg("--member-id")
        .arg(ALICE_MEMBER_ID)
        .env("SECRETENV_HOME", test_dir.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains("Expected file-enc format"));
}

#[test]
fn test_decrypt_rejects_unknown_format() {
    // Test that decrypt rejects files with unknown format
    let temp_dir = TempDir::new().unwrap();
    let test_dir = temp_dir.path();

    // Create a file with unknown content
    let unknown_path = test_dir.join("unknown.txt");
    let content = "This is just some random text that doesn't match any format\n";
    fs::write(&unknown_path, content).unwrap();

    create_test_keystore(&temp_dir, ALICE_MEMBER_ID, "01HTEST0000000000000000000");

    // Try to decrypt unknown file - should fail with specific error
    cmd()
        .arg("decrypt")
        .arg(unknown_path.to_str().unwrap())
        .arg("--member-id")
        .arg(ALICE_MEMBER_ID)
        .env("SECRETENV_HOME", test_dir.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains("Expected file-enc format"));
}

// ============================================================================
// Roundtrip tests
// ============================================================================

#[test]
fn test_decrypt_file_enc_roundtrip_with_out() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // 暗号化するテストデータ
    let original_content = b"SECRET_VALUE=hello_world\n";
    let input_file = home_dir.path().join("secret.txt");
    fs::write(&input_file, original_content).unwrap();

    let encrypted_file = home_dir.path().join("secret.txt.encrypted");
    let decrypted_file = home_dir.path().join("decrypted.txt");

    // encrypt で暗号化
    cmd()
        .arg("encrypt")
        .arg(input_file.to_str().unwrap())
        .arg("--out")
        .arg(encrypted_file.to_str().unwrap())
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    assert!(encrypted_file.exists(), "Encrypted file should exist");

    // decrypt --out で復号
    cmd()
        .arg("decrypt")
        .arg(encrypted_file.to_str().unwrap())
        .arg("--out")
        .arg(decrypted_file.to_str().unwrap())
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_KEY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    // 復号されたファイルの内容が元のデータと一致することを確認
    assert!(decrypted_file.exists(), "Decrypted file should exist");
    let decrypted_content = fs::read(&decrypted_file).unwrap();
    assert_eq!(
        decrypted_content, original_content,
        "Decrypted content should match original"
    );
}

#[test]
fn test_decrypt_nonexistent_file_fails() {
    cmd()
        .arg("decrypt")
        .arg("/nonexistent/path/to/file.kvenc")
        .assert()
        .failure();
}
