// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for io::ssh::external::pubkey module
//!
//! Tests for SSH public key retrieval utilities.

use secretenv::io::ssh::external::pubkey::{
    find_ed25519_key_in_output, load_ssh_public_key_file, load_ssh_public_key_with_descriptor,
};
use secretenv::io::ssh::protocol::key_descriptor::SshKeyDescriptor;
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn test_load_ssh_public_key_file_valid_ed25519() {
    let temp_dir = TempDir::new().unwrap();
    let pub_path = temp_dir.path().join("test.pub");

    let valid_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA test@example.com";
    std::fs::write(&pub_path, format!("{}\n", valid_key)).unwrap();

    let result = load_ssh_public_key_file(&pub_path).unwrap();
    assert_eq!(result, valid_key);
}

#[test]
fn test_load_ssh_public_key_file_invalid_key_type() {
    let temp_dir = TempDir::new().unwrap();
    let pub_path = temp_dir.path().join("test.pub");

    let rsa_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ test@example.com";
    std::fs::write(&pub_path, rsa_key).unwrap();

    let result = load_ssh_public_key_file(&pub_path);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Unsupported key type"));
}

#[test]
fn test_load_ssh_public_key_file_empty() {
    let temp_dir = TempDir::new().unwrap();
    let pub_path = temp_dir.path().join("test.pub");

    std::fs::write(&pub_path, "").unwrap();

    let result = load_ssh_public_key_file(&pub_path);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("empty or missing key type"));
}

#[test]
fn test_load_ssh_public_key_file_not_found() {
    let path = PathBuf::from("/nonexistent/test.pub");
    let result = load_ssh_public_key_file(&path);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Failed to read"));
}

#[test]
fn test_load_ssh_public_key_with_descriptor_public_key() {
    let temp_dir = TempDir::new().unwrap();
    let pub_path = temp_dir.path().join("test.pub");

    let valid_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA test@example.com";
    std::fs::write(&pub_path, format!("{}\n", valid_key)).unwrap();

    let descriptor = SshKeyDescriptor::from_path(pub_path);

    // ssh-keygen path is not used when .pub file is provided
    let result = load_ssh_public_key_with_descriptor("unused-ssh-keygen", &descriptor).unwrap();
    assert_eq!(result, valid_key);
}

#[test]
fn test_find_ed25519_key_in_output() {
    let output = "ssh-rsa AAAA rsa-key\nssh-ed25519 BBBB ed25519-key\n";
    let result = find_ed25519_key_in_output(output).unwrap();
    assert!(result.starts_with("ssh-ed25519"));
}

#[test]
fn test_find_ed25519_key_in_output_not_found() {
    let output = "ssh-rsa AAAA rsa-key\n";
    let result = find_ed25519_key_in_output(output);
    assert!(result.is_err());
}
