// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH public key retrieval utilities

use crate::io::ssh::external::traits::{SshAdd, SshKeygen};
use crate::io::ssh::protocol::constants as ssh;
use crate::io::ssh::protocol::key_descriptor::SshKeyDescriptor;
use crate::io::ssh::SshError;
use crate::support::fs::load_text;
use crate::support::path::display_path_relative_to_cwd;
use crate::{Error, Result};
use std::path::Path;
use std::process::Command;

/// Create an SSH error (convenience for replacing `utils::error::ssh_error`).
fn ssh_error(message: impl Into<String>) -> Error {
    SshError::operation_failed(message).into()
}

/// Load SSH public key from ssh-agent via the `SshAdd` trait.
///
/// Calls `ssh_add.list_keys()` and returns the first ssh-ed25519 key found.
pub fn load_ssh_public_key_from_agent_with_ssh_add(ssh_add: &dyn SshAdd) -> Result<String> {
    let output = ssh_add.list_keys()?;
    find_ed25519_key_in_output(&output)
}

/// Find the first Ed25519 key in ssh-add output lines.
pub fn find_ed25519_key_in_output(output: &str) -> Result<String> {
    output
        .lines()
        .find(|line| {
            line.split_whitespace()
                .next()
                .map(|key_type| key_type == ssh::KEY_TYPE_ED25519)
                .unwrap_or(false)
        })
        .map(|line| line.trim().to_string())
        .ok_or_else(|| {
            ssh_error(format!(
                "No {} key found in ssh-agent.\n\
Check available keys: ssh-add -L\n\
Ensure your SSH agent (e.g., 1Password) has an Ed25519 key available.",
                ssh::KEY_TYPE_ED25519
            ))
        })
}

/// Load SSH public key in OpenSSH format from a private key file using a specific ssh-keygen path.
pub fn load_ssh_public_key_from_keygen(
    ssh_keygen_path: &str,
    ssh_key_path: &Path,
) -> Result<String> {
    let output = Command::new(ssh_keygen_path)
        .args(["-y", "-f"])
        .arg(ssh_key_path)
        .output()
        .map_err(|e| ssh_error(format!("Failed to execute ssh-keygen: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ssh_error(format!("ssh-keygen failed: {stderr}")));
    }

    String::from_utf8(output.stdout)
        .map(|s| s.trim().to_string())
        .map_err(|e| ssh_error(format!("Invalid UTF-8 in ssh-keygen output: {e}")))
}

/// Read SSH public key directly from a .pub file
///
/// This function reads an OpenSSH-format public key from a .pub file
/// and validates that it's an Ed25519 key.
///
/// # Arguments
///
/// * `pub_key_path` - Path to the .pub file
///
/// # Returns
///
/// SSH public key in OpenSSH format (e.g., "ssh-ed25519 AAAA...")
///
/// # Errors
///
/// Returns error if:
/// - File cannot be read
/// - File is empty or contains invalid UTF-8
/// - Key type is not ssh-ed25519
pub fn load_ssh_public_key_file(pub_key_path: &Path) -> Result<String> {
    let content = load_text(pub_key_path).map_err(|error| {
        let message = format!(
            "Failed to read public key file {}: {}",
            display_path_relative_to_cwd(pub_key_path),
            error
        );
        ssh_error(message)
    })?;

    let pubkey = content.trim().to_string();

    // Validate key type is ssh-ed25519
    let key_type = pubkey.split_whitespace().next().ok_or_else(|| {
        ssh_error(format!(
            "Invalid public key format in {}: empty or missing key type",
            display_path_relative_to_cwd(pub_key_path)
        ))
    })?;

    if key_type != ssh::KEY_TYPE_ED25519 {
        return Err(ssh_error(format!(
            "Unsupported key type in {}: found '{}', expected '{}'\n\
            Only Ed25519 keys are supported.",
            display_path_relative_to_cwd(pub_key_path),
            key_type,
            ssh::KEY_TYPE_ED25519
        )));
    }

    Ok(pubkey)
}

/// Load SSH public key using a key descriptor (string-based, legacy)
///
/// For private keys: Derives the public key using `ssh-keygen -y -f`
/// For public keys: Reads the key directly from the .pub file
///
/// # Arguments
///
/// * `ssh_keygen_path` - Path to ssh-keygen command (used only for private keys)
/// * `key_descriptor` - SSH key descriptor (private or public key)
///
/// # Returns
///
/// SSH public key in OpenSSH format (e.g., "ssh-ed25519 AAAA...")
pub fn load_ssh_public_key_with_descriptor(
    ssh_keygen_path: &str,
    key_descriptor: &SshKeyDescriptor,
) -> Result<String> {
    match key_descriptor {
        SshKeyDescriptor::PrivateKey(private_key) => {
            // Derive from private key using ssh-keygen -y
            load_ssh_public_key_from_keygen(ssh_keygen_path, private_key.as_path())
        }
        SshKeyDescriptor::PublicKey(public_key) => {
            // Read directly from .pub file
            load_ssh_public_key_file(public_key.as_path())
        }
    }
}

/// Load SSH public key using a key descriptor via the `SshKeygen` trait.
///
/// For private keys: Derives the public key via `ssh_keygen.derive_public_key()`
/// For public keys: Reads the key directly from the .pub file
pub fn load_ssh_public_key_with_descriptor_trait(
    ssh_keygen: &dyn SshKeygen,
    key_descriptor: &SshKeyDescriptor,
) -> Result<String> {
    match key_descriptor {
        SshKeyDescriptor::PrivateKey(private_key) => {
            ssh_keygen.derive_public_key(private_key.as_path())
        }
        SshKeyDescriptor::PublicKey(public_key) => load_ssh_public_key_file(public_key.as_path()),
    }
}
