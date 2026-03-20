// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Default implementation of the `SshAdd` trait using the system ssh-add command.

use super::traits::SshAdd;
use crate::io::ssh::agent::socket::resolve_agent_socket_path;
use crate::io::ssh::SshError;
use crate::{Error, Result};
use std::process::Command;

/// Default implementation of `SshAdd` that invokes the system `ssh-add` binary.
pub struct DefaultSshAdd {
    ssh_add_path: String,
}

impl DefaultSshAdd {
    /// Create a new `DefaultSshAdd` using the given binary path.
    pub fn new(ssh_add_path: impl Into<String>) -> Self {
        Self {
            ssh_add_path: ssh_add_path.into(),
        }
    }
}

impl SshAdd for DefaultSshAdd {
    fn list_keys(&self) -> Result<String> {
        let socket_path = resolve_agent_socket_path()?;

        let socket_path_str = socket_path.to_str().ok_or_else(|| {
            Error::from(SshError::operation_failed(
                "SSH agent socket path contains invalid UTF-8",
            ))
        })?;

        let output = Command::new(&self.ssh_add_path)
            .arg("-L")
            .env("SSH_AUTH_SOCK", socket_path_str)
            .output()
            .map_err(|e| {
                Error::from(SshError::operation_failed_with_source(
                    format!("Failed to run ssh-add -L: {}", e),
                    e,
                ))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(
                SshError::operation_failed(format!("ssh-add -L failed: {}", stderr)).into(),
            );
        }

        String::from_utf8(output.stdout).map_err(|e| {
            Error::from(SshError::operation_failed_with_source(
                format!("Invalid UTF-8 in ssh-add output: {}", e),
                e,
            ))
        })
    }
}
