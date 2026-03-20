// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! External process execution helpers.

use crate::{Error, Result};
use std::collections::BTreeMap;
use std::process::Command;

/// Execute a command with environment variables and return its exit code.
pub fn execute_command_with_env(
    cmd: &str,
    cmd_args: &[String],
    env_vars: &BTreeMap<String, String>,
) -> Result<i32> {
    let mut command = Command::new(cmd);
    command.args(cmd_args);

    for (key, value) in env_vars {
        command.env(key, value);
    }

    let status = command.status().map_err(|e| Error::Io {
        message: format!("Failed to execute command '{}': {}", cmd, e),
        source: Some(e),
    })?;

    Ok(status.code().unwrap_or(1))
}
