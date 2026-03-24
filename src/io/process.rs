// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! External process execution helpers.

use crate::{Error, Result};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::process::Command;

const STANDARD_ENV_KEYS: &[&str] = &[
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "TERM",
    "TMPDIR",
    "TMP",
    "TEMP",
    "TZ",
    "SHELL",
    "USER",
    "LOGNAME",
];

/// Execute a command with environment variables and return its exit code.
pub fn execute_command_with_env(
    cmd: &str,
    cmd_args: &[String],
    env_vars: &BTreeMap<String, String>,
) -> Result<i32> {
    let mut command = Command::new(cmd);
    command.args(cmd_args);
    configure_child_env(&mut command, env_vars);

    let status = command.status().map_err(|e| Error::Io {
        message: format!("Failed to execute command '{}': {}", cmd, e),
        source: Some(e),
    })?;

    Ok(status.code().unwrap_or(1))
}

fn configure_child_env(command: &mut Command, env_vars: &BTreeMap<String, String>) {
    command.env_clear();

    for (key, value) in load_standard_env_vars() {
        command.env(key, value);
    }

    for (key, value) in env_vars {
        command.env(key, value);
    }
}

fn load_standard_env_vars() -> Vec<(&'static str, OsString)> {
    STANDARD_ENV_KEYS
        .iter()
        .filter_map(|key| std::env::var_os(key).map(|value| (*key, value)))
        .collect()
}
