// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-layer orchestration for `run` command execution.

use crate::app::context::{CommonCommandOptions, SshSigningContext};
use crate::app::kv::build_run_env_command;
use crate::io::process::execute_command_with_env;
use crate::{Error, Result};

/// Execute a child command with decrypted environment variables from kv-enc.
pub fn execute_env_command(
    options: &CommonCommandOptions,
    member_id: Option<String>,
    file_name: Option<&str>,
    command_args: &[String],
    ssh_ctx: Option<SshSigningContext>,
) -> Result<i32> {
    let (cmd, cmd_args) = split_command_args(command_args)?;
    let env_vars = build_run_env_command(options, member_id, file_name, ssh_ctx)?;
    execute_command_with_env(&cmd, &cmd_args, &env_vars)
}

fn split_command_args(command_args: &[String]) -> Result<(String, Vec<String>)> {
    let (cmd, cmd_args) = command_args.split_first().ok_or_else(|| Error::Config {
        message: "No command specified".to_string(),
    })?;
    Ok((cmd.clone(), cmd_args.to_vec()))
}
