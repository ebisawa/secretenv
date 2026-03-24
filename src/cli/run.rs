// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! run command v3 implementation
//!
//! Executes a command with decrypted environment variables.
//!
//! Features:
//! - Uses default kv-enc file (<workspace>/secrets/default.kvenc)
//! - Automatic verify --strict before decryption (MUST - cannot be skipped)
//! - Child process execution with decrypted environment
//! - Exit code forwarding

use clap::Args;

use crate::app::context::CommonCommandOptions;
use crate::app::run::execute_env_command;
use crate::cli::common::options::CommonOptions;
use crate::cli::common::ssh::resolve_ssh_context_optional;
use crate::Result;

#[derive(Args)]
pub struct RunArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Member ID to use
    #[arg(long, short = 'm')]
    pub member_id: Option<String>,

    /// Secret store name; defaults to "default"
    #[arg(long, short = 'n')]
    pub name: Option<String>,

    /// Command to execute (after --)
    #[arg(required = true, last = true)]
    pub command: Vec<String>,
}

pub fn run(args: RunArgs) -> Result<()> {
    let options = CommonCommandOptions::from(&args.common);
    let ssh_ctx = resolve_ssh_context_optional(&options)?;
    let exit_code = execute_env_command(
        &options,
        args.member_id.clone(),
        args.name.as_deref(),
        &args.command,
        ssh_ctx,
    )?;
    std::process::exit(exit_code);
}
