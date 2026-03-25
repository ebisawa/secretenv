// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! encrypt command implementation
//!
//! Encrypts a plain file to file-enc v3 format with automatic signing.
//! Recipients are always all active workspace members.

use clap::Args;
use std::path::PathBuf;

use crate::app::context::options::CommonCommandOptions;
use crate::app::file::encrypt::encrypt_file_command;
use crate::cli::common::options::CommonOptions;
use crate::cli::common::output::file::{resolve_encrypted_output_path, write_encrypted_output};
use crate::cli::common::ssh::resolve_ssh_context_optional;
use crate::Result;

#[derive(Args)]
pub struct EncryptArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Do not embed signer's PublicKey in signature
    #[arg(long)]
    pub no_signer_pub: bool,

    /// Member ID to use
    #[arg(long, short = 'm')]
    pub member_id: Option<String>,

    /// Output file path
    #[arg(long, short = 'o')]
    pub out: Option<PathBuf>,

    /// Input file path
    pub input: PathBuf,
}

pub fn run(args: EncryptArgs) -> Result<()> {
    let options = CommonCommandOptions::from(&args.common);
    let ssh_ctx = resolve_ssh_context_optional(&options, args.member_id.clone())?;
    let encrypted = encrypt_file_command(
        &options,
        args.member_id.clone(),
        args.no_signer_pub,
        &args.input,
        ssh_ctx,
    )?;
    let output_path = resolve_encrypted_output_path(args.out.as_ref(), &args.input)?;

    write_encrypted_output(output_path.as_ref(), &encrypted, args.common.quiet)?;
    Ok(())
}
