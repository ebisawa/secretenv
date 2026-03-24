// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! decrypt command - file-enc decryption

use clap::Args;
use std::path::PathBuf;

use crate::app::context::options::CommonCommandOptions;
use crate::app::file::decrypt::{decrypt_file_command, validate_decrypt_input};
use crate::app::file::output::save_decrypted_file;
use crate::cli::common::options::CommonOptions;
use crate::cli::common::ssh::resolve_ssh_context_optional;
use crate::{Error, Result};

#[derive(Args)]
pub struct DecryptArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Key ID to use [default: auto-select]
    #[arg(long, short = 'k')]
    pub kid: Option<String>,

    /// Member ID to use
    #[arg(long, short = 'm')]
    pub member_id: Option<String>,

    /// Output file path (required)
    #[arg(long, short = 'o')]
    pub out: Option<PathBuf>,

    /// Input file path
    pub input: PathBuf,
}

// ============================================================================
// Main Command Implementation
// ============================================================================

pub fn run(args: DecryptArgs) -> Result<()> {
    validate_decrypt_input(&args.input)?;

    // Require --out option (binary data cannot be written to stdout)
    let out_path = args.out.as_ref().ok_or_else(|| Error::Config {
        message: "requires --out option".to_string(),
    })?;

    let options = CommonCommandOptions::from(&args.common);
    let ssh_ctx = resolve_ssh_context_optional(&options)?;
    let plaintext_bytes = decrypt_file_command(
        &options,
        args.member_id.clone(),
        args.kid.as_deref(),
        &args.input,
        ssh_ctx,
    )?;

    if let Some(message) =
        save_decrypted_file(plaintext_bytes.as_ref(), out_path, args.common.quiet)?
    {
        eprintln!("{message}");
    }

    Ok(())
}
