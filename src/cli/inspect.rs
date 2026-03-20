// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! inspect command - Display encryption metadata without decryption
//!
//! Shows wrap information, recipients, and payload metadata for debugging
//! Supports both kv-enc v3 and file-enc v3 formats

use clap::Args;
use std::path::PathBuf;

use crate::app::context::CommonCommandOptions;
use crate::app::file::inspect_file_command;
use crate::cli::common::options::CommonOptions;
use crate::Result;

#[derive(Args)]
pub struct InspectArgs {
    /// Common options shared across commands
    #[command(flatten)]
    pub common: CommonOptions,

    /// Input file path
    pub input: PathBuf,
}

pub fn run(args: InspectArgs) -> Result<()> {
    let options = CommonCommandOptions::from(&args.common);
    let (input_display, output) = inspect_file_command(&options, &args.input)?;
    eprintln!("Inspecting: {}\n", input_display);
    print!("{}", output);
    Ok(())
}
