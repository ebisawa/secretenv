// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! inspect command - Display encryption metadata without decryption
//!
//! Shows wrap information, recipients, and payload metadata for debugging
//! Supports both kv-enc v3 and file-enc v3 formats

use clap::Args;
use std::path::PathBuf;

use crate::app::context::options::CommonCommandOptions;
use crate::app::file::inspect::{inspect_file_command, InspectSection};
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
    let output = inspect_file_command(&options, &args.input)?;
    eprintln!("Inspecting: {}\n", output.input_display);
    print!("{}", render_inspect_output(&output.title, &output.sections));
    Ok(())
}

fn render_inspect_output(title: &str, sections: &[InspectSection]) -> String {
    let mut out = String::new();
    out.push_str(title);
    out.push('\n');
    out.push('\n');
    for (index, section) in sections.iter().enumerate() {
        out.push('[');
        out.push_str(&section.title);
        out.push_str("]\n");
        for line in &section.lines {
            out.push_str(line);
            out.push('\n');
        }
        if index + 1 != sections.len() {
            out.push('\n');
        }
    }
    out
}
