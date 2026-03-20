// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! File-oriented CLI output helpers for encrypt/decrypt commands.

use crate::support::fs::atomic;
use crate::support::path::display_path_relative_to_cwd;
use crate::Result;
use std::path::{Path, PathBuf};

pub fn save_encrypted_output(
    output_path: Option<&PathBuf>,
    content: &str,
    quiet: bool,
) -> Result<()> {
    match output_path {
        Some(path) => {
            atomic::save_text(path, content)?;
            if !quiet {
                let display_path = display_path_relative_to_cwd(path.as_path());
                eprintln!("Encrypted to: {}", display_path);
            }
        }
        None => print!("{}", content),
    }
    Ok(())
}

pub fn save_decrypted_file(plaintext_bytes: &[u8], output_path: &Path, quiet: bool) -> Result<()> {
    atomic::save_bytes(output_path, plaintext_bytes)?;
    if !quiet {
        eprintln!(
            "Decrypted to: {}",
            display_path_relative_to_cwd(output_path)
        );
    }
    Ok(())
}
