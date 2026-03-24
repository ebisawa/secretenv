// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use crate::support::fs::atomic;
use crate::support::path::display_path_relative_to_cwd;
use crate::{Error, Result};

/// Resolve output path for file-enc format.
///
/// Returns `<input_filename>.encrypted` in current directory if `--out` is not specified.
pub fn resolve_encrypted_output_path(
    explicit_out: Option<&PathBuf>,
    input_path: &Path,
) -> Result<Option<PathBuf>> {
    if let Some(out) = explicit_out {
        return Ok(Some(out.clone()));
    }

    let input_filename = input_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| Error::InvalidArgument {
            message: format!(
                "Cannot derive filename from input path: {}",
                display_path_relative_to_cwd(input_path)
            ),
        })?;

    if input_filename.chars().any(|c| c.is_control()) {
        return Err(Error::InvalidArgument {
            message: format!("E_NAME_INVALID: invalid input filename: {}", input_filename),
        });
    }

    let output_filename = format!("{}.encrypted", input_filename);
    let current_dir = std::env::current_dir().map_err(|e| Error::Io {
        message: format!("Failed to get current directory: {}", e),
        source: Some(e),
    })?;
    Ok(Some(current_dir.join(output_filename)))
}

pub fn save_encrypted_output(
    output_path: Option<&PathBuf>,
    content: &str,
    quiet: bool,
) -> Result<Option<String>> {
    match output_path {
        Some(path) => {
            atomic::save_text(path, content)?;
            Ok(build_output_notice("Encrypted to", path.as_path(), quiet))
        }
        None => {
            print!("{}", content);
            Ok(None)
        }
    }
}

pub fn save_decrypted_file(
    plaintext_bytes: &[u8],
    output_path: &Path,
    quiet: bool,
) -> Result<Option<String>> {
    atomic::save_bytes(output_path, plaintext_bytes)?;
    Ok(build_output_notice("Decrypted to", output_path, quiet))
}

fn build_output_notice(label: &str, output_path: &Path, quiet: bool) -> Option<String> {
    (!quiet).then(|| format!("{}: {}", label, display_path_relative_to_cwd(output_path)))
}
