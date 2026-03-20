// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Atomic filesystem operations.

pub mod atomic;
pub mod lock;

use crate::support::path::display_path_relative_to_cwd;
use crate::{Error, Result};
use std::fs;
use std::fs::ReadDir;
use std::path::Path;

/// Read a file as bytes with consistent path-aware error messages.
pub fn load_bytes(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| Error::Io {
        message: format!(
            "Failed to read file {}: {}",
            display_path_relative_to_cwd(path),
            e
        ),
        source: Some(e),
    })
}

/// Read a UTF-8 text file with consistent path-aware error messages.
pub fn load_text(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(|e| Error::Io {
        message: format!(
            "Failed to read file {}: {}",
            display_path_relative_to_cwd(path),
            e
        ),
        source: Some(e),
    })
}

/// List directory entries with consistent path-aware error messages.
pub fn list_dir(path: &Path) -> Result<ReadDir> {
    fs::read_dir(path).map_err(|e| Error::Io {
        message: format!(
            "Failed to read directory {}: {}",
            display_path_relative_to_cwd(path),
            e
        ),
        source: Some(e),
    })
}

/// Ensure a directory exists with consistent path-aware error messages.
pub fn ensure_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|e| Error::Io {
        message: format!(
            "Failed to create directory {}: {}",
            display_path_relative_to_cwd(path),
            e
        ),
        source: Some(e),
    })
}
