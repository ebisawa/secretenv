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
    fs::read(path).map_err(|e| {
        Error::io_with_source(
            format!(
                "Failed to read file {}: {}",
                display_path_relative_to_cwd(path),
                e
            ),
            e,
        )
    })
}

/// Read a UTF-8 text file with consistent path-aware error messages.
pub fn load_text(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(|e| {
        Error::io_with_source(
            format!(
                "Failed to read file {}: {}",
                display_path_relative_to_cwd(path),
                e
            ),
            e,
        )
    })
}

/// List directory entries with consistent path-aware error messages.
pub fn list_dir(path: &Path) -> Result<ReadDir> {
    fs::read_dir(path).map_err(|e| {
        Error::io_with_source(
            format!(
                "Failed to read directory {}: {}",
                display_path_relative_to_cwd(path),
                e
            ),
            e,
        )
    })
}

/// Ensure a directory exists with consistent path-aware error messages.
pub fn ensure_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|e| {
        Error::io_with_source(
            format!(
                "Failed to create directory {}: {}",
                display_path_relative_to_cwd(path),
                e
            ),
            e,
        )
    })
}

/// Ensure a directory exists with restricted permissions (mode 0700 on Unix).
///
/// Creates the directory recursively if it does not exist. If the directory
/// already exists, its permissions are corrected to 0700.
#[cfg(unix)]
pub fn ensure_dir_restricted(path: &Path) -> Result<()> {
    use std::fs::{DirBuilder, Permissions};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|e| {
            Error::io_with_source(
                format!(
                    "Failed to create directory {}: {}",
                    display_path_relative_to_cwd(path),
                    e
                ),
                e,
            )
        })?;

    fs::set_permissions(path, Permissions::from_mode(0o700)).map_err(|e| {
        Error::io_with_source(
            format!(
                "Failed to set permissions on {}: {}",
                display_path_relative_to_cwd(path),
                e
            ),
            e,
        )
    })
}

/// Ensure a directory exists with restricted permissions (non-Unix fallback).
#[cfg(not(unix))]
pub fn ensure_dir_restricted(path: &Path) -> Result<()> {
    ensure_dir(path)
}

/// Check whether a path has overly permissive permissions.
///
/// Returns `Some(warning_message)` if the path is insecure or cannot be
/// checked, `None` if permissions are acceptable.
#[cfg(unix)]
pub fn check_permission(path: &Path) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            return Some(format!(
                "Cannot check permissions on {}: {}",
                display_path_relative_to_cwd(path),
                e
            ));
        }
    };
    let mode = metadata.permissions().mode();
    let extra_bits = mode & 0o077;
    if extra_bits != 0 {
        let expected = if metadata.is_dir() { "0700" } else { "0600" };
        Some(format!(
            "Insecure permissions {:04o} on {} (expected {})",
            mode & 0o777,
            display_path_relative_to_cwd(path),
            expected,
        ))
    } else {
        None
    }
}

/// Check whether a path has overly permissive permissions (non-Unix fallback).
#[cfg(not(unix))]
pub fn check_permission(_path: &Path) -> Option<String> {
    None
}
