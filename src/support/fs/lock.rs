// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! File locking utilities.

use crate::support::fs::ensure_dir;
use crate::support::path::display_path_relative_to_cwd;
use crate::{Error, Result};
use fd_lock::RwLock;
use std::fs::OpenOptions;
use std::path::Path;

/// Execute a function with an exclusive file lock.
///
/// Creates a lock file (`.{filename}.lock`) in the same directory as the target file
/// and holds an exclusive lock while executing the provided function.
pub fn with_file_lock<T, F>(path: &Path, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| Error::Io {
            message: format!("Invalid file path: {}", display_path_relative_to_cwd(path)),
            source: None,
        })?;
    let lock_file_name = format!(".{}.lock", file_name);
    let lock_path = path
        .parent()
        .map(|p| p.join(&lock_file_name))
        .unwrap_or_else(|| Path::new(&lock_file_name).to_path_buf());

    // Ensure the directory exists before opening the lock file.
    // This is required for cases like `secretenv config set ...` where
    // SECRETENV_HOME/config.toml's parent directory may not be created yet.
    if let Some(lock_parent) = lock_path.parent() {
        ensure_dir(lock_parent).map_err(|e| Error::Io {
            message: format!(
                "Failed to create directory for lock file '{}': {}",
                display_path_relative_to_cwd(lock_parent),
                e
            ),
            source: None,
        })?;
    }

    let lock_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&lock_path)
        .map_err(|e| Error::Io {
            message: format!("Failed to open lock file: {}", e),
            source: Some(e),
        })?;

    let mut lock = RwLock::new(lock_file);
    let _guard = lock.write().map_err(|e| Error::Io {
        message: format!("Failed to acquire lock: {}", e),
        source: None,
    })?;

    f()
}
