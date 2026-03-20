// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared JSON file and string parsing helpers for I/O adapters.

use crate::support::fs::load_text;
use crate::support::path::display_path_relative_to_cwd;
use crate::{Error, Result};
use serde::de::DeserializeOwned;
use std::path::Path;

/// Load and parse a JSON file.
pub fn load_json_file<T: DeserializeOwned>(path: &Path, kind: &str) -> Result<T> {
    let content = load_text(path)?;
    parse_json_str(&content, kind, &display_path_relative_to_cwd(path))
}

/// Parse a JSON string with context labels for error reporting.
pub fn parse_json_str<T: DeserializeOwned>(
    content: &str,
    kind: &str,
    source_name: &str,
) -> Result<T> {
    serde_json::from_str(content).map_err(|e| Error::Parse {
        message: format!("Failed to parse {} from {}: {}", kind, source_name, e),
        source: Some(Box::new(e)),
    })
}
