// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Format-specific error types

use thiserror::Error;

/// Error type for format/parsing operations.
#[derive(Error, Debug)]
pub enum FormatError {
    /// Parsing failed (JSON, base64, TOML, etc.).
    #[error("Parse error: {message}")]
    ParseFailed {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

impl FormatError {
    /// Create a parse error.
    pub fn parse_failed(message: impl Into<String>) -> Self {
        FormatError::ParseFailed {
            message: message.into(),
            source: None,
        }
    }

    /// Create a parse error with a source error.
    pub fn parse_failed_with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        FormatError::ParseFailed {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }
}
