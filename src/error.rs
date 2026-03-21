// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Error types for the secretenv project.

use thiserror::Error;

/// The main error type for secretenv operations.
#[derive(Error, Debug)]
pub enum Error {
    /// JSON Schema validation failed.
    #[error("Schema validation error: {message}")]
    Schema {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Cryptographic operation failed (HPKE, Ed25519, etc.).
    #[error("Cryptographic error: {message}")]
    Crypto {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// SSH-related error (ssh-agent, SSHSIG verification, fingerprint parsing).
    #[error("SSH error: {message}")]
    Ssh {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Verification rule violation.
    #[error("Verification failed [{rule}]: {message}")]
    Verify { rule: String, message: String },

    /// File I/O error.
    #[error("I/O error: {message}")]
    Io {
        message: String,
        #[source]
        source: Option<std::io::Error>,
    },

    /// Parsing error (JSON, base64, etc.).
    #[error("Parse error: {message}")]
    Parse {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Configuration error (missing config, invalid settings).
    #[error("Configuration error: {message}")]
    Config { message: String },

    /// Resource not found (key, member, workspace, file, etc.).
    #[error("Not found: {message}")]
    NotFound { message: String },

    /// Invalid argument or validation failure.
    #[error("Invalid argument: {message}")]
    InvalidArgument { message: String },

    /// Invalid operation error (e.g., attempting to sign with a public key).
    #[error("Invalid operation: {message}")]
    InvalidOperation { message: String },
}

/// A convenient Result type alias using [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Create a verification error.
    pub fn verify(rule: impl Into<String>, message: impl Into<String>) -> Self {
        Error::Verify {
            rule: rule.into(),
            message: message.into(),
        }
    }

    /// Create a parse error.
    pub fn parse(message: impl Into<String>) -> Self {
        Error::Parse {
            message: message.into(),
            source: None,
        }
    }

    /// Create a parse error with a source error.
    pub fn parse_with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Error::Parse {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Create a configuration error.
    pub fn config(message: impl Into<String>) -> Self {
        Error::Config {
            message: message.into(),
        }
    }

    /// Create a not found error.
    pub fn not_found(message: impl Into<String>) -> Self {
        Error::NotFound {
            message: message.into(),
        }
    }

    /// Create an invalid argument error.
    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Error::InvalidArgument {
            message: message.into(),
        }
    }

    /// Create an invalid operation error.
    pub fn invalid_operation(message: impl Into<String>) -> Self {
        Error::InvalidOperation {
            message: message.into(),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io {
            message: err.to_string(),
            source: Some(err),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Parse {
            message: format!("JSON error: {}", err),
            source: Some(Box::new(err)),
        }
    }
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Self {
        Error::Parse {
            message: format!("Base64 decode error: {}", err),
            source: Some(Box::new(err)),
        }
    }
}

impl From<crate::crypto::CryptoError> for Error {
    fn from(err: crate::crypto::CryptoError) -> Self {
        Error::Crypto {
            message: err.to_string(),
            source: None,
        }
    }
}

impl From<crate::io::ssh::SshError> for Error {
    fn from(err: crate::io::ssh::SshError) -> Self {
        let crate::io::ssh::SshError::OperationFailed { message, source } = err;
        Error::Ssh { message, source }
    }
}

impl From<crate::format::FormatError> for Error {
    fn from(err: crate::format::FormatError) -> Self {
        Error::Parse {
            message: err.to_string(),
            source: None,
        }
    }
}

impl From<hkdf::InvalidLength> for Error {
    fn from(err: hkdf::InvalidLength) -> Self {
        Error::Crypto {
            message: format!("HKDF key derivation failed: {}", err),
            source: None,
        }
    }
}
