// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Crypto-specific error types

use thiserror::Error;

/// Error type for cryptographic operations.
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Invalid key format or length.
    #[error("Invalid key: {message}")]
    InvalidKey { message: String },

    /// Cryptographic operation failed (HPKE, AES-GCM, Ed25519, etc.).
    #[error("Operation failed: {message}")]
    OperationFailed {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Key derivation failed (HKDF, etc.).
    #[error("Key derivation failed: {message}")]
    KeyDerivationFailed { message: String },
}

impl CryptoError {
    /// Create an invalid key error.
    pub fn invalid_key(message: impl Into<String>) -> Self {
        CryptoError::InvalidKey {
            message: message.into(),
        }
    }

    /// Create an operation failed error.
    pub fn operation_failed(message: impl Into<String>) -> Self {
        CryptoError::OperationFailed {
            message: message.into(),
            source: None,
        }
    }

    /// Create an operation failed error with a source error.
    pub fn operation_failed_with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        CryptoError::OperationFailed {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Create a key derivation failed error.
    pub fn key_derivation_failed(message: impl Into<String>) -> Self {
        CryptoError::KeyDerivationFailed {
            message: message.into(),
        }
    }
}
