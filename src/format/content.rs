// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Typed wrappers for format-detected encrypted content.
//!
//! These newtypes guarantee that format detection has already been performed
//! on the underlying string, eliminating redundant `detect_format` calls
//! across feature functions.

use crate::format::detection::{detect_format, InputFormat};
use crate::format::kv::parse_kv_document;
use crate::model::file_enc::FileEncDocument;
use crate::model::kv_enc::KvEncDocument;
use crate::{Error, Result};

/// File-enc content (JSON string, format-detected but unparsed).
#[derive(Debug, Clone)]
pub struct FileEncContent(String);

/// KV-enc content (text string, format-detected but unparsed).
#[derive(Debug, Clone)]
pub struct KvEncContent(String);

/// Format-detected encrypted content for dispatch.
pub enum EncryptedContent {
    FileEnc(FileEncContent),
    KvEnc(KvEncContent),
}

impl FileEncContent {
    /// Construct after verifying the content is file-enc format.
    pub fn detect(content: String) -> Result<Self> {
        match detect_format(&content)? {
            InputFormat::FileEnc => Ok(Self(content)),
            other => Err(Error::Parse {
                message: format!("Expected file-enc format, detected {:?}", other),
                source: None,
            }),
        }
    }

    /// Construct without format detection (caller guarantees file-enc format).
    pub fn new_unchecked(content: String) -> Self {
        Self(content)
    }

    /// Parse the JSON content into a `FileEncDocument`.
    ///
    /// Validates JSON depth/element limits and schema conformance before
    /// deserializing into the typed struct.
    pub fn parse(&self) -> Result<FileEncDocument> {
        crate::support::json_limits::validate_json_limits(self.0.as_bytes())?;

        let value: serde_json::Value = serde_json::from_str(&self.0).map_err(|e| Error::Parse {
            message: format!("Failed to parse FileEncDocument JSON: {}", e),
            source: Some(Box::new(e)),
        })?;

        crate::io::schema::validator::embedded_validator()?.validate_file_enc_document(&value)?;

        serde_json::from_value(value).map_err(|e| Error::Parse {
            message: format!("Failed to deserialize FileEncDocument: {}", e),
            source: Some(Box::new(e)),
        })
    }

    /// Serialize a `FileEncDocument` back to pretty-printed JSON.
    pub fn from_document(doc: &FileEncDocument) -> Result<Self> {
        let json = serde_json::to_string_pretty(doc).map_err(|e| Error::Parse {
            message: format!("Failed to serialize FileEncDocument: {}", e),
            source: Some(Box::new(e)),
        })?;
        Ok(Self(json))
    }

    /// Access the underlying string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl KvEncContent {
    /// Construct after verifying the content is kv-enc format.
    pub fn detect(content: String) -> Result<Self> {
        match detect_format(&content)? {
            InputFormat::KvEnc => Ok(Self(content)),
            other => Err(Error::Parse {
                message: format!("Expected kv-enc format, detected {:?}", other),
                source: None,
            }),
        }
    }

    /// Construct without format detection (caller guarantees kv-enc format).
    pub fn new_unchecked(content: String) -> Self {
        Self(content)
    }

    /// Parse the content into a `KvEncDocument`.
    pub fn parse(&self) -> Result<KvEncDocument> {
        parse_kv_document(&self.0)
    }

    /// Access the underlying string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl EncryptedContent {
    /// Detect format and wrap in the appropriate variant.
    pub fn detect(content: String) -> Result<Self> {
        match detect_format(&content)? {
            InputFormat::FileEnc => Ok(Self::FileEnc(FileEncContent(content))),
            InputFormat::KvEnc => Ok(Self::KvEnc(KvEncContent(content))),
            other => Err(Error::Parse {
                message: format!("Expected file-enc or kv-enc format, detected {:?}", other),
                source: None,
            }),
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/format_content_internal_test.rs"]
mod tests;
