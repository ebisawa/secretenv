// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! JSON Schema validator
//!
//! Validates documents against JSON Schema definitions.

use crate::model::identifiers::format::{FILE_ENC_V3, PRIVATE_KEY_V3, PUBLIC_KEY_V3};
use crate::support::fs::load_text;
use crate::support::path::display_path_relative_to_cwd;
use crate::{Error, Result};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::LazyLock;

/// Embedded schema JSON (compiled into the binary)
const EMBEDDED_SCHEMA: &str = include_str!("../../../schemas/secretenv_schema_v3.json");

/// Singleton embedded validator, lazily initialized.
static EMBEDDED_VALIDATOR: LazyLock<std::result::Result<Validator, String>> = LazyLock::new(|| {
    let schema_json: Value = serde_json::from_str(EMBEDDED_SCHEMA)
        .map_err(|e| format!("Failed to parse embedded schema: {}", e))?;
    Validator::from_schema(schema_json)
        .map_err(|e| format!("Failed to compile embedded schema: {}", e))
});

/// Get a reference to the embedded validator (compiled-in schema).
///
/// Uses `LazyLock` for one-time initialization. Returns an error if the
/// embedded schema cannot be parsed or compiled.
pub fn embedded_validator() -> Result<&'static Validator> {
    EMBEDDED_VALIDATOR.as_ref().map_err(|e| Error::Schema {
        message: e.clone(),
        source: None,
    })
}

/// JSON Schema validator that loads schema files.
pub struct Validator {
    schema: jsonschema::Validator,
}

impl Validator {
    /// Create a new validator, loading the v3 comprehensive schema
    pub fn new() -> Result<Self> {
        let schema_json = Self::load_schema_from_paths("secretenv_schema_v3.json")?;
        Self::from_schema(schema_json)
    }

    /// Create a validator from a schema JSON value
    pub fn from_schema(schema_json: Value) -> Result<Self> {
        let compiled = jsonschema::draft202012::options()
            .build(&schema_json)
            .map_err(|e| Error::Schema {
                message: format!("Failed to compile schema: {}", e),
                source: Some(Box::new(e)),
            })?;

        Ok(Self { schema: compiled })
    }

    /// Load a schema file from the schemas/ directory
    pub fn load_schema_from_paths(filename: &str) -> Result<Value> {
        // Try to find schema file relative to the executable or in the project root
        let possible_paths = [
            PathBuf::from("schemas").join(filename),
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("schemas")
                .join(filename),
        ];

        for path in &possible_paths {
            if path.exists() {
                let content = load_text(path)?;
                return serde_json::from_str(&content).map_err(|e| Error::Parse {
                    message: format!(
                        "Failed to parse schema file {}: {}",
                        display_path_relative_to_cwd(path),
                        e
                    ),
                    source: Some(Box::new(e)),
                });
            }
        }

        Err(Error::NotFound {
            message: format!("Schema file not found: {}", filename),
        })
    }

    /// Validate a PublicKey@3
    pub fn validate_public_key(&self, doc: &Value) -> Result<()> {
        self.validate(doc, PUBLIC_KEY_V3)
    }

    /// Validate a PrivateKey@3
    pub fn validate_private_key(&self, doc: &Value) -> Result<()> {
        self.validate(doc, PRIVATE_KEY_V3)
    }

    /// Validate a FileEncDocument@3 (format: secretenv.file@3)
    pub fn validate_file_enc_document(&self, doc: &Value) -> Result<()> {
        self.validate(doc, FILE_ENC_V3)
    }

    /// Validate a KV value v3
    pub fn validate_kv_value(&self, doc: &Value) -> Result<()> {
        self.validate_generic(doc)
    }

    /// Validate a KV file wrap v3
    pub fn validate_kv_file_wrap(&self, doc: &Value) -> Result<()> {
        self.validate_generic(doc)
    }

    fn validate(&self, doc: &Value, expected_format: &str) -> Result<()> {
        // Check format field
        // For PublicKey, PrivateKey, and FileEncDocument v3, format is in protected.format
        let format = if doc.get("protected").is_some() {
            // PublicKey, PrivateKey, or FileEncDocument v3 structure
            doc.get("protected")
                .and_then(|p| p.get("format"))
                .and_then(|f| f.as_str())
        } else {
            // Fallback: check top-level format (for backward compatibility)
            doc.get("format").and_then(|f| f.as_str())
        }
        .ok_or_else(|| Error::Schema {
            message: "Missing or invalid 'format' field".to_string(),
            source: None,
        })?;

        if format != expected_format {
            return Err(Error::Schema {
                message: format!("Expected format '{}', got '{}'", expected_format, format),
                source: None,
            });
        }

        self.validate_generic(doc)
    }

    fn validate_generic(&self, doc: &Value) -> Result<()> {
        if self.schema.is_valid(doc) {
            return Ok(());
        }

        let messages: Vec<String> = self
            .schema
            .iter_errors(doc)
            .map(|error| {
                let path = error.instance_path().to_string();
                if path.is_empty() {
                    error.to_string()
                } else {
                    format!("{}: {}", path, error)
                }
            })
            .collect();

        Err(Error::Schema {
            message: messages.join("; "),
            source: None,
        })
    }
}
