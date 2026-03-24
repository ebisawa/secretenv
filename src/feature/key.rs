// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Keys feature - key generation and management.

pub mod generate;
pub mod manage;
pub mod material;
pub mod portable_export;
pub mod protection;
pub mod public_key_document;

// Re-export key result types
use crate::model::public_key::PublicKey;
use crate::model::ssh::SshDeterminismStatus;
use std::path::PathBuf;

/// Result for key generation.
pub struct KeyNewResult {
    pub member_id: String,
    pub kid: String,
    pub created_at: String,
    pub expires_at: String,
    pub keystore_root: PathBuf,
    pub key_dir: PathBuf,
    pub activated: bool,
    pub ssh_fingerprint: String,
    pub ssh_public_key: String,
    pub ssh_determinism: SshDeterminismStatus,
}

/// Key list info.
#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub kid: String,
    pub member_id: String,
    pub created_at: String,
    pub expires_at: String,
    pub active: bool,
    pub format: String,
}

/// Grouped key list result.
pub struct KeyListResult {
    pub entries: Vec<(String, Vec<KeyInfo>)>,
    pub total_keys: usize,
}

/// Result for key activation.
pub struct KeyActivateResult {
    pub member_id: String,
    pub kid: String,
}

/// Result for key removal.
pub struct KeyRemoveResult {
    pub member_id: String,
    pub kid: String,
    pub was_active: bool,
}

/// Result for key export.
pub struct KeyExportResult {
    pub member_id: String,
    pub kid: String,
    pub public_key: PublicKey,
}
