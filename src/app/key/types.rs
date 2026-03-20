// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::feature::key as feature_key;
use crate::io::verify_online::VerificationStatus;
use crate::model::ssh::SshDeterminismStatus;

#[derive(Debug, Clone)]
pub struct KeyNewResult {
    pub member_id: String,
    pub kid: String,
    pub created_at: String,
    pub expires_at: String,
    pub keystore_root: std::path::PathBuf,
    pub key_dir: std::path::PathBuf,
    pub activated: bool,
    pub ssh_fingerprint: String,
    pub ssh_public_key: String,
    pub ssh_determinism: SshDeterminismStatus,
    pub github_verification: VerificationStatus,
}

impl From<feature_key::KeyNewResult> for KeyNewResult {
    fn from(r: feature_key::KeyNewResult) -> Self {
        Self {
            member_id: r.member_id,
            kid: r.kid,
            created_at: r.created_at,
            expires_at: r.expires_at,
            keystore_root: r.keystore_root,
            key_dir: r.key_dir,
            activated: r.activated,
            ssh_fingerprint: r.ssh_fingerprint,
            ssh_public_key: r.ssh_public_key,
            ssh_determinism: r.ssh_determinism,
            github_verification: VerificationStatus::NotConfigured,
        }
    }
}

#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub kid: String,
    pub member_id: String,
    pub created_at: String,
    pub expires_at: String,
    pub active: bool,
    pub format: String,
}

impl From<feature_key::KeyInfo> for KeyInfo {
    fn from(i: feature_key::KeyInfo) -> Self {
        Self {
            kid: i.kid,
            member_id: i.member_id,
            created_at: i.created_at,
            expires_at: i.expires_at,
            active: i.active,
            format: i.format,
        }
    }
}

pub struct KeyListResult {
    pub entries: Vec<(String, Vec<KeyInfo>)>,
    pub total_keys: usize,
}

impl From<feature_key::KeyListResult> for KeyListResult {
    fn from(r: feature_key::KeyListResult) -> Self {
        Self {
            entries: r
                .entries
                .into_iter()
                .map(|(id, keys)| (id, keys.into_iter().map(KeyInfo::from).collect()))
                .collect(),
            total_keys: r.total_keys,
        }
    }
}

pub struct KeyActivateResult {
    pub member_id: String,
    pub kid: String,
}

impl From<feature_key::KeyActivateResult> for KeyActivateResult {
    fn from(r: feature_key::KeyActivateResult) -> Self {
        Self {
            member_id: r.member_id,
            kid: r.kid,
        }
    }
}

pub struct KeyRemoveResult {
    pub member_id: String,
    pub kid: String,
    pub was_active: bool,
}

impl From<feature_key::KeyRemoveResult> for KeyRemoveResult {
    fn from(r: feature_key::KeyRemoveResult) -> Self {
        Self {
            member_id: r.member_id,
            kid: r.kid,
            was_active: r.was_active,
        }
    }
}

pub struct KeyExportResult {
    pub member_id: String,
    pub kid: String,
}

impl From<feature_key::KeyExportResult> for KeyExportResult {
    fn from(r: feature_key::KeyExportResult) -> Self {
        Self {
            member_id: r.member_id,
            kid: r.kid,
        }
    }
}
