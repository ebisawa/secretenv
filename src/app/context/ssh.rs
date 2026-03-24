// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use crate::app::context::member::resolve_active_key_member_context;
use crate::app::context::options::CommonCommandOptions;
use crate::feature::context::ssh::{
    build_ssh_signing_context as feature_build_ssh_signing_context, find_candidate_by_fingerprint,
    resolve_ssh_key_candidates as feature_resolve_ssh_key_candidates, SshSigningContext,
    SshSigningParams as FeatureSshSigningParams,
};
use crate::io::keystore::active::load_active_kid;
use crate::io::keystore::storage::load_private_key;
use crate::io::ssh::external::pubkey::SshKeyCandidate;
use crate::model::private_key::PrivateKeyAlgorithm;
use crate::{Error, Result};

#[derive(Debug, Clone)]
pub struct SshSigningParams {
    pub ssh_key: Option<PathBuf>,
    pub signing_method: Option<crate::config::types::SshSigner>,
    pub base_dir: Option<PathBuf>,
    pub verbose: bool,
    pub check_determinism: bool,
}

fn build_ssh_signing_params(options: &CommonCommandOptions) -> SshSigningParams {
    SshSigningParams {
        ssh_key: options.identity.clone(),
        signing_method: options.ssh_signer,
        base_dir: options.home.clone(),
        verbose: options.verbose,
        check_determinism: false,
    }
}

fn feature_ssh_signing_params(params: &SshSigningParams) -> FeatureSshSigningParams {
    FeatureSshSigningParams {
        ssh_key: params.ssh_key.clone(),
        signing_method: params.signing_method,
        base_dir: params.base_dir.clone(),
        verbose: params.verbose,
        check_determinism: params.check_determinism,
    }
}

pub fn resolve_ssh_key_candidates(options: &CommonCommandOptions) -> Result<Vec<SshKeyCandidate>> {
    let params = build_ssh_signing_params(options);
    resolve_ssh_key_candidates_with_params(&params)
}

pub fn resolve_ssh_key_candidates_with_params(
    params: &SshSigningParams,
) -> Result<Vec<SshKeyCandidate>> {
    feature_resolve_ssh_key_candidates(&feature_ssh_signing_params(params))
}

pub fn build_ssh_signing_context(
    options: &CommonCommandOptions,
    selected_pubkey: &str,
    check_determinism: bool,
) -> Result<SshSigningContext> {
    let mut params = build_ssh_signing_params(options);
    params.check_determinism = check_determinism;
    build_ssh_signing_context_with_params(&params, selected_pubkey)
}

pub fn build_ssh_signing_context_with_params(
    params: &SshSigningParams,
    selected_pubkey: &str,
) -> Result<SshSigningContext> {
    feature_build_ssh_signing_context(&feature_ssh_signing_params(params), selected_pubkey)
}

pub fn resolve_ssh_context_by_active_key(
    options: &CommonCommandOptions,
) -> Result<SshSigningContext> {
    let resolved = resolve_active_key_member_context(options)?;
    let kid =
        load_active_kid(&resolved.member_id, &resolved.paths.keystore_root)?.ok_or_else(|| {
            Error::NotFound {
                message: format!("No active key for member: {}", resolved.member_id),
            }
        })?;
    let private_key = load_private_key(&resolved.paths.keystore_root, &resolved.member_id, &kid)?;
    let target_fpr = match &private_key.protected.alg {
        PrivateKeyAlgorithm::SshSig { fpr, .. } => fpr.as_str(),
        _ => {
            return Err(Error::Crypto {
                message: "Expected SshSig algorithm for SSH signing context".to_string(),
                source: None,
            });
        }
    };

    let candidates = resolve_ssh_key_candidates(options)?;
    let matched = find_candidate_by_fingerprint(&candidates, target_fpr)?;
    build_ssh_signing_context(options, &matched.public_key, false)
}
