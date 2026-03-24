// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared command execution context resolution.

use crate::config::resolution::member_id::resolve_member_id;
use crate::config::types::SshSigner;
use crate::feature::context::crypto::CryptoContext;
use crate::feature::context::ssh::find_candidate_by_fingerprint;
pub use crate::feature::context::ssh::SshSigningContext;
use crate::feature::context::ssh::{
    build_ssh_signing_context as feature_build_ssh_signing_context,
    resolve_ssh_key_candidates as feature_resolve_ssh_key_candidates, SshSigningParams,
};
use crate::io::config::paths::get_base_dir;
use crate::io::keystore::active::load_active_kid;
use crate::io::keystore::resolver::KeystoreResolver;
use crate::io::keystore::storage::load_private_key;
pub use crate::io::ssh::external::pubkey::SshKeyCandidate;
use crate::io::workspace::detection::{resolve_optional_workspace, WorkspaceRoot};
use crate::model::private_key::PrivateKeyAlgorithm;
use crate::{Error, Result};
use std::path::PathBuf;

/// App-facing copy of common CLI options used by orchestration code.
#[derive(Debug, Clone)]
pub struct CommonCommandOptions {
    pub home: Option<PathBuf>,
    pub identity: Option<PathBuf>,
    pub quiet: bool,
    pub verbose: bool,
    pub workspace: Option<PathBuf>,
    pub ssh_signer: Option<SshSigner>,
}

impl CommonCommandOptions {
    /// Resolve base directory from options, environment, or defaults.
    pub fn resolve_base_dir(&self) -> Result<PathBuf> {
        match &self.home {
            Some(path) => Ok(path.clone()),
            None => get_base_dir(),
        }
    }

    /// Resolve keystore root from options or defaults.
    pub fn resolve_keystore_root(&self) -> Result<PathBuf> {
        KeystoreResolver::resolve(self.home.as_ref())
    }
}

/// Resolve the workspace if one is explicitly configured or auto-detectable.
///
/// Returns `Ok(None)` only when no workspace is configured and none can be
/// detected from the current repository context.
pub fn load_optional_workspace(options: &CommonCommandOptions) -> Result<Option<WorkspaceRoot>> {
    resolve_optional_workspace(options.workspace.clone())
}

/// Resolve a workspace and fail if none is configured or auto-detectable.
pub fn require_workspace(options: &CommonCommandOptions, purpose: &str) -> Result<WorkspaceRoot> {
    load_optional_workspace(options)?.ok_or_else(|| Error::Config {
        message: format!("Workspace is required for {}", purpose),
    })
}

/// Fully resolved command execution context.
pub struct ExecutionContext {
    pub member_id: String,
    pub key_ctx: CryptoContext,
    pub keystore_root: PathBuf,
    pub workspace_root: Option<WorkspaceRoot>,
}

impl ExecutionContext {
    /// Resolve workspace, signer, member ID, and key material for a command.
    pub fn load(
        options: &CommonCommandOptions,
        member_id: Option<String>,
        explicit_kid: Option<&str>,
        ssh_ctx: SshSigningContext,
    ) -> Result<Self> {
        let workspace_root = load_optional_workspace(options)?;
        let base_dir = options.resolve_base_dir()?;
        let member_id = resolve_member_id(member_id, Some(base_dir.as_path()))?;

        let keystore_root = options.resolve_keystore_root()?;
        let key_ctx = CryptoContext::load(
            &member_id,
            ssh_ctx.backend.as_ref(),
            &ssh_ctx.public_key,
            explicit_kid,
            Some(&keystore_root),
            workspace_root.as_ref().map(|w| w.root_path.clone()),
            options.verbose,
        )?;

        Ok(Self {
            member_id,
            key_ctx,
            keystore_root,
            workspace_root,
        })
    }

    /// Dispatch to SSH-based or environment variable key loading.
    ///
    /// When `ssh_ctx` is `None`, env-var mode is assumed and
    /// `load_from_env()` handles key resolution.
    pub fn resolve(
        options: &CommonCommandOptions,
        member_id: Option<String>,
        explicit_kid: Option<&str>,
        ssh_ctx: Option<SshSigningContext>,
    ) -> Result<Self> {
        match ssh_ctx {
            Some(ctx) => Self::load(options, member_id, explicit_kid, ctx),
            None => {
                if member_id.is_some() {
                    tracing::warn!(
                        "Ignoring --member-id in environment variable key mode \
                         (member_id is derived from SECRETENV_PRIVATE_KEY)"
                    );
                }
                Self::load_from_env(options)
            }
        }
    }

    /// Load execution context from environment variables (CI mode).
    ///
    /// Uses SECRETENV_PRIVATE_KEY and SECRETENV_KEY_PASSWORD instead of
    /// the local keystore and SSH key decryption. Requires a workspace.
    pub fn load_from_env(options: &CommonCommandOptions) -> Result<Self> {
        let workspace_root =
            require_workspace(options, "environment variable key loading (CI mode)")?;
        let keystore_root = options.resolve_keystore_root()?;

        let key_ctx = CryptoContext::load_from_env(workspace_root.root_path.clone())?;
        let member_id = key_ctx.member_id.clone();

        Ok(Self {
            member_id,
            key_ctx,
            keystore_root,
            workspace_root: Some(workspace_root),
        })
    }
}

/// Build SshSigningParams from CommonCommandOptions.
///
/// Determinism check is disabled by default. Key generation commands
/// should call `with_determinism_check` to enable it.
pub fn build_ssh_signing_params(options: &CommonCommandOptions) -> SshSigningParams {
    SshSigningParams {
        ssh_key: options.identity.clone(),
        signing_method: options.ssh_signer,
        base_dir: options.home.clone(),
        verbose: options.verbose,
        check_determinism: false,
    }
}

/// Resolve SSH key candidates (Phase 1 wrapper).
pub fn resolve_ssh_key_candidates(options: &CommonCommandOptions) -> Result<Vec<SshKeyCandidate>> {
    let params = build_ssh_signing_params(options);
    feature_resolve_ssh_key_candidates(&params)
}

/// Build SSH signing context from selected public key (Phase 3 wrapper).
pub fn build_ssh_signing_context(
    options: &CommonCommandOptions,
    selected_pubkey: &str,
    check_determinism: bool,
) -> Result<SshSigningContext> {
    let mut params = build_ssh_signing_params(options);
    params.check_determinism = check_determinism;
    feature_build_ssh_signing_context(&params, selected_pubkey)
}

/// Resolve SSH signing context by matching the active key's SSH fingerprint
/// against ssh-agent candidates. No interactive selection.
pub fn resolve_ssh_context_by_active_key(
    options: &CommonCommandOptions,
) -> Result<SshSigningContext> {
    let base_dir = options.resolve_base_dir()?;
    let member_id = resolve_member_id(None, Some(base_dir.as_path()))?;
    let keystore_root = options.resolve_keystore_root()?;

    let kid = load_active_kid(&member_id, &keystore_root)?.ok_or_else(|| Error::NotFound {
        message: format!("No active key for member: {}", member_id),
    })?;
    let private_key = load_private_key(&keystore_root, &member_id, &kid)?;
    let target_fpr = match &private_key.protected.alg {
        PrivateKeyAlgorithm::SshSig { fpr, .. } => fpr.as_str(),
        _ => {
            return Err(crate::Error::Crypto {
                message: "Expected SshSig algorithm for SSH signing context".to_string(),
                source: None,
            });
        }
    };

    let candidates = resolve_ssh_key_candidates(options)?;
    let matched = find_candidate_by_fingerprint(&candidates, target_fpr)?;
    build_ssh_signing_context(options, &matched.public_key, false)
}
