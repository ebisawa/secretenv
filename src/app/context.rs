// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared command execution context resolution.

use crate::config::resolution::member_id::resolve_member_id;
use crate::config::types::SshSigner;
use crate::feature::context::crypto::CryptoContext;
use crate::feature::context::ssh::{resolve_ssh_signing_context, SshSigningParams};
use crate::io::config::paths::get_base_dir;
use crate::io::keystore::resolver::KeystoreResolver;
use crate::io::workspace::detection::{resolve_optional_workspace, WorkspaceRoot};
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
    ) -> Result<Self> {
        let workspace_root = load_optional_workspace(options)?;
        let base_dir = options.resolve_base_dir()?;
        let member_id = resolve_member_id(member_id, Some(base_dir.as_path()))?;

        let ssh_ctx = resolve_ssh_signing_context(&SshSigningParams {
            ssh_key: options.identity.clone(),
            signing_method: options.ssh_signer,
            base_dir: Some(base_dir.clone()),
            verbose: options.verbose,
        })?;

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
}
