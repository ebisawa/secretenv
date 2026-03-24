// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use crate::app::context::crypto::{load_crypto_context, load_crypto_context_from_env};
use crate::app::context::member::resolve_member_context;
use crate::app::context::options::CommonCommandOptions;
use crate::app::context::paths::ResolvedCommandPaths;
use crate::feature::context::crypto::CryptoContext;
use crate::feature::context::ssh::SshSigningContext;
use crate::{Error, Result};

/// Fully resolved command execution context.
pub struct ExecutionContext {
    pub member_id: String,
    pub key_ctx: CryptoContext,
    pub keystore_root: PathBuf,
    pub workspace_root: Option<crate::io::workspace::detection::WorkspaceRoot>,
}

impl ExecutionContext {
    /// Resolve workspace, signer, member ID, and key material for a command.
    pub fn load(
        options: &CommonCommandOptions,
        member_id: Option<String>,
        explicit_kid: Option<&str>,
        ssh_ctx: SshSigningContext,
    ) -> Result<Self> {
        let resolved = resolve_member_context(options, member_id)?;
        let workspace_root = resolved.paths.workspace_root.clone();
        let keystore_root = resolved.paths.keystore_root.clone();
        let key_ctx = load_crypto_context(
            &resolved.member_id,
            ssh_ctx.backend.as_ref(),
            &ssh_ctx.public_key,
            explicit_kid,
            Some(&keystore_root),
            workspace_root.as_ref().map(|w| w.root_path.clone()),
            options.verbose,
        )?;

        Ok(Self {
            member_id: resolved.member_id,
            key_ctx,
            keystore_root,
            workspace_root,
        })
    }

    /// Dispatch to SSH-based or environment variable key loading.
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
                    return Err(Error::InvalidArgument {
                        message: "--member-id cannot be used in environment variable key mode \
                                 (member_id is derived from SECRETENV_PRIVATE_KEY)"
                            .to_string(),
                    });
                }
                if explicit_kid.is_some() {
                    return Err(Error::InvalidArgument {
                        message: "--kid cannot be used in environment variable key mode \
                                 (kid is derived from SECRETENV_PRIVATE_KEY)"
                            .to_string(),
                    });
                }
                Self::load_from_env(options)
            }
        }
    }

    /// Load execution context from environment variables (CI mode).
    pub fn load_from_env(options: &CommonCommandOptions) -> Result<Self> {
        let resolved = ResolvedCommandPaths::require_workspace(
            options,
            "environment variable key loading (CI mode)",
        )?;
        let workspace_root = resolved.workspace_root.expect("workspace required");
        let keystore_root = resolved.keystore_root;
        let key_ctx =
            load_crypto_context_from_env(workspace_root.root_path.clone(), options.verbose)?;
        let member_id = key_ctx.member_id.clone();

        Ok(Self {
            member_id,
            key_ctx,
            keystore_root,
            workspace_root: Some(workspace_root),
        })
    }
}
