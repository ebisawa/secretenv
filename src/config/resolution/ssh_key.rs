// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH Key resolution
//!
//! Resolves SSH key path based on the following priority order:
//! 1. CLI option (-i)
//! 2. Environment variable (SECRETENV_SSH_KEY)
//! 3. Global config (SECRETENV_HOME/config.toml)
//! 4. Default (~/.ssh/id_ed25519)

use crate::io::ssh::protocol::SshKeyDescriptor;
use crate::support::path::display_path_relative_to_cwd;
use crate::{Error, Result};
use std::path::{Path, PathBuf};

use super::common::{expand_tilde, get_default_ssh_key_path, resolve_string_with_priority};

/// Source of SSH key configuration
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshKeySource {
    /// CLI option (-i)
    Cli,
    /// Environment variable (SECRETENV_SSH_KEY)
    Env,
    /// Global config (SECRETENV_HOME/config.toml)
    GlobalConfig,
    /// Default path (~/.ssh/id_ed25519)
    Default,
}

/// Resolved SSH key information
#[derive(Debug, Clone)]
pub struct ResolvedSshKey {
    /// Resolved path
    pub path: PathBuf,
    /// Source of the configuration
    pub source: SshKeySource,
    /// Whether the file exists
    pub exists: bool,
}

/// Resolve SSH key candidate with source and existence information
///
/// This function returns a candidate even if the file doesn't exist,
/// allowing callers to make decisions based on the source and existence.
///
/// # Priority Order
///
/// 1. `ssh_key_opt` parameter (CLI option -i)
/// 2. `SECRETENV_SSH_KEY` environment variable
/// 3. Global config (`SECRETENV_HOME/config.toml`)
/// 4. Default path (`~/.ssh/id_ed25519`)
pub fn resolve_ssh_key_candidate(
    ssh_key_opt: Option<PathBuf>,
    base_dir: Option<&Path>,
) -> Result<ResolvedSshKey> {
    // Priority 1: CLI option
    if let Some(ssh_key) = ssh_key_opt {
        let exists = ssh_key.exists();
        return Ok(ResolvedSshKey {
            path: ssh_key,
            source: SshKeySource::Cli,
            exists,
        });
    }

    // Priority 2: Environment variable
    if let Ok(ssh_key_str) = std::env::var("SECRETENV_SSH_KEY") {
        let ssh_key = PathBuf::from(ssh_key_str);
        let exists = ssh_key.exists();
        return Ok(ResolvedSshKey {
            path: ssh_key,
            source: SshKeySource::Env,
            exists,
        });
    }

    // Priority 3: Global config
    if let Some(ssh_key_path_str) =
        resolve_string_with_priority(None, None, "ssh_key", base_dir, None)?
    {
        let expanded = expand_tilde(&ssh_key_path_str)?;
        let exists = expanded.exists();
        return Ok(ResolvedSshKey {
            path: expanded,
            source: SshKeySource::GlobalConfig,
            exists,
        });
    }

    // Priority 4: Default path (~/.ssh/id_ed25519)
    let default_path = get_default_ssh_key_path()?;
    let exists = default_path.exists();
    Ok(ResolvedSshKey {
        path: default_path,
        source: SshKeySource::Default,
        exists,
    })
}

/// Resolve SSH key path based on priority order (Phase 1.5)
///
/// This is a strict wrapper around `resolve_ssh_key_candidate()` that
/// enforces file existence for backward compatibility.
///
/// # Priority Order
///
/// 1. `ssh_key_opt` parameter (CLI option -i)
/// 2. `SECRETENV_SSH_KEY` environment variable
/// 3. Global config (`SECRETENV_HOME/config.toml`)
/// 4. Default path (`~/.ssh/id_ed25519`)
pub fn resolve_ssh_key(ssh_key_opt: Option<PathBuf>, base_dir: Option<&Path>) -> Result<PathBuf> {
    let candidate = resolve_ssh_key_candidate(ssh_key_opt, base_dir)?;

    if !candidate.exists {
        let source_str = match candidate.source {
            SshKeySource::Cli => "CLI option",
            SshKeySource::Env => "SECRETENV_SSH_KEY",
            SshKeySource::GlobalConfig => "global config",
            SshKeySource::Default => {
                return Err(Error::NotFound {
                    message:
                        "SSH key not configured and default path (~/.ssh/id_ed25519) not found"
                            .to_string(),
                });
            }
        };
        return Err(Error::NotFound {
            message: format!(
                "SSH key file from {} does not exist: {}",
                source_str,
                display_path_relative_to_cwd(&candidate.path)
            ),
        });
    }

    Ok(candidate.path)
}

/// Resolve SSH key descriptor with automatic key type detection
///
/// This function resolves the SSH key path using the same priority order as
/// `resolve_ssh_key()`, then automatically detects whether the key is a private
/// key or a public key (.pub file) and returns the appropriate descriptor.
///
/// # Priority Order
///
/// 1. `ssh_key_opt` parameter (CLI option -i)
/// 2. `SECRETENV_SSH_KEY` environment variable
/// 3. Global config (`SECRETENV_HOME/config.toml`)
/// 4. Default path (`~/.ssh/id_ed25519`)
///
/// # Key Type Detection
///
/// Files ending with `.pub` extension are treated as public keys.
/// All other files are treated as private keys.
pub fn resolve_ssh_key_descriptor(
    ssh_key_opt: Option<PathBuf>,
    base_dir: Option<&Path>,
) -> Result<SshKeyDescriptor> {
    let path = resolve_ssh_key(ssh_key_opt, base_dir)?;
    Ok(SshKeyDescriptor::from_path(path))
}
