// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::config::resolution::common::{resolve_ssh_add_path, resolve_ssh_keygen_path};
use crate::config::resolution::ssh_key::{
    resolve_ssh_key_candidate, resolve_ssh_key_descriptor, ResolvedSshKey, SshKeySource,
};
use crate::config::resolution::ssh_signer::{resolve_ssh_signer, resolve_ssh_signer_config};
use crate::config::types::SshSigner;
use crate::feature::context::ssh::params::{ResolvedSshCommands, SshSigningParams};
use crate::io::ssh::protocol::SshKeyDescriptor;
use crate::support::path::display_path_relative_to_cwd;
use crate::{Error, Result};
use std::path::{Path, PathBuf};
use tracing::debug;

pub(crate) fn resolve_signing_method(
    params: &SshSigningParams,
    base_dir: Option<&Path>,
) -> Result<SshSigner> {
    let signing_method_config = resolve_ssh_signer_config(params.signing_method, base_dir)?;
    let signing_method = resolve_ssh_signer(signing_method_config);

    if params.verbose {
        debug!("[SSH] Signing method: {}", signing_method);
    }

    Ok(signing_method)
}

pub(crate) fn resolve_ssh_commands(base_dir: Option<&Path>) -> Result<ResolvedSshCommands> {
    Ok(ResolvedSshCommands {
        ssh_keygen_path: resolve_ssh_keygen_path(base_dir)?,
        ssh_add_path: resolve_ssh_add_path(base_dir)?,
    })
}

pub(crate) fn resolve_key_descriptor_lenient(
    ssh_key: &Option<PathBuf>,
    base_dir: Option<&Path>,
) -> SshKeyDescriptor {
    resolve_ssh_key_descriptor(ssh_key.clone(), base_dir).unwrap_or_else(|_| {
        let candidate = resolve_ssh_key_candidate(ssh_key.clone(), base_dir);
        let path = candidate
            .map(|resolved| resolved.path)
            .unwrap_or_else(|_| PathBuf::from("~/.ssh/id_ed25519"));
        SshKeyDescriptor::from_path(path)
    })
}

pub(crate) fn build_not_found_error(candidate: &ResolvedSshKey) -> Error {
    let source_str = match candidate.source {
        SshKeySource::Cli => "CLI option",
        SshKeySource::Env => "SECRETENV_SSH_KEY",
        SshKeySource::GlobalConfig => "global config",
        SshKeySource::Default => unreachable!(),
    };

    Error::NotFound {
        message: format!(
            "SSH key file from {} does not exist: {}",
            source_str,
            display_path_relative_to_cwd(&candidate.path)
        ),
    }
}
