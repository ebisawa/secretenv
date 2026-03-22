// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unified SSH signing context resolution.
//!
//! Provides a single entry point (`resolve_ssh_signing_context`) for resolving
//! all SSH signing configuration, replacing the previously duplicated logic in
//! `cli/common/setup/ssh.rs` and `feature/key/ssh.rs`.

use crate::config::resolution::common::{resolve_ssh_add_path, resolve_ssh_keygen_path};
use crate::config::resolution::ssh_key::{
    resolve_ssh_key_candidate, resolve_ssh_key_descriptor, SshKeySource,
};
use crate::config::resolution::ssh_signer::{resolve_ssh_signer, resolve_ssh_signer_config};
use crate::config::types::SshSigner;
use crate::io::ssh::backend::{build_backend, SignatureBackend};
use crate::io::ssh::external::add::DefaultSshAdd;
use crate::io::ssh::external::keygen::DefaultSshKeygen;
use crate::io::ssh::external::pubkey::{
    load_ed25519_keys_from_agent, load_ssh_key_candidate_from_file, SshKeyCandidate,
};
use crate::io::ssh::protocol::constants as ssh;
use crate::io::ssh::protocol::{build_sha256_fingerprint, SshKeyDescriptor};
use crate::model::identifiers::context::SSH_DETERMINISM_CHECK_MESSAGE;
use crate::model::ssh::SshDeterminismStatus;
use crate::support::path::display_path_relative_to_cwd;
use crate::{Error, Result};
use std::path::PathBuf;
use tracing::debug;

const NON_DETERMINISTIC_SIGNATURE_MESSAGE: &str =
    "Non-deterministic signature detected: same input produced different signatures";

/// Input parameters for SSH signing context resolution (CLI-type independent).
pub struct SshSigningParams {
    pub ssh_key: Option<PathBuf>,
    pub signing_method: Option<SshSigner>,
    pub base_dir: Option<PathBuf>,
    pub verbose: bool,
}

/// Resolved SSH signing context.
pub struct SshSigningContext {
    pub signing_method: SshSigner,
    pub public_key: String,
    pub fingerprint: String,
    pub backend: Box<dyn SignatureBackend>,
    pub determinism: SshDeterminismStatus,
}

struct ResolvedSshCommands {
    ssh_keygen_path: String,
    ssh_add_path: String,
}

/// Resolve SSH key candidates from the given parameters.
///
/// Returns a list of candidate keys that can be used for signing.
/// For explicit key or ssh-keygen mode, returns a single candidate.
/// For ssh-agent mode without an explicit key, returns all Ed25519 keys
/// found in the agent.
pub fn resolve_ssh_key_candidates(params: &SshSigningParams) -> Result<Vec<SshKeyCandidate>> {
    let base_dir = params.base_dir.as_deref();
    let signing_method = resolve_signing_method(params, base_dir)?;
    let commands = resolve_ssh_commands(base_dir)?;
    let ssh_keygen = DefaultSshKeygen::new(commands.ssh_keygen_path.clone());
    let ssh_add = DefaultSshAdd::new(commands.ssh_add_path.clone());

    match signing_method {
        SshSigner::SshKeygen => {
            let descriptor = resolve_ssh_key_descriptor(params.ssh_key.clone(), base_dir)?;
            let candidate = load_ssh_key_candidate_from_file(&ssh_keygen, &descriptor)?;
            Ok(vec![candidate])
        }
        SshSigner::SshAgent => {
            let resolved = resolve_ssh_key_candidate(params.ssh_key.clone(), base_dir)?;
            let is_explicit = resolved.source != SshKeySource::Default;

            if is_explicit {
                if !resolved.exists {
                    return Err(build_not_found_error(&resolved));
                }
                let descriptor = SshKeyDescriptor::from_path(resolved.path);
                let candidate = load_ssh_key_candidate_from_file(&ssh_keygen, &descriptor)?;
                Ok(vec![candidate])
            } else {
                load_ed25519_keys_from_agent(&ssh_add)
            }
        }
    }
}

/// Build an SSH signing context from already-selected public key.
///
/// Re-resolves signing method and SSH commands (cheap config lookups),
/// validates the key, computes fingerprint, builds backend, and probes
/// determinism.
pub fn build_ssh_signing_context(
    params: &SshSigningParams,
    selected_pubkey: &str,
) -> Result<SshSigningContext> {
    let base_dir = params.base_dir.as_deref();
    let signing_method = resolve_signing_method(params, base_dir)?;
    let commands = resolve_ssh_commands(base_dir)?;

    validate_ssh_key_type(selected_pubkey)?;
    let fingerprint = build_sha256_fingerprint(selected_pubkey)?;

    let key_descriptor = resolve_key_descriptor_lenient(&params.ssh_key, base_dir);

    let backend = {
        let ssh_keygen = Box::new(DefaultSshKeygen::new(commands.ssh_keygen_path.clone()));
        build_backend(signing_method, ssh_keygen, key_descriptor)
    };

    let determinism = probe_determinism(backend.as_ref(), selected_pubkey, params.verbose)?;

    Ok(SshSigningContext {
        signing_method,
        public_key: selected_pubkey.to_string(),
        fingerprint,
        backend,
        determinism,
    })
}

/// Resolve a complete SSH signing context from the given parameters.
///
/// Temporary wrapper that resolves candidates and picks the first one.
pub fn resolve_ssh_signing_context(params: &SshSigningParams) -> Result<SshSigningContext> {
    let candidates = resolve_ssh_key_candidates(params)?;
    let first = candidates.first().ok_or_else(|| Error::NotFound {
        message: "No SSH Ed25519 keys found. Check ssh-agent or specify a key with -i.".to_string(),
    })?;
    build_ssh_signing_context(params, &first.public_key)
}

/// Resolve key descriptor, falling back to the config-resolved candidate path.
///
/// For agent mode without an explicit key, `resolve_ssh_key_descriptor` may
/// fail because the default key file doesn't exist. In that case we still
/// need a descriptor for the backend, so we fall back to the candidate path.
fn resolve_key_descriptor_lenient(
    ssh_key: &Option<PathBuf>,
    base_dir: Option<&std::path::Path>,
) -> SshKeyDescriptor {
    resolve_ssh_key_descriptor(ssh_key.clone(), base_dir).unwrap_or_else(|_| {
        let candidate = resolve_ssh_key_candidate(ssh_key.clone(), base_dir);
        let path = candidate
            .map(|c| c.path)
            .unwrap_or_else(|_| PathBuf::from("~/.ssh/id_ed25519"));
        SshKeyDescriptor::from_path(path)
    })
}

/// Build a NotFound error for a non-existent explicit SSH key.
fn build_not_found_error(candidate: &crate::config::resolution::ssh_key::ResolvedSshKey) -> Error {
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

fn resolve_signing_method(
    params: &SshSigningParams,
    base_dir: Option<&std::path::Path>,
) -> Result<SshSigner> {
    let signing_method_config = resolve_ssh_signer_config(params.signing_method, base_dir)?;
    let signing_method = resolve_ssh_signer(signing_method_config);

    if params.verbose {
        debug!("[SSH] Signing method: {}", signing_method);
    }

    Ok(signing_method)
}

fn resolve_ssh_commands(base_dir: Option<&std::path::Path>) -> Result<ResolvedSshCommands> {
    Ok(ResolvedSshCommands {
        ssh_keygen_path: resolve_ssh_keygen_path(base_dir)?,
        ssh_add_path: resolve_ssh_add_path(base_dir)?,
    })
}

fn probe_determinism(
    backend: &dyn SignatureBackend,
    ssh_pub: &str,
    verbose: bool,
) -> Result<SshDeterminismStatus> {
    let determinism = match backend.check_determinism(ssh_pub, SSH_DETERMINISM_CHECK_MESSAGE) {
        Ok(()) => Ok(SshDeterminismStatus::Verified),
        Err(error) if is_non_deterministic_signature_error(&error) => Ok(
            SshDeterminismStatus::Failed {
            message: "SSH signature determinism check failed. This SSH key cannot be used for key generation.".to_string(),
            },
        ),
        Err(error) => Err(error),
    };
    if verbose {
        match &determinism {
            Ok(status) => debug!("[SSH] Determinism check: {}", status.is_verified()),
            Err(error) => debug!("[SSH] Determinism check failed: {}", error),
        }
    }
    determinism
}

fn is_non_deterministic_signature_error(error: &Error) -> bool {
    error
        .to_string()
        .contains(NON_DETERMINISTIC_SIGNATURE_MESSAGE)
}

/// Validate that SSH key type is Ed25519.
fn validate_ssh_key_type(ssh_pub: &str) -> Result<()> {
    let key_type = ssh_pub.split_whitespace().next().unwrap_or("unknown");
    if key_type != ssh::KEY_TYPE_ED25519 {
        return Err(Error::InvalidArgument {
            message: format!("Only Ed25519 SSH keys are supported. Got: {}", key_type),
        });
    }
    Ok(())
}
