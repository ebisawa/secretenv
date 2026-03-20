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
use crate::config::resolution::ssh_signer::{
    resolve_ssh_signer_config, resolve_ssh_signer_with_key,
};
use crate::config::types::SshSigner;
use crate::io::ssh::backend::{build_backend, SignatureBackend};
use crate::io::ssh::external::add::DefaultSshAdd;
use crate::io::ssh::external::keygen::DefaultSshKeygen;
use crate::io::ssh::external::pubkey::{
    load_ssh_public_key_from_agent_with_ssh_add, load_ssh_public_key_with_descriptor_trait,
};
use crate::io::ssh::external::traits::SshKeygen;
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

struct ResolvedSshKeyMaterial {
    signing_method: SshSigner,
    key_descriptor: SshKeyDescriptor,
    public_key: String,
    fingerprint: String,
}

/// Resolve a complete SSH signing context from the given parameters.
///
/// 1. Resolves signing method (auto / ssh-agent / ssh-keygen)
/// 2. Resolves SSH command paths (ssh-keygen, ssh-add)
/// 3. Resolves SSH key and loads public key
/// 4. Validates Ed25519 key type
/// 5. Computes fingerprint
/// 6. Builds signature backend
/// 7. Checks determinism
pub fn resolve_ssh_signing_context(params: &SshSigningParams) -> Result<SshSigningContext> {
    let base_dir = params.base_dir.as_deref();
    let signing_method = resolve_signing_method(params, base_dir)?;
    let commands = resolve_ssh_commands(base_dir)?;
    let key_material = resolve_ssh_key_material(params, signing_method, &commands, base_dir)?;
    let backend = build_signature_backend(&key_material, &commands);
    let determinism =
        probe_determinism(backend.as_ref(), &key_material.public_key, params.verbose)?;

    Ok(SshSigningContext {
        signing_method: key_material.signing_method,
        public_key: key_material.public_key,
        fingerprint: key_material.fingerprint,
        backend,
        determinism,
    })
}

fn resolve_signing_method(
    params: &SshSigningParams,
    base_dir: Option<&std::path::Path>,
) -> Result<SshSigner> {
    let signing_method_config = resolve_ssh_signer_config(params.signing_method, base_dir)?;
    let signing_method =
        resolve_ssh_signer_with_key(signing_method_config, params.ssh_key.is_some());

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

fn resolve_ssh_key_material(
    params: &SshSigningParams,
    signing_method: SshSigner,
    commands: &ResolvedSshCommands,
    base_dir: Option<&std::path::Path>,
) -> Result<ResolvedSshKeyMaterial> {
    let ssh_keygen = DefaultSshKeygen::new(commands.ssh_keygen_path.clone());
    let ssh_add = DefaultSshAdd::new(commands.ssh_add_path.clone());
    let (key_descriptor, public_key) = resolve_key_and_pubkey(
        signing_method,
        &params.ssh_key,
        &ssh_keygen,
        &ssh_add,
        base_dir,
    )?;

    validate_ssh_key_type(&public_key)?;
    let fingerprint = build_sha256_fingerprint(&public_key)?;

    Ok(ResolvedSshKeyMaterial {
        signing_method,
        key_descriptor,
        public_key,
        fingerprint,
    })
}

fn build_signature_backend(
    key_material: &ResolvedSshKeyMaterial,
    commands: &ResolvedSshCommands,
) -> Box<dyn SignatureBackend> {
    let ssh_keygen = Box::new(DefaultSshKeygen::new(commands.ssh_keygen_path.clone()));
    build_backend(
        key_material.signing_method,
        ssh_keygen,
        key_material.key_descriptor.clone(),
    )
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

/// Resolve SSH key descriptor and load the public key.
fn resolve_key_and_pubkey(
    signing_method: SshSigner,
    ssh_key: &Option<PathBuf>,
    ssh_keygen: &dyn SshKeygen,
    ssh_add: &DefaultSshAdd,
    base_dir: Option<&std::path::Path>,
) -> Result<(SshKeyDescriptor, String)> {
    match signing_method {
        SshSigner::SshAgent => resolve_key_and_pubkey_agent(ssh_key.clone(), ssh_add, base_dir),
        SshSigner::SshKeygen => {
            resolve_key_and_pubkey_keygen(ssh_key.clone(), ssh_keygen, base_dir)
        }
    }
}

/// Resolve key and public key for ssh-agent mode.
fn resolve_key_and_pubkey_agent(
    ssh_key: Option<PathBuf>,
    ssh_add: &DefaultSshAdd,
    base_dir: Option<&std::path::Path>,
) -> Result<(SshKeyDescriptor, String)> {
    let candidate = resolve_ssh_key_candidate(ssh_key, base_dir)?;

    // If explicitly specified but file doesn't exist, error
    if !candidate.exists && candidate.source != SshKeySource::Default {
        let source_str = match candidate.source {
            SshKeySource::Cli => "CLI option",
            SshKeySource::Env => "SECRETENV_SSH_KEY",
            SshKeySource::GlobalConfig => "global config",
            SshKeySource::Default => unreachable!(),
        };
        return Err(Error::NotFound {
            message: format!(
                "SSH key file from {} does not exist: {}",
                source_str,
                display_path_relative_to_cwd(&candidate.path)
            ),
        });
    }

    let ssh_pub = load_ssh_public_key_from_agent_with_ssh_add(ssh_add)?;
    let descriptor = SshKeyDescriptor::from_path(candidate.path);

    Ok((descriptor, ssh_pub))
}

/// Resolve key and public key for ssh-keygen mode.
fn resolve_key_and_pubkey_keygen(
    ssh_key: Option<PathBuf>,
    ssh_keygen: &dyn SshKeygen,
    base_dir: Option<&std::path::Path>,
) -> Result<(SshKeyDescriptor, String)> {
    let descriptor = resolve_ssh_key_descriptor(ssh_key, base_dir)?;
    let ssh_pub = load_ssh_public_key_with_descriptor_trait(ssh_keygen, &descriptor)?;

    Ok((descriptor, ssh_pub))
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
