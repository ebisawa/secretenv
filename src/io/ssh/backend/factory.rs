// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Signature backend factory

use super::signature_backend::SignatureBackend;
use super::ssh_agent::SshAgentBackend;
use super::ssh_keygen::SshKeygenBackend;
use crate::config::types::SshSigner;
use crate::io::ssh::agent::client::DefaultAgentSigner;
use crate::io::ssh::external::traits::SshKeygen;
use crate::io::ssh::protocol::key_descriptor::SshKeyDescriptor;

/// Factory: create backend based on config
///
/// # Arguments
///
/// * `method` - Signing method from config (SshAgent or SshKeygen)
/// * `ssh_keygen` - Implementation of the `SshKeygen` trait (used only for SshKeygen method)
/// * `key_descriptor` - SSH key descriptor (private or public key, used only for SshKeygen method)
///
/// # Returns
///
/// Boxed SignatureBackend implementation
pub fn build_backend(
    method: SshSigner,
    ssh_keygen: Box<dyn SshKeygen>,
    key_descriptor: SshKeyDescriptor,
) -> Box<dyn SignatureBackend> {
    match method {
        SshSigner::SshAgent => Box::new(SshAgentBackend::new(Box::new(DefaultAgentSigner))),
        SshSigner::SshKeygen => Box::new(SshKeygenBackend::new(ssh_keygen, key_descriptor)),
    }
}
