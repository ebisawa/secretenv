// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH agent client for signing operations

use super::socket::resolve_agent_socket_path;
use super::traits::AgentSigner;
use super::validation::{find_key_in_agent, validate_agent_has_keys, validate_key_present};
use crate::io::ssh::protocol::parse::decode_ssh_public_key_blob;
use crate::io::ssh::protocol::types::Ed25519RawSignature;
use crate::io::ssh::SshError;
use crate::Result;
use ssh_agent_client_rs::Client;
use ssh_key::PublicKey;
use std::path::Path;

/// Default ssh-agent signer that communicates with a real ssh-agent.
pub struct DefaultAgentSigner;

impl AgentSigner for DefaultAgentSigner {
    fn sign(&self, ssh_pubkey: &str, message: &[u8]) -> Result<Ed25519RawSignature> {
        // Parse and validate public key
        decode_ssh_public_key_blob(ssh_pubkey)?;

        let public_key = PublicKey::from_openssh(ssh_pubkey).map_err(|e| {
            crate::Error::from(SshError::operation_failed_with_source(
                format!("invalid SSH public key: {}", e),
                e,
            ))
        })?;

        // Resolve socket path
        let socket_path = resolve_agent_socket_path()?;

        // Connect to agent
        let mut client = Client::connect(Path::new(&socket_path)).map_err(|e| {
            crate::Error::from(SshError::operation_failed_with_source(
                format!("ssh-agent connect failed: {}", e),
                e,
            ))
        })?;

        // List identities
        let identities = client.list_all_identities().map_err(|e| {
            crate::Error::from(SshError::operation_failed_with_source(
                format!("ssh-agent list identities failed: {}", e),
                e,
            ))
        })?;

        // Validate agent has keys
        validate_agent_has_keys(&mut client, &socket_path)?;

        // Check if target key is present
        let target_key_present = find_key_in_agent(&client, &identities, &public_key)?;
        validate_key_present(target_key_present, &socket_path)?;

        // Sign message
        let signature = client.sign(public_key, message).map_err(|e| {
            crate::Error::from(SshError::operation_failed_with_source(
                format!("ssh-agent sign failed: {}", e),
                e,
            ))
        })?;

        // ssh_key::Signature::as_bytes() returns raw 64-byte Ed25519 signature
        Ed25519RawSignature::from_slice(signature.as_bytes())
    }
}
