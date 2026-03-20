// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH agent backend implementation

use super::signature_backend::SignatureBackend;
use crate::io::ssh::agent::traits::AgentSigner;
use crate::io::ssh::protocol::sshsig;
use crate::io::ssh::protocol::types::Ed25519RawSignature;
use crate::io::ssh::SshError;
use crate::Result;

/// ssh-agent backend (Method A)
///
/// Communicates directly with ssh-agent via SSH_AUTH_SOCK.
/// Requires:
/// - `SSH_AUTH_SOCK` environment variable set
/// - Target key loaded in ssh-agent
pub struct SshAgentBackend {
    agent_signer: Box<dyn AgentSigner>,
}

impl SshAgentBackend {
    pub fn new(agent_signer: Box<dyn AgentSigner>) -> Self {
        Self { agent_signer }
    }
}

impl SignatureBackend for SshAgentBackend {
    fn sign_for_ikm(
        &self,
        ssh_pubkey: &str,
        challenge_bytes: &[u8],
    ) -> Result<Ed25519RawSignature> {
        let sshsig_signed_data = sshsig::build_sshsig_signed_data(challenge_bytes);

        // agent_signer.sign returns Ed25519RawSignature directly
        self.agent_signer
            .sign(ssh_pubkey, &sshsig_signed_data)
            .map_err(|e| {
                crate::Error::from(SshError::operation_failed_with_source(
                    format!(
                        "ssh-agent signing failed: {}\n\
                    Diagnostic: The error message above should include the agent socket path.\n\
                    Ensure the key is loaded in that agent.\n\
                    Alternative: Set config 'ssh_signer: ssh-keygen'",
                        e
                    ),
                    e,
                ))
            })
    }
}
