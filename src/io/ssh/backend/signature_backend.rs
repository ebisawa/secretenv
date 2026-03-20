// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Signature backend trait

use crate::io::ssh::protocol::types::Ed25519RawSignature;
use crate::io::ssh::SshError;
use crate::Result;

/// Signature backend producing SSHSIG-compatible signature blobs (IKM)
///
/// This trait abstracts the signature acquisition mechanism.
/// Both implementations (ssh-agent and ssh-keygen) produce equivalent IKM:
/// Ed25519 raw signature bytes (64 bytes, RFC 8709), derived from the SSH
/// signature blob (SSH wire `string algorithm` + `string signature`).
pub trait SignatureBackend {
    /// Sign challenge_bytes and return signature blob (IKM)
    ///
    /// # Arguments
    ///
    /// * `ssh_pubkey` - SSH public key in authorized_keys format
    /// * `challenge_bytes` - Data to sign (will be wrapped in SSHSIG signed_data)
    ///
    /// # Returns
    ///
    /// Ed25519 raw signature (64 bytes) suitable for use as IKM in SA-SIG-KDF.
    ///
    /// # Errors
    ///
    /// Returns detailed diagnostic errors if signing fails
    fn sign_for_ikm(&self, ssh_pubkey: &str, challenge_bytes: &[u8])
        -> Result<Ed25519RawSignature>;

    /// Sign challenge bytes and ensure the derived IKM is deterministic.
    ///
    /// This signs the same challenge twice and returns the first signature only
    /// when both results match byte-for-byte.
    fn sign_deterministic_for_ikm(
        &self,
        ssh_pubkey: &str,
        challenge_bytes: &[u8],
    ) -> Result<Ed25519RawSignature> {
        let sig1 = self.sign_for_ikm(ssh_pubkey, challenge_bytes)?;
        let sig2 = self.sign_for_ikm(ssh_pubkey, challenge_bytes)?;

        if sig1 != sig2 {
            return Err(SshError::operation_failed(
                "Non-deterministic signature detected: same input produced different signatures",
            )
            .into());
        }

        Ok(sig1)
    }

    /// Check that signing is deterministic
    ///
    /// Signs the same challenge twice and verifies identical output.
    /// This is critical for SA-SIG-KDF correctness.
    ///
    /// # Errors
    ///
    /// Returns error if signatures differ or signing fails
    fn check_determinism(&self, ssh_pubkey: &str, challenge_bytes: &[u8]) -> Result<()> {
        let _ = self.sign_deterministic_for_ikm(ssh_pubkey, challenge_bytes)?;
        Ok(())
    }
}
