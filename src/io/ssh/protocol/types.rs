// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH signature type safety
//!
//! Provides type-safe wrappers for different SSH signature formats to prevent
//! confusion between raw Ed25519 signatures, SSH signature blobs, and SSHSIG blobs.

use super::constants as ssh;
use super::sshsig::parse_sshsig_blob;
use super::wire::ssh_string_decode;
use crate::io::ssh::SshError;
use crate::Result;
use zeroize::Zeroizing;

/// Ed25519 raw signature (64 bytes)
///
/// This is the canonical form used as IKM (Input Keying Material) for key derivation.
/// It represents the raw Ed25519 signature bytes as specified in RFC 8709.
///
/// This is wrapped in Zeroizing for secure memory clearing, as it is used as
/// input keying material for key derivation and contains sensitive cryptographic data.
#[derive(Debug, Clone)]
pub struct Ed25519RawSignature(Zeroizing<[u8; 64]>);

impl PartialEq for Ed25519RawSignature {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.0.as_ref().ct_eq(other.0.as_ref()).into()
    }
}

impl Eq for Ed25519RawSignature {}

impl Ed25519RawSignature {
    /// Create a new Ed25519RawSignature from 64 bytes
    ///
    /// # Arguments
    ///
    /// * `bytes` - Exactly 64 bytes of Ed25519 signature data
    pub fn new(bytes: [u8; 64]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Get the raw signature bytes
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Convert to a vector of bytes
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Try to create from a slice
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is not exactly 64 bytes
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(SshError::operation_failed(format!(
                "Invalid Ed25519 signature length: expected 64 bytes, got {}",
                bytes.len()
            ))
            .into());
        }
        let mut out = [0u8; 64];
        out.copy_from_slice(bytes);
        Ok(Self(Zeroizing::new(out)))
    }
}

/// SSH signature blob (SSH wire format)
///
/// Format: `string algorithm` + `string signature`
/// This is the format returned by SSHSIG parsing and used in SSH protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshSignatureBlob(Vec<u8>);

impl SshSignatureBlob {
    /// Create a new SshSignatureBlob from bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Extract Ed25519 raw signature from SSH signature blob
    ///
    /// Parses the SSH wire format (`string algorithm` + `string signature`)
    /// and extracts the raw 64-byte Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The blob is not a valid SSH string format
    /// - The algorithm is not "ssh-ed25519"
    /// - The signature is not exactly 64 bytes
    pub fn extract_ed25519_raw(&self) -> Result<Ed25519RawSignature> {
        // Fast-path: already raw Ed25519 signature bytes.
        if self.0.len() == 64 {
            let mut out = [0u8; 64];
            out.copy_from_slice(&self.0);
            return Ok(Ed25519RawSignature::new(out));
        }

        // Otherwise, interpret as SSH signature blob:
        //   string algorithm
        //   string signature
        let (algo, rest) = ssh_string_decode(&self.0)?;
        if algo != ssh::KEY_TYPE_ED25519.as_bytes() {
            return Err(SshError::operation_failed(format!(
                "Unsupported SSH signature algorithm '{}': expected '{}'",
                String::from_utf8_lossy(algo),
                ssh::KEY_TYPE_ED25519
            ))
            .into());
        }

        let (sig, rest) = ssh_string_decode(rest)?;
        if !rest.is_empty() {
            return Err(
                SshError::operation_failed("Invalid SSH signature blob: trailing bytes").into(),
            );
        }
        if sig.len() != 64 {
            return Err(SshError::operation_failed(format!(
                "Invalid Ed25519 signature length: expected 64 bytes, got {}",
                sig.len()
            ))
            .into());
        }

        let mut out = [0u8; 64];
        out.copy_from_slice(sig);
        Ok(Ed25519RawSignature::new(out))
    }
}

/// SSHSIG blob (complete SSHSIG format)
///
/// Format: magic + version + publickey + namespace + reserved + hashalg + signature
/// This is the complete binary SSHSIG format.
#[derive(Debug, Clone)]
pub struct SshsigBlob(Vec<u8>);

impl SshsigBlob {
    /// Create a new SshsigBlob from bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Extract SSH signature blob from SSHSIG blob
    ///
    /// Parses the SSHSIG format and extracts the signature field (SSH signature blob).
    ///
    /// # Errors
    ///
    /// Returns an error if the blob is not a valid SSHSIG format
    pub fn extract_signature_blob(&self) -> Result<SshSignatureBlob> {
        parse_sshsig_blob(self.as_bytes())
    }

    /// Extract Ed25519 raw signature from SSHSIG blob (convenience method)
    ///
    /// This is a convenience method that combines `extract_signature_blob()` and
    /// `extract_ed25519_raw()`.
    ///
    /// # Errors
    ///
    /// Returns an error if the blob is not a valid SSHSIG format or if the
    /// signature cannot be extracted
    pub fn extract_ed25519_raw(&self) -> Result<Ed25519RawSignature> {
        let sig_blob = self.extract_signature_blob()?;
        sig_blob.extract_ed25519_raw()
    }
}

/// SSHSIG armored format (Base64-encoded SSHSIG)
///
/// Format: Base64-encoded SSHSIG blob with BEGIN/END markers
/// This is the format output by `ssh-keygen -Y sign`.
#[derive(Debug, Clone)]
pub struct SshsigArmored(String);

impl SshsigArmored {
    /// Create a new SshsigArmored from a string
    pub fn new(armored: String) -> Self {
        Self(armored)
    }

    /// Get the armored string
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Extract SSHSIG blob from armored format
    ///
    /// Decodes the base64 content and returns the SSHSIG blob.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No base64 content is found
    /// - Base64 decoding fails
    pub fn extract_blob(&self) -> Result<SshsigBlob> {
        use super::base64::decode_base64_armored;
        let blob = decode_base64_armored(self.as_str())?;
        Ok(SshsigBlob::new(blob))
    }

    /// Extract Ed25519 raw signature from armored format (convenience method)
    ///
    /// This is a convenience method that combines `extract_blob()`,
    /// `extract_signature_blob()`, and `extract_ed25519_raw()`.
    ///
    /// # Errors
    ///
    /// Returns an error if the armored format is invalid or if the signature
    /// cannot be extracted
    pub fn extract_ed25519_raw(&self) -> Result<Ed25519RawSignature> {
        let blob = self.extract_blob()?;
        blob.extract_ed25519_raw()
    }
}
