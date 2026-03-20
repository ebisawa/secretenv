// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Fixed-size cryptographic primitive types with type safety

/// AES-256-GCM nonce (12 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AesNonce([u8; 12]);

impl AesNonce {
    /// Create a new AES nonce from 12 bytes
    pub fn new(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    /// Get the nonce bytes
    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

impl_fixed_size_type!(AesNonce, 12, "AES nonce");

/// XChaCha20-Poly1305 nonce (24 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XChaChaNonce([u8; 24]);

impl XChaChaNonce {
    /// Size of XChaCha nonce in bytes
    pub const SIZE: usize = 24;

    /// Create a new XChaCha nonce from 24 bytes
    pub fn new(bytes: [u8; 24]) -> Self {
        Self(bytes)
    }

    /// Get the nonce bytes
    pub fn as_bytes(&self) -> &[u8; 24] {
        &self.0
    }
}

impl_fixed_size_type!(XChaChaNonce, 24, "XChaCha nonce");

/// HKDF salt (16 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Salt([u8; 16]);

impl Salt {
    /// Create a new salt from 16 bytes
    pub fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Get the salt bytes
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl_fixed_size_type!(Salt, 16, "salt");
