// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! AES-256-GCM symmetric encryption
//!
//! Key: 32 bytes, Nonce: 12 bytes (MUST be unique), Tag: 16 bytes (not truncated)

use crate::crypto::crypto_error;
use crate::crypto::types::data::{Aad, Ciphertext, Plaintext};
use crate::crypto::types::keys::AesKey;
use crate::crypto::types::primitives::AesNonce;
use crate::Result;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use zeroize::Zeroizing;

/// Encrypts plaintext using AES-256-GCM. Returns ciphertext with 16-byte tag appended.
pub fn encrypt(
    key: &AesKey,
    nonce: &AesNonce,
    aad: &Aad,
    plaintext: &Plaintext,
) -> Result<Ciphertext> {
    let cipher = Aes256Gcm::new(key.as_bytes().into());
    let nonce = Nonce::from_slice(nonce.as_bytes());

    cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext.as_bytes(),
                aad: aad.as_bytes(),
            },
        )
        .map(Ciphertext::from)
        .map_err(|e| crypto_error("AES-GCM encryption failed", format!("{}", e)))
}

/// Decrypts ciphertext using AES-256-GCM.
/// Returns plaintext wrapped in Zeroizing for secure memory clearing.
pub fn decrypt(
    key: &AesKey,
    nonce: &AesNonce,
    aad: &Aad,
    ciphertext: &Ciphertext,
) -> Result<Zeroizing<Plaintext>> {
    let cipher = Aes256Gcm::new(key.as_bytes().into());
    let nonce = Nonce::from_slice(nonce.as_bytes());

    let plaintext = cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: ciphertext.as_bytes(),
                aad: aad.as_bytes(),
            },
        )
        .map(|v| Zeroizing::new(Plaintext::from(v)))
        .map_err(|e| {
            crypto_error(
                "AES-GCM decryption failed (wrong key/AAD or tampered data)",
                format!("{}", e),
            )
        })?;

    Ok(plaintext)
}
