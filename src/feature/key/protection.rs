// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH-based private key protection (encryption/decryption).

pub mod binding;
pub mod encryption;
pub mod key_derivation;
pub mod password_encryption;
pub mod password_key_derivation;

pub use encryption::{decrypt_private_key, encrypt_private_key, PrivateKeyEncryptionParams};
pub use password_encryption::{
    decrypt_private_key_with_password, encrypt_private_key_with_password,
};
