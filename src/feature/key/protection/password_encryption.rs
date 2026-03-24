// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Password-based private key encryption/decryption using Argon2id + XChaCha20-Poly1305.

use super::encryption::{decode_encryption_params, decrypt_and_deserialize, serialize_and_encrypt};
use super::password_key_derivation::{self, Argon2Params, DEFAULT_ARGON2_PARAMS};
use crate::model::identifiers::{alg, format};
use crate::model::private_key::{
    PrivateKey, PrivateKeyAlgorithm, PrivateKeyPlaintext, PrivateKeyProtected,
};
use crate::support::base64url::b64_encode;
use crate::{Error, Result};

/// Build protected header for password-based PrivateKey encryption
fn build_protected_header(
    member_id: &str,
    kid: &str,
    params: &Argon2Params,
    salt: &crate::crypto::types::primitives::Salt,
    created_at: &str,
    expires_at: &str,
) -> PrivateKeyProtected {
    PrivateKeyProtected {
        format: format::PRIVATE_KEY_V3.to_string(),
        member_id: member_id.to_string(),
        kid: kid.to_string(),
        alg: PrivateKeyAlgorithm::Argon2id {
            m: params.m(),
            t: params.t(),
            p: params.p(),
            salt: b64_encode(salt.as_bytes()),
            aead: alg::AEAD_XCHACHA20_POLY1305.to_string(),
        },
        created_at: created_at.to_string(),
        expires_at: expires_at.to_string(),
    }
}

/// Encrypt a private key with a password using Argon2id key derivation
pub fn encrypt_private_key_with_password(
    plaintext: &PrivateKeyPlaintext,
    member_id: &str,
    kid: &str,
    created_at: &str,
    expires_at: &str,
    password: &str,
) -> Result<PrivateKey> {
    let salt = password_key_derivation::generate_salt();

    let protected = build_protected_header(
        member_id,
        kid,
        &DEFAULT_ARGON2_PARAMS,
        &salt,
        created_at,
        expires_at,
    );

    let enc_key = password_key_derivation::derive_key_from_password(
        password,
        &salt,
        kid,
        &DEFAULT_ARGON2_PARAMS,
    )?;

    let encrypted = serialize_and_encrypt(
        plaintext,
        &enc_key,
        &protected,
        false,
        "encrypt_private_key_with_password",
    )?;

    Ok(PrivateKey {
        protected,
        encrypted,
    })
}

/// Decrypt a private key that was encrypted with a password
pub fn decrypt_private_key_with_password(
    private_key: &PrivateKey,
    password: &str,
) -> Result<PrivateKeyPlaintext> {
    let params = match &private_key.protected.alg {
        PrivateKeyAlgorithm::Argon2id { m, t, p, aead, .. } => {
            if aead != alg::AEAD_XCHACHA20_POLY1305 {
                return Err(Error::Crypto {
                    message: format!(
                        "Unsupported AEAD algorithm '{}', expected '{}'",
                        aead,
                        alg::AEAD_XCHACHA20_POLY1305
                    ),
                    source: None,
                });
            }
            Argon2Params::new(*m, *t, *p)?
        }
        _ => {
            return Err(Error::Crypto {
                message: "Expected Argon2id algorithm, got SSH-based".to_string(),
                source: None,
            });
        }
    };

    let (salt, nonce, ct, aad) = decode_encryption_params(private_key)?;

    let enc_key = password_key_derivation::derive_key_from_password(
        password,
        &salt,
        &private_key.protected.kid,
        &params,
    )?;

    decrypt_and_deserialize(
        &enc_key,
        &nonce,
        &aad,
        &ct,
        &private_key.protected.kid,
        false,
        "decrypt_private_key_with_password",
    )
}
