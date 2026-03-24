// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Password-based key derivation for PrivateKey protection (Argon2id + HKDF-SHA256)

use crate::crypto::kdf;
use crate::crypto::types::data::{Ikm, Info};
use crate::crypto::types::keys::XChaChaKey;
use crate::crypto::types::primitives::Salt;
use crate::model::identifiers::context;
use crate::Result;
use argon2::Argon2;
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

/// Argon2id parameters for password hashing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory cost in KiB
    pub m: u32,
    /// Time cost (iterations)
    pub t: u32,
    /// Parallelism degree
    pub p: u32,
}

/// Default Argon2id parameters: m=47104 KiB (46 MiB), t=1, p=1
pub const DEFAULT_ARGON2_PARAMS: Argon2Params = Argon2Params {
    m: 47104,
    t: 1,
    p: 1,
};

const MIN_MEMORY_COST: u32 = 19456;
const MIN_TIME_COST: u32 = 1;
const MIN_PARALLELISM: u32 = 1;

/// Generate a random 16-byte salt
pub fn generate_salt() -> Salt {
    let mut salt_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut salt_bytes);
    Salt::new(salt_bytes)
}

/// Validate Argon2id parameters against minimum thresholds
pub fn validate_argon2_params(params: &Argon2Params) -> Result<()> {
    if params.m < MIN_MEMORY_COST {
        return Err(crate::Error::Crypto {
            message: format!(
                "Argon2id memory cost too low: {} KiB (minimum: {} KiB)",
                params.m, MIN_MEMORY_COST
            ),
            source: None,
        });
    }
    if params.t < MIN_TIME_COST {
        return Err(crate::Error::Crypto {
            message: format!(
                "Argon2id time cost too low: {} (minimum: {})",
                params.t, MIN_TIME_COST
            ),
            source: None,
        });
    }
    if params.p < MIN_PARALLELISM {
        return Err(crate::Error::Crypto {
            message: format!(
                "Argon2id parallelism too low: {} (minimum: {})",
                params.p, MIN_PARALLELISM
            ),
            source: None,
        });
    }
    Ok(())
}

/// Derive an encryption key from a password using Argon2id + HKDF-SHA256
///
/// Pipeline:
/// 1. Password + salt -> Argon2id -> 32-byte IKM
/// 2. IKM + salt -> HKDF-SHA256 (with kid-bound info) -> XChaChaKey
pub fn derive_key_from_password(
    password: &str,
    salt: &Salt,
    kid: &str,
    params: &Argon2Params,
) -> Result<XChaChaKey> {
    validate_argon2_params(params)?;

    let ikm = argon2id_hash(password, salt, params)?;

    let info = Info::from_string(&format!(
        "{}:{}",
        context::PASSWORD_PRIVATE_KEY_ENC_INFO_PREFIX_V3,
        kid
    ));
    let cek = kdf::expand_to_array(&Ikm::from(ikm.as_ref()), Some(salt), &info)?;
    XChaChaKey::from_slice(cek.as_bytes())
}

/// Hash password with Argon2id, returning a 32-byte IKM wrapped in Zeroizing
fn argon2id_hash(
    password: &str,
    salt: &Salt,
    params: &Argon2Params,
) -> Result<Zeroizing<[u8; 32]>> {
    let argon2_params =
        argon2::Params::new(params.m, params.t, params.p, Some(32)).map_err(|e| {
            crate::Error::Crypto {
                message: format!("Invalid Argon2id parameters: {}", e),
                source: None,
            }
        })?;
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2_params,
    );

    let mut output = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt.as_bytes(), output.as_mut())
        .map_err(|e| crate::Error::Crypto {
            message: format!("Argon2id hashing failed: {}", e),
            source: None,
        })?;

    Ok(output)
}
