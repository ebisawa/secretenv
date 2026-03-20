// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH key derivation for PrivateKey protection

use crate::crypto::kdf;
use crate::crypto::types::data::{Ikm, Info};
use crate::crypto::types::keys::XChaChaKey;
use crate::crypto::types::primitives::Salt;
use crate::io::ssh::backend::SignatureBackend;
use crate::model::identifiers::context;
use crate::Result;
use rand::rngs::OsRng;
use rand::RngCore;
use tracing::debug;

const NON_DETERMINISTIC_SIGNATURE_MESSAGE: &str =
    "Non-deterministic signature detected: same input produced different signatures";

/// Build sign_message for SSH signature
///
/// Format:
/// ```text
/// secretenv:key-protection@3
/// {kid}
/// {hex(salt)}
/// ```
pub fn build_sign_message(kid: &str, salt: &Salt) -> String {
    format!(
        "{}\n{}\n{}",
        context::SSH_KEY_PROTECTION_SIGN_MESSAGE_PREFIX_V3,
        kid,
        hex::encode(salt.as_bytes())
    )
}

/// Generate a random salt for key derivation
pub fn generate_salt() -> Salt {
    let mut salt_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut salt_bytes);
    Salt::new(salt_bytes)
}

/// Derive encryption key for a PrivateKey using SSH signature
pub fn derive_key_from_ssh(
    kid: &str,
    salt: &Salt,
    backend: &dyn SignatureBackend,
    ssh_pubkey: &str,
    debug: bool,
) -> Result<XChaChaKey> {
    let message = build_sign_message(kid, salt);
    if debug {
        debug!(
            "[CRYPTO] SSH: sign_for_ikm x2 determinism check (kid: {})",
            kid
        );
    }
    let raw_sig = backend
        .sign_deterministic_for_ikm(ssh_pubkey, message.as_bytes())
        .map_err(map_determinism_error)?;
    if debug {
        debug!(
            "[CRYPTO] HKDF-SHA256: private key enc key derivation (kid: {})",
            kid
        );
    }
    let ikm = Ikm::from(&raw_sig.as_bytes()[..]);
    let info = Info::from_string(&format!(
        "{}:{}",
        context::SSH_PRIVATE_KEY_ENC_INFO_PREFIX_V3,
        kid
    ));
    let cek = kdf::expand_to_array(&ikm, Some(salt), &info)?;
    XChaChaKey::from_slice(cek.as_bytes())
}

fn map_determinism_error(error: crate::Error) -> crate::Error {
    if error
        .to_string()
        .contains(NON_DETERMINISTIC_SIGNATURE_MESSAGE)
    {
        return crate::Error::Crypto {
            message: "W_SSH_NONDETERMINISTIC: SSH signature is non-deterministic".into(),
            source: None,
        };
    }

    error
}
