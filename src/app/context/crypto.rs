// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use tracing::debug;

use crate::feature::context::crypto::{
    build_signing_key, validate_and_wrap_private_key_ssh, CryptoContext,
};
use crate::feature::context::env_key;
use crate::feature::key::protection::encryption::decrypt_private_key;
use crate::io::config::paths::get_base_dir;
use crate::io::keystore::helpers::resolve_kid;
use crate::io::keystore::paths::get_keystore_root_from_base;
use crate::io::keystore::public_key_source::{
    KeystorePublicKeySource, PublicKeySource, WorkspacePublicKeySource,
};
use crate::io::keystore::storage::load_private_key;
use crate::io::ssh::backend::SignatureBackend;
use crate::model::private_key::PrivateKeyAlgorithm;
use crate::{Error, Result};

pub fn is_env_key_mode() -> bool {
    env_key::is_env_key_mode()
}

pub fn load_crypto_context(
    member_id: &str,
    backend: &dyn SignatureBackend,
    ssh_pubkey: &str,
    explicit_kid: Option<&str>,
    keystore_root: Option<&PathBuf>,
    workspace_path: Option<PathBuf>,
    debug_enabled: bool,
) -> Result<CryptoContext> {
    if debug_enabled {
        debug!(
            "[CRYPTO] load_crypto_context: member_id={}, explicit_kid={}",
            member_id,
            explicit_kid.unwrap_or("(none)")
        );
    }

    let keystore_root = match keystore_root {
        Some(path) => path.clone(),
        None => {
            let base_dir = get_base_dir()?;
            get_keystore_root_from_base(&base_dir)
        }
    };
    let kid = resolve_kid(&keystore_root, member_id, explicit_kid)?;
    if debug_enabled {
        debug!("[CRYPTO] load_crypto_context: resolved kid={}", kid);
    }

    let encrypted_private_key = load_private_key(&keystore_root, member_id, &kid)?;
    let private_key_plaintext =
        decrypt_private_key(&encrypted_private_key, backend, ssh_pubkey, debug_enabled)?;

    let ssh_fpr = match &encrypted_private_key.protected.alg {
        PrivateKeyAlgorithm::SshSig { fpr, .. } => fpr.as_str(),
        _ => {
            return Err(Error::Crypto {
                message: "Expected SshSig algorithm for SSH-based decryption".to_string(),
                source: None,
            });
        }
    };

    let private_key = validate_and_wrap_private_key_ssh(
        private_key_plaintext,
        &encrypted_private_key.protected.member_id,
        &encrypted_private_key.protected.kid,
        ssh_fpr,
    )?;
    let signing_key = build_signing_key(private_key.document())?;
    let pub_key_source: Box<dyn PublicKeySource> =
        Box::new(KeystorePublicKeySource::new(keystore_root));

    Ok(CryptoContext {
        member_id: member_id.to_string(),
        kid,
        pub_key_source,
        workspace_path,
        private_key,
        signing_key,
    })
}

pub fn load_crypto_context_from_env(
    workspace_path: PathBuf,
    debug_enabled: bool,
) -> Result<CryptoContext> {
    let (private_key, member_id) = env_key::load_private_key_from_env(debug_enabled)?;
    let kid = private_key.proof().kid.clone();

    let pub_key_source = WorkspacePublicKeySource::new(workspace_path.clone());
    let own_public_key = pub_key_source.load_public_key(&member_id)?;
    env_key::verify_own_public_key(private_key.document(), &own_public_key)?;
    let signing_key = build_signing_key(private_key.document())?;

    Ok(CryptoContext {
        member_id,
        kid,
        pub_key_source: Box::new(pub_key_source),
        workspace_path: Some(workspace_path),
        private_key,
        signing_key,
    })
}
