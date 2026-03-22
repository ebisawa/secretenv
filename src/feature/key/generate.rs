// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key generation logic.

use super::KeyNewResult;
use crate::config::types::SshSigner;
use crate::feature::context::ssh::{
    resolve_ssh_signing_context, SshSigningContext, SshSigningParams,
};
pub use crate::feature::key::material::{build_identity_keys, generate_keypairs};
use crate::feature::key::protection::{self, PrivateKeyEncryptionParams};
pub use crate::feature::key::public_key_document::{build_public_key, PublicKeyBuildParams};
use crate::feature::key::{material, public_key_document};
use crate::io::keystore::active::set_active_kid;
use crate::io::keystore::resolver::KeystoreResolver;
use crate::io::keystore::storage::save_key_pair_atomic;
use crate::model::private_key::PrivateKey;
use crate::model::public_key::{GithubAccount, Identity, PublicKey};
use crate::model::ssh::SshDeterminismStatus;
use crate::Result;
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::path::{Path, PathBuf};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

/// Options for key generation.
pub struct KeyGenerationOptions {
    pub member_id: String,
    pub home: Option<PathBuf>,
    pub ssh_key: Option<PathBuf>,
    pub ssh_signer: Option<SshSigner>,
    pub created_at: String,
    pub expires_at: String,
    pub no_activate: bool,
    pub debug: bool,
    pub github_account: Option<GithubAccount>,
    pub verbose: bool,
    /// Pre-resolved SSH signing context. When provided, skips runtime resolution.
    pub ssh_context: Option<SshSigningContext>,
}

/// Pipeline for key generation.
struct KeyGenerationPipeline {
    opts: KeyGenerationOptions,
}

impl KeyGenerationPipeline {
    fn new(opts: KeyGenerationOptions) -> Self {
        Self { opts }
    }

    /// Ensure keystore directory exists.
    fn ensure_keystore(&self) -> Result<PathBuf> {
        ensure_keystore_dir(&self.opts.home)
    }

    /// Resolve SSH context.
    fn resolve_ssh(&self) -> Result<SshSigningContext> {
        resolve_ssh_signing_context(&SshSigningParams {
            ssh_key: self.opts.ssh_key.clone(),
            signing_method: self.opts.ssh_signer,
            base_dir: self.opts.home.clone(),
            verbose: self.opts.verbose,
        })
    }

    fn ensure_determinism(status: &SshDeterminismStatus) -> Result<()> {
        if let SshDeterminismStatus::Failed { message } = status {
            return Err(crate::Error::Crypto {
                message: message.clone(),
                source: None,
            });
        }
        Ok(())
    }

    /// Encrypt private key.
    fn encrypt_private_key(
        &self,
        kem_sk: &X25519SecretKey,
        kem_pk: &X25519PublicKey,
        sig_sk: &SigningKey,
        sig_pk: &VerifyingKey,
        kid: &str,
        ssh_context: &SshSigningContext,
    ) -> Result<PrivateKey> {
        let plaintext = material::build_private_key_plaintext(kem_sk, kem_pk, sig_sk, sig_pk);
        protection::encrypt_private_key(&PrivateKeyEncryptionParams {
            plaintext: &plaintext,
            member_id: self.opts.member_id.clone(),
            kid: kid.to_string(),
            backend: ssh_context.backend.as_ref(),
            ssh_pubkey: &ssh_context.public_key,
            ssh_fpr: ssh_context.fingerprint.clone(),
            created_at: self.opts.created_at.clone(),
            expires_at: self.opts.expires_at.clone(),
            debug: self.opts.debug,
        })
    }

    /// Save and activate key.
    fn save_and_activate(
        &self,
        keystore_root: &Path,
        kid: &str,
        private_key: &PrivateKey,
        public_key: &PublicKey,
    ) -> Result<()> {
        save_and_activate(
            keystore_root,
            &self.opts.member_id,
            kid,
            private_key,
            public_key,
            self.opts.no_activate,
        )
    }

    /// Execute the pipeline.
    fn execute(mut self) -> Result<KeyNewResult> {
        let keystore_root = self.ensure_keystore()?;
        let pre_resolved = self.opts.ssh_context.take();
        let ssh_context = match pre_resolved {
            Some(ctx) => ctx,
            None => self.resolve_ssh()?,
        };
        Self::ensure_determinism(&ssh_context.determinism)?;
        let (kid, kem_sk, kem_pk, sig_sk, sig_pk) = material::generate_keypairs()?;

        let identity_keys = material::build_identity_keys(&kem_pk, &sig_pk)?;
        let attestation = public_key_document::build_attestation(&ssh_context, &identity_keys)?;
        let identity = Identity {
            keys: identity_keys,
            attestation,
        };

        let public_key =
            public_key_document::build_public_key(&public_key_document::PublicKeyBuildParams {
                member_id: &self.opts.member_id,
                kid: &kid,
                identity,
                created_at: &self.opts.created_at,
                expires_at: &self.opts.expires_at,
                sig_sk: &sig_sk,
                debug: self.opts.debug,
                github_account: self.opts.github_account.clone(),
            })?;

        let private_key =
            self.encrypt_private_key(&kem_sk, &kem_pk, &sig_sk, &sig_pk, &kid, &ssh_context)?;
        self.save_and_activate(&keystore_root, &kid, &private_key, &public_key)?;

        let key_dir = keystore_root.join(&self.opts.member_id).join(&kid);
        Ok(KeyNewResult {
            member_id: self.opts.member_id,
            kid,
            created_at: self.opts.created_at,
            expires_at: self.opts.expires_at,
            keystore_root,
            key_dir,
            activated: !self.opts.no_activate,
            ssh_fingerprint: ssh_context.fingerprint,
            ssh_public_key: ssh_context.public_key,
            ssh_determinism: ssh_context.determinism,
        })
    }
}

/// Generate a new key pair and save to keystore.
pub fn generate_key(opts: KeyGenerationOptions) -> Result<KeyNewResult> {
    KeyGenerationPipeline::new(opts).execute()
}

/// Ensure keystore directory exists.
pub(crate) fn ensure_keystore_dir(home: &Option<PathBuf>) -> Result<PathBuf> {
    KeystoreResolver::resolve_and_ensure(home.as_ref())
}

/// Save and activate key.
pub(crate) fn save_and_activate(
    keystore_root: &Path,
    member_id: &str,
    kid: &str,
    private_key: &PrivateKey,
    public_key: &PublicKey,
    no_activate: bool,
) -> Result<()> {
    save_key_pair_atomic(keystore_root, member_id, kid, private_key, public_key)?;
    if !no_activate {
        set_active_kid(member_id, kid, keystore_root)?;
    }
    Ok(())
}
