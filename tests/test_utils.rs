// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Common test utilities for environment variable management

// Test-only key generation helpers
#[path = "../tests/test_utils/crypto_context.rs"]
pub mod crypto_context;
#[path = "../tests/test_utils/ed25519_backend.rs"]
pub mod ed25519_backend;
#[path = "../tests/test_utils/fixture.rs"]
mod fixture;
#[path = "../tests/test_utils/fixture_generator.rs"]
pub mod fixture_generator;
pub mod keygen_helpers;
#[allow(unused_imports)]
pub use crypto_context::setup_member_key_context;
#[allow(unused_imports)]
pub use fixture::{
    create_temp_ssh_keypair_in_dir, load_fixture_ssh_pubkey, save_public_key, setup_test_keystore,
    setup_test_keystore_from_fixtures, setup_test_workspace, setup_test_workspace_from_fixtures,
};
#[allow(unused_imports)]
pub use keygen_helpers::{create_test_private_key, keygen_test};

use secretenv::io::ssh::agent::traits::AgentSigner;
use secretenv::io::ssh::external::traits::SshKeygen;
use secretenv::io::ssh::protocol::types::Ed25519RawSignature;
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

static CWD_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

struct CwdGuard {
    original: PathBuf,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl CwdGuard {
    fn enter(dir: &Path) -> Self {
        let lock = CWD_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir).unwrap();
        Self {
            original,
            _lock: lock,
        }
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.original);
    }
}

/// Run a closure with the process current directory temporarily changed.
///
/// This is serialized via a global mutex because the current directory is
/// process-global and Rust tests run in parallel by default.
pub fn with_temp_cwd<R>(dir: &Path, f: impl FnOnce() -> R) -> R {
    let _guard = CwdGuard::enter(dir);
    f()
}

/// Stub `SshKeygen` implementation for tests that need a `Box<dyn SshKeygen>`.
///
/// Returns dummy values without invoking any external commands.
/// Useful for constructing `SshKeygenBackend` or `build_backend` in tests.
#[allow(dead_code)]
struct StubSshKeygen;

impl SshKeygen for StubSshKeygen {
    fn derive_public_key(&self, _key_path: &Path) -> secretenv::Result<String> {
        Ok(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA stub"
                .to_string(),
        )
    }
    fn sign(&self, _key_path: &Path, _namespace: &str, _data: &[u8]) -> secretenv::Result<String> {
        // Return a minimal valid SSHSIG armored signature
        Ok("-----BEGIN SSH SIGNATURE-----\n\
            U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
            AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n\
            -----END SSH SIGNATURE-----\n"
            .to_string())
    }
    fn verify(
        &self,
        _ssh_pubkey: &str,
        _namespace: &str,
        _message: &[u8],
        _signature: &str,
    ) -> secretenv::Result<()> {
        Ok(())
    }
}

/// Create a boxed stub `SshKeygen` for testing.
#[allow(dead_code)]
pub fn stub_ssh_keygen() -> Box<dyn SshKeygen> {
    Box::new(StubSshKeygen)
}

/// Stub `AgentSigner` implementation for tests that need a `Box<dyn AgentSigner>`.
///
/// Returns a dummy zero-filled signature without connecting to ssh-agent.
#[allow(dead_code)]
struct StubAgentSigner;

impl AgentSigner for StubAgentSigner {
    fn sign(&self, _ssh_pubkey: &str, _message: &[u8]) -> secretenv::Result<Ed25519RawSignature> {
        Ok(Ed25519RawSignature::new([0u8; 64]))
    }
}

/// Create a boxed stub `AgentSigner` for testing.
#[allow(dead_code)]
pub fn stub_agent_signer() -> Box<dyn AgentSigner> {
    Box::new(StubAgentSigner)
}

/// Global mutex for tests that modify environment variables.
/// All tests that modify environment variables must hold this lock.
pub static ENV_MUTEX: Mutex<()> = Mutex::new(());

/// RAII guard that holds the env mutex and restores env vars on drop.
pub struct EnvGuard {
    vars: Vec<(String, Option<String>)>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EnvGuard {
    pub fn new(keys: &[&str]) -> Self {
        let lock = ENV_MUTEX.lock().unwrap();
        let vars = keys
            .iter()
            .map(|&k| (k.to_string(), std::env::var(k).ok()))
            .collect();
        Self { vars, _lock: lock }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, value) in &self.vars {
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
    }
}
