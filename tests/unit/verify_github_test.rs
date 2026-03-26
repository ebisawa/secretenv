// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for GitHub binding_claims.github_account verification.

use secretenv::io::verify_online::github::{
    resolve_github_id_by_username_with_api, verify_github_account_with_api, GitHubApi,
    GitHubApiFuture, GitHubKeyRecord,
};
use secretenv::model::public_key::{
    Attestation, BindingClaims, GithubAccount, Identity, IdentityKeys, JwkOkpPublicKey, PublicKey,
    PublicKeyProtected,
};
use secretenv::model::verification::BindingVerificationProof;
use secretenv::{Error, Result};

const TEST_SSH_PUBKEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@example.com";

struct FakeGitHubApi {
    user_result: Result<(u64, String)>,
    keys_result: Result<Vec<GitHubKeyRecord>>,
}

impl GitHubApi for FakeGitHubApi {
    fn fetch_user_by_login<'a>(&'a self, _login: &'a str) -> GitHubApiFuture<'a, (u64, String)> {
        Box::pin(async move {
            match &self.user_result {
                Ok((id, login)) => Ok((*id, login.clone())),
                Err(Error::Verify { rule, message }) => Err(Error::Verify {
                    rule: rule.clone(),
                    message: message.clone(),
                }),
                Err(other) => Err(Error::Verify {
                    rule: "V-GITHUB-API".to_string(),
                    message: other.to_string(),
                }),
            }
        })
    }

    fn fetch_keys<'a>(&'a self, _login: &'a str) -> GitHubApiFuture<'a, Vec<GitHubKeyRecord>> {
        Box::pin(async move {
            match &self.keys_result {
                Ok(keys) => Ok(keys.clone()),
                Err(Error::Verify { rule, message }) => Err(Error::Verify {
                    rule: rule.clone(),
                    message: message.clone(),
                }),
                Err(other) => Err(Error::Verify {
                    rule: "V-GITHUB-API".to_string(),
                    message: other.to_string(),
                }),
            }
        })
    }
}

fn sample_public_key() -> PublicKey {
    PublicKey {
        protected: PublicKeyProtected {
            format: "secretenv.public.key@4".to_string(),
            member_id: "alice@example.com".to_string(),
            kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
            identity: Identity {
                keys: IdentityKeys {
                    kem: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: "X25519".to_string(),
                        x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                    },
                    sig: JwkOkpPublicKey {
                        kty: "OKP".to_string(),
                        crv: "Ed25519".to_string(),
                        x: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string(),
                    },
                },
                attestation: Attestation {
                    method: "ssh".to_string(),
                    pub_: TEST_SSH_PUBKEY.to_string(),
                    sig: "signature".to_string(),
                },
            },
            binding_claims: Some(BindingClaims {
                github_account: Some(GithubAccount {
                    id: 42,
                    login: "alice".to_string(),
                }),
            }),
            expires_at: "2099-12-31T00:00:00Z".to_string(),
            created_at: Some("2026-01-01T00:00:00Z".to_string()),
        },
        signature: "sig".to_string(),
    }
}

#[tokio::test]
async fn test_resolve_github_id_by_username_with_fake_api() {
    let api = FakeGitHubApi {
        user_result: Ok((42, "alice".to_string())),
        keys_result: Ok(Vec::new()),
    };

    let result = resolve_github_id_by_username_with_api("alice", false, &api).await;

    assert_eq!(result.unwrap(), (42, "alice".to_string()));
}

#[tokio::test]
async fn test_verify_github_account_with_fake_api() {
    let public_key = sample_public_key();
    let api = FakeGitHubApi {
        user_result: Ok((42, "alice".to_string())),
        keys_result: Ok(vec![GitHubKeyRecord {
            id: 100,
            key: TEST_SSH_PUBKEY.to_string(),
        }]),
    };

    let result = verify_github_account_with_api(&public_key, false, None, &api)
        .await
        .unwrap();

    assert!(result.is_verified());
    assert_eq!(result.matched_key_id, Some(100));
    assert_eq!(
        result
            .verified_bindings
            .as_ref()
            .expect("verified bindings")
            .proof()
            .matched_key_id,
        Some(100)
    );
}

#[tokio::test]
async fn test_verify_github_account_rejects_id_mismatch() {
    let public_key = sample_public_key();
    let api = FakeGitHubApi {
        user_result: Ok((7, "alice".to_string())),
        keys_result: Ok(Vec::new()),
    };

    let result = verify_github_account_with_api(&public_key, false, None, &api).await;

    assert!(matches!(result, Err(Error::Verify { .. })));
}

#[tokio::test]
async fn test_verify_github_account_reports_missing_matching_key() {
    let public_key = sample_public_key();
    let api = FakeGitHubApi {
        user_result: Ok((42, "alice".to_string())),
        keys_result: Ok(vec![GitHubKeyRecord {
            id: 200,
            key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA other@example.com".to_string(),
        }]),
    };

    let result = verify_github_account_with_api(&public_key, false, None, &api)
        .await
        .unwrap();

    assert!(!result.is_verified());
    assert_eq!(result.matched_key_id, None);
}

#[tokio::test]
async fn test_verify_github_account_reports_not_configured_without_binding_claims() {
    let mut public_key = sample_public_key();
    public_key.protected.binding_claims = None;
    let api = FakeGitHubApi {
        user_result: Ok((42, "alice".to_string())),
        keys_result: Ok(Vec::new()),
    };

    let result = verify_github_account_with_api(&public_key, false, None, &api)
        .await
        .unwrap();

    assert_eq!(
        result.status,
        secretenv::io::verify_online::VerificationStatus::NotConfigured
    );
    assert_eq!(
        result.message,
        "No binding_claims.github_account configured"
    );
}

#[tokio::test]
async fn test_verify_github_account_reports_not_configured_for_invalid_attestation() {
    let mut public_key = sample_public_key();
    public_key.protected.identity.attestation.pub_ = "invalid-ssh-key".to_string();
    let api = FakeGitHubApi {
        user_result: Ok((42, "alice".to_string())),
        keys_result: Ok(Vec::new()),
    };

    let result = verify_github_account_with_api(&public_key, false, None, &api)
        .await
        .unwrap();

    assert_eq!(
        result.status,
        secretenv::io::verify_online::VerificationStatus::NotConfigured
    );
    assert_eq!(
        result.message,
        "Invalid attestation.pub (cannot compute fingerprint)"
    );
}

#[tokio::test]
async fn test_verify_github_account_uses_known_account_without_user_lookup() {
    let public_key = sample_public_key();
    let api = FakeGitHubApi {
        user_result: Err(Error::Verify {
            rule: "V-GITHUB-API".to_string(),
            message: "user lookup should be skipped".to_string(),
        }),
        keys_result: Ok(vec![GitHubKeyRecord {
            id: 100,
            key: TEST_SSH_PUBKEY.to_string(),
        }]),
    };

    let result =
        verify_github_account_with_api(&public_key, false, Some((42, "alice".to_string())), &api)
            .await
            .unwrap();

    assert!(result.is_verified());
    assert_eq!(result.matched_key_id, Some(100));
}

#[test]
fn test_github_account_structure_github_has_id_and_login() {
    let github = GithubAccount {
        id: 12345,
        login: "alice".to_string(),
    };
    assert_eq!(github.id, 12345);
    assert_eq!(github.login, "alice");
}

#[test]
fn test_verification_result_verified_bindings_some() {
    use secretenv::io::verify_online::{VerificationResult, VerificationStatus};
    use secretenv::model::public_key::VerifiedBindingClaims;

    let claims = BindingClaims {
        github_account: Some(GithubAccount {
            id: 99,
            login: "bob".to_string(),
        }),
    };
    let proof = BindingVerificationProof::new(
        "github".to_string(),
        Some("SHA256:fp".to_string()),
        Some(100),
    );
    let verified_bindings = VerifiedBindingClaims::new(claims, proof);

    let result = VerificationResult {
        member_id: "bob@example.com".to_string(),
        status: VerificationStatus::Verified,
        message: "SSH key verified on GitHub".to_string(),
        fingerprint: Some("SHA256:fp".to_string()),
        matched_key_id: Some(100),
        verified_bindings: Some(verified_bindings),
    };

    assert!(result.is_verified());
    let bindings = result
        .verified_bindings
        .as_ref()
        .expect("verified_bindings");
    assert_eq!(
        bindings.claims().github_account.as_ref().unwrap().login,
        "bob"
    );
    assert_eq!(bindings.proof().method, "github");
    assert_eq!(bindings.proof().matched_key_id, Some(100));
}
