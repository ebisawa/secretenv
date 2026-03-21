// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for core/usecase/common module
//!
//! Tests for common decryption helpers and member key context.

use crate::cli_common::ALICE_MEMBER_ID;
use crate::keygen_helpers::make_verified_members;
use crate::test_utils::setup_test_keystore;
use secretenv::feature::context::crypto::CryptoContext;
use secretenv::feature::decrypt::file::decrypt_file_document;
use secretenv::feature::encrypt::file::encrypt_file_document;
use secretenv::feature::encrypt::SigningContext;
use secretenv::feature::kv::decrypt::decrypt_kv_document;
use secretenv::feature::kv::encrypt::encrypt_kv_document;
use secretenv::feature::verify::file::verify_file_document;
use secretenv::feature::verify::kv::verify_kv_document;
use secretenv::format::kv::dotenv::parse_dotenv;
use secretenv::format::kv::parse_kv_document;
use secretenv::format::token::TokenCodec;
use secretenv::io::keystore::storage::{list_kids, load_public_key};
use secretenv::io::ssh::backend::signature_backend::SignatureBackend;
use secretenv::io::ssh::backend::ssh_keygen::SshKeygenBackend;
use secretenv::io::ssh::external::keygen::DefaultSshKeygen;
use secretenv::io::ssh::protocol::key_descriptor::SshKeyDescriptor;

#[test]
fn test_parse_verify_decrypt_kv() {
    // Setup test keystore
    let temp_dir = setup_test_keystore(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    // Setup SSH backend for CryptoContext
    let ssh_pub =
        std::fs::read_to_string(temp_dir.path().join(".ssh").join("test_ed25519.pub")).unwrap();
    let backend: Box<dyn SignatureBackend> = Box::new(SshKeygenBackend::new(
        Box::new(DefaultSshKeygen::new("ssh-keygen")),
        SshKeyDescriptor::from_path(temp_dir.path().join(".ssh").join("test_ed25519")),
    ));

    // Load CryptoContext (use active key) - this gives us the signing key
    let key_ctx = CryptoContext::load(
        ALICE_MEMBER_ID,
        backend.as_ref(),
        &ssh_pub,
        None, // Use active key
        Some(&keystore_root),
        Some(temp_dir.path().join("workspace")),
        false,
    )
    .unwrap();

    // Get public key from keystore
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();

    // Create kv-enc content using signing key from CryptoContext
    let kv_map = parse_dotenv("DATABASE_URL=postgres://localhost\nAPI_KEY=secret123\n").unwrap();
    let recipients = vec![ALICE_MEMBER_ID.to_string()];
    let members = vec![public_key.clone()];
    let verified_members = make_verified_members(&members);

    let encrypted = encrypt_kv_document(
        &kv_map,
        &recipients,
        &verified_members,
        &SigningContext {
            signing_key: &key_ctx.signing_key,
            signer_kid: kid,
            signer_pub: Some(public_key),
            debug: false,
        },
        TokenCodec::JsonJcs,
    )
    .unwrap();

    // Verify and decrypt
    let doc = parse_kv_document(&encrypted).unwrap();
    let workspace_path = temp_dir.path().join("workspace");
    let verified_doc = verify_kv_document(&doc, Some(&workspace_path), false).unwrap();
    let decrypted = decrypt_kv_document(
        &verified_doc,
        ALICE_MEMBER_ID,
        &key_ctx.kid,
        &key_ctx.private_key,
        false,
    )
    .unwrap();

    // Verify decrypted content (convert Zeroizing<Vec<u8>> to String for comparison)
    let db_url = decrypted
        .get("DATABASE_URL")
        .map(|v| String::from_utf8(v.to_vec()).unwrap());
    let api_key = decrypted
        .get("API_KEY")
        .map(|v| String::from_utf8(v.to_vec()).unwrap());
    assert_eq!(db_url, Some("postgres://localhost".to_string()));
    assert_eq!(api_key, Some("secret123".to_string()));
}

#[test]
fn test_parse_verify_decrypt_file() {
    // Setup test keystore
    let temp_dir = setup_test_keystore(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    // Setup SSH backend for CryptoContext
    let ssh_pub =
        std::fs::read_to_string(temp_dir.path().join(".ssh").join("test_ed25519.pub")).unwrap();
    let backend: Box<dyn SignatureBackend> = Box::new(SshKeygenBackend::new(
        Box::new(DefaultSshKeygen::new("ssh-keygen")),
        SshKeyDescriptor::from_path(temp_dir.path().join(".ssh").join("test_ed25519")),
    ));

    // Load CryptoContext (use active key) - this gives us the signing key
    let key_ctx = CryptoContext::load(
        ALICE_MEMBER_ID,
        backend.as_ref(),
        &ssh_pub,
        None, // Use active key
        Some(&keystore_root),
        Some(temp_dir.path().join("workspace")),
        false,
    )
    .unwrap();

    // Get public key from keystore
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();

    // Create file-enc content using signing key from CryptoContext
    let content = b"Hello, World!";
    let recipient_ids = vec![ALICE_MEMBER_ID.to_string()];
    let members = vec![public_key.clone()];
    let verified_members = make_verified_members(&members);

    let file_enc_doc = encrypt_file_document(
        content,
        &recipient_ids,
        &verified_members,
        &SigningContext {
            signing_key: &key_ctx.signing_key,
            signer_kid: kid,
            signer_pub: Some(public_key),
            debug: false,
        },
    )
    .unwrap();

    let encrypted_json = serde_json::to_string(&file_enc_doc).unwrap();

    // Verify and decrypt
    let doc: secretenv::model::file_enc::FileEncDocument =
        serde_json::from_str(&encrypted_json).unwrap();
    let workspace_path = temp_dir.path().join("workspace");
    let verified_doc = verify_file_document(&doc, Some(&workspace_path), false).unwrap();
    let decrypted = decrypt_file_document(
        &verified_doc,
        ALICE_MEMBER_ID,
        &key_ctx.kid,
        &key_ctx.private_key,
        false,
    )
    .unwrap();

    // Verify decrypted content (compare Zeroizing<Vec<u8>> with &[u8] using as_ref())
    assert_eq!(decrypted.as_ref() as &[u8], content);
}

#[test]
fn test_crypto_context_load() {
    // Setup test keystore
    let temp_dir = setup_test_keystore(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    // Setup SSH backend
    let ssh_pub =
        std::fs::read_to_string(temp_dir.path().join(".ssh").join("test_ed25519.pub")).unwrap();
    let backend: Box<dyn SignatureBackend> = Box::new(SshKeygenBackend::new(
        Box::new(DefaultSshKeygen::new("ssh-keygen")),
        SshKeyDescriptor::from_path(temp_dir.path().join(".ssh").join("test_ed25519")),
    ));

    // Get kid from keystore
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();

    // Load CryptoContext
    let key_ctx = CryptoContext::load(
        ALICE_MEMBER_ID,
        backend.as_ref(),
        &ssh_pub,
        Some(kid),
        Some(&keystore_root),
        Some(temp_dir.path().join("workspace")),
        false,
    )
    .unwrap();

    // Verify context
    assert_eq!(key_ctx.member_id, ALICE_MEMBER_ID);
    assert_eq!(key_ctx.kid, *kid);
    assert_eq!(key_ctx.keystore_root, keystore_root);
}

#[test]
fn test_crypto_context_load_without_explicit_kid() {
    // Setup test keystore
    let temp_dir = setup_test_keystore(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    // Setup SSH backend
    let ssh_pub =
        std::fs::read_to_string(temp_dir.path().join(".ssh").join("test_ed25519.pub")).unwrap();
    let backend: Box<dyn SignatureBackend> = Box::new(SshKeygenBackend::new(
        Box::new(DefaultSshKeygen::new("ssh-keygen")),
        SshKeyDescriptor::from_path(temp_dir.path().join(".ssh").join("test_ed25519")),
    ));

    // Load CryptoContext without explicit kid (should use active key)
    let key_ctx = CryptoContext::load(
        ALICE_MEMBER_ID,
        backend.as_ref(),
        &ssh_pub,
        None,
        Some(&keystore_root),
        Some(temp_dir.path().join("workspace")),
        false,
    )
    .unwrap();

    // Verify context
    assert_eq!(key_ctx.member_id, ALICE_MEMBER_ID);
    assert!(!key_ctx.kid.is_empty());
    assert_eq!(key_ctx.keystore_root, keystore_root);
}
