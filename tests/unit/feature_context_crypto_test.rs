// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for core/usecase/common module
//!
//! Tests for common decryption helpers and member key context.

use crate::cli_common::ALICE_MEMBER_ID;
use crate::keygen_helpers::make_verified_members;
use crate::test_utils::{setup_member_key_context, setup_test_keystore_from_fixtures};
use secretenv::feature::decrypt::file::decrypt_file_document;
use secretenv::feature::encrypt::file::encrypt_file_document;
use secretenv::feature::envelope::signature::SigningContext;
use secretenv::feature::kv::decrypt::decrypt_kv_document;
use secretenv::feature::kv::encrypt::encrypt_kv_document;
use secretenv::feature::verify::file::verify_file_document;
use secretenv::feature::verify::kv::signature::verify_kv_document;
use secretenv::format::kv::document::parse_kv_document;
use secretenv::format::kv::dotenv::parse_dotenv;
use secretenv::format::token::TokenCodec;
use secretenv::io::keystore::storage::{list_kids, load_public_key};

#[test]
fn test_parse_verify_decrypt_kv() {
    // Setup test keystore
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    // Load CryptoContext (use active key) - this gives us the signing key
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);

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
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    // Load CryptoContext (use active key) - this gives us the signing key
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);

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
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    // Get kid from keystore
    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();

    // Load CryptoContext
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, Some(kid));

    // Verify context
    assert_eq!(key_ctx.member_id, ALICE_MEMBER_ID);
    assert_eq!(key_ctx.kid, *kid);
    // Verify pub_key_source works by loading the signer's public key
    let loaded = key_ctx.pub_key_source.load_public_key(ALICE_MEMBER_ID);
    assert!(loaded.is_ok());
}

#[test]
fn test_crypto_context_load_without_explicit_kid() {
    // Setup test keystore
    let temp_dir = setup_test_keystore_from_fixtures(ALICE_MEMBER_ID);

    // Load CryptoContext without explicit kid (should use active key)
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, None);

    // Verify context
    assert_eq!(key_ctx.member_id, ALICE_MEMBER_ID);
    assert!(!key_ctx.kid.is_empty());
    // Verify pub_key_source works by loading the signer's public key
    let loaded = key_ctx.pub_key_source.load_public_key(ALICE_MEMBER_ID);
    assert!(loaded.is_ok());
}
