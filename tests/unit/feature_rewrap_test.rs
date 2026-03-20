// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for core/usecase/rewrap module
//!
//! Tests for file-enc rewrap, including signature verification at entry.

use crate::cli_common::ALICE_MEMBER_ID;
use crate::keygen_helpers::make_verified_members;
use crate::test_utils::{setup_test_keystore, stub_ssh_keygen};
use base64::Engine;
use secretenv::feature::context::crypto::CryptoContext;
use secretenv::feature::encrypt::file::encrypt_file_document;
use secretenv::feature::encrypt::SigningContext;
use secretenv::feature::rewrap::file::rewrap_file_document;
use secretenv::feature::rewrap::RewrapOptions;
use secretenv::format::content::FileEncContent;
use secretenv::io::keystore::storage::{list_kids, load_public_key};
use secretenv::io::ssh::backend::signature_backend::SignatureBackend;
use secretenv::io::ssh::backend::ssh_keygen::SshKeygenBackend;
use secretenv::io::ssh::protocol::key_descriptor::SshKeyDescriptor;
use std::fs;
use tempfile::TempDir;

/// Create workspace members directory with the member's public key file.
///
/// The rewrap flow calls `list_active_member_ids(workspace_root)` to determine target recipients,
/// so the workspace must have a `members/active/<member_id>.json` file.
fn setup_workspace_members(temp_dir: &TempDir, member_id: &str, kid: &str) {
    let keystore_root = temp_dir.path().join("keys");
    let public_key = load_public_key(&keystore_root, member_id, kid).unwrap();
    let members_dir = temp_dir.path().join("members/active");
    fs::create_dir_all(&members_dir).unwrap();
    fs::create_dir_all(temp_dir.path().join("members/incoming")).unwrap();
    let member_file = members_dir.join(format!("{}.json", member_id));
    fs::write(
        &member_file,
        serde_json::to_string_pretty(&public_key).unwrap(),
    )
    .unwrap();
}

fn setup_member_key_context(temp_dir: &TempDir, member_id: &str, kid: &str) -> CryptoContext {
    let keystore_root = temp_dir.path().join("keys");
    let ssh_pub =
        std::fs::read_to_string(temp_dir.path().join(".ssh").join("test_ed25519.pub")).unwrap();
    let backend: Box<dyn SignatureBackend> = Box::new(SshKeygenBackend::new(
        stub_ssh_keygen(),
        SshKeyDescriptor::from_path(temp_dir.path().join(".ssh").join("test_ed25519")),
    ));

    CryptoContext::load(
        member_id,
        backend.as_ref(),
        &ssh_pub,
        Some(kid),
        Some(&keystore_root),
        Some(temp_dir.path().join("workspace")),
        false,
    )
    .unwrap()
}

/// Build RewrapOptions with no special operations (pure sync behavior).
fn rewrap_options_default(debug: bool) -> RewrapOptions {
    RewrapOptions {
        rotate_key: false,
        clear_disclosure_history: false,
        token_codec: None,
        no_signer_pub: false,
        debug,
    }
}

#[test]
fn test_rewrap_file_flow_rejects_invalid_signature() {
    // Create valid file-enc content, then tamper the signature so verification fails.
    let temp_dir = setup_test_keystore(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, kid);

    let content = b"secret";
    let recipient_ids = vec![ALICE_MEMBER_ID.to_string()];
    let members = make_verified_members(&[public_key]);

    let file_enc_doc = encrypt_file_document(
        content,
        &recipient_ids,
        &members,
        &SigningContext {
            signing_key: &key_ctx.signing_key,
            signer_kid: kid,
            signer_pub: None,
            debug: false,
        },
    )
    .unwrap();

    let mut file_enc_doc_tampered = file_enc_doc.clone();
    file_enc_doc_tampered.signature.sig =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"tampered_signature");
    let json = serde_json::to_string_pretty(&file_enc_doc_tampered).unwrap();

    let options = rewrap_options_default(false);
    let result = rewrap_file_document(
        &options,
        &FileEncContent::new_unchecked(json),
        ALICE_MEMBER_ID,
        &key_ctx,
        Some(temp_dir.path()),
    );

    assert!(
        result.is_err(),
        "rewrap_file_document must fail on invalid signature"
    );
}

#[test]
fn test_rewrap_file_flow_succeeds_with_valid_signature() {
    let temp_dir = setup_test_keystore(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, kid);
    setup_workspace_members(&temp_dir, ALICE_MEMBER_ID, kid);

    let content = b"secret";
    let recipient_ids = vec![ALICE_MEMBER_ID.to_string()];
    let members = make_verified_members(&[public_key]);

    let file_enc_doc = encrypt_file_document(
        content,
        &recipient_ids,
        &members,
        &SigningContext {
            signing_key: &key_ctx.signing_key,
            signer_kid: kid,
            signer_pub: None,
            debug: false,
        },
    )
    .unwrap();

    let json = serde_json::to_string_pretty(&file_enc_doc).unwrap();
    let options = rewrap_options_default(false);
    let result = rewrap_file_document(
        &options,
        &FileEncContent::new_unchecked(json),
        ALICE_MEMBER_ID,
        &key_ctx,
        Some(temp_dir.path()),
    );

    assert!(
        result.is_ok(),
        "rewrap_file_document must succeed with valid signature: {:?}",
        result.err()
    );
}
