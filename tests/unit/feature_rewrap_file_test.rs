// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for feature/rewrap/file module (file-enc document rewrap operations).

use crate::cli_common::{ALICE_MEMBER_ID, BOB_MEMBER_ID};
use crate::keygen_helpers::make_verified_members;
use crate::test_utils::{setup_test_keystore, stub_ssh_keygen};
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

/// Build CryptoContext for a member in a test keystore.
fn setup_member_key_context(temp_dir: &TempDir, member_id: &str, kid: &str) -> CryptoContext {
    let keystore_root = temp_dir.path().join("keys");
    let ssh_pub =
        fs::read_to_string(temp_dir.path().join(".ssh").join("test_ed25519.pub")).unwrap();
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

/// Create workspace members directory with the member's public key file.
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

/// Build default RewrapOptions.
fn rewrap_options_default(debug: bool) -> RewrapOptions {
    RewrapOptions {
        rotate_key: false,
        clear_disclosure_history: false,
        token_codec: None,
        no_signer_pub: false,
        debug,
    }
}

/// Encrypt file content for alice (single recipient), returning the JSON string.
fn encrypt_file_for_alice(temp_dir: &TempDir, kid: &str, key_ctx: &CryptoContext) -> String {
    let keystore_root = temp_dir.path().join("keys");
    let public_key = load_public_key(&keystore_root, ALICE_MEMBER_ID, kid).unwrap();
    let members = make_verified_members(&[public_key]);
    let content = b"test secret data";
    let recipient_ids = vec![ALICE_MEMBER_ID.to_string()];

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

    serde_json::to_string_pretty(&file_enc_doc).unwrap()
}

/// Encrypt file content for alice and bob (two recipients), returning the JSON string.
fn encrypt_file_for_alice_and_bob(
    temp_dir: &TempDir,
    alice_kid: &str,
    bob_kid: &str,
    key_ctx: &CryptoContext,
) -> String {
    let keystore_root = temp_dir.path().join("keys");
    let alice_pub = load_public_key(&keystore_root, ALICE_MEMBER_ID, alice_kid).unwrap();
    let bob_pub = load_public_key(&keystore_root, BOB_MEMBER_ID, bob_kid).unwrap();
    let members = make_verified_members(&[alice_pub, bob_pub]);
    let content = b"test secret data";
    let recipient_ids = vec![ALICE_MEMBER_ID.to_string(), BOB_MEMBER_ID.to_string()];

    let file_enc_doc = encrypt_file_document(
        content,
        &recipient_ids,
        &members,
        &SigningContext {
            signing_key: &key_ctx.signing_key,
            signer_kid: alice_kid,
            signer_pub: None,
            debug: false,
        },
    )
    .unwrap();

    serde_json::to_string_pretty(&file_enc_doc).unwrap()
}

/// Setup a two-member keystore (alice + bob) in one TempDir.
///
/// Returns (temp_dir, alice_kid, bob_kid).
fn setup_two_member_keystore() -> (TempDir, String, String) {
    let temp_dir = setup_test_keystore(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    let alice_kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let alice_kid = alice_kids.first().unwrap().clone();

    let (bob_private, bob_public) = crate::keygen_helpers::keygen_test(BOB_MEMBER_ID).unwrap();
    let bob_kid = bob_public.protected.kid.clone();
    let bob_private_doc = crate::keygen_helpers::create_test_private_key(
        &bob_private,
        &bob_public.protected.member_id,
        &bob_public.protected.kid,
    )
    .unwrap();
    secretenv::io::keystore::storage::save_key_pair_atomic(
        &keystore_root,
        BOB_MEMBER_ID,
        &bob_kid,
        &bob_private_doc,
        &bob_public,
    )
    .unwrap();

    (temp_dir, alice_kid, bob_kid)
}

#[test]
fn test_rewrap_file_add_recipient() {
    let (temp_dir, alice_kid, bob_kid) = setup_two_member_keystore();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, &alice_kid);

    // Encrypt for alice only
    let json = encrypt_file_for_alice(&temp_dir, &alice_kid, &key_ctx);

    // Setup workspace with both alice and bob as active members
    setup_workspace_members(&temp_dir, ALICE_MEMBER_ID, &alice_kid);
    setup_workspace_members(&temp_dir, BOB_MEMBER_ID, &bob_kid);

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
        "rewrap adding recipient must succeed: {:?}",
        result.err()
    );

    // Parse the rewrapped document to verify bob was added
    let rewrapped = result.unwrap();
    let doc: secretenv::model::file_enc::FileEncDocument =
        serde_json::from_str(&rewrapped).unwrap();
    let recipient_ids: Vec<&str> = doc.protected.wrap.iter().map(|w| w.rid.as_str()).collect();
    assert!(
        recipient_ids.contains(&BOB_MEMBER_ID),
        "rewrapped document must include bob as a recipient, got: {:?}",
        recipient_ids
    );
    assert!(
        recipient_ids.contains(&ALICE_MEMBER_ID),
        "rewrapped document must still include alice as a recipient, got: {:?}",
        recipient_ids
    );
}

#[test]
fn test_rewrap_file_remove_recipient() {
    let (temp_dir, alice_kid, bob_kid) = setup_two_member_keystore();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, &alice_kid);

    // Encrypt for alice and bob
    let json = encrypt_file_for_alice_and_bob(&temp_dir, &alice_kid, &bob_kid, &key_ctx);

    // Setup workspace with only alice (bob removed)
    setup_workspace_members(&temp_dir, ALICE_MEMBER_ID, &alice_kid);

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
        "rewrap removing recipient must succeed: {:?}",
        result.err()
    );

    // After removal, bob should not be in the wrap recipients
    let rewrapped = result.unwrap();
    let doc: secretenv::model::file_enc::FileEncDocument =
        serde_json::from_str(&rewrapped).unwrap();
    let recipient_ids: Vec<&str> = doc.protected.wrap.iter().map(|w| w.rid.as_str()).collect();
    assert!(
        !recipient_ids.contains(&BOB_MEMBER_ID),
        "rewrapped document must not include bob as a recipient, got: {:?}",
        recipient_ids
    );
    assert!(
        recipient_ids.contains(&ALICE_MEMBER_ID),
        "rewrapped document must still include alice, got: {:?}",
        recipient_ids
    );
}

#[test]
fn test_rewrap_file_rotate_key() {
    let temp_dir = setup_test_keystore(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, kid);
    setup_workspace_members(&temp_dir, ALICE_MEMBER_ID, kid);

    let json = encrypt_file_for_alice(&temp_dir, kid, &key_ctx);

    let options = RewrapOptions {
        rotate_key: true,
        clear_disclosure_history: false,
        token_codec: None,
        no_signer_pub: false,
        debug: false,
    };
    let result = rewrap_file_document(
        &options,
        &FileEncContent::new_unchecked(json.clone()),
        ALICE_MEMBER_ID,
        &key_ctx,
        Some(temp_dir.path()),
    );

    assert!(
        result.is_ok(),
        "rewrap with rotate_key must succeed: {:?}",
        result.err()
    );

    // Rotated content must be valid JSON and wrap items should differ
    let rewrapped = result.unwrap();
    let original_doc: secretenv::model::file_enc::FileEncDocument =
        serde_json::from_str(&json).unwrap();
    let rotated_doc: secretenv::model::file_enc::FileEncDocument =
        serde_json::from_str(&rewrapped).unwrap();

    // The encrypted key material in wrap items should change after rotation
    let original_ct = &original_doc.protected.wrap[0].ct;
    let rotated_ct = &rotated_doc.protected.wrap[0].ct;
    assert_ne!(
        original_ct, rotated_ct,
        "wrap ct must change after key rotation"
    );
}

#[test]
fn test_rewrap_file_clear_disclosure_history() {
    let (temp_dir, alice_kid, bob_kid) = setup_two_member_keystore();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, &alice_kid);

    // Encrypt for alice and bob
    let json = encrypt_file_for_alice_and_bob(&temp_dir, &alice_kid, &bob_kid, &key_ctx);

    // Setup workspace with only alice (bob removed) => removal creates disclosure history
    setup_workspace_members(&temp_dir, ALICE_MEMBER_ID, &alice_kid);

    let remove_options = rewrap_options_default(false);
    let after_remove = rewrap_file_document(
        &remove_options,
        &FileEncContent::new_unchecked(json),
        ALICE_MEMBER_ID,
        &key_ctx,
        Some(temp_dir.path()),
    )
    .unwrap();

    // Verify disclosure history exists after removal
    let after_remove_doc: secretenv::model::file_enc::FileEncDocument =
        serde_json::from_str(&after_remove).unwrap();
    assert!(
        after_remove_doc.protected.removed_recipients.is_some(),
        "removed_recipients should exist after removing bob"
    );

    // Now rewrap again with clear_disclosure_history
    let clear_options = RewrapOptions {
        rotate_key: false,
        clear_disclosure_history: true,
        token_codec: None,
        no_signer_pub: false,
        debug: false,
    };
    let result = rewrap_file_document(
        &clear_options,
        &FileEncContent::new_unchecked(after_remove),
        ALICE_MEMBER_ID,
        &key_ctx,
        Some(temp_dir.path()),
    );

    assert!(
        result.is_ok(),
        "rewrap with clear_disclosure_history must succeed: {:?}",
        result.err()
    );

    // After clearing, removed_recipients should be None
    let cleared = result.unwrap();
    let cleared_doc: secretenv::model::file_enc::FileEncDocument =
        serde_json::from_str(&cleared).unwrap();
    assert!(
        cleared_doc.protected.removed_recipients.is_none(),
        "removed_recipients must be cleared after clear_disclosure_history"
    );
}

#[test]
fn test_rewrap_file_preserves_payload() {
    let temp_dir = setup_test_keystore(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, kid);
    setup_workspace_members(&temp_dir, ALICE_MEMBER_ID, kid);

    let json = encrypt_file_for_alice(&temp_dir, kid, &key_ctx);

    let options = rewrap_options_default(false);
    let result = rewrap_file_document(
        &options,
        &FileEncContent::new_unchecked(json),
        ALICE_MEMBER_ID,
        &key_ctx,
        Some(temp_dir.path()),
    );

    assert!(result.is_ok(), "rewrap must succeed: {:?}", result.err());

    let rewrapped = result.unwrap();
    let doc: secretenv::model::file_enc::FileEncDocument =
        serde_json::from_str(&rewrapped).unwrap();

    assert_eq!(
        doc.protected.format, "secretenv.file@3",
        "format field must be preserved as secretenv.file@3"
    );
}

#[test]
fn test_rewrap_file_requires_workspace() {
    let temp_dir = setup_test_keystore(ALICE_MEMBER_ID);
    let keystore_root = temp_dir.path().join("keys");

    let kids = list_kids(&keystore_root, ALICE_MEMBER_ID).unwrap();
    let kid = kids.first().unwrap();
    let key_ctx = setup_member_key_context(&temp_dir, ALICE_MEMBER_ID, kid);

    let json = encrypt_file_for_alice(&temp_dir, kid, &key_ctx);

    let options = rewrap_options_default(false);
    let result = rewrap_file_document(
        &options,
        &FileEncContent::new_unchecked(json),
        ALICE_MEMBER_ID,
        &key_ctx,
        None,
    );

    assert!(
        result.is_err(),
        "rewrap_file_document must fail when workspace_root is None"
    );

    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("workspace"),
        "error message must mention workspace, got: {}",
        err_msg
    );
}
