// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for crypto module

use secretenv::crypto::kem::{X25519PublicKey, X25519SecretKey};
use secretenv::crypto::sign::{sign_bytes, verify_bytes};
use secretenv::model::identifiers::alg::SIGNATURE_ED25519;
use serde::{Deserialize, Serialize};

// Test helper to generate X25519 keypair from seed
fn generate_x25519_keypair(seed: [u8; 32]) -> (X25519SecretKey, X25519PublicKey) {
    // Apply X25519 clamping (RFC 7748 section 5)
    let mut clamped = seed;
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;

    let secret = x25519_dalek::StaticSecret::from(clamped);
    let public = x25519_dalek::PublicKey::from(&secret);

    (
        X25519SecretKey::from_bytes(clamped),
        X25519PublicKey::from_bytes(*public.as_bytes()),
    )
}

// Test helper to generate Ed25519 keypair from seed
fn generate_ed25519_keypair(
    seed: [u8; 32],
) -> (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();
    (sk, vk)
}

// AES-GCM tests

#[test]
fn test_aes_gcm_encrypt_decrypt_roundtrip() {
    use secretenv::crypto::aead::aes_gcm::{
        decrypt as aes_gcm_decrypt, encrypt as aes_gcm_encrypt,
    };
    use secretenv::crypto::types::data::{Aad, Plaintext};
    use secretenv::crypto::types::keys::AesKey;
    use secretenv::crypto::types::primitives::AesNonce;

    let key = AesKey::new([42u8; 32]);
    let nonce = AesNonce::new([1u8; 12]);
    let aad = Aad::from(b"test-aad" as &[u8]);
    let plaintext = Plaintext::from(b"Hello, secretenv!" as &[u8]);

    let ciphertext = aes_gcm_encrypt(&key, &nonce, &aad, &plaintext).unwrap();
    let decrypted = aes_gcm_decrypt(&key, &nonce, &aad, &ciphertext).unwrap();

    assert_eq!(plaintext.as_bytes(), decrypted.as_bytes());
}

#[test]
fn test_aes_gcm_wrong_key_error() {
    use secretenv::crypto::aead::aes_gcm::{
        decrypt as aes_gcm_decrypt, encrypt as aes_gcm_encrypt,
    };
    use secretenv::crypto::types::data::{Aad, Plaintext};
    use secretenv::crypto::types::keys::AesKey;
    use secretenv::crypto::types::primitives::AesNonce;

    let key1 = AesKey::new([1u8; 32]);
    let key2 = AesKey::new([2u8; 32]);
    let nonce = AesNonce::new([0u8; 12]);
    let aad = Aad::from(b"test-aad" as &[u8]);
    let plaintext = Plaintext::from(b"secret data" as &[u8]);

    let ciphertext = aes_gcm_encrypt(&key1, &nonce, &aad, &plaintext).unwrap();
    let result = aes_gcm_decrypt(&key2, &nonce, &aad, &ciphertext);

    assert!(result.is_err(), "Decryption with wrong key should fail");
}

#[test]
fn test_aes_gcm_wrong_aad_error() {
    use secretenv::crypto::aead::aes_gcm::{
        decrypt as aes_gcm_decrypt, encrypt as aes_gcm_encrypt,
    };
    use secretenv::crypto::types::data::{Aad, Plaintext};
    use secretenv::crypto::types::keys::AesKey;
    use secretenv::crypto::types::primitives::AesNonce;

    let key = AesKey::new([42u8; 32]);
    let nonce = AesNonce::new([1u8; 12]);
    let aad1 = Aad::from(b"correct-aad" as &[u8]);
    let aad2 = Aad::from(b"wrong-aad" as &[u8]);
    let plaintext = Plaintext::from(b"secret data" as &[u8]);

    let ciphertext = aes_gcm_encrypt(&key, &nonce, &aad1, &plaintext).unwrap();
    let result = aes_gcm_decrypt(&key, &nonce, &aad2, &ciphertext);

    assert!(result.is_err(), "Decryption with wrong AAD should fail");
}

#[test]
fn test_aes_gcm_tampered_ciphertext_error() {
    use secretenv::crypto::aead::aes_gcm::{
        decrypt as aes_gcm_decrypt, encrypt as aes_gcm_encrypt,
    };
    use secretenv::crypto::types::data::{Aad, Ciphertext, Plaintext};
    use secretenv::crypto::types::keys::AesKey;
    use secretenv::crypto::types::primitives::AesNonce;

    let key = AesKey::new([42u8; 32]);
    let nonce = AesNonce::new([1u8; 12]);
    let aad = Aad::from(b"test-aad" as &[u8]);
    let plaintext = Plaintext::from(b"secret data" as &[u8]);

    let mut ciphertext_bytes = aes_gcm_encrypt(&key, &nonce, &aad, &plaintext)
        .unwrap()
        .into_bytes();
    if let Some(byte) = ciphertext_bytes.get_mut(0) {
        *byte ^= 0xFF;
    }
    let ciphertext = Ciphertext::from(ciphertext_bytes);

    assert!(aes_gcm_decrypt(&key, &nonce, &aad, &ciphertext).is_err());
}

#[test]
fn test_aes_gcm_ciphertext_includes_tag() {
    use secretenv::crypto::aead::aes_gcm::encrypt as aes_gcm_encrypt;
    use secretenv::crypto::types::data::{Aad, Plaintext};
    use secretenv::crypto::types::keys::AesKey;
    use secretenv::crypto::types::primitives::AesNonce;

    let key = AesKey::new([42u8; 32]);
    let nonce = AesNonce::new([1u8; 12]);
    let aad = Aad::from(b"test-aad" as &[u8]);
    let plaintext = Plaintext::from(b"Hello!" as &[u8]);

    let ciphertext = aes_gcm_encrypt(&key, &nonce, &aad, &plaintext).unwrap();
    assert_eq!(ciphertext.as_bytes().len(), plaintext.as_bytes().len() + 16);
}

#[test]
fn test_aes_gcm_empty_plaintext() {
    use secretenv::crypto::aead::aes_gcm::{
        decrypt as aes_gcm_decrypt, encrypt as aes_gcm_encrypt,
    };
    use secretenv::crypto::types::data::{Aad, Plaintext};
    use secretenv::crypto::types::keys::AesKey;
    use secretenv::crypto::types::primitives::AesNonce;

    let key = AesKey::new([42u8; 32]);
    let nonce = AesNonce::new([1u8; 12]);
    let aad = Aad::from(b"test-aad" as &[u8]);
    let plaintext = Plaintext::from(b"" as &[u8]);

    let ciphertext = aes_gcm_encrypt(&key, &nonce, &aad, &plaintext).unwrap();
    let decrypted = aes_gcm_decrypt(&key, &nonce, &aad, &ciphertext).unwrap();

    assert_eq!(plaintext.as_bytes(), decrypted.as_bytes());
    assert_eq!(ciphertext.as_bytes().len(), 16);
}

#[test]
fn test_aes_gcm_decrypted_is_zeroizing() {
    use secretenv::crypto::aead::aes_gcm::{
        decrypt as aes_gcm_decrypt, encrypt as aes_gcm_encrypt,
    };
    use secretenv::crypto::types::data::{Aad, Plaintext};
    use secretenv::crypto::types::keys::AesKey;
    use secretenv::crypto::types::primitives::AesNonce;
    use zeroize::Zeroizing;

    let key = AesKey::new([42u8; 32]);
    let nonce = AesNonce::new([1u8; 12]);
    let aad = Aad::from(b"test-aad" as &[u8]);
    let plaintext = Plaintext::from(b"secret" as &[u8]);

    let ciphertext = aes_gcm_encrypt(&key, &nonce, &aad, &plaintext).unwrap();
    let decrypted: Zeroizing<Plaintext> = aes_gcm_decrypt(&key, &nonce, &aad, &ciphertext).unwrap();
    assert_eq!(decrypted.as_bytes(), plaintext.as_bytes());
}

// HPKE tests

#[test]
fn test_hpke_enc_length() {
    use secretenv::crypto::kem::seal_base;
    use secretenv::crypto::types::data::{Aad, Info, Plaintext};

    let member_seed = [1u8; 32];
    let (_, pk) = generate_x25519_keypair(member_seed);

    let info = Info::from(b"test-info" as &[u8]);
    let aad = Aad::from(b"test-aad" as &[u8]);
    let plaintext = Plaintext::from(b"data" as &[u8]);

    let (enc, _) = seal_base(&pk, &info, &aad, &plaintext).unwrap();
    assert_eq!(enc.as_bytes().len(), 32);
}

#[test]
fn test_hpke_different_info_error() {
    use secretenv::crypto::kem::{open_base, seal_base};
    use secretenv::crypto::types::data::{Aad, Ciphertext, Enc, Info, Plaintext};

    let member_seed = [42u8; 32];
    let (sk, pk) = generate_x25519_keypair(member_seed);

    let info1 = Info::from(b"correct-info" as &[u8]);
    let info2 = Info::from(b"wrong-info" as &[u8]);
    let aad = Aad::from(b"test-aad" as &[u8]);
    let plaintext = Plaintext::from(b"secret" as &[u8]);

    let (enc, ciphertext) = seal_base(&pk, &info1, &aad, &plaintext).unwrap();
    let enc_obj = Enc::from(enc.into_bytes());
    let ct_obj = Ciphertext::from(ciphertext.into_bytes());
    assert!(open_base(&sk, &enc_obj, &info2, &aad, &ct_obj).is_err());
}

#[test]
fn test_hpke_different_aad_error() {
    use secretenv::crypto::kem::{open_base, seal_base};
    use secretenv::crypto::types::data::{Aad, Ciphertext, Enc, Info, Plaintext};

    let member_seed = [42u8; 32];
    let (sk, pk) = generate_x25519_keypair(member_seed);

    let info = Info::from(b"test-info" as &[u8]);
    let aad1 = Aad::from(b"correct-aad" as &[u8]);
    let aad2 = Aad::from(b"wrong-aad" as &[u8]);
    let plaintext = Plaintext::from(b"secret" as &[u8]);

    let (enc, ciphertext) = seal_base(&pk, &info, &aad1, &plaintext).unwrap();
    let enc_obj = Enc::from(enc.into_bytes());
    let ct_obj = Ciphertext::from(ciphertext.into_bytes());
    assert!(open_base(&sk, &enc_obj, &info, &aad2, &ct_obj).is_err());
}

#[test]
fn test_hpke_wrong_recipient_key_error() {
    use secretenv::crypto::kem::{open_base, seal_base};
    use secretenv::crypto::types::data::{Aad, Ciphertext, Enc, Info, Plaintext};

    let (_, alice_pk) = generate_x25519_keypair([1u8; 32]);
    let (bob_sk, _) = generate_x25519_keypair([2u8; 32]);

    let info = Info::from(b"test-info" as &[u8]);
    let aad = Aad::from(b"test-aad" as &[u8]);
    let plaintext = Plaintext::from(b"secret" as &[u8]);

    let (enc, ciphertext) = seal_base(&alice_pk, &info, &aad, &plaintext).unwrap();
    let enc_obj = Enc::from(enc.into_bytes());
    let ct_obj = Ciphertext::from(ciphertext.into_bytes());
    assert!(open_base(&bob_sk, &enc_obj, &info, &aad, &ct_obj).is_err());
}

#[test]
fn test_hpke_ciphertext_length() {
    use secretenv::crypto::kem::seal_base;
    use secretenv::crypto::types::data::{Aad, Info, Plaintext};

    let member_seed = [42u8; 32];
    let (_, pk) = generate_x25519_keypair(member_seed);

    let info = Info::from(b"test-info" as &[u8]);
    let aad = Aad::from(b"test-aad" as &[u8]);
    let plaintext = Plaintext::from(b"Hello!" as &[u8]);

    let (_, ciphertext) = seal_base(&pk, &info, &aad, &plaintext).unwrap();
    assert_eq!(ciphertext.as_bytes().len(), plaintext.as_bytes().len() + 16);
}

#[test]
fn test_hpke_empty_plaintext() {
    use secretenv::crypto::kem::{open_base, seal_base};
    use secretenv::crypto::types::data::{Aad, Ciphertext, Enc, Info, Plaintext};

    let member_seed = [42u8; 32];
    let (sk, pk) = generate_x25519_keypair(member_seed);

    let info = Info::from(b"test-info" as &[u8]);
    let aad = Aad::from(b"test-aad" as &[u8]);
    let plaintext = Plaintext::from(b"" as &[u8]);

    let (enc, ciphertext) = seal_base(&pk, &info, &aad, &plaintext).unwrap();
    let enc_obj = Enc::from(enc.into_bytes());
    let ct_obj = Ciphertext::from(ciphertext.into_bytes());
    let decrypted = open_base(&sk, &enc_obj, &info, &aad, &ct_obj).unwrap();
    assert!(decrypted.as_bytes().is_empty());
}

// Ed25519 signature tests

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct TestDocument {
    format: String,
    data: String,
    version: u32,
}

#[test]
fn test_ed25519_sign_verify_roundtrip() {
    let member_seed = [42u8; 32];
    let (signing_key, verifying_key) = generate_ed25519_keypair(member_seed);

    let doc = TestDocument {
        format: "test@1".to_string(),
        data: "hello".to_string(),
        version: 1,
    };

    // JCS normalize the document
    let canonical_bytes = secretenv::format::jcs::normalize(&doc).unwrap();
    let signature = sign_bytes(
        &canonical_bytes,
        &signing_key,
        "01HTEST0000000000000000000",
        None,
        SIGNATURE_ED25519,
    )
    .unwrap();
    verify_bytes(
        &canonical_bytes,
        &verifying_key,
        &signature,
        SIGNATURE_ED25519,
    )
    .unwrap();
}

#[test]
fn test_ed25519_wrong_key_error() {
    let (alice_sk, _) = generate_ed25519_keypair([1u8; 32]);
    let (_, bob_vk) = generate_ed25519_keypair([2u8; 32]);

    let doc = TestDocument {
        format: "test@1".to_string(),
        data: "secret".to_string(),
        version: 1,
    };

    let canonical_bytes = secretenv::format::jcs::normalize(&doc).unwrap();
    let signature = sign_bytes(
        &canonical_bytes,
        &alice_sk,
        "01HTEST0000000000000000000",
        None,
        SIGNATURE_ED25519,
    )
    .unwrap();
    assert!(verify_bytes(&canonical_bytes, &bob_vk, &signature, SIGNATURE_ED25519,).is_err());
}

#[test]
fn test_ed25519_tampered_document_error() {
    let member_seed = [42u8; 32];
    let (signing_key, verifying_key) = generate_ed25519_keypair(member_seed);

    let original_doc = TestDocument {
        format: "test@1".to_string(),
        data: "original".to_string(),
        version: 1,
    };

    let original_canonical = secretenv::format::jcs::normalize(&original_doc).unwrap();
    let signature = sign_bytes(
        &original_canonical,
        &signing_key,
        "01HTEST0000000000000000000",
        None,
        SIGNATURE_ED25519,
    )
    .unwrap();

    let tampered_doc = TestDocument {
        format: "test@1".to_string(),
        data: "tampered".to_string(),
        version: 1,
    };

    let tampered_canonical = secretenv::format::jcs::normalize(&tampered_doc).unwrap();
    assert!(verify_bytes(
        &tampered_canonical,
        &verifying_key,
        &signature,
        SIGNATURE_ED25519,
    )
    .is_err());
}

#[test]
fn test_ed25519_signature_structure() {
    let member_seed = [42u8; 32];
    let (signing_key, _) = generate_ed25519_keypair(member_seed);

    let doc = TestDocument {
        format: "test@1".to_string(),
        data: "data".to_string(),
        version: 1,
    };

    let canonical_bytes = secretenv::format::jcs::normalize(&doc).unwrap();
    let signature = sign_bytes(
        &canonical_bytes,
        &signing_key,
        "01HTEST0000000000000000000",
        None,
        SIGNATURE_ED25519,
    )
    .unwrap();

    assert_eq!(signature.alg, SIGNATURE_ED25519);
    assert!(!signature.sig.is_empty());
    assert!(signature.sig.len() >= 86); // Ed25519 (64B) Base64
}

#[test]
fn test_ed25519_payload_hash_verification() {
    let member_seed = [42u8; 32];
    let (signing_key, verifying_key) = generate_ed25519_keypair(member_seed);

    let doc = TestDocument {
        format: "test@1".to_string(),
        data: "data".to_string(),
        version: 1,
    };

    let canonical_bytes = secretenv::format::jcs::normalize(&doc).unwrap();
    let signature = sign_bytes(
        &canonical_bytes,
        &signing_key,
        "01HTEST0000000000000000000",
        None,
        SIGNATURE_ED25519,
    )
    .unwrap();
    verify_bytes(
        &canonical_bytes,
        &verifying_key,
        &signature,
        SIGNATURE_ED25519,
    )
    .unwrap();
}

#[test]
fn test_ed25519_deterministic_signing() {
    let member_seed = [42u8; 32];
    let (signing_key, _) = generate_ed25519_keypair(member_seed);

    let doc = TestDocument {
        format: "test@1".to_string(),
        data: "data".to_string(),
        version: 1,
    };

    let canonical_bytes = secretenv::format::jcs::normalize(&doc).unwrap();
    let sig1 = sign_bytes(
        &canonical_bytes,
        &signing_key,
        "01HTEST0000000000000000000",
        None,
        SIGNATURE_ED25519,
    )
    .unwrap();
    let sig2 = sign_bytes(
        &canonical_bytes,
        &signing_key,
        "01HTEST0000000000000000000",
        None,
        SIGNATURE_ED25519,
    )
    .unwrap();

    assert_eq!(sig1.sig, sig2.sig);
}

#[test]
fn test_ed25519_jcs_normalization_applied() {
    let member_seed = [42u8; 32];
    let (signing_key, verifying_key) = generate_ed25519_keypair(member_seed);

    let doc = TestDocument {
        format: "test@1".to_string(),
        data: "data".to_string(),
        version: 1,
    };

    let canonical_bytes = secretenv::format::jcs::normalize(&doc).unwrap();
    let signature = sign_bytes(
        &canonical_bytes,
        &signing_key,
        "01HTEST0000000000000000000",
        None,
        SIGNATURE_ED25519,
    )
    .unwrap();
    verify_bytes(
        &canonical_bytes,
        &verifying_key,
        &signature,
        SIGNATURE_ED25519,
    )
    .unwrap();
}
