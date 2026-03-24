// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for password-based key derivation (Argon2id + HKDF-SHA256)

use secretenv::crypto::types::primitives::Salt;
use secretenv::feature::key::protection::password_key_derivation::{
    derive_key_from_password, generate_salt,
};

#[test]
fn test_derive_key_from_password_deterministic() {
    let salt = Salt::new([1u8; 16]);
    let kid = "test-kid-001";
    let password = "correct horse battery staple";

    let key1 = derive_key_from_password(password, &salt, kid, false).unwrap();
    let key2 = derive_key_from_password(password, &salt, kid, false).unwrap();

    assert_eq!(key1.as_bytes().len(), 32);
    assert_eq!(key1.as_bytes(), key2.as_bytes());
}

#[test]
fn test_derive_key_different_passwords_differ() {
    let salt = Salt::new([2u8; 16]);
    let kid = "test-kid-002";

    let key1 = derive_key_from_password("password-a", &salt, kid, false).unwrap();
    let key2 = derive_key_from_password("password-b", &salt, kid, false).unwrap();

    assert_ne!(key1.as_bytes(), key2.as_bytes());
}

#[test]
fn test_derive_key_different_salts_differ() {
    let salt1 = Salt::new([3u8; 16]);
    let salt2 = Salt::new([4u8; 16]);
    let kid = "test-kid-003";
    let password = "same-password";

    let key1 = derive_key_from_password(password, &salt1, kid, false).unwrap();
    let key2 = derive_key_from_password(password, &salt2, kid, false).unwrap();

    assert_ne!(key1.as_bytes(), key2.as_bytes());
}

#[test]
fn test_generate_salt_length() {
    let salt = generate_salt();
    assert_eq!(salt.as_bytes().len(), 16);
}

#[test]
fn test_generate_salt_randomness() {
    let salt1 = generate_salt();
    let salt2 = generate_salt();
    assert_ne!(salt1.as_bytes(), salt2.as_bytes());
}

#[test]
fn test_derive_key_different_kids_differ() {
    let salt = Salt::new([5u8; 16]);
    let password = "same-password-for-both";

    let key1 = derive_key_from_password(password, &salt, "kid-aaa", false).unwrap();
    let key2 = derive_key_from_password(password, &salt, "kid-bbb", false).unwrap();

    assert_ne!(
        key1.as_bytes(),
        key2.as_bytes(),
        "Same password and salt with different kids must produce different keys"
    );
}
