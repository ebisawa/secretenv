// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for password-based key derivation (Argon2id + HKDF-SHA256)

use secretenv::crypto::types::primitives::Salt;
use secretenv::feature::key::protection::password_key_derivation::{
    derive_key_from_password, generate_salt, validate_argon2_params, Argon2Params,
    DEFAULT_ARGON2_PARAMS,
};

#[test]
fn test_derive_key_from_password_deterministic() {
    let salt = Salt::new([1u8; 16]);
    let kid = "test-kid-001";
    let password = "correct horse battery staple";

    let key1 = derive_key_from_password(password, &salt, kid, &DEFAULT_ARGON2_PARAMS).unwrap();
    let key2 = derive_key_from_password(password, &salt, kid, &DEFAULT_ARGON2_PARAMS).unwrap();

    assert_eq!(key1.as_bytes().len(), 32);
    assert_eq!(key1.as_bytes(), key2.as_bytes());
}

#[test]
fn test_derive_key_different_passwords_differ() {
    let salt = Salt::new([2u8; 16]);
    let kid = "test-kid-002";

    let key1 = derive_key_from_password("password-a", &salt, kid, &DEFAULT_ARGON2_PARAMS).unwrap();
    let key2 = derive_key_from_password("password-b", &salt, kid, &DEFAULT_ARGON2_PARAMS).unwrap();

    assert_ne!(key1.as_bytes(), key2.as_bytes());
}

#[test]
fn test_derive_key_different_salts_differ() {
    let salt1 = Salt::new([3u8; 16]);
    let salt2 = Salt::new([4u8; 16]);
    let kid = "test-kid-003";
    let password = "same-password";

    let key1 = derive_key_from_password(password, &salt1, kid, &DEFAULT_ARGON2_PARAMS).unwrap();
    let key2 = derive_key_from_password(password, &salt2, kid, &DEFAULT_ARGON2_PARAMS).unwrap();

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
fn test_validate_argon2_params_default_ok() {
    assert!(validate_argon2_params(&DEFAULT_ARGON2_PARAMS).is_ok());
}

#[test]
fn test_validate_argon2_params_m_too_low_fails() {
    let params = Argon2Params {
        m: 1024,
        t: 1,
        p: 1,
    };
    assert!(validate_argon2_params(&params).is_err());
}

#[test]
fn test_validate_argon2_params_t_zero_fails() {
    let params = Argon2Params {
        m: 47104,
        t: 0,
        p: 1,
    };
    assert!(validate_argon2_params(&params).is_err());
}

#[test]
fn test_validate_argon2_params_p_zero_fails() {
    let params = Argon2Params {
        m: 47104,
        t: 1,
        p: 0,
    };
    assert!(validate_argon2_params(&params).is_err());
}
