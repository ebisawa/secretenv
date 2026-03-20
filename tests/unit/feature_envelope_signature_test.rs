// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use super::*;

#[test]
fn test_sign_and_append_kv_sig_produces_sig_line() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let kid = "test-kid";
    let unsigned = ":SECRETENV_KV 3\n:HEAD {}\n:WRAP {}\nKEY token\n";

    let result = sign_and_append_kv_sig(
        unsigned,
        &signing_key,
        kid,
        None,
        TokenCodec::JsonJcs,
        false,
        "test",
    );

    assert!(result.is_ok());
    let signed = result.unwrap();
    assert!(signed.starts_with(unsigned));
    assert!(signed.contains(":SIG "));
    assert!(signed.ends_with('\n'));
}

#[test]
fn test_sign_and_append_kv_sig_preserves_unsigned_content() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let unsigned = ":SECRETENV_KV 3\n:HEAD tok\n:WRAP tok\nA val\nB val\n";

    let signed = sign_and_append_kv_sig(
        unsigned,
        &signing_key,
        "kid",
        None,
        TokenCodec::JsonJcs,
        false,
        "test",
    )
    .unwrap();

    assert!(signed.starts_with(unsigned));
    let extra = &signed[unsigned.len()..];
    assert!(extra.starts_with(":SIG "));
    assert_eq!(extra.matches('\n').count(), 1);
}
