// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV feature - get/set/unset/list operations.

pub mod builder;
pub mod decrypt;
pub mod encrypt;
mod mutate;
mod query;
pub(crate) mod rewrite;
pub(crate) mod sign;

pub use mutate::{set_kv_entry, unset_kv_entry, KvSetResult, KvWriteContext};
pub use query::{
    check_kv_entry_disclosed, decrypt_all_kv_values, decrypt_kv_value, list_kv_keys,
    list_kv_keys_with_disclosed,
};
