// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Member feature - member management (verification, add, promotion).

pub mod add;
pub mod promotion;
pub mod verification;

// Re-export for backward compatibility with existing `feature::member::*` paths.
pub use verification::{classify_verification_results, verify_incoming_members, verify_member};
