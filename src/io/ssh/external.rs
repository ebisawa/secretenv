// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! External SSH tool adapters (ssh-keygen, ssh-add)

pub mod add;
pub mod keygen;
pub mod pubkey;
pub mod temp_file;
pub mod traits;
