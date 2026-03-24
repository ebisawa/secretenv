// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-layer member registration helpers for init/join flows.

mod setup;
mod types;
mod workspace;

pub use setup::{
    apply_registration, build_init_registration, build_join_registration,
    build_registration_outcome, resolve_registration_key_plan,
};
pub use types::MemberStatus;
pub use types::{
    MemberKeySetupResult, MemberSetupResult, PreparedRegistration, RegistrationKeyPlan,
    RegistrationMode, RegistrationOutcome, RegistrationResult,
};
