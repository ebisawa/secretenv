// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-layer orchestration for rewrap flows.

mod execution;
mod plan;
mod promotion;
mod types;

pub use execution::execute_rewrap_batch;
pub use plan::build_rewrap_batch_plan;
pub use promotion::{
    build_promotion_decision, PromotionBlockError, PromotionDecision, PromotionWarning,
};
pub use types::{
    IncomingGithubAccount, IncomingVerificationCategory, IncomingVerificationItem,
    IncomingVerificationReport, RewrapBatchOutcome, RewrapBatchPlan, RewrapBatchRequest,
    RewrapFileFailure, RewrapFileSuccess,
};
