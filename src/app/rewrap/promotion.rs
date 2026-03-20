// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::rewrap::IncomingVerificationItem;

use super::types::IncomingVerificationReport;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromotionWarning {
    VerificationFailed { member_id: String, message: String },
    ForceSkippedTofu,
    ForceNoEligibleMembers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromotionBlockError {
    OnlineVerificationFailed,
    TofuConfirmationRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromotionDecision {
    None,
    AutoAccept {
        accepted_member_ids: Vec<String>,
        warnings: Vec<PromotionWarning>,
    },
    Prompt {
        candidates: Vec<IncomingVerificationItem>,
    },
    Blocked {
        warnings: Vec<PromotionWarning>,
        error: PromotionBlockError,
    },
}

pub fn build_promotion_decision(
    report: &IncomingVerificationReport,
    force: bool,
    is_interactive: bool,
) -> PromotionDecision {
    if force {
        let mut warnings = build_failed_warnings(report);
        let accepted_member_ids = report.non_failed_member_ids();
        warnings.push(
            if accepted_member_ids.is_empty() && !report.failed.is_empty() {
                PromotionWarning::ForceNoEligibleMembers
            } else {
                PromotionWarning::ForceSkippedTofu
            },
        );
        return PromotionDecision::AutoAccept {
            accepted_member_ids,
            warnings,
        };
    }

    if !report.failed.is_empty() {
        return PromotionDecision::Blocked {
            warnings: build_failed_warnings(report),
            error: PromotionBlockError::OnlineVerificationFailed,
        };
    }

    let candidates: Vec<IncomingVerificationItem> = report
        .verified
        .iter()
        .chain(report.not_configured.iter())
        .cloned()
        .collect();

    if candidates.is_empty() {
        return PromotionDecision::None;
    }

    if !is_interactive {
        return PromotionDecision::Blocked {
            warnings: Vec::new(),
            error: PromotionBlockError::TofuConfirmationRequired,
        };
    }

    PromotionDecision::Prompt { candidates }
}

fn build_failed_warnings(report: &IncomingVerificationReport) -> Vec<PromotionWarning> {
    report
        .failed
        .iter()
        .map(|result| PromotionWarning::VerificationFailed {
            member_id: result.member_id.clone(),
            message: result.message.clone(),
        })
        .collect()
}
