// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Common formatting functions for inspection.

use crate::model::common::{RemovedRecipient, WrapItem};
use crate::model::file_enc::FilePayload;
use crate::support::kid::build_kid_display;

/// Append file payload information.
pub(crate) fn append_file_payload_info(payload: &FilePayload, out: &mut String) {
    push_line(out, "  Protected:");
    push_line(out, format!("    format:    {}", payload.protected.format));
    push_line(
        out,
        format!("    alg.aead:  {}", payload.protected.alg.aead),
    );
    push_line(out, "  Encrypted:");
    push_line(out, format!("    nonce:  {}", payload.encrypted.nonce));
    push_line(
        out,
        format!(
            "    ct:     {} bytes ({}...)",
            payload.encrypted.ct.len(),
            &payload.encrypted.ct[..payload.encrypted.ct.len().min(64)]
        ),
    );
}

/// Append wrap item information.
pub(crate) fn append_wrap_item(index: usize, wrap: &WrapItem, out: &mut String) {
    let kid_display = build_kid_display(&wrap.kid).unwrap_or_else(|_| wrap.kid.clone());
    push_line(out, format!("  [{}] rid:  {}", index, wrap.rid));
    push_line(out, format!("      kid:  {}", kid_display));
    push_line(out, format!("      alg:  {}", wrap.alg));
    push_line(
        out,
        format!("      enc:  {}...", &wrap.enc[..wrap.enc.len().min(32)]),
    );
    push_line(
        out,
        format!("      ct:   {}...", &wrap.ct[..wrap.ct.len().min(32)]),
    );
}

/// Append removed recipients history.
pub(crate) fn append_removed_recipients(removed: Option<&Vec<RemovedRecipient>>, out: &mut String) {
    if let Some(removed) = removed {
        if !removed.is_empty() {
            push_line(out, "");
            push_line(
                out,
                format!("Removed Recipients History ({}):", removed.len()),
            );
            for r in removed {
                let kid_display = build_kid_display(&r.kid).unwrap_or_else(|_| r.kid.clone());
                push_line(
                    out,
                    format!(
                        "  - {} (kid: {}, removed at {})",
                        r.rid, kid_display, r.removed_at
                    ),
                );
            }
        }
    }
}

/// Append signer attestation information for any document type.
pub(crate) fn append_signer_info(
    signer_pub: Option<&crate::model::public_key::PublicKey>,
    out: &mut String,
) {
    if let Some(signer_pub) = signer_pub {
        let attestation = &signer_pub.protected.identity.attestation;
        push_line(
            out,
            format!(
                "Signer:     {} (claimed, not verified)",
                signer_pub.protected.member_id
            ),
        );
        push_line(out, format!("Attestation Method: {}", attestation.method));
        if attestation.pub_.is_empty() {
            push_line(out, "Attestation Pubkey: (empty)");
        } else {
            let shown_len = attestation.pub_.len().min(60);
            let shown = &attestation.pub_[..shown_len];
            let suffix = if attestation.pub_.len() > shown_len {
                "..."
            } else {
                ""
            };
            push_line(out, format!("Attestation Pubkey: {}{}", shown, suffix));
        }
    } else {
        push_line(out, "Signer:     (not embedded, search by kid)");
    }
}

/// Push a line to output string.
pub(crate) fn push_line(out: &mut String, line: impl AsRef<str>) {
    out.push_str(line.as_ref());
    out.push('\n');
}
