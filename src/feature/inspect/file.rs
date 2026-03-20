// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! File-enc inspection.

use crate::model::file_enc::FileEncDocument;

use super::formatter::{
    append_file_payload_info, append_removed_recipients, append_signer_info, append_wrap_item,
    push_line,
};

/// Format file-enc header information.
fn build_file_enc_header_display(doc: &FileEncDocument, out: &mut String) {
    push_line(out, "=== File-Enc v3 Metadata ===");
    push_line(out, format!("Format:     {}", doc.protected.format));
    push_line(out, format!("Secret ID:  {}", doc.protected.sid));
}

/// Format file-enc recipients list.
fn build_file_enc_recipients_display(doc: &FileEncDocument, out: &mut String) {
    let recipients = doc.recipients();
    push_line(out, "");
    push_line(out, format!("Recipients ({}):", recipients.len()));
    for rid in recipients {
        push_line(out, format!("  - {}", rid));
    }
}

/// Format file-enc payload information.
fn build_file_enc_payload_display(doc: &FileEncDocument, out: &mut String) {
    push_line(out, "");
    push_line(out, "Payload:");
    append_file_payload_info(&doc.protected.payload, out);
}

/// Format file-enc wrap data.
fn build_file_enc_wrap_display(doc: &FileEncDocument, out: &mut String) {
    push_line(out, "");
    push_line(
        out,
        format!("Wrap Data ({} recipients):", doc.protected.wrap.len()),
    );
    for (i, wrap) in doc.protected.wrap.iter().enumerate() {
        append_wrap_item(i, wrap, out);
    }
    append_removed_recipients(doc.protected.removed_recipients.as_ref(), out);
}

/// Format file-enc signature information.
fn build_file_enc_signature_display(doc: &FileEncDocument, out: &mut String) {
    push_line(out, "");
    push_line(out, format!("Created:  {}", doc.protected.created_at));
    push_line(out, format!("Updated:  {}", doc.protected.updated_at));

    let sig = &doc.signature;
    push_line(out, "");
    push_line(out, "Signature:");
    push_line(out, format!("  alg:    {}", sig.alg));
    push_line(out, format!("  kid:    {}", sig.kid));
    append_signer_info(sig.signer_pub.as_ref(), out);
    push_line(
        out,
        format!("  sig:    {}...", &sig.sig[..sig.sig.len().min(404)]),
    );
}

/// Inspect a file-enc document and write formatted output.
pub(crate) fn inspect_file_enc(doc: &FileEncDocument, out: &mut String) {
    build_file_enc_header_display(doc, out);
    build_file_enc_recipients_display(doc, out);
    build_file_enc_payload_display(doc, out);
    build_file_enc_wrap_display(doc, out);
    build_file_enc_signature_display(doc, out);

    push_line(out, "");
    push_line(out, "=========================");
}
