// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! File-enc inspection.

use crate::model::file_enc::FileEncDocument;

use super::formatter::{
    append_file_payload_info, append_removed_recipients, append_signer_info, append_wrap_item,
    push_line,
};
use super::{build_section, InspectSection, InspectView};

fn build_section_lines(build: impl FnOnce(&mut String)) -> Vec<String> {
    let mut out = String::new();
    build(&mut out);
    out.lines().map(ToOwned::to_owned).collect()
}

fn build_file_enc_header_section(doc: &FileEncDocument) -> InspectSection {
    build_section(
        "Header",
        vec![
            format!("Format:     {}", doc.protected.format),
            format!("Secret ID:  {}", doc.protected.sid),
        ],
    )
}

fn build_file_enc_recipients_section(doc: &FileEncDocument) -> InspectSection {
    let mut lines = Vec::new();
    lines.push(format!("Recipients ({}):", doc.recipients().len()));
    lines.extend(
        doc.recipients()
            .into_iter()
            .map(|rid| format!("  - {}", rid)),
    );
    build_section("Recipients", lines)
}

fn build_file_enc_payload_section(doc: &FileEncDocument) -> InspectSection {
    build_section(
        "Payload",
        build_section_lines(|out| append_file_payload_info(&doc.protected.payload, out)),
    )
}

fn build_file_enc_wrap_section(doc: &FileEncDocument) -> InspectSection {
    build_section(
        "Wrap Data",
        build_section_lines(|out| {
            push_line(
                out,
                format!("Wrap Data ({} recipients):", doc.protected.wrap.len()),
            );
            for (i, wrap) in doc.protected.wrap.iter().enumerate() {
                append_wrap_item(i, wrap, out);
            }
            append_removed_recipients(doc.protected.removed_recipients.as_ref(), out);
        }),
    )
}

fn build_file_enc_signature_section(doc: &FileEncDocument) -> InspectSection {
    build_section(
        "Signature",
        build_section_lines(|out| {
            push_line(out, format!("Created:  {}", doc.protected.created_at));
            push_line(out, format!("Updated:  {}", doc.protected.updated_at));
            let sig = &doc.signature;
            push_line(out, format!("  alg:    {}", sig.alg));
            push_line(out, format!("  kid:    {}", sig.kid));
            append_signer_info(sig.signer_pub.as_ref(), out);
            push_line(
                out,
                format!("  sig:    {}...", &sig.sig[..sig.sig.len().min(404)]),
            );
        }),
    )
}

pub(crate) fn inspect_file_enc(doc: &FileEncDocument) -> InspectView {
    InspectView {
        title: "=== File-Enc v3 Metadata ===".to_string(),
        sections: vec![
            build_file_enc_header_section(doc),
            build_file_enc_recipients_section(doc),
            build_file_enc_payload_section(doc),
            build_file_enc_wrap_section(doc),
            build_file_enc_signature_section(doc),
        ],
    }
}
