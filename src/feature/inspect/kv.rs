// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV-enc inspection.

use crate::format::kv::enc::KvEncLine;
use crate::format::token::TokenCodec;
use crate::model::kv_enc::{KvEncDocument, KvEntryValue, KvFileSignature, KvHeader, KvWrap};
use crate::Result;

use super::formatter::{
    append_removed_recipients, append_signer_info, append_wrap_item, push_line,
};

/// Parsed kv-enc inspection data.
struct KvEncInspectionData {
    version: Option<String>,
    head_data: Option<(KvHeader, String)>,
    wrap_data: Option<(KvWrap, String)>,
    entries: Vec<(String, KvEntryValue, String)>,
    signature: Option<(KvFileSignature, String)>,
}

/// Format HEAD data section.
fn build_kv_enc_header_display(data: &KvEncInspectionData, out: &mut String) {
    if let Some((ref head, _token)) = &data.head_data {
        push_line(out, "");
        push_line(out, "--- HEAD Data ---");
        push_line(out, format!("SID:        {}", head.sid));
        push_line(out, format!("Created:    {}", head.created_at));
        push_line(out, format!("Updated:    {}", head.updated_at));
    }
}

/// Format WRAP data section.
fn build_kv_enc_wrap_display(data: &KvEncInspectionData, out: &mut String) {
    if let Some((ref wrap, _token)) = &data.wrap_data {
        push_line(out, "");
        push_line(out, "--- WRAP Data ---");

        push_line(out, format!("Recipients ({}):", wrap.wrap.len()));
        for rid in &wrap.wrap {
            push_line(out, format!("  - {}", rid.rid));
        }

        push_line(out, "");
        push_line(out, "Wrap Items:");
        for (i, wrap_item) in wrap.wrap.iter().enumerate() {
            append_wrap_item(i, wrap_item, out);
        }

        append_removed_recipients(wrap.removed_recipients.as_ref(), out);
    }
}

/// Format entries section.
fn build_kv_enc_entries_display(data: &KvEncInspectionData, out: &mut String) {
    push_line(out, "");
    push_line(out, format!("--- Entries ({}) ---", data.entries.len()));
    for (i, (key, entry, _token)) in data.entries.iter().enumerate() {
        push_line(out, format!("[{}] Key: {}", i, key));

        push_line(out, "  Encryption:");
        push_line(out, format!("    aead:   {}", entry.aead));
        push_line(out, format!("    salt:   {}", entry.salt));
        push_line(out, format!("    nonce:  {}", entry.nonce));

        push_line(
            out,
            format!(
                "    ct:     {} bytes ({}...)",
                entry.ct.len(),
                &entry.ct[..entry.ct.len().min(40)]
            ),
        );

        if entry.disclosed {
            push_line(out, "  Status:     [DISCLOSED] Secret may need rotation");
        }
    }
}

/// Format signature section.
fn build_kv_enc_signature_display(data: &KvEncInspectionData, out: &mut String) {
    if let Some((ref signature, ref _token)) = data.signature {
        push_line(out, "");
        push_line(out, "--- Signature ---");

        push_line(out, format!("Algorithm:  {}", signature.alg));
        push_line(out, format!("Kid:        {}", signature.kid));
        append_signer_info(signature.signer_pub.as_ref(), out);
        push_line(
            out,
            format!(
                "Signature:  {}...",
                &signature.sig[..signature.sig.len().min(40)]
            ),
        );
    }
}

/// Build inspection data from a KvEncDocument (verified or not).
fn kv_enc_document_to_inspection_data(doc: &KvEncDocument) -> Result<KvEncInspectionData> {
    let mut version = None;
    let mut entries = Vec::new();
    for line in doc.lines() {
        match line {
            KvEncLine::Header { version: v } => version = Some(v.to_string()),
            KvEncLine::KV { key, token } => {
                let entry: KvEntryValue = TokenCodec::decode_auto(token)?;
                entries.push((key.clone(), entry, token.clone()));
            }
            _ => {}
        }
    }
    let signature: Option<(KvFileSignature, String)> =
        TokenCodec::decode_auto(doc.signature_token())
            .ok()
            .map(|s| (s, String::new()));
    Ok(KvEncInspectionData {
        version,
        head_data: Some((doc.head().clone(), String::new())),
        wrap_data: Some((doc.wrap().clone(), String::new())),
        entries,
        signature,
    })
}

/// Inspect a kv-enc document and write formatted output.
pub(crate) fn inspect_kv_enc(doc: &KvEncDocument, out: &mut String) -> Result<()> {
    let data = kv_enc_document_to_inspection_data(doc)?;

    push_line(out, "=== KV-Enc v3 Metadata ===");
    push_line(out, "");

    if let Some(ref version) = data.version {
        push_line(out, format!("Version: {}", version));
    }

    build_kv_enc_header_display(&data, out);
    build_kv_enc_wrap_display(&data, out);
    build_kv_enc_entries_display(&data, out);
    build_kv_enc_signature_display(&data, out);

    push_line(out, "");
    push_line(out, "=========================");
    push_line(out, format!("Total Entries: {}", data.entries.len()));
    Ok(())
}
