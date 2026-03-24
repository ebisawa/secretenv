// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::feature::envelope::signature::verify_kv_signature;
use crate::feature::verify::key_loader::load_verifying_key_from_signature;
use crate::feature::verify::report::{build_error_report, build_success_report};
use crate::feature::verify::SignatureVerificationReport;
use crate::format::content::KvEncContent;
use crate::format::kv::document::parse_kv_document;
use crate::format::schema::document::parse_kv_signature_token;
use crate::model::kv_enc::document::KvEncDocument;
use crate::model::kv_enc::verified::VerifiedKvEncDocument;
use crate::model::verification::SignatureVerificationProof;
use crate::support::limits::validate_wrap_count;
use crate::Result;

pub fn verify_kv_content(
    content: &KvEncContent,
    workspace_path: Option<&std::path::Path>,
    debug: bool,
) -> Result<VerifiedKvEncDocument> {
    let doc = content.parse()?;
    verify_kv_document(&doc, workspace_path, debug)
}

pub fn verify_kv_content_report(
    content: &KvEncContent,
    workspace_path: Option<&std::path::Path>,
) -> SignatureVerificationReport {
    verify_kv_document_report(content.as_str(), workspace_path, false)
}

pub fn verify_kv_document_report(
    content: &str,
    workspace_path: Option<&std::path::Path>,
    debug: bool,
) -> SignatureVerificationReport {
    match parse_kv_document(content) {
        Ok(doc) => {
            let signature = match parse_kv_signature_token(&doc.signature_token) {
                Ok(sig) => sig,
                Err(e) => return build_error_report(format!("E_PARSE: {}", e)),
            };
            match load_verifying_key_from_signature(&signature, workspace_path, debug) {
                Ok(loaded) => {
                    match verify_kv_signature(&doc, &loaded.verifying_key, &signature, debug) {
                        Ok(()) => build_success_report(
                            loaded.member_id,
                            loaded.source,
                            loaded.warnings,
                            loaded.public_key,
                        ),
                        Err(e) => build_error_report(format!("{}", e)),
                    }
                }
                Err(e) => build_error_report(format!("{}", e)),
            }
        }
        Err(e) => build_error_report(format!("E_PARSE: {}", e)),
    }
}

pub fn verify_kv_document(
    doc: &KvEncDocument,
    workspace_path: Option<&std::path::Path>,
    debug: bool,
) -> Result<VerifiedKvEncDocument> {
    validate_wrap_count(doc.wrap.wrap.len(), "Document")?;
    let signature = parse_kv_signature_token(&doc.signature_token)?;

    let loaded = load_verifying_key_from_signature(&signature, workspace_path, debug)?;
    verify_kv_signature(doc, &loaded.verifying_key, &signature, debug)?;

    let proof = SignatureVerificationProof::new(
        loaded.member_id,
        signature.kid.clone(),
        loaded.source,
        loaded.warnings,
    );

    Ok(VerifiedKvEncDocument::new(doc.clone(), proof))
}
