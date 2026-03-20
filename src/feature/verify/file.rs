// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! File-enc signature verification.

use super::SignatureVerificationReport;
use crate::feature::envelope::signature::verify_file_signature;
use crate::format::content::FileEncContent;
use crate::model::file_enc::FileEncDocument;
use crate::model::file_enc::VerifiedFileEncDocument;
use crate::model::verification::SignatureVerificationProof;
use crate::{Error, Result};

use super::key_loader::load_verifying_key_from_signature;
use super::report::{build_error_report, build_success_report};

/// Parse and verify file-enc content.
pub fn verify_file_content(
    content: &FileEncContent,
    workspace_path: Option<&std::path::Path>,
    debug: bool,
) -> Result<VerifiedFileEncDocument> {
    let doc = content.parse()?;
    verify_file_document(&doc, workspace_path, debug)
}

/// Build a verification report directly from file-enc content.
pub fn verify_file_content_report(
    content: &FileEncContent,
    workspace_path: Option<&std::path::Path>,
) -> SignatureVerificationReport {
    match content.parse() {
        Ok(doc) => verify_file_document_report(&doc, workspace_path, false),
        Err(e) => SignatureVerificationReport {
            verified: false,
            signer_member_id: None,
            source: None,
            warnings: Vec::new(),
            message: e.to_string(),
            signer_public_key: None,
        },
    }
}

/// Verify signature of FileEncDocument and return report
///
/// This function uses Verified types internally and converts the result to a report
/// for display purposes.
///
/// # Arguments
/// * `doc` - FileEncDocument structure to verify
/// * `workspace_path` - Path to workspace directory
/// * `debug` - Enable debug logging
///
/// # Returns
/// SignatureVerificationReport with verification result
pub fn verify_file_document_report(
    doc: &FileEncDocument,
    workspace_path: Option<&std::path::Path>,
    debug: bool,
) -> SignatureVerificationReport {
    let signature = &doc.signature;
    match load_verifying_key_from_signature(signature, workspace_path, debug) {
        Ok(loaded) => {
            let protected = doc.protected_for_signing();
            match verify_file_signature(protected, &loaded.verifying_key, signature, debug) {
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

/// Verify signature of FileEncDocument and return VerifiedFileEncDocument wrapper
///
/// This function performs signature verification and returns a `VerifiedFileEncDocument`
/// if successful. The VerifiedFileEncDocument wrapper ensures type-level guarantees that the
/// document has been verified before it can be used in trusted operations.
///
/// # Arguments
/// * `doc` - FileEncDocument structure to verify
/// * `workspace_path` - Path to workspace directory
/// * `debug` - Enable debug logging
///
/// # Returns
/// `Ok(VerifiedFileEncDocument)` if signature is valid, error otherwise
pub fn verify_file_document(
    doc: &FileEncDocument,
    workspace_path: Option<&std::path::Path>,
    debug: bool,
) -> Result<VerifiedFileEncDocument> {
    // DoS protection: check wrap count limit
    if doc.protected.wrap.len() > crate::support::limits::MAX_WRAP_ITEMS {
        return Err(Error::Crypto {
            message: format!(
                "Document exceeds maximum wrap count ({} > {})",
                doc.protected.wrap.len(),
                crate::support::limits::MAX_WRAP_ITEMS
            ),
            source: None,
        });
    }

    let signature = &doc.signature;

    let loaded = load_verifying_key_from_signature(signature, workspace_path, debug)?;
    let protected = doc.protected_for_signing();
    verify_file_signature(protected, &loaded.verifying_key, signature, debug)?;

    let proof = SignatureVerificationProof::new(
        loaded.member_id,
        signature.kid.clone(),
        loaded.source,
        loaded.warnings,
    );

    Ok(VerifiedFileEncDocument::new(doc.clone(), proof))
}
