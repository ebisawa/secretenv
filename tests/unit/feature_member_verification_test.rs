use super::*;

fn dummy_bindings() -> crate::model::public_key::VerifiedBindingClaims {
    use crate::model::public_key::{BindingClaims, VerifiedBindingClaims};
    use crate::model::verification::BindingVerificationProof;
    VerifiedBindingClaims::new(
        BindingClaims {
            github_account: None,
        },
        BindingVerificationProof::new("github".to_string(), None, None),
    )
}

#[test]
fn test_classify_all_verified() {
    let results = vec![VerificationResult::verified(
        "alice",
        "SSH key verified on GitHub (id=1, login=alice-gh)".to_string(),
        "SHA256:abc".to_string(),
        42,
        dummy_bindings(),
    )];
    let (verified, failed, not_configured) = classify_verification_results(&results);
    assert_eq!(verified.len(), 1);
    assert!(failed.is_empty());
    assert!(not_configured.is_empty());
}

#[test]
fn test_classify_mixed() {
    let results = vec![
        VerificationResult::verified(
            "alice",
            "OK".to_string(),
            "SHA256:abc".to_string(),
            42,
            dummy_bindings(),
        ),
        VerificationResult::failed("bob", "SSH key not found".to_string(), None),
        VerificationResult::not_configured("carol", "No binding_claims", None),
    ];
    let (verified, failed, not_configured) = classify_verification_results(&results);
    assert_eq!(verified.len(), 1);
    assert_eq!(verified[0].member_id, "alice");
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].member_id, "bob");
    assert_eq!(not_configured.len(), 1);
    assert_eq!(not_configured[0].member_id, "carol");
}

#[test]
fn test_classify_empty() {
    let results: Vec<VerificationResult> = vec![];
    let (verified, failed, not_configured) = classify_verification_results(&results);
    assert!(verified.is_empty());
    assert!(failed.is_empty());
    assert!(not_configured.is_empty());
}
