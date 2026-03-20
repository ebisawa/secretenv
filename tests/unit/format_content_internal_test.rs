use super::*;

#[test]
fn file_enc_detect_rejects_non_json() {
    let result = FileEncContent::detect("not json".to_string());
    assert!(result.is_err());
}

#[test]
fn kv_enc_detect_rejects_json() {
    let result = KvEncContent::detect(r#"{"format":"secretenv.file@3"}"#.to_string());
    assert!(result.is_err());
}

#[test]
fn encrypted_content_detect_rejects_unknown() {
    let result = EncryptedContent::detect("random text".to_string());
    assert!(result.is_err());
}

#[test]
fn new_unchecked_preserves_content() {
    let content = "test content";
    let file = FileEncContent::new_unchecked(content.to_string());
    assert_eq!(file.as_str(), content);

    let kv = KvEncContent::new_unchecked(content.to_string());
    assert_eq!(kv.as_str(), content);
}
