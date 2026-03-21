// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Permission validation tests for keystore storage

#[cfg(unix)]
mod unix_tests {
    use secretenv::io::keystore::storage::load_private_key;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[test]
    fn test_load_private_key_rejects_insecure_permissions() {
        let temp_dir = TempDir::new().unwrap();
        let member_id = "test@example.com";
        let kid = "01ABCDEFGHIJKLMNOPQRSTUVWX";
        let key_dir = temp_dir.path().join(member_id).join(kid);
        fs::create_dir_all(&key_dir).unwrap();

        let private_path = key_dir.join("private.json");
        fs::write(&private_path, r#"{"dummy": true}"#).unwrap();
        fs::set_permissions(&private_path, fs::Permissions::from_mode(0o644)).unwrap();

        let err = load_private_key(temp_dir.path(), member_id, kid).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Insecure permissions"));
        assert!(msg.contains("0644"));
    }

    #[test]
    fn test_load_private_key_accepts_secure_permissions() {
        let temp_dir = TempDir::new().unwrap();
        let member_id = "test@example.com";
        let kid = "01ABCDEFGHIJKLMNOPQRSTUVWX";
        let key_dir = temp_dir.path().join(member_id).join(kid);
        fs::create_dir_all(&key_dir).unwrap();

        let private_path = key_dir.join("private.json");
        fs::write(&private_path, r#"{"dummy": true}"#).unwrap();
        fs::set_permissions(&private_path, fs::Permissions::from_mode(0o600)).unwrap();

        // Should fail with parse error, NOT permission error
        let err = load_private_key(temp_dir.path(), member_id, kid).unwrap_err();
        let msg = err.to_string();
        assert!(!msg.contains("Insecure permissions"));
    }
}
