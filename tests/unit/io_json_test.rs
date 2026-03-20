// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use secretenv::io::json::{load_json_file, parse_json_str};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct SampleDocument {
    name: String,
}

#[test]
fn test_load_json_file_reads_document() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().join("sample.json");
    std::fs::write(&path, r#"{"name":"alice"}"#).unwrap();

    let doc: SampleDocument = load_json_file(&path, "sample").unwrap();

    assert_eq!(
        doc,
        SampleDocument {
            name: "alice".to_string(),
        }
    );
}

#[test]
fn test_load_json_file_reports_parse_error() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().join("sample.json");
    std::fs::write(&path, "{not-json").unwrap();

    let err = load_json_file::<SampleDocument>(&path, "sample").expect_err("expected parse error");

    let message = err.to_string();
    assert!(message.contains("Failed to parse sample"));
}

#[test]
fn test_parse_json_str_parses_document() {
    let doc: SampleDocument =
        parse_json_str(r#"{"name":"bob"}"#, "sample", "inline sample").unwrap();

    assert_eq!(
        doc,
        SampleDocument {
            name: "bob".to_string(),
        }
    );
}
