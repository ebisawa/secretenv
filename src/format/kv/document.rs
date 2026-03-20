// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV-enc document parsing and structural validation.

use crate::format::kv::dotenv::is_valid_key_name;
use crate::format::kv::enc::canonical::extract_head_and_wrap_tokens;
use crate::format::kv::enc::parser::{KvEncLine, KvEncParser};
use crate::format::token::TokenCodec;
use crate::model::kv_enc::{KvEncDocument, KvEntryValue, KvHeader, KvWrap};
use crate::{Error, Result};

/// Parse kv-enc content into a typed document with format-level validation.
pub fn parse_kv_document(content: &str) -> Result<KvEncDocument> {
    let lines = KvEncParser::new(content).parse_all()?;

    validate_kv_file_structure(&lines)?;
    validate_kv_structure(&lines)?;

    let (head_token, wrap_token) = extract_head_and_wrap_tokens(&lines)?;
    let signature_token = parse_kv_signature_token(&lines)?;

    let head: KvHeader = TokenCodec::decode_auto(&head_token).map_err(|e| Error::Parse {
        message: format!("Failed to parse HEAD token: {}", e),
        source: Some(Box::new(e)),
    })?;

    let wrap: KvWrap = TokenCodec::decode_auto(&wrap_token).map_err(|e| Error::Parse {
        message: format!("Failed to parse WRAP token: {}", e),
        source: Some(Box::new(e)),
    })?;

    let validator = crate::io::schema::validator::embedded_validator()?;
    let head_value = serde_json::to_value(&head).map_err(|e| Error::Parse {
        message: format!("Failed to serialize HEAD for schema validation: {}", e),
        source: Some(Box::new(e)),
    })?;
    validator.validate_kv_value(&head_value)?;

    let wrap_value = serde_json::to_value(&wrap).map_err(|e| Error::Parse {
        message: format!("Failed to serialize WRAP for schema validation: {}", e),
        source: Some(Box::new(e)),
    })?;
    validator.validate_kv_file_wrap(&wrap_value)?;

    Ok(KvEncDocument::new(
        content.to_string(),
        lines,
        head,
        wrap,
        signature_token,
    ))
}

/// Validate kv-enc structure (WRAP and KV tokens).
fn validate_kv_structure(lines: &[KvEncLine]) -> Result<()> {
    for line in lines {
        match line {
            KvEncLine::Wrap { token } => {
                TokenCodec::decode_auto::<KvWrap>(token).map_err(|e| Error::Parse {
                    message: format!("Invalid WRAP token structure: {}", e),
                    source: Some(Box::new(e)),
                })?;
            }
            KvEncLine::KV { key, token } => {
                let entry: KvEntryValue =
                    TokenCodec::decode_auto(token).map_err(|e| Error::Parse {
                        message: format!(
                            "Invalid KV entry token structure for key '{}': {}",
                            key, e
                        ),
                        source: Some(Box::new(e)),
                    })?;

                if key != &entry.k {
                    return Err(Error::Verify {
                        rule: "E_KEY_MISMATCH".to_string(),
                        message: format!(
                            "kv-enc v3: KEY mismatch for '{}': line KEY '{}' does not match token.k '{}'",
                            key, key, entry.k
                        ),
                    });
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_unique_line(
    logical_lines: &[(usize, &KvEncLine)],
    matcher: fn(&KvEncLine) -> bool,
    label: &str,
    missing_rule: &str,
    expected_position: Option<usize>,
    position_rule: &str,
    position_message: &str,
) -> Result<()> {
    let count = logical_lines
        .iter()
        .filter(|(_, line)| matcher(line))
        .count();
    if count == 0 {
        return Err(Error::Verify {
            rule: missing_rule.to_string(),
            message: format!("kv-enc v3: missing {} line", label),
        });
    }
    if count > 1 {
        return Err(Error::Verify {
            rule: "E_SCHEMA_INVALID".to_string(),
            message: format!(
                "kv-enc v3: {} line appears {} times (must be exactly once)",
                label, count
            ),
        });
    }
    if let Some(pos) = expected_position {
        if logical_lines.len() <= pos || !matcher(logical_lines[pos].1) {
            return Err(Error::Verify {
                rule: position_rule.to_string(),
                message: position_message.to_string(),
            });
        }
    }
    Ok(())
}

fn validate_no_data_after_sig(lines: &[KvEncLine]) -> Result<()> {
    let mut found_sig = false;
    for line in lines {
        match line {
            KvEncLine::Sig { .. } => found_sig = true,
            KvEncLine::KV { .. }
            | KvEncLine::Head { .. }
            | KvEncLine::Wrap { .. }
            | KvEncLine::Header { .. } => {
                if found_sig {
                    return Err(Error::Verify {
                        rule: "E_SCHEMA_INVALID".to_string(),
                        message:
                            "kv-enc v3: data lines (HEAD/WRAP/KV) must not appear after :SIG line"
                                .to_string(),
                    });
                }
            }
            KvEncLine::Empty => {}
        }
    }
    Ok(())
}

fn validate_kv_keys(lines: &[KvEncLine]) -> Result<()> {
    let mut seen_keys = std::collections::HashSet::new();
    for line in lines {
        if let KvEncLine::KV { key, .. } = line {
            if !is_valid_key_name(key) {
                return Err(Error::Verify {
                    rule: "E_SCHEMA_INVALID".to_string(),
                    message: format!(
                        "kv-enc v3: invalid KEY format '{}' (must match ^[A-Za-z_][A-Za-z0-9_]*$)",
                        key
                    ),
                });
            }
            if !seen_keys.insert(key.clone()) {
                return Err(Error::Verify {
                    rule: "E_DUPLICATE_KEY".to_string(),
                    message: format!(
                        "kv-enc v3: duplicate KEY '{}' (each KEY must appear only once)",
                        key
                    ),
                });
            }
        }
    }
    Ok(())
}

fn validate_kv_header_lines(logical_lines: &[(usize, &KvEncLine)]) -> Result<()> {
    validate_unique_line(
        logical_lines,
        |line| matches!(line, KvEncLine::Header { .. }),
        ":SECRETENV_KV",
        "E_SCHEMA_INVALID",
        Some(0),
        "E_SCHEMA_INVALID",
        "kv-enc v3: :SECRETENV_KV 3 must be the first line",
    )?;
    validate_unique_line(
        logical_lines,
        |line| matches!(line, KvEncLine::Head { .. }),
        ":HEAD",
        "E_SCHEMA_INVALID",
        Some(1),
        "E_SCHEMA_INVALID",
        "kv-enc v3: :HEAD must be the second line (after :SECRETENV_KV 3)",
    )?;
    validate_unique_line(
        logical_lines,
        |line| matches!(line, KvEncLine::Wrap { .. }),
        ":WRAP",
        "E_WRAP_LINE_MISSING",
        Some(2),
        "E_WRAP_LINE_POSITION",
        "kv-enc v3: :WRAP must be the third line (after :HEAD)",
    )?;
    validate_unique_line(
        logical_lines,
        |line| matches!(line, KvEncLine::Sig { .. }),
        ":SIG",
        "E_SIG_LINE_MISSING",
        Some(logical_lines.len() - 1),
        "E_SCHEMA_INVALID",
        "kv-enc v3: :SIG must be the last logical line (after all KV entries)",
    )?;
    Ok(())
}

/// Validate kv-enc file structure independently of signature verification.
pub fn validate_kv_file_structure(lines: &[KvEncLine]) -> Result<()> {
    let logical_lines: Vec<(usize, &KvEncLine)> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| !matches!(line, KvEncLine::Empty))
        .collect();

    if logical_lines.is_empty() {
        return Err(Error::Parse {
            message: "kv-enc file is empty or contains only empty lines and comments".to_string(),
            source: None,
        });
    }

    validate_kv_header_lines(&logical_lines)?;
    validate_no_data_after_sig(lines)?;
    validate_kv_keys(lines)?;

    Ok(())
}

fn parse_kv_signature_token(lines: &[KvEncLine]) -> Result<String> {
    lines
        .iter()
        .find_map(|line| match line {
            KvEncLine::Sig { token } => Some(token.clone()),
            _ => None,
        })
        .ok_or_else(|| Error::Crypto {
            message: "kv-enc v3 has no SIG line (v3 requires signatures)".to_string(),
            source: None,
        })
}
