// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for SSH OpenSSH config parsing
//!
//! Tests for parsing logic (parse_identity_agent, unquote, trim_comment)

use secretenv::io::ssh::openssh_config::{parse_identity_agent, trim_comment, unquote};

#[test]
fn test_unquote_double() {
    assert_eq!(unquote(r#""hello world""#), "hello world");
    assert_eq!(unquote(r#""~/path/to/sock""#), "~/path/to/sock");
}

#[test]
fn test_unquote_single() {
    assert_eq!(unquote("'hello world'"), "hello world");
    assert_eq!(unquote("'~/path/to/sock'"), "~/path/to/sock");
}

#[test]
fn test_unquote_no_quotes() {
    assert_eq!(unquote("hello world"), "hello world");
    assert_eq!(unquote("~/path/to/sock"), "~/path/to/sock");
}

#[test]
fn test_trim_comment() {
    assert_eq!(trim_comment("key value # comment"), "key value ");
    assert_eq!(trim_comment("key value"), "key value");
    assert_eq!(
        trim_comment(r#"key "value # not comment""#),
        r#"key "value # not comment""#
    );
}

#[test]
fn test_parse_identity_agent_host_star() {
    let config = r#"
Host *
    IdentityAgent "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"
"#;
    let result = parse_identity_agent(config).unwrap();
    assert!(result.is_some());
    let path = result.unwrap();
    assert!(path.to_string_lossy().contains("1password"));
}

#[test]
fn test_parse_identity_agent_global() {
    let config = r#"
IdentityAgent "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"
"#;
    let result = parse_identity_agent(config).unwrap();
    assert!(result.is_some());
}

#[test]
fn test_parse_identity_agent_none() {
    let config = r#"
Host *
    IdentityAgent none
"#;
    let result = parse_identity_agent(config).unwrap();
    assert!(result.is_none());
}

#[test]
fn test_parse_identity_agent_case_insensitive() {
    let config = r#"
host *
    identityagent "~/test.sock"
"#;
    let result = parse_identity_agent(config).unwrap();
    assert!(result.is_some());
}

#[test]
fn test_parse_identity_agent_priority_host_star() {
    let config = r#"
IdentityAgent "/global/sock"
Host *
    IdentityAgent "~/host_star/sock"
"#;
    let result = parse_identity_agent(config).unwrap();
    assert!(result.is_some());
    let path = result.unwrap();
    assert!(path.to_string_lossy().contains("host_star"));
}

#[test]
fn test_parse_identity_agent_with_comments() {
    let config = r#"
# This is a comment
Host *
    # Another comment
    IdentityAgent "~/test.sock"  # Inline comment
"#;
    let result = parse_identity_agent(config).unwrap();
    assert!(result.is_some());
}

#[test]
fn test_parse_identity_agent_single_quotes() {
    let config = r#"
Host *
    IdentityAgent '~/test.sock'
"#;
    let result = parse_identity_agent(config).unwrap();
    assert!(result.is_some());
}

#[test]
fn test_parse_identity_agent_no_quotes() {
    let config = r#"
Host *
    IdentityAgent ~/test.sock
"#;
    let result = parse_identity_agent(config).unwrap();
    assert!(result.is_some());
}

#[test]
fn test_parse_identity_agent_multiple_host_blocks() {
    let config = r#"
Host example.com
    IdentityAgent /other/sock

Host *
    IdentityAgent "~/host_star/sock"
"#;
    let result = parse_identity_agent(config).unwrap();
    assert!(result.is_some());
    let path = result.unwrap();
    assert!(path.to_string_lossy().contains("host_star"));
}

#[test]
fn test_parse_identity_agent_not_found() {
    let config = r#"
Host example.com
    User alice
"#;
    let result = parse_identity_agent(config).unwrap();
    assert!(result.is_none());
}
