use super::*;
use std::fs;
use tempfile::TempDir;

fn setup_workspace_with_incoming(member_ids: &[&str]) -> TempDir {
    let tmp = TempDir::new().unwrap();
    let active_dir = tmp.path().join("members/active");
    let incoming_dir = tmp.path().join("members/incoming");
    fs::create_dir_all(&active_dir).unwrap();
    fs::create_dir_all(&incoming_dir).unwrap();
    for id in member_ids {
        let path = incoming_dir.join(format!("{}.json", id));
        fs::write(
            &path,
            r#"{"protected":{"member_id":"__ID__"}}"#.replace("__ID__", id),
        )
        .unwrap();
    }
    tmp
}

#[test]
fn test_promote_specified_selects_only_specified() {
    let tmp = setup_workspace_with_incoming(&["alice", "bob", "carol"]);
    let promoted =
        promote_specified_incoming_members(tmp.path(), &["alice".to_string(), "carol".to_string()])
            .unwrap();
    assert_eq!(promoted, vec!["alice".to_string(), "carol".to_string()]);
    assert!(tmp.path().join("members/active/alice.json").exists());
    assert!(tmp.path().join("members/active/carol.json").exists());
    assert!(tmp.path().join("members/incoming/bob.json").exists());
    assert!(!tmp.path().join("members/active/bob.json").exists());
}

#[test]
fn test_promote_specified_conflict_error() {
    let tmp = setup_workspace_with_incoming(&["alice"]);
    fs::write(tmp.path().join("members/active/alice.json"), "{}").unwrap();
    let result = promote_specified_incoming_members(tmp.path(), &["alice".to_string()]);
    assert!(result.is_err());
    assert!(tmp.path().join("members/incoming/alice.json").exists());
}

#[test]
fn test_promote_specified_not_found_error() {
    let tmp = setup_workspace_with_incoming(&["alice"]);
    let result = promote_specified_incoming_members(tmp.path(), &["nonexistent".to_string()]);
    assert!(result.is_err());
}

#[test]
fn test_promote_specified_empty_list() {
    let tmp = setup_workspace_with_incoming(&["alice"]);
    let promoted = promote_specified_incoming_members(tmp.path(), &[]).unwrap();
    assert!(promoted.is_empty());
    assert!(tmp.path().join("members/incoming/alice.json").exists());
}

#[test]
fn test_delete_member_removes_file() {
    let tmp = TempDir::new().unwrap();
    let active_dir = tmp.path().join("members/active");
    fs::create_dir_all(&active_dir).unwrap();
    fs::write(active_dir.join("alice.json"), "{}").unwrap();

    delete_member(tmp.path(), "alice").unwrap();

    assert!(!active_dir.join("alice.json").exists());
}

#[test]
fn test_delete_member_not_found() {
    let tmp = TempDir::new().unwrap();
    let active_dir = tmp.path().join("members/active");
    fs::create_dir_all(&active_dir).unwrap();

    let result = delete_member(tmp.path(), "nonexistent");
    assert!(result.is_err());
}

#[test]
fn test_save_member_content_incoming_new() {
    let tmp = TempDir::new().unwrap();
    let incoming_dir = tmp.path().join("members/incoming");
    fs::create_dir_all(&incoming_dir).unwrap();

    save_member_content(tmp.path(), MemberStatus::Incoming, "alice", "{}", false).unwrap();

    assert!(incoming_dir.join("alice.json").exists());
    let content = fs::read_to_string(incoming_dir.join("alice.json")).unwrap();
    assert_eq!(content, "{}");
}

#[test]
fn test_save_member_content_creates_directory_if_missing() {
    let tmp = TempDir::new().unwrap();

    save_member_content(tmp.path(), MemberStatus::Incoming, "alice", "{}", false).unwrap();

    let content = fs::read_to_string(tmp.path().join("members/incoming/alice.json")).unwrap();
    assert_eq!(content, "{}");
}

#[test]
fn test_save_member_content_incoming_already_exists_no_force() {
    let tmp = TempDir::new().unwrap();
    let incoming_dir = tmp.path().join("members/incoming");
    fs::create_dir_all(&incoming_dir).unwrap();
    fs::write(incoming_dir.join("alice.json"), "old").unwrap();

    let result = save_member_content(tmp.path(), MemberStatus::Incoming, "alice", "new", false);
    assert!(result.is_err());
    let content = fs::read_to_string(incoming_dir.join("alice.json")).unwrap();
    assert_eq!(content, "old");
}

#[test]
fn test_save_member_content_force_overwrite() {
    let tmp = TempDir::new().unwrap();
    let incoming_dir = tmp.path().join("members/incoming");
    fs::create_dir_all(&incoming_dir).unwrap();
    fs::write(incoming_dir.join("alice.json"), "old").unwrap();

    save_member_content(tmp.path(), MemberStatus::Incoming, "alice", "new", true).unwrap();

    let content = fs::read_to_string(incoming_dir.join("alice.json")).unwrap();
    assert_eq!(content, "new");
}

#[test]
fn test_save_member_content_active_error_uses_active_directory_name() {
    let tmp = TempDir::new().unwrap();
    let active_dir = tmp.path().join("members/active");
    fs::create_dir_all(&active_dir).unwrap();
    fs::write(active_dir.join("alice.json"), "old").unwrap();

    let result = save_member_content(tmp.path(), MemberStatus::Active, "alice", "new", false);
    let err = result.unwrap_err().to_string();

    assert!(err.contains("active/"));
}

#[test]
fn test_find_active_member_by_kid_returns_matching_member() {
    let tmp = TempDir::new().unwrap();
    let active_dir = tmp.path().join("members/active");
    fs::create_dir_all(&active_dir).unwrap();
    fs::write(
        active_dir.join("alice.json"),
        build_public_key_json("alice", "kid-alice"),
    )
    .unwrap();
    fs::write(
        active_dir.join("bob.json"),
        build_public_key_json("bob", "kid-bob"),
    )
    .unwrap();

    let found = find_active_member_by_kid(tmp.path(), "kid-bob")
        .unwrap()
        .unwrap();

    assert_eq!(found.protected.member_id, "bob");
}

fn build_public_key_json(member_id: &str, kid: &str) -> String {
    format!(
        r#"{{
  "protected": {{
    "format": "secretenv.public.key@3",
    "member_id": "{member_id}",
    "kid": "{kid}",
    "identity": {{
      "keys": {{
        "kem": {{"kty":"OKP","crv":"X25519","x":"AQ"}},
        "sig": {{"kty":"OKP","crv":"Ed25519","x":"AQ"}}
      }},
      "attestation": {{
        "method": "ssh",
        "pub": "ssh-ed25519 AAAA test@example.com",
        "sig": "AQ"
      }}
    }},
    "expires_at": "2099-01-01T00:00:00Z"
  }},
  "signature": "AQ"
}}"#
    )
}
