<!-- Copyright 2026 Satoshi Ebisawa -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Copilot Instructions for secretenv Reviews

Use these instructions when reviewing changes in this repository with GitHub Copilot.

## Project Context

- `secretenv` is an offline-first CLI for sharing encrypted secrets in Git repositories.
- The project manages `.env`-style key/value secrets and encrypted files without requiring a dedicated server.
- The security model depends on authenticated encryption, signature verification, recipient integrity, and predictable workspace/key management behavior.

## Review Priorities

Focus on real defects first. Prefer concrete findings over style advice.

1. Security regressions in encryption, decryption, signature verification, recipient handling, key rotation, or key storage.
2. Behavior changes that conflict with the documented CLI or workspace semantics.
3. Layering violations and dependency direction regressions.
4. Missing or weak tests for changed behavior.
5. Naming, structure, and maintainability issues that make future defects more likely.

## Architecture Rules

This repository follows a directional layering model:

```text
cli -> app -> feature
app -> io | format | model | config
feature -> crypto | format | model | io | config
format -> crypto | model | support
crypto -> model | support
config -> io | support
```

Check for these violations:

- `cli` must not directly depend on `feature` or `io`.
- `app` must not print to stdout/stderr or contain interactive UI details.
- `feature` must not depend on `cli` or `app`.
- `io` must not depend on `feature`, `app`, or `cli`.
- `format` must not depend on `feature`.
- `crypto` must not depend on `app` or `cli`.

## Rust Conventions

When reviewing Rust code, verify that changes follow these repository conventions:

- Prefer small, focused functions. Split functions that become hard to read.
- Use Rust 2018 module style. Avoid `mod.rs`.
- Prefer `use` imports over long `crate::...` paths inside implementation code.
- Comments must be in English.
- New source files should include the repository copyright header and SPDX line.
- Public and `pub(crate)` names should follow the established naming rules:
  - `load_*` for reads from storage
  - `save_*` for writes to storage
  - `build_*` for construction
  - `resolve_*` for dynamic resolution
  - `encrypt_*` / `decrypt_*`, `sign_*` / `verify_*`, `wrap_*` / `unwrap_*`
  - Avoid `create_*`, `prepare_*`, `read_*`, and `write_*`
- CLI-only verbs such as `run_*`, `setup_*`, and `print_*` should stay in `cli`.

## Testing Expectations

Treat missing validation as a review issue when behavior changes.

- Rust changes should normally be covered by tests.
- Prefer independent unit tests under `tests/unit/` rather than inline tests when possible.
- Test names should follow `test_<target>_<scenario>[_fails|_error|_roundtrip]`.
- Test file names should follow `<module_path>_test.rs`.
- Watch for changes that should require updates to `cargo test`, `cargo clippy`, or `cargo fmt -- --check` expectations.

## Files Worth Consulting During Review

Use repository documentation when needed to judge correctness:

- `README.md`
- `README_ja.md`
- `CLAUDE.md`
- `guides/product_brief_v3_en.md`
- `guides/security_design_v3_en.md`
- `guides/user_guide_en.md`
- `schemas/secretenv_schema_v3.json`

Prioritize the English guides unless the reviewed change is clearly documented only in Japanese.

## Review Output Style

- Report findings first, ordered by severity.
- Be explicit about the impact and the failing scenario.
- Reference the affected file and function whenever possible.
- Call out missing tests separately from implementation bugs.
- If no concrete defect is found, say that clearly and mention residual risk areas instead of inventing nits.

## What Not to Do

- Do not focus on cosmetic nits before correctness and security.
- Do not recommend architectural shortcuts that break the layer boundaries above.
- Do not suggest keeping backward compatibility if a cleaner replacement is clearly intended by the change.
- Do not ask for documentation updates unless behavior, CLI usage, or security-relevant semantics actually changed.
