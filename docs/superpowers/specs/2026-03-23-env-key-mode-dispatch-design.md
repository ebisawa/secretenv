# Environment Variable Key Mode Dispatch

## Problem

`SECRETENV_PRIVATE_KEY` environment variable support is implemented at the feature/app layer
(`env_key::load_private_key_from_env`, `ExecutionContext::load_from_env`) but never invoked.
All CLI commands unconditionally call `resolve_ssh_context_for_active_key()`, which fails in
CI environments where no SSH agent or local keystore is available.

## Approach

CLI-layer dispatch: each command checks `is_env_key_mode()` before attempting SSH resolution.
When env mode is active, SSH context resolution is skipped entirely and the app layer receives
`None` for the SSH context, triggering `ExecutionContext::load_from_env()`.

## Design

### CLI Layer

Add a helper in `cli/common/ssh.rs`:

```rust
pub fn resolve_ssh_context_optional(
    options: &CommonCommandOptions,
) -> Result<Option<SshSigningContext>> {
    if is_env_key_mode() {
        Ok(None)
    } else {
        Ok(Some(resolve_ssh_context_for_active_key(options)?))
    }
}
```

Each CLI command replaces `resolve_ssh_context_for_active_key(&options)?`
with `resolve_ssh_context_optional(&options)?`.

### App Layer

All public app functions change `SshSigningContext` parameter to `Option<SshSigningContext>`.

Internal dispatch via a helper on `ExecutionContext`:

```rust
pub fn resolve(
    options: &CommonCommandOptions,
    member_id: Option<String>,
    explicit_kid: Option<&str>,
    ssh_ctx: Option<SshSigningContext>,
) -> Result<Self> {
    match ssh_ctx {
        Some(ctx) => Self::load(options, member_id, explicit_kid, ctx),
        None => Self::load_from_env(options),
    }
}
```

### Affected Files

**CLI layer** (replace SSH resolution call):

| File | Function |
|------|----------|
| `cli/decrypt.rs` | `run()` |
| `cli/encrypt.rs` | `run()` |
| `cli/get.rs` | `run()` |
| `cli/run.rs` | `run()` |
| `cli/set.rs` | `run()` |
| `cli/unset.rs` | `run()` |
| `cli/import.rs` | `run()` |
| `cli/rewrap/batch.rs` | `execute_batch_rewrap()` |
| `cli/key/operations.rs` | export command |

**App layer** (change `SshSigningContext` to `Option<SshSigningContext>`):

| File | Function/Type |
|------|---------------|
| `app/context.rs` | `ExecutionContext::resolve()` (new) |
| `app/file.rs` | `EncryptFileSession::load()`, `DecryptFileSession::load_execution()`, public fns |
| `app/kv.rs` | `KvReadSession::load()`, `KvWriteSession`, public fns |
| `app/run.rs` | `execute_env_command()` |
| `app/rewrap/execution.rs` | `execute_rewrap_batch()` |

**CLI legacy** (fix existing issue):

| File | Issue |
|------|-------|
| `cli/rewrap/context.rs` | `ExecutionContext::load()` called with wrong arity; align with new `resolve()` |

### Behavior

- `SECRETENV_PRIVATE_KEY` set: skip SSH, load key from env vars, resolve public keys from workspace
- `SECRETENV_PRIVATE_KEY` not set: existing SSH-based flow unchanged
- `member_id` and `explicit_kid` from CLI args are ignored in env mode (derived from env key)

### Test Strategy

- Unit tests for `resolve_ssh_context_optional()`: verify None when env var set, Some otherwise
- Unit tests for `ExecutionContext::resolve()`: verify dispatch to correct path
- Integration test: set `SECRETENV_PRIVATE_KEY` + `SECRETENV_KEY_PASSWORD`, run decrypt/get commands
- Existing tests must continue to pass (no SSH context change when env var absent)
