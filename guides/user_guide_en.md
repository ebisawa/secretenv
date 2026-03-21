# secretenv User Guide

> A self-contained guide for teams getting started with secretenv.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Design Philosophy](#2-design-philosophy)
3. [Core Concepts](#3-core-concepts)
4. [Security Model](#4-security-model)
5. [Installation](#5-installation)
6. [Quick Start (Team Leader)](#6-quick-start-team-leader)
7. [Joining as a New Member](#7-joining-as-a-new-member)
8. [Daily Usage (KV Store)](#8-daily-usage-kv-store)
9. [File Encryption and Decryption](#9-file-encryption-and-decryption)
10. [Member Management](#10-member-management)
11. [Key Management and Rotation](#11-key-management-and-rotation)
12. [Operational Guidelines](#12-operational-guidelines)
13. [FAQ](#13-faq)
14. [Command Reference](#14-command-reference)

---

## 1. Introduction

### What is secretenv?

Team development requires sharing secrets — database passwords, API keys, certificates — among multiple members. Common approaches are often problematic:

- Pasting passwords in plaintext to Slack or Teams
- Leaving real values as comments in `.env.example`
- Former members retaining passwords that were shared with them

secretenv is a CLI tool that solves these problems by **managing encrypted secrets in a Git repository**, allowing teams to share secrets safely and traceably.

### What it solves

- Encrypt `.env` files and certificates and store them in the repository for safe team sharing
- Update access to encrypted files as members are added or removed
- Encrypted files themselves record who had access and when
- Works offline — no server or network required

### What it does not solve

secretenv intentionally omits certain features. These are listed explicitly to prevent overreliance.

- **Insider misuse**: It cannot prevent a legitimate member from misusing decrypted content
- **Revoking past disclosures**: Removing a member does not invalidate values they previously obtained (see [Chapter 10](#10-member-management))
- **Large-scale ACL management**: There is no central policy engine defining who should have access to which secret
- **Key leakage protection**: If local key files are compromised, defense relies on OS-level security

---

## 2. Design Philosophy

### Offline-First

All core operations in secretenv — encryption, decryption, signature verification, rewrap — work without a network connection. Online verification via the GitHub API is an optional feature, not a requirement.

This design ensures consistent operation during network outages or in air-gapped environments.

### Git Integration Model

secretenv manages the `.secretenv/` directory via Git. This has important implications.

**PR review becomes a security gate**: When a new member joins, their public key file is submitted as a PR. Existing members review and merge it just like a code review — no separate approval system is needed.

**Change history is automatic**: `git log` tracks who added or removed members and when secrets were updated.

**Do not add `.secretenv/` to `.gitignore`**. This directory is intentionally managed by Git.

### Policy-Less Design

secretenv has no policy file defining "who can access which secret." Instead, **the encrypted file itself remembers who the recipients are**.

Each encrypted file contains a content key (wrap) encrypted for each recipient. Only the member holding the corresponding private key can decrypt their wrap, extract the content key, and read the secret.

### Diff-Friendly kv-enc

The `kv-enc` format for managing `.env`-style secrets **encrypts each entry individually**.

When only one key's value is updated, only that entry changes — others remain untouched. This minimizes Git diffs and makes review easier. Adding a new entry also does not require decrypting existing entries.

### Disclosure Tracking

When a member is removed and `rewrap` is run, the disclosure history (`removed_recipients`) is recorded in the encrypted file.

This tracks the fact that "a removed member previously had access to this secret." Use `secretenv inspect` to review this history and decide whether to update secret values.

---

## 3. Core Concepts

This chapter defines terms that appear frequently throughout the guide. Reading this before the command chapters will make everything easier to understand.

### Workspace

The `.secretenv/` directory inside a Git repository is the Workspace. It stores encrypted files and member information shared by the team.

```
.secretenv/
├── members/
│   ├── active/       ← public keys of approved members
│   └── incoming/     ← public keys of pending members
├── secrets/          ← encrypted secrets
└── config.toml       ← local configuration (optional)
```

secretenv automatically searches for `.secretenv/` from the current directory upward, stopping at the Git repository root.

### Member ID

`member_id` is an ASCII identifier. It must start with an alphanumeric character (`A-Za-z0-9`), may contain only `A-Za-z0-9._@+-`, and its length is 1 to 254 characters (pattern: `^[A-Za-z0-9][A-Za-z0-9._@+-]{0,253}$`). It resembles an email address, but `@` is not required. No actual email is sent or received; it simply serves as a unique identifier within the team.

### kid (Key Generation ID)

A ULID-format identifier such as `01HY0G8N3P5X7QRSTV0WXYZ123` that represents the version of a key.

A single member can have multiple kids (for example, an old kid and a new kid coexisting after annual rotation). The encrypted file records which kid was used for encryption, so decryption always uses the appropriate key.

### kv-enc (KV Encrypted Format)

An encrypted version of `KEY=VALUE` pairs equivalent to a `.env` file. File extension: `.kvenc`.

Because each entry is encrypted independently, updating one key does not affect others, and Git diffs are minimal. kv-enc is recommended for day-to-day secrets management.

### file-enc (File Encrypted Format)

A format that encrypts an entire file (text or binary). File extension: `.encrypted`. Suitable for sharing certificates and binary files.

### active / incoming

Represents a member's approval state.

- **incoming**: A member who has just submitted a join request via `secretenv join`. Not yet included as a recipient in encrypted files.
- **active**: A member approved by an existing member via `rewrap`. Included as a recipient in encrypted files.

### rewrap

The operation that updates recipient information in all encrypted files after members are added or removed.

- Promotes incoming members to active
- Synchronizes the active member list with recipients in all encrypted files
- For kv-enc, regenerates the content key (MK) and re-encrypts all entries when a member is removed

### TOFU (Trust On First Use)

TOFU stands for "Trust On First Use."

When promoting an incoming member to active via `rewrap`, secretenv interactively asks "is this public key really from the requester?" The screen displays the GitHub login name, user ID, and SSH key fingerprint, and the operator approves with `y` / `N`.

```
Member bob@example.com
  GitHub login: bob-gh (id: 12345678)
  SSH key fingerprint: SHA256:xxxxx...
Approve? [y/N]:
```

This confirmation is important because if a malicious third party submits a PR impersonating a real member, "an unfamiliar GitHub account or SSH key will appear," enabling detection. Using `--force` skips the TOFU check, disabling this safeguard.

---

## 4. Security Model

### Key Trust Model (4 Layers)

secretenv verifies "is this public key really from this person?" through multiple layers. Trust is established through a combination of layers, not a single mechanism.

| Layer | Mechanism | What it proves | Limitation |
|-------|-----------|---------------|------------|
| Layer 1 | Self-signature | The private key holder created this public key | Does not prove identity |
| Layer 2 | SSH attestation | Links the secretenv key to an SSH key | Cannot identify who owns the SSH key |
| Layer 3 | TOFU confirmation | Links the key to a person (visual confirmation) | Skipped when `--force` is used |
| Layer 4 | Online verify | Cross-checks with GitHub (supplementary evidence) | Invalid if GitHub account is compromised |

### Threat Model

| Attacker | Capability | Defense |
|----------|-----------|---------|
| Repository tamperer | Can modify files in `.secretenv/` | Tampering detected by signature verification |
| Malicious insider | Retains decrypted content as a legitimate member | Tracked via disclosure history (recovery impossible) |
| Public key substitution attack | Forges a member's public key file | Defended by self-signature, attestation, and online verification |
| Key rotation attack | Attempts to reuse wraps from older key generations | kid is included in HPKE info, key generation mismatch is detected |

**Assumption**: This defense model assumes that write access to the repository is properly managed. On GitHub, changes to `members/active/` are verified through PR review.

### Trust Boundary

```
[Trusted (secure)]
  Local machine
  ~/.config/secretenv/keys/  ← private key storage
  SSH Ed25519 private key

[Workspace (potentially tampered)]
  .secretenv/members/        ← defended by signatures and online verification
  .secretenv/secrets/        ← defended by signature verification

[External systems (optional)]
  GitHub API                 ← used only for online verification
```

---

## 5. Installation

### Prerequisites

- Rust toolchain (`cargo` must be available)
- Ed25519 SSH key (`~/.ssh/id_ed25519`)
- SSH agent (recommended) or ssh-keygen

### Build and Install

```bash
# Clone the repository and install
git clone <secretenv-repo>
cd secretenv
cargo install --path .
```

After installation, run `secretenv --help` to see the list of commands.

### Verify SSH Agent

secretenv uses SSH keys to protect private keys. Verify that your SSH agent is running.

```bash
# Check SSH agent
ssh-add -l

# If no keys are listed, add your key
ssh-add ~/.ssh/id_ed25519
```

**Note**: SSH keys must be in Ed25519 format (RSA and others are not supported).

```bash
# Generate an Ed25519 key if you don't have one
ssh-keygen -t ed25519 -C "your@email.com"
```

### Configuration (Optional)

You can save frequently used options to a configuration file.

```bash
# Set default member_id (allows omitting --member-id going forward)
secretenv config set member_id alice@example.com

# Set GitHub account (for online verification)
secretenv config set github_user alice-gh

# Set SSH signing method (default "auto" works for most cases)
# auto: tries ssh-agent first, then ssh-keygen
# ssh-agent: use SSH agent
# ssh-keygen: use ssh-keygen command
secretenv config set ssh_signer auto

# Set SSH key (select a specific key when multiple keys are loaded in ssh-agent)
secretenv config set ssh_key ~/.ssh/id_ed25519_work
```

The configuration file is located at `~/.config/secretenv/config.toml`.

---

## 6. Quick Start (Team Leader)

Follow these steps when introducing secretenv to your team for the first time.

### Step 1: Prepare a repository

```bash
# Start with an existing repository
cd /path/to/your-repo

# Or create a new repository
git init my-project
cd my-project
```

### Step 2: Initialize the Workspace

```bash
secretenv init --member-id alice@example.com
```

Output:

```
Creating workspace .secretenv/
  Created members/active/
  Created members/incoming/
  Created secrets/
Using SSH key: SHA256:xxxxx... (from ~/.ssh/id_ed25519)
SSH signature determinism: OK
Generated and activated key for 'alice@example.com':
  Key ID:   01HY0G8N3P5X7QRSTV0WXYZ123
  Expires:  2027-03-19T00:00:00Z
Added 'alice@example.com' to members/active/
```

`init` automatically:

- Creates the `.secretenv/` directory structure
- Generates an HPKE key pair locally (`~/.config/secretenv/keys/alice@example.com/`)
- Registers your public key at `members/active/alice@example.com.json`

### Step 3: Add your first secrets

```bash
# Add secrets in KV format
secretenv set DATABASE_URL "postgres://user:pass@localhost/mydb"
secretenv set API_KEY "sk-your-api-key"

# Or bulk-import an existing .env file
secretenv import .env
```

### Step 4: Commit to Git

```bash
git add .secretenv/
git commit -m "Initialize secretenv workspace"
```

### Step 5: Have team members join

Once the Workspace is ready, direct other members to the steps in [Chapter 7](#7-joining-as-a-new-member).

When a member submits a PR, approve it following the [member addition workflow in Chapter 10](#member-addition-git-workflow).

---

## 7. Joining as a New Member

Follow these steps to join an existing Workspace.

### Step 1: Clone the repository

```bash
git clone <repo-url>
cd my-project
```

### Step 2: Submit a join request

```bash
secretenv join --member-id bob@example.com
```

Output:

```
Using SSH key: SHA256:xxxxx... (from ~/.ssh/id_ed25519)
Generated and activated key for 'bob@example.com':
  Key ID:   01HWXXXXXXXXXXXXXXXXXXXXX
  Expires:  2027-03-19T00:00:00Z
Added 'bob@example.com' to members/incoming/

Ready! Create a PR to share your public key with the team.
An existing member needs to run 'secretenv rewrap' to approve your membership.
```

Unlike `init`, `join` does not create a Workspace — it only places your public key in `members/incoming/`.

### Step 3: Create a PR

```bash
git checkout -b join/bob
git add .secretenv/members/incoming/bob@example.com.json
git commit -m "Add bob to secretenv (incoming)"
git push origin join/bob
```

Create a PR on GitHub (or your Git hosting service) and request a review from existing members.

### Step 4: Ask an existing member to run rewrap

After the PR is merged, an existing member runs `secretenv rewrap` to approve you. Once rewrap is committed, you will be able to access secrets.

### Step 5: Verify access

```bash
# Pull the latest changes
git pull

# Verify access
secretenv get DATABASE_URL
secretenv run -- env | grep MY_APP
```

---

## 8. Daily Usage (KV Store)

### Adding and Updating Entries

```bash
# Basic usage
secretenv set DATABASE_URL "postgres://user:pass@localhost/db"

# Save to a different store (with -n option)
secretenv set -n staging DATABASE_URL "postgres://user:pass@staging/db"
secretenv set -n prod DATABASE_URL "postgres://user:pass@prod/db"
```

If no store is specified, the value is saved to `default` (`.secretenv/secrets/default.kvenc`).

**To avoid leaving secrets in shell history**: use `--stdin` for passwords and tokens.

```bash
# Pipe the value
echo "super-secret-token" | secretenv set SECRET_TOKEN --stdin

# Interactive input (for passwords)
secretenv set SECRET_TOKEN --stdin
# → Waits for input. Press Ctrl+D to confirm.
```

### Removing Entries

```bash
secretenv unset OLD_KEY
secretenv unset -n staging OLD_KEY
```

### Retrieving Entries

```bash
# Get a specific key's value
secretenv get DATABASE_URL

# Output in KEY="VALUE" format
secretenv get --with-key DATABASE_URL

# Get all entries
secretenv get --all

# Get all entries in KEY="VALUE" format
secretenv get --all --with-key

# Get from a different store
secretenv get -n staging DATABASE_URL
```

### Listing Keys

```bash
# List key names (values are not displayed)
secretenv list

# List keys from a different store
secretenv list -n staging
```

`list` shows only key names without decrypting anything. Use `get` to retrieve values.

### Running Commands with Secrets Injected as Environment Variables

```bash
# Inject all secrets from the default store as environment variables
secretenv run -- ./my-app

# Use a different store
secretenv run -n staging -- ./my-app

# Pass multiple arguments
secretenv run -- python manage.py runserver
```

### Bulk Importing a .env File

```bash
# Import .env into the default store
secretenv import .env

# Import into a different store
secretenv import -n staging staging.env
```

Existing keys are overwritten.

---

## 9. File Encryption and Decryption

Use `encrypt` / `decrypt` for secrets that don't fit the KV format, such as certificates and binary files.

### Encrypting

```bash
# Encrypt a file (generates <filename>.encrypted in the current directory)
secretenv encrypt certs/ca.pem
# → ./ca.pem.encrypted

# Specify an output path
secretenv encrypt certs/ca.pem --out .secretenv/secrets/ca.pem.encrypted
```

A signature is attached automatically during encryption.

### Decrypting

```bash
# Signature verification is performed before decryption
secretenv decrypt ca.pem.encrypted --out certs/ca.pem
```

### Inspecting Metadata

You can examine an encrypted file's metadata without decrypting it.

```bash
secretenv inspect .secretenv/secrets/default.kvenc
secretenv inspect ca.pem.encrypted
```

Information displayed:

- List of recipients
- Signer and signing kid
- Encryption algorithm
- Created and updated timestamps
- Disclosure history (records of access by removed members)

### When to Use Which Format

| Scenario | Recommended | Reason |
|----------|-------------|--------|
| `.env` key-value pairs | kv-enc (`set`, `import`) | Minimal diff, entry-level operations |
| Certificate files (PEM) | file-enc (`encrypt`) | Binary support |
| SSH private keys | file-enc (`encrypt`) | Binary support |
| Files tens of MB or larger | Consider external storage | Base64 encoding inflates size by ~4/3 |
| Files hundreds of MB or larger | Not recommended | Adds large files to the Git repository |

---

## 10. Member Management

### Member Addition Git Workflow

When a new member submits a PR via `secretenv join`, follow this flow to approve them.

**Why PR review matters**: Reviewing and merging a PR is the decision to "trust this person's public key." Merging a PR from an unknown person without review means adding them as a recipient of your secrets.

```bash
# 1. After merging the new member's PR, pull the latest
git pull

# 2. Run rewrap
#    - Automatically runs online verification (GitHub API lookup)
#    - TOFU confirmation (visually verify the displayed key information)
secretenv rewrap

# TOFU confirmation example (the confirmation prompt described in Chapter 3):
# Member bob@example.com
#   GitHub login: bob-gh (id: 12345678)
#   SSH key fingerprint: SHA256:xxxxx...
# Approve? [y/N]: y    ← verify this is really their key before pressing y

# 3. Commit and push changes
git add .secretenv/
git commit -m "Approve bob and rewrap secrets"
git push
```

After `rewrap` completes:
- `members/incoming/bob@example.com.json` moves to `members/active/`
- Bob's wrap (encrypted content key) is added to all encrypted files

### Listing Members

```bash
# Show all members (active + incoming)
secretenv member list

# Show details for a specific member
secretenv member show bob@example.com
```

### Verifying Members

```bash
# Verify public keys for all members (with online verification)
secretenv member verify

# Verify specific members only
secretenv member verify alice@example.com bob@example.com
```

### Removing Members

**Important**: Removing a member and running rewrap **does not invalidate secret values that member previously obtained**. It is cryptographically impossible to "revoke past disclosures."

```bash
# 1. Remove the member from the workspace
secretenv member remove alice@example.com

# 2. Run rewrap (removes alice from all encrypted files)
#    For kv-enc: content key (MK) is regenerated and all entries are re-encrypted
#    For file-enc: alice's wrap is removed
secretenv rewrap

# 3. Commit
git add .secretenv/
git commit -m "Remove alice from secretenv"
```

### Required Steps After Removal

1. **Update secret values**: Change any values the removed member knew to new values.

```bash
secretenv set API_KEY "new-api-key"
secretenv set DATABASE_PASSWORD "new-password"
```

2. **Review disclosure history**: Use `secretenv inspect` to check disclosure records for the removed member.

3. **Clear disclosure history**: After updating secret values, you can clear the disclosure history.

```bash
secretenv rewrap --clear-disclosure-history
```

---

## 11. Key Management and Rotation

### Key States

| State | Description |
|-------|-------------|
| active | Key used for encryption and signing. One per member_id. |
| available | Can decrypt but is not used for encryption or signing. |
| expired | Past expiration date. Can still decrypt (with a warning). |

### Listing Keys

```bash
secretenv key list
```

### Regular Rotation

Keys expire one year after generation by default. Warnings appear starting 30 days before expiration.

```bash
# 1. Generate a new key (automatically becomes active)
secretenv key new

# Specify an expiration date
secretenv key new --expires-at 2028-01-01T00:00:00Z
secretenv key new --valid-for 2y    # 2 years
secretenv key new --valid-for 180d  # 180 days

# 2. Update your public key in the workspace
secretenv init --force

# 3. Create and merge a PR
git add .secretenv/members/active/alice@example.com.json
git commit -m "Rotate alice's key"
git push

# 4. After merge: update wraps in all secrets with the new key
secretenv rewrap

# 5. Commit
git add .secretenv/secrets/
git commit -m "Rewrap secrets for alice's new key"
git push

# 6. Keep the old key for now (may be needed to decrypt past secrets)
#    Remove after a sufficient transition period
secretenv key remove <old_kid>
```

### Content Key Rotation

Separately from member key rotation, you can rotate the content keys (MK/DEK) of encrypted files themselves.

```bash
secretenv rewrap --rotate-key
```

This regenerates the MK/DEK for all files, invalidating any content keys previously obtained by removed members.

### Activating a Specific Key

```bash
secretenv key activate <kid>
```

### Recommended Old Key Retention Period

Before deleting an old key, confirm:

- All team members have obtained encrypted files rewrapped with the new key
- No operations remain that require decrypting secrets encrypted with the old key

As a guideline, retain old keys for 1–3 months after rewrap completion.

---

## 12. Operational Guidelines

### Checklist When a Member Leaves

1. Remove the member with `secretenv member remove <member_id>`
2. Update all encrypted files with `secretenv rewrap`
3. Commit with `git add .secretenv/ && git commit -m "Remove <member>"`
4. Review disclosure history with `secretenv inspect`
5. Update any secret values (API keys, passwords, etc.) the departing member may have known
6. After updating, clear disclosure history with `secretenv rewrap --clear-disclosure-history`
7. Confirm access revocation in related services (GitHub, AWS, databases, etc.)

### Obligation to Rotate Secret Values

**Cryptographic removal is not information erasure.** `member remove` + `rewrap` prevents the member from decrypting new secrets going forward, but it cannot invalidate values they have already decrypted.

For true security, always rotate any values that departing or removed members may have known.

### Using `--force` in CI/CD and Its Risks

CI/CD environments typically lack a TTY (interactive terminal), so `--force` may be required to automatically skip the TOFU confirmation in `rewrap`.

**Risk of `--force`**: As explained in Chapter 3, the TOFU check is the "last line of defense" against public key substitution attacks. Skipping it with `--force` means a fraudulent public key could go undetected.

Rules for safe use of `--force` in CI/CD:

1. **Complete new member approvals in an interactive environment first**: Before running CI/CD, run `rewrap` interactively to promote incoming members to active. CI/CD should only be used for accessing already-active members.
2. **Perform post-hoc verification after `--force`**: Run `secretenv member verify` to cross-check all members against GitHub.
3. **Limit `--force` usage**: Use `--force` only in limited contexts like CI/CD pipelines, not in day-to-day interactive use.

Note: Members who explicitly fail online verification are still rejected for promotion even when `--force` is used.

```yaml
# GitHub Actions example
- name: Run app with secrets
  env:
    SECRETENV_MEMBER_ID: ci@example.com
    SECRETENV_HOME: /tmp/secretenv
  run: |
    secretenv run --force -- ./my-app
```

**Recommendation**: Create a dedicated member ID for CI/CD (e.g., `ci@example.com`) and manage its rotation explicitly.

### Regular Auditing with `secretenv inspect`

```bash
# Check metadata for each encrypted file
secretenv inspect .secretenv/secrets/default.kvenc

# Things to verify:
# - No unnecessary members in recipients
# - No notable entries in removed_recipients (disclosure history)
# - Signer is correct
# - No nearly-expired keys are being used
```

### What Not to Add to `.gitignore`

Do not add the entire `.secretenv/` directory to `.gitignore`. It is intentionally managed by Git.

However, decrypted plaintext files should be added to `.gitignore`.

```gitignore
# Ignore decrypted temporary files
*.pem
.env
```

---

## 13. FAQ

### Q: Is a server required?

No. secretenv operates without a server. Encrypted files are stored in the Git repository and commands run locally. Online verification via the GitHub API is an optional feature.

### Q: Is it safe to commit public key files to GitHub?

Yes. `members/active/*.json` contains public keys (the encryption public key and the SSH public key fingerprint), but no private keys whatsoever. Public keys are, by definition, safe to share publicly.

Decrypting secrets requires the private key stored locally at `~/.config/secretenv/keys/`. This private key is never included in Git.

### Q: Does removing a member erase past secrets?

No. Removing a member and running rewrap does not eliminate values that member has already decrypted — those values may still exist on their machine.

To eliminate the risk of exposure after removal, always rotate the values (API keys, passwords, etc.) the member may have known.

### Q: Why is the SSH agent needed?

secretenv private keys (HPKE private keys) are protected by an SSH Ed25519 key instead of a passphrase. Every secretenv operation requires decryption using the SSH key, so using an SSH agent is convenient to avoid entering a passphrase each time.

In environments where an SSH agent is unavailable, you can switch to signing with the `ssh-keygen` command using the `--ssh-keygen` option.

When multiple keys are loaded in the SSH agent, you can explicitly specify which key to use with the `-i` option or the `ssh_key` configuration:

```bash
secretenv encrypt -i ~/.ssh/id_ed25519_work secret.env
```

### Q: How do I manage separate secrets for multiple projects?

Each Git repository can have its own independent `.secretenv/`. Run `secretenv init` in each project to manage them as independent Workspaces.

Even if the same member participates in multiple projects, their HPKE key is registered as an independent recipient in each Workspace.

### Q: Should I use `secretenv run` or manually load a `.env` file?

`secretenv run` is recommended for these reasons:

- No plaintext `.env` file is left on disk
- The latest secrets are decrypted on each run, so value updates take effect immediately
- Signature verification runs automatically, preventing command execution with tampered secrets

---

## 14. Command Reference

### Common Options (Available for All Commands)

| Option | Description |
|--------|-------------|
| `--home <path>` | Specify base directory (default: `~/.config/secretenv/`) |
| `-w` / `--workspace <path>` | Specify Workspace Root |
| `-m` / `--member-id <id>` | Specify member_id |
| `-i` / `--identity <path>` | Specify SSH key file path (also used for key selection with ssh-agent) |
| `--ssh-agent` | Use SSH agent |
| `--ssh-keygen` | Use ssh-keygen command |
| `--json` | Output in JSON format |
| `-q` / `--quiet` | Minimal output |
| `-v` / `--verbose` | Verbose logging |
| `-f` / `--force` | Skip confirmation prompts |

### Initialization and Joining

| Command | Description |
|---------|-------------|
| `secretenv init [--member-id <id>] [--force]` | Initialize a Workspace or re-register yourself (added directly to active) |
| `secretenv join [--member-id <id>] [--force]` | Request to join an existing Workspace (added to incoming) |

### KV Operations

| Command | Description |
|---------|-------------|
| `secretenv set [-n <name>] <KEY> <VALUE>` | Add or update an entry |
| `secretenv set [-n <name>] <KEY> --stdin` | Read value from stdin and set it |
| `secretenv get [-n <name>] <KEY>` | Retrieve and display a specific key's value |
| `secretenv get [-n <name>] --all` | Retrieve and display all entries |
| `secretenv get [-n <name>] [--all] --with-key` | Output in `KEY="VALUE"` format |
| `secretenv unset [-n <name>] <KEY>` | Remove an entry |
| `secretenv list [-n <name>]` | List key names (values not displayed) |
| `secretenv import [-n <name>] <file>` | Bulk import a `.env` file |
| `secretenv run [-n <name>] -- <command>` | Run a command with secrets injected as environment variables |

### File Operations

| Command | Description |
|---------|-------------|
| `secretenv encrypt <file> [--out <path>]` | Encrypt a file (file-enc) |
| `secretenv decrypt <file> --out <path>` | Decrypt a file |
| `secretenv inspect <file>` | Display encrypted file metadata (no decryption needed) |

### Member Management

| Command | Description |
|---------|-------------|
| `secretenv member list` | List all members |
| `secretenv member show <member_id>` | Show details for a specific member |
| `secretenv member verify [<member_id>...]` | Verify member public keys (with online verification) |
| `secretenv member remove <member_id>` | Remove a member from the Workspace |
| `secretenv rewrap [--force] [--rotate-key] [--clear-disclosure-history]` | Promote incoming → active and sync recipients in all encrypted files |

### Key Management

| Command | Description |
|---------|-------------|
| `secretenv key new [--expires-at <datetime>] [--valid-for <duration>]` | Generate a new key (automatically activated) |
| `secretenv key list` | List keys |
| `secretenv key activate <kid>` | Activate a specific key |
| `secretenv key remove <kid>` | Remove a key |

### Configuration

| Command | Description |
|---------|-------------|
| `secretenv config set <key> <value>` | Set a configuration value |
| `secretenv config get <key>` | Get a configuration value |
| `secretenv config list` | List all configuration values |
| `secretenv config unset <key>` | Remove a configuration value |

Configuration keys: `member_id`, `ssh_signer` (`auto` / `ssh-agent` / `ssh-keygen`), `ssh_key`, `github_user`

---

*This guide covers everything needed for day-to-day secretenv usage. For detailed cryptographic specifications and internal design, refer to the project's internal documentation.*
