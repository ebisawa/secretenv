# SecretEnv v3 Security Design

---

## 0. Document Information

| Item | Value |
|------|-------|
| Version | 1.4 |
| Date | 2026-03-23 |

### Purpose of This Document

This document describes the security design of SecretEnv v3. It summarizes the **background behind major design decisions** and the **main security considerations** in the system.

---

## 1. Executive Summary

SecretEnv is an offline-first encrypted file sharing CLI tool for safely sharing secrets such as `.env` files and certificates within a team. It can use a Git repository as a distribution medium, but does not depend on Git's existence.

### Main Design Ideas

1. **HPKE (RFC 9180) multi-recipient key wrapping** — Wraps the Content Key individually with each recipient's public key, allowing recipients to be added or removed without re-encrypting the payload
2. **Cryptographic context binding for ciphertext uniqueness** — Binds `sid` (file identifier), `kid` (key generation), and `k` (entry key) in AAD and HPKE info, reducing the risk of mixing up what a ciphertext belongs to
3. **Defence-in-Depth (layered security)** — Uses the same context in multiple places so that a single implementation mistake is less likely to become a serious security issue
4. **Ed25519 signatures and PublicKey attestation** — Tamper detection for encrypted files, SSH-key binding, and optional GitHub online verification
5. **Passwordless PrivateKey protection via SSH key reuse** — Derives an encryption key with HKDF using Ed25519's deterministic signature as IKM, eliminating the need for additional password management

### Chosen Cryptographic Primitives and Design Intent

SecretEnv uses widely adopted standardized cryptographic primitives such as HPKE, Ed25519, HKDF-SHA256, and XChaCha20-Poly1305. These were selected based on their established security properties, but the security of the overall system still depends not only on the primitives themselves, but also on implementation quality, key management, and operational practice.

| Goal | Main mechanism | Design intent |
|------|----------------|---------------|
| **Confidentiality** | HPKE wrap + XChaCha20-Poly1305 AEAD | Ensure that only currently authorized members can decrypt |
| **Tamper detection** | Ed25519 signatures | Make modification of encrypted files and metadata detectable |
| **Context binding** | `sid` / `k` in AAD | Prevent reuse or substitution across different secrets or entries |
| **Key rotation consistency** | `kid` in HPKE info | Prevent mix-ups between key generations |
| **Key consistency** | PublicKey self-signature | Allow verification that the same private key holder created the PublicKey |
| **Stronger key identity checks** | SSH attestation + TOFU confirmation + online verification | Reduce the risk of public key substitution |

**Notes:**
- **Key consistency** means that the same private key holder created the PublicKey, but it does not by itself establish real-world identity.
- **Stronger key identity checks** are an operational mechanism that combines multiple trust layers to improve confidence in a public key. Correct TOFU execution is a precondition, and the effect is reduced when `--force` is used. See §2.5 for details.

---

## 2. Threat Model and Security Goals

### 2.1 Attacker Model

| Attacker | Capability | Assumed Scenario |
|----------|-----------|----------------|
| **Repository tamperer** | Can arbitrarily tamper with files under `.secretenv/` | Malicious CI, compromised Git server, unauthorized push |
| **Public key substituter** | Can replace `members/active/<id>.json` with a forged public key | MITM during new member addition, unauthorized commit to repository |
| **Key rotation attacker** | Retains old-generation wraps and attempts decryption with new keys | Exploiting weaknesses in the key update process |
| **Context confusion attacker** | Swaps ciphertext components between different secrets | Copy-and-paste across encrypted files |

**Assumption: Repository write access control**

The above attacker model assumes that write access to the repository is properly managed. In the main target environment of Git + GitHub operation, changes to `members/active/` are verified through PR review. Attackers with unrestricted write access to the repository (e.g., compromised repository administrator privileges) are outside the scope of this model. In environments where this assumption is not met, access control at the repository layer must be implemented separately, in addition to the incoming → active promotion process.

### 2.2 Trust Boundary

```mermaid
graph TB
    subgraph trusted["Trusted"]
        LocalTerminal[Local machine]
        LocalKeystore["Local key storage<br/>~/.config/secretenv/keys/"]
        SSHKey[SSH Ed25519 private key]
    end

    subgraph untrusted["Untrusted (potentially tampered)"]
        MembersDir[".secretenv/members/<br/>PublicKey files"]
        SecretsDir[".secretenv/secrets/<br/>Encrypted files"]
    end

    subgraph external["External systems (optional)"]
        GitHub["GitHub API<br/>for online verification"]
    end

    LocalTerminal -->|key generation / decryption| LocalKeystore
    LocalTerminal -->|attestation| SSHKey
    LocalTerminal -->|encryption / verification| MembersDir
    LocalTerminal -->|encryption / decryption| SecretsDir
    LocalTerminal -.->|online verification| GitHub

    style trusted fill:#90EE90
    style untrusted fill:#FFE4B5
    style external fill:#E0E0E0
```

**Trusted elements:**
- Local machine and local key storage (`~/.config/secretenv/keys/`)
- User's SSH Ed25519 private key
- GitHub API (only during online verification, optional)

**Untrusted elements:**
- Workspace `members/` directory — verified by signatures and attestation
- Workspace `secrets/` directory — verified by signatures

### 2.3 Security Goals

**Goals:**
- Confidentiality of encrypted files (only current recipients can decrypt)
- Authenticity of encrypted files (tamper detection)
- Binding of ciphertext to context (swap prevention)
- Cryptographic binding of key generations (wrap reuse prevention)
- Proof of signer and public key identity

**Non-goals:**
- Full Forward Secrecy as a system-wide property (discussed in §12)
- Recovery of previously disclosed content (cryptographically impossible) — For file-enc, the DEK is maintained when content is not changed upon recipient removal. The same DEK = same content, and this was legitimately disclosed to former recipients. Use `--rotate-key` to regenerate the DEK when true revocation is needed. For kv-enc, the DEK is automatically regenerated upon recipient removal.
- Prevention of insider misuse of legitimately decrypted content
- Access control via central policy (policy-less design)

### 2.4 Defense Matrix

| Security Goal | Defense Mechanism | Relevant Section |
|--------------|------------------|-----------------|
| Confidentiality | HPKE wrap + AEAD (XChaCha20-Poly1305) | §5, §6 |
| Authenticity | Ed25519 signature (PureEdDSA) | §8 |
| Context binding (inter-file) | `sid` in AAD | §9 |
| Context binding (inter-entry) | `k` in AAD | §9 |
| Key generation binding | `kid` in HPKE info | §9 |
| Public key authenticity | SSH attestation + TOFU confirmation + online verification | §2.5, §8 |
| Wrap integrity | Ed25519 signature protects `protected` (including wrap) | §8 |
| PrivateKey protection | SSH signature-based key derivation + AEAD | §7 |
| DoS resistance | Input size limits | §11 |

### 2.5 Trust Model

"Key authenticity" in SecretEnv is not determined by a single mechanism. Instead, the system combines the following layers to provide more evidence for human trust decisions. No single layer alone establishes identity.

**Layer 1: Self-signature (key consistency)**

The self-signature included in a PublicKey shows that "the entity that created this PublicKey holds the corresponding private key." This supports **consistency** of the key, but does not establish **identity**. An attacker who creates a new SecretEnv key pair can generate a PublicKey with a valid self-signature.

The role of self-signature is limited to **tamper prevention** of existing PublicKeys. Modifying any field of a PublicKey in `members/active/` will cause self-signature verification to fail.

**Layer 2: SSH attestation (key binding)**

SSH attestation cryptographically ties a SecretEnv key pair to an SSH key. However, who owns the SSH key itself cannot be determined at this layer. An attacker can generate valid attestation by attesting their SecretEnv key with their own SSH key.

**Layer 3: TOFU confirmation (key → person binding)**

The user running `rewrap` visually confirms the SSH fingerprint and GitHub account information of the incoming member. This is the same trust model as confirming a first connection in SSH's `known_hosts`. **This is where the binding between key and person (as a basis for judgment) is first established for use in the workspace.**

When TOFU confirmation is skipped (with `--force`), promotion proceeds without interactive confirmation, so there is less evidence available for the identity decision. However, members who have been explicitly failed by online verification are excluded from promotion even when `--force` is used.

**Layer 4: Online verify (supplementary evidence)**

Automatically checks SSH public key registration via the GitHub API. This is useful supplementary evidence as long as the GitHub account is not compromised, but it does not establish identity on its own.

**Verification key for signature verification**

The verification key referenced during signature verification is determined by one of the following: the PublicKey identified from the workspace `members/active/` by `signature.kid`, or the PublicKey embedded in `signature.signer_pub` if present. When `signer_pub` is embedded, that PublicKey is confirmed via self-signature, expiration, `kid` match, and attestation (`attestation.method`) verification. The local keystore is used for private key storage but is not used as a public key source for signature verification. The workspace `active` is not a "trusted anchor" that provides trust to other users. Each user is responsible for judging the trustworthiness of a key (deciding which person's key to accept). Supporting information for this judgment is provided through SSH attestation and GitHub `binding_claims` (online verify).

**Risks of `--force` and recommended operation**: Since `--force` skips the interactive TOFU confirmation, it weakens the last line of defense against public key substitution attacks. However, in environments where online verification is available, promotion of members who fail verification is refused even with `--force`. In non-interactive environments such as CI/CD pipelines, `--force` may be necessary, in which case the following operations are recommended:
- In CI/CD environments, run `rewrap` in an interactive environment first to complete member promotion, then use `--force` in CI/CD
- After using `--force`, run `member verify` for online verification and post-hoc confirm the legitimacy of promoted members
- Manage the use of `--force` as a team operational policy and avoid unrestricted use

**Composite trust**

Stronger confidence in key authenticity depends on the above layers working as intended. However, the ways this confidence can break down differ by attack scenario:

- **Tampering with existing keys**: Requires SSH private key compromise. Since self-signature and SSH attestation cannot be forged, tampering cannot succeed without the original key holder's SSH private key.
- **Inserting a new key**: Can succeed with only TOFU misapproval (or omission via `--force`). An attacker can generate valid self-signature and attestation with their own key, so the victim's SSH key compromise is not required.

The conditions listed above are a composite of these multiple attack scenarios.

---

## 3. Selection of Cryptographic Primitives

### 3.1 Algorithm Summary

| Algorithm | Parameters | RFC | Purpose |
|-----------|-----------|-----|---------|
| HPKE Base mode | suite `hpke-32-1-3` | RFC 9180 | Content Key wrap/unwrap |
| DHKEM(X25519, HKDF-SHA256) | kem_id=32 (0x0020) | RFC 9180 | KEM (key encapsulation) |
| HKDF-SHA256 | kdf_id=1 (0x0001) | RFC 5869 | KDF (key derivation) |
| ChaCha20-Poly1305 | aead_id=3 (0x0003) | RFC 8439 | HPKE internal AEAD |
| XChaCha20-Poly1305 | nonce 24 bytes, key 32 bytes | — | payload / entry / PrivateKey encryption |
| Ed25519 (PureEdDSA) | — | RFC 8032 | Signing and verification |
| HKDF-SHA256 | — | RFC 5869 | CEK derivation, PrivateKey enc_key derivation |
| JCS | — | RFC 8785 | Deterministic JSON canonicalization |
| base64url (no padding) | — | RFC 4648 §5 | Binary encoding |

### 3.2 HPKE (RFC 9180)

**Rationale:**
- A standardized hybrid public key encryption scheme with a consistent definition of the KEM + KDF + AEAD combination
- Base mode provides ephemeral key isolation per wrap (however, if a recipient's long-term key is compromised, all existing wraps for that recipient can be decrypted; see §12.1)
- Clear suite ID identification via IANA Registry

**Suite configuration:**
```
hpke-32-1-3
├── kem_id  = 32 (0x0020) DHKEM(X25519, HKDF-SHA256)
├── kdf_id  = 1  (0x0001) HKDF-SHA256
└── aead_id = 3  (0x0003) ChaCha20-Poly1305
```

**Comparison with alternatives:**

| Alternative | Reason for rejection |
|-------------|---------------------|
| RSA-OAEP | Large key size; Forward Secrecy cannot be naturally achieved |
| ECIES (custom construction) | Not standardized; high risk of misconfiguration |
| Age (X25519-ChaChaPoly) | Less structured than HPKE for this use; insufficient flexibility for info/AAD |

**Known limitations:**
- Base mode does not provide sender authentication (supplemented by signatures)
- X25519 provides 128-bit security level

### 3.3 XChaCha20-Poly1305

**Rationale:**
- 24-byte nonce makes random nonce collision risk practically negligible (birthday bound at 2^96)
- Consistent performance even in environments without AES-NI
- Does not provide misuse resistance, but practical security is ensured by the large nonce space

**Comparison with alternatives:**

| Alternative | Reason for rejection |
|-------------|---------------------|
| AES-256-GCM | 12-byte nonce has high collision risk in multi-key usage |
| AES-256-GCM-SIV | Nonce misuse resistance is appealing, but rejected due to implementation complexity and limited adoption |

**Known limitations:**
- Nonce reuse is catastrophic (encrypting with the same key and nonce is prohibited)
- Compression before encryption is prohibited (to avoid compression oracle attacks CRIME/BREACH)

### 3.4 Ed25519 (RFC 8032 PureEdDSA)

**Rationale:**
- **Deterministic signatures**: Always generates the same signature for the same input. An essential property for use as IKM in PrivateKey protection.
- Fast signing and verification
- Affinity with SSH ecosystem (ssh-ed25519)

**Comparison with alternatives:**

| Alternative | Reason for rejection |
|-------------|---------------------|
| ECDSA (P-256) | Non-deterministic signatures (mitigable with RFC 6979, but handling varies across SSH implementations) |
| Ed448 | Insufficient adoption in the SSH ecosystem |

**Known limitations:**
- 128-bit security level
- Context separation is not provided by PureEdDSA itself (addressed by JCS canonicalization + protocol identifiers)

### 3.5 HKDF-SHA256 (RFC 5869)

**Rationale:**
- Standardized key derivation function
- The `info` parameter allows safely deriving purpose-specific keys from the same IKM
- The `salt` parameter allows deriving different keys even from the same IKM and info

**Uses:**
- CEK derivation for kv-enc (MK + salt + sid → CEK)
- enc_key derivation for PrivateKey protection (SSH signature + salt + kid → enc_key)

### 3.6 JCS (RFC 8785)

**Rationale:**
- Provides deterministic canonicalization of JSON objects
- Eliminates ambiguity in key ordering and number representation, ensuring consistency of signatures, AAD, and HPKE info
- No ambiguity arises even when string fields like `sid` contain arbitrary characters

### 3.7 Known Properties of the Standard Primitives Used Here

The security properties that SecretEnv relies on for each primitive are summarized below.

| Primitive | Security Definition | Basis |
|-----------|--------------------|----|
| HPKE Base mode (RFC 9180) | Standardized mechanism for recipient-specific key delivery | Base mode does not provide sender authentication, so Ed25519 signatures are used as a separate check against insider attacks. |
| XChaCha20-Poly1305 | Widely used authenticated encryption construction | Nonce uniqueness is an important precondition (see §3.8). |
| Ed25519 (PureEdDSA) | Widely used standardized signature scheme | Used in SecretEnv for signing encrypted files and PublicKey documents. |
| HKDF-SHA256 | PRF security | Per RFC 5869. When IKM has sufficient entropy, the output is pseudorandom. The IKM for CEK derivation (MK) is 32 bytes from CSPRNG. |

**Security dependency:**

```
Confidentiality ── HPKE IND-CCA2 ─┐
                                    ├─ Overall confidentiality
payload AEAD IND-CCA2 ─────────────┘

Signatures ── Ed25519 ── Tamper detection

CEK independence ── HKDF PRF security ── Cryptographic independence between entries
```

**Preconditions and limitations:**
- HPKE Base mode assumes confidentiality of the recipient's long-term private key. If the long-term key is compromised, all wraps for that recipient can be decrypted (see §12.1).
- XChaCha20-Poly1305 depends on nonce uniqueness in practice, and nonce reuse can lead to serious problems.
- Ed25519 assumes private key confidentiality. In SecretEnv, the signing private key is stored encrypted by PrivateKey protection (§7).

### 3.8 Nonce Safety Margin

XChaCha20-Poly1305 uses a 24-byte (192-bit) nonce. In SecretEnv's design, there are no cases where the same symmetric key is used for multiple encryptions. DEK (file-enc), CEK (kv-enc entry), and enc_key (PrivateKey protection) are each uniquely generated or derived per encryption, so the risk of nonce collision is structurally eliminated.

The choice of 192-bit nonce space serves as a safety net in case future design changes introduce same-key reuse.

---

## 4. Key Hierarchy and Key Lifecycle

### 4.1 Key Types and Relationships

```mermaid
graph TB
    SSHKey["SSH Ed25519 key<br/>(user-owned)"]
    SecretEnvKP["SecretEnv key pair<br/>kid: ULID"]
    KEM_PK["X25519 public key<br/>(KEM)"]
    KEM_SK["X25519 private key<br/>(KEM)"]
    SIG_PK["Ed25519 public key<br/>(signing)"]
    SIG_SK["Ed25519 private key<br/>(signing)"]
    DEK["DEK<br/>32 bytes"]
    MK["MK<br/>32 bytes"]
    CEK["CEK<br/>32 bytes"]

    SSHKey -->|"attestation<br/>(identity support)"| SecretEnvKP
    SSHKey -->|"PrivateKey protection<br/>(IKM derivation)"| SIG_SK
    SecretEnvKP --> KEM_PK
    SecretEnvKP --> KEM_SK
    SecretEnvKP --> SIG_PK
    SecretEnvKP --> SIG_SK
    KEM_PK -->|"HPKE wrap"| DEK
    KEM_PK -->|"HPKE wrap"| MK
    SIG_SK -->|"Ed25519 sign"| DEK
    SIG_SK -->|"Ed25519 sign"| MK
    MK -->|"HKDF-SHA256"| CEK

    style SSHKey fill:#FFB6C1
    style DEK fill:#FFE4B5
    style MK fill:#FFE4B5
    style CEK fill:#90EE90
```

This diagram intentionally separates the SSH key from the SecretEnv key pair.

- The **SSH key** is an external authentication key already owned by the user; it does not directly encrypt or sign SecretEnv workspace payloads
- The **SecretEnv key pair** is the application-specific key material used for encryption, decryption, signing, and verification inside the workspace
- The SSH key has only two roles
  - **attestation**: show which SSH key backs a SecretEnv public key
  - **PrivateKey protection**: derive the `enc_key` used to unlock the SecretEnv private key stored in the local keystore

Therefore, the SSH key is not the SecretEnv key pair itself. It is an outer key used to support provenance checks and local protection of the SecretEnv key pair.

### 4.2 Key Parameter Summary

| Key type | Size | Generation method | Purpose | Zeroization required |
|----------|------|------------------|---------|---------------------|
| SSH Ed25519 private key | 32 bytes | User-managed | attestation, PrivateKey protection | N/A (OS-managed) |
| X25519 private key (KEM) | 32 bytes | CSPRNG | HPKE unwrap | MUST |
| X25519 public key (KEM) | 32 bytes | Derived from X25519 private key | HPKE wrap | — |
| Ed25519 private key (signing) | 32 bytes | CSPRNG | Signature generation | MUST |
| Ed25519 public key (signing) | 32 bytes | Derived from Ed25519 private key | Signature verification | — |
| DEK (Data Encryption Key) | 32 bytes | CSPRNG | file-enc payload encryption | MUST |
| MK (Master Key) | 32 bytes | CSPRNG | CEK derivation source for kv-enc | MUST |
| CEK (Content Encryption Key) | 32 bytes | Derived via HKDF-SHA256 | kv-enc entry encryption | MUST |
| enc_key (for PrivateKey protection) | 32 bytes | Derived via HKDF-SHA256 | PrivateKey AEAD encryption | MUST |

Notes:

- `enc_key` is not a stored or pre-existing key; it is a transient symmetric key derived from SSH signing output each time
- The same SSH key can protect multiple SecretEnv key generations, but different `kid` / `salt` values produce different `enc_key` values
- The `private.json` stored in the local keystore contains only the ciphertext of SecretEnv private key material; the SSH private key itself remains outside SecretEnv storage

### 4.3 Key Lifecycle

Each SecretEnv key pair has a `kid` (key generation ID) identified by a ULID and follows this lifecycle:

```
generated → active → expired
              │
              └── rotate (generate new key pair with new kid)
```

- **Generated**: Key pair is generated by the `key new` command. A ULID is assigned as `kid`.
- **Active**: State usable for encryption and signing. `expires_at` has not been reached.
- **Expired**: State past `expires_at`. Encryption (wrap) operations are rejected. Signature verification is permitted with a warning (to allow verification of data legitimately signed in the past).

### 4.4 Key Rotation

Key rotation has two levels:

**1. rewrap (Content Key maintained)**
- DEK/MK is not changed
- Only wraps are updated for recipient changes (member additions, key updates)
- Payload re-encryption is not needed

**2. rewrap --rotate-key (Content Key regenerated)**
- New DEK/MK is generated
- Payload is re-encrypted
- For use after key compromise or for periodic rotation

### 4.5 Key Relationship Diagrams

#### file-enc key relationships

```mermaid
graph TB
    subgraph recipients["Recipients (PublicKey)"]
        PK1["PublicKey 1<br/>kid: 01H..."]
        PK2["PublicKey 2<br/>kid: 01H..."]
    end

    subgraph wrap["HPKE Wrap"]
        W1["wrap_item 1<br/>kid: 01H..."]
        W2["wrap_item 2<br/>kid: 01H..."]
    end

    DEK["DEK<br/>32 bytes<br/>CSPRNG"]

    subgraph payload["Payload"]
        PT[Plaintext file]
        CT["Ciphertext<br/>XChaCha20-Poly1305"]
    end

    PK1 -->|HPKE Encaps| W1
    PK2 -->|HPKE Encaps| W2
    DEK -->|HPKE wrap| W1
    DEK -->|HPKE wrap| W2
    DEK -->|AEAD encrypt| CT
    PT -->|AEAD encrypt| CT

    style DEK fill:#FFE4B5
    style CT fill:#FFB6C1
```

#### kv-enc key relationships

```mermaid
graph TB
    subgraph recipients["Recipients (PublicKey)"]
        PK1["PublicKey 1<br/>kid: 01H..."]
        PK2["PublicKey 2<br/>kid: 01H..."]
    end

    subgraph wrap["HPKE Wrap"]
        W1["wrap_item 1<br/>kid: 01H..."]
        W2["wrap_item 2<br/>kid: 01H..."]
    end

    MK["MK<br/>32 bytes<br/>CSPRNG"]

    subgraph cek["CEK Derivation"]
        CEK1["CEK1<br/>HKDF(MK, salt1, sid)"]
        CEK2["CEK2<br/>HKDF(MK, salt2, sid)"]
    end

    subgraph entries["Encrypted Entries"]
        E1["Entry 1: DATABASE_URL"]
        E2["Entry 2: API_KEY"]
    end

    PK1 -->|HPKE Encaps| W1
    PK2 -->|HPKE Encaps| W2
    MK -->|HPKE wrap| W1
    MK -->|HPKE wrap| W2
    MK -->|HKDF-SHA256| CEK1
    MK -->|HKDF-SHA256| CEK2
    CEK1 -->|AEAD encrypt| E1
    CEK2 -->|AEAD encrypt| E2

    style MK fill:#FFE4B5
    style CEK1 fill:#90EE90
    style CEK2 fill:#90EE90
```

---

## 5. file-enc Protocol

### 5.0 Data Structure Overview

file-enc is a JSON-format file with a two-layer structure consisting of signed data (`protected`) and the signature (`signature`).

**Structurally important security properties:**

1. **Signature coverage**: The `wrap` array and `payload` are stored within `protected`. Therefore, the Ed25519 signature over the entire `protected` protects the integrity of both wrap (key distribution) and payload (ciphertext).
2. **Dual presence of sid**: `sid` exists both directly under `protected` and within `payload.protected`. Verifying that both match at decryption time detects payload swapping.
3. **Payload envelope**: The payload itself has a protected header (`payload.protected`), whose JCS canonicalization becomes the AEAD AAD. This establishes the payload's cryptographic binding independently from the outer signature.

#### Overall file structure (JSON layout)

The overall structure of file-enc nests in order: top level (signed container) → `protected` (signed data) → `wrap` (DEK distribution) / `payload` (ciphertext).

```
{
  "protected": {
    "format": "secretenv.file@3",    // format identifier
    "sid": "<UUID>",                 // uniquely identifies the file (used to bind wrap/payload)
    "wrap": [
      {
        "rid": "<member_id>",        // recipient's member_id (informational only)
        "kid": "<ULID>",             // recipient key ID (keystore lookup key; included in HPKE info)
        "alg": "hpke-32-1-3",        // HPKE algorithm identifier
        "enc": "<b64url>",           // HPKE encapsulated key (enc in base mode)
        "ct": "<b64url>"             // HPKE ciphertext (ct wrapping DEK)
      }
      // ... one element per recipient ...
    ],
    "payload": {
      "protected": {
        "format": "secretenv.file.payload@3",
        "sid": "<UUID>",             // same as protected.sid (verified before decryption)
        "alg": { "aead": "xchacha20-poly1305" }
      },
      "encrypted": {
        "nonce": "<b64url>",         // 24 bytes
        "ct": "<b64url>"             // AEAD ciphertext (entire plaintext file)
      }
    },
    "created_at": "<RFC3339>",       // file creation timestamp
    "updated_at": "<RFC3339>"        // file update timestamp
  },
  "signature": {
    // signature_v3 (§8.2): signature over JCS-canonicalized protected, etc.
  }
}
```

This layout allows (1) the signature to detect tampering in the entire `protected` (= wrap and payload), while (2) the payload has its own header binding via `payload.protected` as AAD, independent from the outer signature.

### 5.1 Encryption Flow

```
1. DEK generation     — 32 bytes, CSPRNG
2. HPKE wrap          — wrap DEK with each recipient's public key
3. AEAD encryption    — encrypt plaintext file with DEK using XChaCha20-Poly1305
4. Ed25519 signature  — JCS-canonicalize the entire protected object and sign
```

### 5.2 DEK Generation

- 32 bytes of cryptographically secure random bytes (`OsRng`)
- Unique per file-enc file
- Zeroized after use

### 5.3 HPKE wrap

For each recipient:

```
info_bytes = jcs({
    "kid": <wrap_item.kid>,
    "p": "secretenv:file:hpke-wrap@3",
    "sid": <protected.sid>
})

aad_bytes = info_bytes   // defence-in-depth

(enc, ct) = HPKE.SealBase(pk_recip, info_bytes, aad_bytes, DEK)
```

**Design decision: why HPKE info and AAD are identical**

HPKE internally passes info to the KDF and AAD to the AEAD. By making them identical:
- The AAD layer defends against bypass attacks at the KDF stage
- The info layer defends against bypass attacks at the AEAD stage
- Defence-in-depth is achieved

### 5.4 Payload Encryption

```
payload.protected = {
    "format": "secretenv.file.payload@3",
    "sid": <protected.sid>,          // same value as outer sid
    "alg": { "aead": "xchacha20-poly1305" }
}

aad = jcs(payload.protected)
nonce = random(24 bytes)
ct = XChaCha20Poly1305.Encrypt(DEK, nonce, aad, plaintext)

// store nonce and ct in payload.encrypted
payload.encrypted = { "nonce": b64url(nonce), "ct": b64url(ct) }
```

### 5.5 Decryption Flow

```
1. Signature verification  — immediate error on failure (decryption does not proceed)
2. Key lookup              — locate private key in keystore by kid
3. wrap_item search        — find the matching wrap_item by kid (not rid)
4. HPKE unwrap             — reconstruct info/AAD and recover DEK
5. sid verification        — confirm payload.protected.sid == protected.sid
6. AEAD decryption         — decrypt payload with DEK
```

**Important: Signature verification precedes decryption.** Decrypting a ciphertext with an invalid signature exposes the cryptographic primitive to malicious input and increases the attack surface for side-channel attacks.

### 5.6 Difference Between rewrap and rotate-key

| Operation | DEK | wrap | payload | Purpose |
|-----------|-----|------|---------|---------|
| `rewrap` (file-enc) | Maintained | Updated | Maintained | Recipient addition/removal/key update |
| `rewrap` (kv-enc, on recipient removal) | Regenerated | Updated | Re-encrypted | Content Key is automatically regenerated when a recipient is removed |
| `rewrap --rotate-key` | Regenerated | Updated | Re-encrypted | Content Key rotation |

---

## 6. kv-enc Protocol

### 6.0 Data Structure Overview

kv-enc is a line-based text format consisting of the following line types:

```
:SECRETENV_KV 3          ← version identifier (included in signed data)
:HEAD <token>             ← file metadata (sid, timestamps)
:WRAP <token>             ← HPKE wrap array of MK + removed_recipients
<KEY> <token>             ← encrypted entry (contains salt, nonce, ct)
:SIG <token>              ← Ed25519 signature
```

Each token is a JCS-canonicalized JSON object encoded in base64url.

**Structurally important security properties:**

1. **Signature coverage**: All lines except `:SIG` (`:SECRETENV_KV 3`, `:HEAD`, `:WRAP`, all KEY lines) are signed. Including the version line defends against version downgrade attacks.
2. **Separation of wrap and entries**: Unlike file-enc, wrap (`:WRAP` line) and encrypted entries (KEY lines) exist as independent lines. This means wrap regeneration is not required for partial updates via `set`.
3. **Entry self-containment**: Each entry token contains its own `salt`, `k` (KEY), `aead`, `nonce`, and `ct`. The `sid` is obtained from `:HEAD` and used for CEK derivation and AAD construction.
4. **canonical_bytes construction**: The signed data is the byte sequence of all lines concatenated with LF (0x0A) terminators. CRLF is normalized to LF. The field separator is space (0x20).

### 6.1 Design Rationale for Two-Layer Key Structure

kv-enc adopts a two-layer key structure of MK → CEK:

```
MK (1 per file) ─── HPKE wrap ──→ each recipient
  │
  ├── HKDF(MK, salt1, sid) ──→ CEK1 ──→ entry1 encryption
  ├── HKDF(MK, salt2, sid) ──→ CEK2 ──→ entry2 encryption
  └── HKDF(MK, saltN, sid) ──→ CEKN ──→ entryN encryption
```

**Why two layers:**
- When updating a specific entry with `set`, other entries do not need to be re-encrypted
- Partial decryption of a specific entry with `get` is possible
- There is no need to re-execute HPKE wrap for all recipients each time

### 6.1.1 Encryption/Decryption Flow Overview

**Encryption flow:**

```
1. MK generation      — 32 bytes, CSPRNG
2. HPKE wrap          — wrap MK with each recipient's public key (info = AAD)
3. For each entry:
   a. salt generation — 16 bytes, CSPRNG
   b. CEK derivation  — HKDF-SHA256(MK, salt, sid)
   c. AEAD encryption — encrypt VALUE with CEK using XChaCha20-Poly1305
4. Ed25519 signature  — sign canonical_bytes of all lines (see §8.3)
```

**Decryption flow:**

```
1. SIG line verification — immediate error on failure (decryption does not proceed)
2. Key lookup            — locate private key in keystore by kid
3. HPKE unwrap           — reconstruct info/AAD and recover MK
4. For each entry:
   a. CEK derivation    — HKDF-SHA256(MK, salt, sid)
   b. AAD construction  — jcs({"k", "p", "sid"})
   c. AEAD decryption   — decrypt ciphertext with CEK
```

As with file-enc (§5.5), **signature verification precedes decryption**.

### 6.2 CEK Derivation

```
salt_bytes = base64url_decode(entry.salt)   // 16 bytes

CEK = HKDF-SHA256(
    ikm    = MK,                            // 32 bytes
    salt   = salt_bytes,                    // 16 bytes
    info   = jcs({
        "p":   "secretenv:kv:cek@3",
        "sid": <HEAD.sid>
    }),
    length = 32
)
```

Including `sid` in info means that even if an entry is copied between different files, a different CEK is derived, causing decryption to fail.

### 6.3 Entry AAD

```
aad = jcs({
    "k":   <entry.k>,                      // dotenv KEY
    "p":   "secretenv:kv:payload@3",
    "sid": <HEAD.sid>
})
```

**Design decisions:**
- Include `k` → prevents entry swapping within the same file
- Include `sid` → double-binding with CEK derivation info (defence-in-depth)
- Do not include `salt` → already used as HKDF salt argument
- Do not include `recipients` → to allow wrap replacement while keeping payload fixed during rewrap

### 6.4 HPKE wrap (kv)

```
info_bytes = jcs({
    "kid": <wrap_item.kid>,
    "p":   "secretenv:kv:hpke-wrap@3",
    "sid": <HEAD.sid>
})

aad_bytes = info_bytes   // defence-in-depth: same policy as file-enc
```

As with file-enc (§5.3), the same bytes are used for HPKE info and AAD. This ensures binding at both the KDF stage and the AEAD stage in kv-enc wraps as well, achieving defence-in-depth.

### 6.5 Partial Decryption (get / set)

The kv-enc design allows operating on specific entries without decrypting all entries:

- **get**: SIG verification → MK unwrap → CEK derivation for specified KEY → decrypt only that entry
- **set**: SIG verification → MK unwrap → new salt generation → CEK derivation → VALUE encryption → entry addition/replacement → SIG regeneration

### 6.6 Behavior on Recipient Removal

When a recipient is removed from kv-enc:

1. Generate new MK
2. Re-encrypt all entries with CEK derived from the new MK
3. Record the removed member in `removed_recipients`
4. Attach `disclosed: true` to all entries
5. Update the WRAP line

The `disclosed` flag makes visible the entries that may have been disclosed to the removed recipient, supporting the decision to update secrets.

---

## 7. PrivateKey Protection

### 7.1 Passwordless Design via SSH Key Reuse

SecretEnv's PrivateKey (KEM private key + signing private key) is encrypted and protected using the user's existing SSH Ed25519 key. This eliminates the need for password management specific to SecretEnv.

What is protected here is the SecretEnv private key stored in the local keystore. The SSH key does not directly decrypt workspace secrets. Instead, it first unlocks the SecretEnv private key in the local keystore, and the recovered SecretEnv private key is then used for HPKE unwrap and Ed25519 signing.

### 7.1.1 Relationship Between the SSH Key and the SecretEnv Key Pair

- The SSH key is an **existing user-owned authentication key** outside SecretEnv
- The SecretEnv key pair is an **application-specific key pair** managed per `kid`
- On the PublicKey side, the SSH key appears in attestation, showing which SSH key is bound to the SecretEnv key pair
- On the PrivateKey side, the same SSH key protects the encrypted SecretEnv private key stored in the local keystore

Therefore, the SSH key and the SecretEnv key pair are not fused into a single key. One SSH key may protect multiple generations of SecretEnv keys, while the actual file-enc / kv-enc cryptographic operations are performed by the SecretEnv key pair after it has been decrypted.

### 7.1.2 What Is Stored in the local keystore

Each key-generation directory in the local keystore contains two files.

- `public.json`: a PublicKey document that can be distributed to the workspace
- `private.json`: an encrypted SecretEnv private key document

`private.json` itself has two layers.

- `protected`: header fields such as `member_id`, `kid`, `alg.fpr`, `alg.salt`, `created_at`, and `expires_at`; these define the decryption conditions and tamper-detection scope
- `encrypted`: the ciphertext containing the actual SecretEnv private key material

Here `alg.fpr` is only an identifier for the SSH key used to protect that key generation. It is not the SSH private key itself.

### 7.2 Key Derivation Pipeline

```mermaid
graph LR
    Msg["Sign message<br/>(kid + salt)"] -->|SSHSIG signing| SSHSign["SSH Ed25519 signature"]
    SSHKey["SSH private key<br/>(identified by alg.fpr)"] --> SSHSign
    SSHSign -->|"raw signature<br/>64 bytes"| IKM["IKM"]
    IKM --> HKDF["HKDF-SHA256"]
    Salt["alg.salt<br/>(16 bytes)"] --> HKDF
    HKDF -->|32 bytes| EncKey["enc_key"]
    EncKey --> AEAD["XChaCha20-Poly1305"]
    Plaintext["Private key material<br/>(keys JSON)"] --> AEAD
    AAD["AAD = jcs(protected)"] --> AEAD
    AEAD --> CT["encrypted.ct"]
```

### 7.3 Sign Message

```
secretenv:key-protection@3
{kid}
{hex(salt)}
```

Each line is separated by LF (`0x0A`). Since `member_id` is an arbitrary string, it is not used for cryptographic purposes; only `kid` (ULID) is used.

### 7.4 SSHSIG signed_data

SSH signatures conform to the SSHSIG format:

```
byte[6]      "SSHSIG"
SSH_STRING   namespace = "secretenv"
SSH_STRING   reserved = ""
SSH_STRING   hash_algorithm = "sha256"
SSH_STRING   SHA256(sign_message)
```

### 7.5 Encryption Key Derivation

```
enc_key = HKDF-SHA256(
    ikm    = ed25519_raw_signature_bytes,    // 64 bytes
    salt   = protected.alg.salt,             // 16 bytes
    info   = "secretenv:private-key-enc@3:{kid}",
    length = 32
)
```

This `enc_key` is not a stored fixed key. It is re-derived from the same SSH signing capability during both encryption and decryption.

### 7.6 Determinism Check

Ed25519 (RFC 8032 PureEdDSA) generates deterministic signatures by specification, but to eliminate the possibility of non-deterministic signatures due to implementation defects, on each encryption and decryption:

1. Execute **2 signatures** with the SSH key on the same signed_data
2. Confirm that the extracted Ed25519 raw signature bytes (64 bytes) match
3. If they do not match, output `W_SSH_NONDETERMINISTIC` and abort processing

**Reason:** Non-deterministic signatures would derive different IKM at encryption and decryption time, making **decryption impossible**.

### 7.6.1 Conditions for Successful Decryption

To decrypt `private.json` in the local keystore, all of the following conditions must hold.

1. The SSH key corresponding to `protected.alg.fpr` must be usable
2. That SSH key must produce deterministic signatures for identical input
3. The sign message must be reconstructible from `protected.alg.salt` and `kid`
4. `protected` must be untampered so that AAD verification over `jcs(protected)` succeeds

Conversely, an attacker does not necessarily need to steal the SSH private key file itself; any actor with equivalent signing capability can derive `enc_key`.

### 7.7 AAD

```
aad = jcs(protected)
```

Using the JCS-canonicalized bytes of the entire `protected` object as AAD means that `format`, `member_id`, `kid`, `alg`, `created_at`, and `expires_at` are all subject to tamper detection. Notably, including `expires_at` in AAD detects tampering with the expiration date.

### 7.7.1 How to Read the Decryption Flow

The high-level local keystore protection flow is:

1. Load `private.json`
2. Read `kid`, `salt`, and the SSH key fingerprint from `protected`
3. Rebuild the sign message from `kid + salt`
4. Ask the SSH key to sign and extract raw Ed25519 signature bytes as IKM
5. Derive `enc_key` via HKDF
6. Decrypt the ciphertext using `jcs(protected)` as AAD

This means the SSH key is both an authentication mechanism for local keystore access and, in practice, the source of decryption capability.

### 7.8 Trust Assumptions

Since PrivateKey protection derives IKM from SSH signatures, **any entity that can execute `sign_for_ikm` can derive the encryption key and decrypt the PrivateKey**. This equivalence is an intentional design decision, but the following is stated to clarify trust boundaries.

| Entity | Can decrypt | Notes |
|--------|------------|-------|
| Local user (direct file access) | **Yes** | Normal use |
| ssh-agent (local) | **Yes** | Can issue signing requests if key is loaded |
| ssh-agent forwarding | **Yes** | Can issue signing requests from remote host. Weakens protection. |
| Local malware | **Yes** | If it can access key files or agent socket |
| CI/CD environment | **Yes** | If SSH key is deployed. Dedicated key recommended. |
| Hardware token (FIDO2) | **No** | Ed25519-SK uses non-deterministic signatures, so IKM derivation is impossible. Detected by §7.6 determinism check. |

**Note on ssh-agent forwarding**: In environments with agent forwarding enabled, processes on the remote host can send signing requests to the local ssh-agent. This allows administrators or malware on the remote host to decrypt the PrivateKey. Disabling agent forwarding is recommended in environments using SecretEnv.

**Clarifying design intent**: The equivalence between SSH signing capability and PrivateKey decryption capability is an intentional design decision. SecretEnv uses the existing SSH authentication infrastructure as a trust anchor for cryptographic key protection, eliminating the need for additional password or master key management. This tradeoff means that the SSH key's protection level becomes the upper bound of SecretEnv's secret protection level. Therefore, proper SSH key management (setting passphrases, restricting agent forwarding, considering hardware token use) is essential to SecretEnv's security.

Operationally, local keystore file permissions and SSH key handling must not be treated as separate concerns. Even if `private.json` has safe filesystem permissions, any actor on the same host that can freely use the SSH key or agent socket can ultimately decrypt the SecretEnv private key as well.

### 7.9 Password-Based Key Protection (`argon2id-hkdf-sha256`)

As an alternative to SSH-based protection, SecretEnv supports password-based private key protection using `argon2id-hkdf-sha256`. This scheme is designed for CI/CD environments where SSH keys and `ssh-agent` are unavailable.

#### 7.9.1 Use Case

CI platforms provide "secret variables" that are stored securely and exposed as environment variables at runtime. This protection scheme enables exporting a SecretEnv private key in a portable, password-protected format that can be registered as a CI secret variable and used without any SSH infrastructure.

#### 7.9.2 Key Derivation Pipeline

```
Password + salt (16 bytes, random) → Argon2id (m=47104, t=1, p=1) → 32-byte IKM
IKM + salt → HKDF-SHA256 (info: "secretenv:password-private-key-enc@3:{kid}") → 32-byte encryption key
```

The salt is intentionally reused for both Argon2id and HKDF steps. This is safe because the two algorithms have different internal structures and the salt serves different roles in each (Argon2id uses it as a salt parameter, HKDF uses it as the salt input to HKDF-Extract).

The HKDF info string (`secretenv:password-private-key-enc@3:{kid}`) differs from the SSH-based scheme (`secretenv:private-key-enc@3:{kid}`) to ensure domain separation between the two key derivation paths.

#### 7.9.3 Argon2id Parameters and Password Requirements

- Default parameters at export time: m=47104 (46 MiB), t=1, p=1 (OWASP recommended)
- Parameters are recorded in the `alg` object of the private key document and read from it at decryption time (not hardcoded)
- Minimum parameter validation at decryption: m >= 19456 (19 MiB), t >= 1, p >= 1 (reject trivially weak parameters)
- Minimum password length: 8 characters
- Future parameter changes are forward-compatible: existing keys retain their recorded parameters

#### 7.9.4 Security Trade-offs in CI Environments

Environment variables (`SECRETENV_KEY_PASSWORD`) persist in process memory and may be visible via `/proc/*/environ` on Linux. This is an accepted trade-off consistent with how CI platforms handle secret variables. The password and decrypted key material are zeroized after use where the Rust type system permits (using the `zeroize` crate).

#### 7.9.5 Public Key Verification in Environment Variable Mode

In environment variable mode, the local keystore is not available. Public keys (including the signer's own) are resolved from the workspace's `members/active/` directory instead.

To verify the signer's own public key from the workspace:

1. Look up `members/active/<member_id>.json` (where `member_id` is from the environment variable key's `protected.member_id`)
2. Verify `identity.keys.sig.x` matches the Ed25519 public key from the decrypted private key plaintext
3. Verify `identity.keys.kem.x` matches the X25519 public key from the decrypted private key plaintext (trustworthy because it is protected by AAD-bound authenticated encryption)
4. Verify the PublicKey document's self-signature using the Ed25519 public key
5. Standard attestation verification also applies

This provides equivalent trust guarantees to the local keystore path, since the private key's authenticity is established by successful authenticated decryption, and the public key's correspondence is verified by component matching.

---

## 8. Signature and Verification Architecture

### 8.0 signature_v3 Common Format

Both file-enc and kv-enc use a common signature structure called `signature_v3`. This structure has the following security properties:

- **Self-contained verification**: The signer's PublicKey (`signer_pub`) can optionally be embedded within the signature. This allows signature verification and signer identification to complete without referencing an external keystore.
- **Explicit key generation**: Containing `kid` (key generation ID) makes it clear which generation of key was used for signing.
- **Ed25519 raw signature**: The signature value is base64url-encoded Ed25519 raw signature bytes (64 bytes) — a fixed length of 86 characters.

When the signature token contains `signer_pub`, it can also chain-verify the PublicKey's self-signature and SSH attestation, forming an offline trust chain.

### 8.1 Comparison of Signing Methods

| Item | file-enc | kv-enc |
|------|----------|--------|
| Signed data | `jcs(protected)` | canonical_bytes (concatenation of text lines) |
| Format | `signature` field in JSON | `:SIG` line (last line) |
| Tamper detection scope | Entire `protected` (sid, wrap, payload, timestamps) | HEAD / WRAP / all entry lines |
| Signature algorithm | `eddsa-ed25519` (PureEdDSA) | `eddsa-ed25519` (PureEdDSA) |
| Signature format | `signature_v3` format | `signature_v3` format |

### 8.2 file-enc Signature

```
canonical_bytes = jcs(protected)
signature = ed25519_sign(sig_priv, canonical_bytes)
```

- The `protected` object is JCS-canonicalized and signed directly (RFC 8032 PureEdDSA)
- `wrap`, `payload`, and `removed_recipients` are all contained within `protected` and therefore protected by the signature
- The `signature` field is not included in the signed data

### 8.3 kv-enc Signature

canonical_bytes construction procedure:

1. Normalize line endings in the input file to LF (0x0A) (CRLF → LF)
2. Concatenate in order all lines including the first line `:SECRETENV_KV 3` except the `:SIG` line
3. Append **line terminator** LF (0x0A) to the end of each line
4. The **field separator** within each line is space (0x20) (not tab)

Concrete byte-level example:
```
:SECRETENV_KV 3\n      ← line terminator: LF (0x0A)
:HEAD <token>\n         ← field separator: space (0x20), line terminator: LF
:WRAP <token>\n         ← field separator: space (0x20), line terminator: LF
DATABASE_URL <token>\n  ← field separator: space (0x20), line terminator: LF
```

**Distinction**: The LF in step 3 is a **line terminator**, while the space in step 4 is a **field separator** between the line header and the token. These serve different roles.

```
canonical_bytes = concat_lines_with_lf(all_lines_except_SIG)
signature = ed25519_sign(sig_priv, canonical_bytes)
```

### 8.4 PublicKey Self-Signature

A PublicKey has a self-signature over its `protected` object:

```
canonical_bytes = jcs(protected)
signature = ed25519_sign(identity.keys.sig private key, canonical_bytes)
```

This shows that "the holder of the corresponding private key created this PublicKey."

### 8.5 SSH Attestation

SSH key attestation over the `identity.keys` of a PublicKey:

1. JCS-canonicalize `identity.keys`
2. Compute SHA256 of the canonicalized bytes
3. Sign with the SSH key (namespace: `secretenv`)
4. Extract Ed25519 raw signature bytes (64 bytes) and store

This allows offline verification of the binding between the SecretEnv key pair and the SSH key.

### 8.6 Online Verification (GitHub)

When `binding_claims.github_account` exists, the fingerprint of `attestation.pub` is cross-checked against the public keys obtained from the GitHub API. This confirms that the SSH key is registered to the claimed GitHub account.

---

## 9. Context Binding Design (Defence-in-Depth)

This chapter explains the binding model used in SecretEnv's security design.

### 9.1 System of Binding Elements

| Binding element | Description | Attack it defends against |
|----------------|-------------|--------------------------|
| `sid` | File identifier (UUID) | Swapping ciphertext components between different files |
| `kid` | Key generation ID (ULID) | Reusing wraps across different key generations |
| `k` | dotenv KEY | Swapping entries within the same kv-enc file |
| `p` | Protocol identifier | Reusing data across different protocols |

### 9.2 Rationale for Double-Binding

Why `sid` is included in both info and AAD:

**For kv-enc:**
- Including `sid` in CEK derivation info → `sid` affects CEK at the HKDF stage
- Also including `sid` in payload AAD → `sid` is also verified at the AEAD stage

While info alone is cryptographically sufficient, also including it in AAD provides:
1. **Implementation bug resilience**: If CEK is derived with the wrong `sid`, AEAD verification will fail
2. **Safety net for future changes**: Detection layer for changes to CEK derivation logic
3. **Miswiring detection**: Early detection when the wrong file's `sid` is mistakenly applied

### 9.3 HPKE info = AAD Design

In file-enc wrap, the same bytes are used for HPKE info and AAD:

```
info_bytes = jcs({"kid": ..., "p": "secretenv:file:hpke-wrap@3", "sid": ...})
aad_bytes  = info_bytes
```

This applies the same binding at both the KDF stage and the AEAD stage, so a bypass of one stage is detected by the other.

### 9.4 Design Decision to Exclude recipients from Payload AAD

Recipients (the list of rids in the wrap array) are **not** included in payload AAD.

**Reason:** To allow replacing only wraps while keeping payload fixed during `rewrap`. If recipients were included in AAD, the entire payload would need to be re-encrypted every time a recipient changes.

Recipient integrity is protected by **Ed25519 signatures** (wraps are contained within `protected`, which is the signed data).

### 9.5 Binding Matrix (Most Important Table)

| Binding element | Protocol | HPKE info | HPKE AAD | CEK info | payload AAD | Signature | Attack defended against |
|----------------|----------|-----------|----------|----------|-------------|-----------|------------------------|
| `sid` | file-enc wrap | **included** | **= info** | — | — | **included** | Reusing wraps across different files |
| `sid` | file-enc payload | — | — | — | **included** | **included** | Swapping payload between different files |
| `sid` | kv-enc wrap | **included** | **= info** | — | — | **included** | Reusing wraps across different files |
| `sid` | kv-enc CEK derivation | — | — | **included** | — | — | Copying entries between different files |
| `sid` | kv-enc payload | — | — | — | **included** | **included** | Defence-in-depth (duplication with CEK info) |
| `kid` | file-enc wrap | **included** | **= info** | — | — | **included** | Reusing old-generation wraps |
| `kid` | kv-enc wrap | **included** | **= info** | — | — | **included** | Reusing old-generation wraps |
| `k` | kv-enc payload | — | — | — | **included** | **included** | Swapping entries within the same file |
| `p` | all protocols | **included** | **included** | **included** | **included** | — | Reusing data across different protocols |

**Note on the HPKE AAD column** — For both file-enc and kv-enc, HPKE AAD = HPKE info (same bytes). This applies the same binding at both the KDF stage and the AEAD stage (see §9.3).

---

## 10. Attack Scenario Analysis

### 10.1 Repository Tampering

| Item | Content |
|------|---------|
| **Attack** | Attacker tampers with encrypted files in `.secretenv/secrets/` |
| **Capability** | Write access to the repository |
| **Defense** | Ed25519 signature verification detects tampering with `protected` (file-enc) or the entire file (kv-enc) |
| **Result** | Decryption refused with `E_SIGNATURE_INVALID` |

### 10.2 Public Key Substitution

**10.2.1 Tampering with an existing PublicKey**

| Item | Content |
|------|---------|
| **Attack** | Attacker tampers with fields in `members/active/<id>.json` |
| **Capability** | Write access to the repository |
| **Defense** | (1) Self-signature verification — a forged key cannot generate a valid signature over the original `protected`. (2) SSH attestation verification — attestation with the original SSH key cannot be forged. |
| **Result** | Refused with `E_SELF_SIG_INVALID` or `E_ATTESTATION_INVALID` |

**10.2.2 Attacker inserting a new key**

| Item | Content |
|------|---------|
| **Attack** | Attacker creates their own SecretEnv key + SSH key and places it in `members/incoming/` |
| **Capability** | Write access to the repository + their own SSH Ed25519 key |
| **Self-signature / attestation** | The attacker can generate valid self-signature and attestation with their own keys. These verifications will succeed. |
| **Defense** | (1) TOFU confirmation — the user running `rewrap` visually verifies the SSH fingerprint and GitHub account, and rejects suspicious keys. (2) Online verification — the SSH key linked to the attacker's GitHub account is displayed, enabling detection of impersonation. |
| **Result** | Rejected by TOFU confirmation (if the user makes the correct judgment). When `--force` is used, this defense is disabled, creating a risk that ciphertext with untrusted keys is accepted. |

**Important**: Self-signature prevents tampering with existing PublicKeys, but cannot prevent an attacker from creating a new PublicKey following legitimate procedures with their own key. The final defense against new key insertion is TOFU confirmation (§2.5, Layer 3). Skipping TOFU with `--force` intentionally disables this defense, and its use requires careful consideration.

### 10.3 Payload Swapping (Between Different Secrets)

| Item | Content |
|------|---------|
| **Attack** | Attacker copies the payload of file-enc A into file-enc B |
| **Capability** | Write access to the repository |
| **Defense** | (1) `sid` is included in payload AAD, so `sid` mismatch causes AEAD decryption failure. (2) Signature verification detects tampering with `protected` (including `sid` modification). |
| **Result** | AEAD decryption failure or signature verification failure |

### 10.4 Entry Swapping (Within the Same kv-enc)

| Item | Content |
|------|---------|
| **Attack** | Attacker copies the ciphertext of entry A in a kv-enc to entry B in the same file |
| **Capability** | Write access to the repository |
| **Defense** | (1) AAD contains `k` (KEY), so `k` mismatch causes AEAD decryption failure. (2) Signature verification detects line swapping. |
| **Result** | AEAD decryption failure or signature verification failure |

### 10.5 Reusing Old Wraps

| Item | Content |
|------|---------|
| **Attack** | Attacker copies an old-generation wrap_item into a new encrypted file |
| **Capability** | Access to old encrypted files |
| **Defense** | HPKE info contains `kid`, so key generation mismatch causes unwrap failure |
| **Result** | HPKE unwrap failure |

### 10.6 PrivateKey Metadata Tampering

| Item | Content |
|------|---------|
| **Attack** | Attacker tampers with a field in PrivateKey's `protected` (e.g., `expires_at`) |
| **Capability** | Access to the local filesystem |
| **Defense** | AAD is constructed from `jcs(protected)`, so any field change in `protected` causes AEAD decryption failure |
| **Result** | XChaCha20-Poly1305 decryption failure |

### 10.7 Entry Copying Between kv-enc Files

| Item | Content |
|------|---------|
| **Attack** | Attacker copies an entry from kv-enc file A into kv-enc file B |
| **Capability** | Write access to the repository |
| **Defense** | (1) MK differs between files, so CEK derivation differs due to MK mismatch, causing decryption failure. (2) CEK derivation info contains `sid`, so even with the same MK, a different CEK is derived. (3) AAD also contains `sid`, causing AEAD decryption failure as well (defence-in-depth). |
| **Result** | AEAD decryption failure due to CEK mismatch |

---

## 11. Implementation Security Requirements

### 11.1 Memory Safety (Zeroizing)

| Target | Requirement | Implementation |
|--------|------------|---------------|
| KEM private key | Zeroize after use (MUST) | `Zeroizing<[u8; 32]>` |
| Signing private key | Zeroize after use (MUST) | `Zeroizing` wrapper |
| DEK / MK / CEK | Zeroize after use (MUST) | `Zeroizing` wrapper / `Cek::new` |
| Decrypted plaintext | Zeroize after use (SHOULD) | `Zeroizing<Plaintext>` |

As a representative implementation technique, secret keys and decrypted plaintext are erased on scope exit by zeroizing wrappers.

### 11.2 DoS Limits

| Target | Limit | Purpose |
|--------|-------|---------|
| Elements in wrap array | 1,000 entries | Prevent memory exhaustion |
| kv-enc file size | 16 MiB | Prevent memory exhaustion |
| kv-enc KEY lines | 10,000 lines | Prevent computational explosion |
| base64url token length | 1 MiB | Limit parse time |
| base64url ciphertext length | 16 MiB | Prevent memory exhaustion |
| JSON parse depth | 32 levels | Prevent computational explosion |
| JSON element count | 10,000 elements | Prevent computational explosion |

### 11.3 Strict base64url Validation

- Reject invalid characters (anything other than `A-Za-z0-9_-`)
- Reject padding (`=`)
- Reject whitespace and newlines
- Validate fixed-length fields:

| Field | base64url string length | Decoded byte length |
|-------|------------------------|---------------------|
| `attestation.sig` | 86 characters | 64 bytes |
| `signature_v3.sig` | 86 characters | 64 bytes |
| XChaCha20-Poly1305 `nonce` | 32 characters | 24 bytes |
| kv-enc entry `salt` | 22 characters | 16 bytes |

### 11.4 Processing Order

Decryption processing must strictly follow this order:

```
1. Format validation (schema conformance)
2. Signature verification (tamper detection)
3. Referential integrity check (warning only)
4. Decryption processing (only after successful signature verification)
```

Executing decryption while bypassing signature verification is prohibited (MUST NOT).

### 11.5 Libraries Used (Rust crates)

| Purpose | Crate | Notes |
|---------|-------|-------|
| HPKE | `hpke` | X25519-HKDF-SHA256 + ChaCha20-Poly1305 |
| XChaCha20-Poly1305 | `chacha20poly1305` | AEAD |
| Ed25519 | `ed25519-dalek` | Signing and verification |
| HKDF | `hkdf` + `sha2` | Key derivation |
| Zeroizing | `zeroize` | Memory zeroization |
| CSPRNG | `rand` (`OsRng`) | Cryptographic random numbers |
| base64url | `base64` (`URL_SAFE_NO_PAD`) | Encoding and decoding |

---

## 12. Limitations and Non-Goals

### 12.1 Scope of Forward Secrecy

HPKE Base mode provides ephemeral key isolation per wrap via ephemeral keys. However:
- If a recipient's long-term private key is compromised, **all existing wraps** for that recipient can be unwrapped
- Running `rewrap --rotate-key` to regenerate the Content Key after compromise can prevent damage from spreading to newly encrypted data going forward

**Note:** This is different from conventional Forward Secrecy (the property that past sessions cannot be decrypted after a session ends). SecretEnv's `--rotate-key` is a **damage limitation measure** after key compromise and does not retroactively strengthen the protection of data encrypted before the compromise.

### 12.2 Irrecoverability of Past Disclosures

Even if a recipient is removed, content that was previously decryptable is cryptographically irrecoverable. The `removed_recipients` and `disclosed` flags track disclosure history to support operational decisions about updating secrets.

### 12.3 Insider Misuse

It is not possible to prevent a workspace member who has legitimately decrypted content from misusing it. Access control is outside the scope of SecretEnv and must be implemented in a separate system.

### 12.4 Policy-Less Design

SecretEnv does not provide a central policy defining "who should have which secrets." Recipients are derived from the encrypted file itself (the wrap array), and it is assumed that each member manages them appropriately.

### 12.5 No Compression

Compression before encryption is not performed. This is an intentional design decision to avoid compression oracle attacks (in the class of CRIME/BREACH).

---

## 13. References and RFC List

| Specification | Purpose |
|--------------|---------|
| RFC 9180 — Hybrid Public Key Encryption | HPKE (wrap/unwrap) |
| RFC 8439 — ChaCha20 and Poly1305 | HPKE internal AEAD |
| RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA) | Ed25519 signature (PureEdDSA) |
| RFC 8037 — CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JOSE | JWK OKP key representation |
| RFC 7517 — JSON Web Key (JWK) | Key representation format |
| RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function (HKDF) | Key derivation |
| RFC 8785 — JSON Canonicalization Scheme (JCS) | Deterministic JSON canonicalization |
| RFC 4648 — The Base16, Base32, and Base64 Data Encodings | base64url encoding |
| RFC 2119 — Key words for use in RFCs to Indicate Requirement Levels | Requirement level keywords |
| OpenSSH PROTOCOL.sshsig | SSHSIG signature format |
| IANA HPKE Registry | HPKE suite ID |

---

## Appendix

### Appendix A: Complete Cryptographic Parameter Table

| Parameter | Value | Purpose |
|-----------|-------|---------|
| HPKE suite | `hpke-32-1-3` | wrap algorithm identifier |
| kem_id | 32 (0x0020) DHKEM(X25519, HKDF-SHA256) | KEM |
| kdf_id | 1 (0x0001) HKDF-SHA256 | HPKE internal KDF |
| aead_id | 3 (0x0003) ChaCha20-Poly1305 | HPKE internal AEAD |
| payload AEAD | `xchacha20-poly1305` | payload / entry encryption |
| payload nonce | 24 bytes | XChaCha20-Poly1305 nonce |
| payload key | 32 bytes | DEK / CEK |
| signature alg | `eddsa-ed25519` | signature algorithm |
| signature size | 64 bytes | Ed25519 raw signature |
| HKDF output | 32 bytes | CEK / enc_key |
| salt (kv-enc entry) | 16 bytes | CEK derivation |
| salt (PrivateKey) | 16 bytes | enc_key derivation |
| AEAD tag | 16 bytes | Poly1305 authentication tag |
| X25519 public key | 32 bytes | KEM public key |
| X25519 secret key | 32 bytes | KEM private key |
| Ed25519 public key | 32 bytes | signing public key |
| Ed25519 secret key | 32 bytes | signing private key |
| PrivateKey KDF | `sshsig-ed25519-hkdf-sha256` | key derivation method identifier |

### Appendix B: info/AAD Byte Construction Procedure and Examples

#### B.1 file-enc HPKE info

```
Input:
  sid = "550e8400-e29b-41d4-a716-446655440000"
  kid = "01HY0G8N3P5X7QRSTV0WXYZ123"

Construction:
  json = {"kid":"01HY0G8N3P5X7QRSTV0WXYZ123","p":"secretenv:file:hpke-wrap@3","sid":"550e8400-e29b-41d4-a716-446655440000"}
  info_bytes = jcs(json)
  aad_bytes = info_bytes

Constant: context::HPKE_WRAP_FILE_V3 = "secretenv:file:hpke-wrap@3"
```

#### B.2 kv-enc HPKE info

```
Input:
  sid = "550e8400-e29b-41d4-a716-446655440000"
  kid = "01HY0G8N3P5X7QRSTV0WXYZ123"

Construction:
  json = {"kid":"01HY0G8N3P5X7QRSTV0WXYZ123","p":"secretenv:kv:hpke-wrap@3","sid":"550e8400-e29b-41d4-a716-446655440000"}
  info_bytes = jcs(json)

Constant: context::HPKE_WRAP_KV_FILE_V3 = "secretenv:kv:hpke-wrap@3"
```

#### B.3 kv-enc CEK derivation info

```
Input:
  sid = "550e8400-e29b-41d4-a716-446655440000"

Construction:
  json = {"p":"secretenv:kv:cek@3","sid":"550e8400-e29b-41d4-a716-446655440000"}
  info_bytes = jcs(json)

Constant: context::KV_CEK_INFO_PREFIX_V3 = "secretenv:kv:cek@3"
```

#### B.4 kv-enc payload AAD

```
Input:
  sid = "550e8400-e29b-41d4-a716-446655440000"
  k   = "DATABASE_URL"

Construction:
  json = {"k":"DATABASE_URL","p":"secretenv:kv:payload@3","sid":"550e8400-e29b-41d4-a716-446655440000"}
  aad_bytes = jcs(json)

Constant: context::PAYLOAD_KV_V3 = "secretenv:kv:payload@3"
```

#### B.5 file-enc payload AAD

```
Input:
  payload.protected = {
    "format": "secretenv.file.payload@3",
    "sid": "550e8400-e29b-41d4-a716-446655440000",
    "alg": { "aead": "xchacha20-poly1305" }
  }

Construction:
  aad_bytes = jcs(payload.protected)
```

#### B.6 PrivateKey AAD

```
Input:
  protected = {
    "format": "secretenv.private.key@3",
    "member_id": "alice@example.com",
    "kid": "01HY0G8N3P5X7QRSTV0WXYZ123",
    "alg": {
      "kdf": "sshsig-ed25519-hkdf-sha256",
      "fpr": "sha256:...",
      "salt": "...",
      "aead": "xchacha20-poly1305"
    },
    "created_at": "2026-01-14T00:00:00Z",
    "expires_at": "2027-01-14T00:00:00Z"
  }

Construction:
  aad_bytes = jcs(protected)
```

#### B.7 PrivateKey protection enc_key derivation

```
Input:
  kid  = "01HY0G8N3P5X7QRSTV0WXYZ123"
  salt = a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 (hex, 16 bytes)

Sign message:
  "secretenv:key-protection@3\n01HY0G8N3P5X7QRSTV0WXYZ123\na1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"

IKM:
  ed25519_raw_signature_bytes (64 bytes)

enc_key:
  HKDF-SHA256(
    ikm  = IKM,
    salt = salt,
    info = "secretenv:private-key-enc@3:01HY0G8N3P5X7QRSTV0WXYZ123",
    length = 32
  )

Constant: context::SSH_KEY_PROTECTION_SIGN_MESSAGE_PREFIX_V3 = "secretenv:key-protection@3"
Constant: context::SSH_PRIVATE_KEY_ENC_INFO_PREFIX_V3 = "secretenv:private-key-enc@3"
```

### Appendix C: Overall Key Relationship Diagram

```mermaid
graph TB
    subgraph user["User"]
        SSH["SSH Ed25519 key"]
    end

    subgraph secretenv_keys["SecretEnv key pair (kid: ULID)"]
        KEM_PK["X25519 public key"]
        KEM_SK["X25519 private key"]
        SIG_PK["Ed25519 public key"]
        SIG_SK["Ed25519 private key"]
    end

    subgraph public_key["PublicKey (workspace)"]
        PK_DOC["secretenv.public.key@3<br/>self-signature + SSH attestation"]
    end

    subgraph private_key["PrivateKey (local keystore)"]
        PK_ENC["secretenv.private.key@3<br/>SSH signature-based encryption"]
    end

    subgraph file_enc["file-enc"]
        DEK["DEK (32 bytes)"]
        FILE_WRAP["wrap (HPKE)"]
        FILE_PAYLOAD["payload (XChaCha20-Poly1305)"]
        FILE_SIG["signature (Ed25519)"]
    end

    subgraph kv_enc["kv-enc"]
        MK["MK (32 bytes)"]
        KV_WRAP["WRAP line (HPKE)"]
        CEK["CEK (HKDF-derived)"]
        ENTRY["entry (XChaCha20-Poly1305)"]
        KV_SIG["SIG line (Ed25519)"]
    end

    SSH -->|attestation| PK_DOC
    SSH -->|IKM derivation| PK_ENC
    KEM_PK --> PK_DOC
    SIG_PK --> PK_DOC
    KEM_SK --> PK_ENC
    SIG_SK --> PK_ENC

    KEM_PK -->|HPKE Encaps| FILE_WRAP
    KEM_PK -->|HPKE Encaps| KV_WRAP
    DEK --> FILE_WRAP
    DEK --> FILE_PAYLOAD
    SIG_SK --> FILE_SIG

    MK --> KV_WRAP
    MK -->|HKDF| CEK
    CEK --> ENTRY
    SIG_SK --> KV_SIG

    style SSH fill:#FFB6C1
    style DEK fill:#FFE4B5
    style MK fill:#FFE4B5
    style CEK fill:#90EE90
```
