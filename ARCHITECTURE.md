# Kista Architecture Document

**Architect:** Rúnhild Svartdóttir  
**Date:** 2026-05-09  
**Version:** 1.0.0-review  
**Status:** PRE-PRODUCTION REVIEW — issues identified, see code review

---

## 1. Charter

A self-sovereign, encrypted credential vault for a single user. No external password managers, no cloud sync, no network calls. The user owns their key, owns their data, and can operate the tool on Linux, macOS, and Windows without modification.

## 2. Domain Boundaries

 credstore operates inside **four domains**. Each domain owns its own concern and must not leak into another.

### Domain 1 — Cryptography (Crypto Layer)

**Owning concern:** Key generation, encryption, decryption, key storage, key integrity.

| Boundary | In Scope | Out of Scope |
|---|---|---|
| Key lifecycle | Generate Fernet key, persist to disk, read from disk, verify integrity | Key rotation (not yet implemented), key derivation from passphrase, multi-key support |
| Encryption | Encrypt bytes → ciphertext, Decrypt ciphertext → bytes | Algorithm selection, envelope encryption, re-encryption |
| Key file security | Set `0o600` on key file, verify readability | Full disk audit, SELinux/AppArmor enforcement |

**Interface contracts:**

```
gen_key() -> str
    Returns: URL-safe base64 Fernet key string.
    Side effects: None.

get_key() -> bytes
    Returns: Raw key bytes read from VAULT_KEY.
    Side effects: MAY create VAULT_KEY if missing.
    Raises: PermissionError if VAULT_KEY unreadable.
    
encrypt(data: bytes, key: bytes) -> bytes
    Returns: Fernet-encrypted ciphertext.
    Pre: len(data) > 0, len(key) == 44 (base64 Fernet key)
    
decrypt(data: bytes, key: bytes) -> bytes
    Returns: Decrypted plaintext bytes.
    Raises: cryptography.fernet.InvalidToken on tampered/corrupted data.
```

### Domain 2 — Persistence (Vault Layer)

**Owning concern:** Vault file I/O, serialization, atomic writes, backup/restore, metadata.

| Boundary | In Scope | Out of Scope |
|---|---|---|
| Vault file management | Read, write, verify vault.json.enc; vault_meta.json indexing | Git-backed version history, cloud replication |
| Atomicity | Write-then-rename to prevent torn writes | Transactions, locking |
| Backup | Export encrypted vault file, import and merge | Incremental backups, differential backups |
| Metadata | Unencrypted index of service names and timestamps | Full metadata encryption, attestation |

**Interface contracts:**

```
load_vault(key: bytes) -> dict
    Returns: {"version": int, "entries": {str: Entry}, "created": ISO8601, "updated": ISO8601}
    Side effects: MAY create empty vault dict if VAULT_FILE missing.
    Raises: InvalidToken on wrong key / corruption.
             JSONDecodeError on malformed plaintext.
             
save_vault(vault: dict, key: bytes) -> None
    Side effects: Writes VAULT_FILE (encrypted) and VAULT_META (plaintext index).
    Atomicity: CURRENTLY NOT ATOMIC — identified bug, see review.
    Raises: PermissionError, OSError on disk failure.
```

### Domain 3 — Commands (CLI Layer)

**Owning concern:** Argument parsing, user interaction, output formatting, exit codes.

| Boundary | In Scope | Out of Scope |
|---|---|---|
| CLI parsing | argparse subcommands, flags, positional args | Shell completion, interactive mode, REPL |
| Exit codes | 0 = success, 1 = error (currently implicit via sys.exit(1)) | Structured exit codes for different error types |
| Output | Human-readable terminal output | JSON output mode, machine-readable format, piping |
| Input | CLI args only (no stdin password reading) | Interactive password prompting, piped input |

**Interface contracts:**

```
cmd_init(args) -> None     ; exit 0 on success or exists
cmd_add(args) -> None      ; exit 1 on duplicate without --force
cmd_get(args) -> None      ; exit 1 if not found
cmd_list(args) -> None     ; exit 0, filtered by --tags
cmd_update(args) -> None   ; exit 1 if not found; no-op if no fields given
cmd_remove(args) -> None   ; exit 1 if not found
cmd_check(args) -> None    ; exit 0 always (prints status)
cmd_status(args) -> None   ; exit 0
cmd_export(args) -> None   ; exit 1 if no vault exists
cmd_import(args) -> None   ; exit 1 on decrypt failure or file not found
```

### Domain 4 — Entry Model (Data Layer)

**Owning concern:** The shape and validation of a credential entry.

**Current schema (implicit, no validation):**

```json
{
  "service": "str — lowercase key, required",
  "username": "str — optional",
  "password": "str — optional",
  "email": "str — optional",
  "url": "str — optional",
  "notes": "str — optional",
  "tags": ["str"] — optional, comma-separated input",
  "created": "ISO8601 — auto-set on add",
  "updated": "ISO8601 — auto-set on add/update"
}
```

**Missing from schema (see review):**
- `password_expires` — rotation tracking
- `password_strength` — audit metric
- `last_rotated` — when password was last changed
- `rotation_days` — how often to rotate (per-entry policy)
- `verification_status` — email verified, 2FA enabled, etc.

---

## 3. Data Flow

### 3.1 Read Path (cmd_get, cmd_list, cmd_check, cmd_status)

```
CLI args → argparse → cmd_*(args)
                         │
                         ▼
                    _get_key()
                         │
                         ▼
              read VAULT_KEY from disk
                         │
                         ▼
                    _load_vault(key)
                         │
                   ┌─────┴─────┐
                   │           │
             VAULT_FILE      (empty dict
             exists?          if missing)
                   │           │
                   ▼           │
            read_bytes()      │
                   │           │
                   ▼           │
          Fernet.decrypt()    │
                   │           │
                   ▼           │
           json.loads()       │
                   │           │
                   └─────┬─────┘
                         │
                         ▼
                    vault dict
                         │
                         ▼
                  format & print
```

### 3.2 Write Path (cmd_add, cmd_update, cmd_remove, cmd_import)

```
CLI args → argparse → cmd_*(args)
                         │
                         ▼
                   _get_key()
                         │
                         ▼
                   _load_vault(key)
                         │
                         ▼
                   mutate vault dict
                         │
                         ▼
                   _save_vault(vault, key)
                         │
                    ┌────┴────┐
                    │         │
             json.dumps()   vault["updated"] = now
                    │         │
                    ▼         │
           Fernet.encrypt()   │
                    │         │
                    ▼         │
          VAULT_FILE          │
          .write_bytes()      │
                    │         │
                    ▼         │
          VAULT_META          │
          .write_text()       │
                    │         │
                    ▼         ▼
                  success / raise
```

### 3.3 Export/Import Flow

```
EXPORT:  VAULT_FILE ──copy2──► destination (no re-encryption)

IMPORT:  source file ──read──► _decrypt(src_bytes, current_key)
                                      │
                              ┌───────┴───────┐
                              │               │
                          success          InvalidToken
                              │               │
                              ▼               ▼
                     json.loads()      "different key" error
                              │
                              ▼
                     merge into current vault
                              │
                              ▼
                     _save_vault()
```

---

## 4. File Layout

```
~/.hermes/credentials/
├── .vault_key          # Fernet key, chmod 600 (MUST be 600)
├── vault.json.enc      # Encrypted vault, chmod 600
└── vault_meta.json     # Plaintext index (service names + timestamps only)
```

**Invariant:** `.vault_key` and `vault.json.enc` MUST be mode 600/400 (owner-read-write only). `vault_meta.json` is intentionally readable — it contains no secrets.

---

## 5. Security Model

### 5.1 Threat Model

| Threat | Mitigation | Status |
|---|---|---|
| Vault file read by other users | chmod 600 + home directory permissions | ✅ On POSIX |
| Key file read by other users | chmod 600 | ✅ On POSIX |
| Vault file tampering | Fernet HMAC-SHA256 | ✅ Built into Fernet |
| Vault file corruption | Fernet decrypt failure → error | ⚠️ No recovery path |
| Password visible in `ps` output | Password passed as CLI arg | ❌ **CRITICAL** |
| Password in shell history | Password passed as CLI arg | ❌ **CRITICAL** |
| Concurrent writes | No locking | ❌ Race condition |
| Memory dumps | Secrets in process memory | ⚠️ Unmitigated (acceptable for CLI tool) |
| Windows file permissions | chmod calls | ❌ **BROKEN on Windows** |
| Plaintext metadata | vault_meta.json | ⚠️ Info leak (service names) |

### 5.2 Cryptographic Details

- **Algorithm:** Fernet (AES-128-CBC + HMAC-SHA256 using PKCS7 padding)
- **Key:** 32 bytes = 16-byte signing key + 16-byte encryption key, URL-safe base64 encoded
- **IV:** Random 16-byte IV per encryption operation
- **Timestamp:** Embedded in Fernet token; decrypt verifies the token is not expired (default TTL: none)
- **Key derivation:** None. Key is randomly generated, stored on disk.

---

## 6. Integration Points

| External Tool | Integration Method | Data Exchange |
|---|---|---|
| Email client | `kista get email-provider → password → write config` | Password only |
| OAuth services | `kista get oauth-creds → notes field has paths` | Paths only (no tokens) |
| Bitwarden | None (kista is the alternative) | — |
| credential-rotation skill | `kista update <svc> --password NEW` after rotation | Two-way |
| Email providers | `kista add email-* --email ... --password ...` | One-way (store) |

---

## 7. Failure Modes

| Failure | Current Behavior | Required Behavior |
|---|---|---|
| Corrupted VAULT_FILE | `InvalidToken` unhandled → traceback → exit | Graceful error + offer backup path |
| Missing VAULT_KEY | New key generated, old data irrecoverable | Detect mismatch, warn, offer recovery |
| Permission denied on write | `PermissionError` unhandled → traceback | Graceful message with remediation |
| Invalid JSON in decrypted vault | `JSONDecodeError` unhandled → traceback | Graceful error + offer backup scan |
| Empty password stored | Stored as `""`, silently stripped | Warn user, offer password generation |
| Concurrent write | Data loss via race condition | File locking or atomic writes |
| Disk full during write | `OSError` unhandled → partial write | Atomic write prevents partial files |
| Special chars in password | Passed via CLI args → may break shell | Interactive password input mode needed |