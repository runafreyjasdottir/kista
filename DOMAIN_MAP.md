# Kista Domain Map

**Architect:** Rúnhild Svartdóttir  
**Date:** 2026-05-09  
**Version:** 1.0.0-review

---

## Domain Responsibility Matrix

Each function in `credstore.py` mapped to its owning domain. Cross-domain calls are shown with `→`.

```
┌─────────────────────────────────────────────────────────┐
│                    CLI Layer (Domain 3)                  │
│   Entry point, arg parsing, user interaction, output    │
├─────────────────────────────────────────────────────────┤
│  main()          → Cmd dispatch                         │
│  cmd_init()      → Crypto.get_key, Vault.save           │
│  cmd_add()       → Crypto.get_key, Vault.load,          │
│                     Vault.save, Data validation          │
│  cmd_get()       → Crypto.get_key, Vault.load           │
│  cmd_list()      → Crypto.get_key, Vault.load           │
│  cmd_update()    → Crypto.get_key, Vault.load,          │
│                     Vault.save, Data validation          │
│  cmd_remove()    → Crypto.get_key, Vault.load,          │
│                     Vault.save                           │
│  cmd_check()     → Crypto.get_key, Vault.load           │
│  cmd_status()    → Crypto.get_key, Vault.load           │
│  cmd_export()    → File copy only                       │
│  cmd_import()    → Crypto.get_key, Crypto.decrypt,      │
│                     Vault.load, Vault.save               │
└─────────────────────────────────────────────────────────┘
          │                          │
          ▼                          ▼
┌──────────────────────┐  ┌──────────────────────────┐
│  Crypto Layer        │  │  Vault Layer             │
│  (Domain 1)          │  │  (Domain 2)              │
├──────────────────────┤  ├──────────────────────────┤
│  _gen_key()          │  │  _load_vault()           │
│  _get_key()          │  │  _save_vault()           │
│  _encrypt()          │  │  _ensure_dir()           │
│  _decrypt()          │  │                          │
└──────────────────────┘  └──────────────────────────┘
          │                          │
          ▼                          ▼
┌─────────────────────────────────────────────────────────┐
│               Filesystem / Disk Layer                    │
│  VAULT_KEY  VAULT_FILE  VAULT_META                     │
│  (key bytes) (encrypted)  (plaintext index)             │
└─────────────────────────────────────────────────────────┘
```

---

## What Belongs Where

### Domain 1 — Cryptography

**Owns:** All key management, encrypt/decrypt primitives, key file I/O.

| Responsibility | Current Location | Should Be | Status |
|---|---|---|---|
| Key generation | `_gen_key()` | ✅ Correct domain | ✅ |
| Key file read/write | `_get_key()` | ✅ Correct domain | ✅ |
| Encrypt | `_encrypt()` | ✅ Correct domain | ✅ |
| Decrypt | `_decrypt()` | ✅ Correct domain | ✅ |
| Key rotation | *missing* | Crypto domain | ❌ Not implemented |
| Key derivation from passphrase | *missing* | Crypto domain | ❌ Not implemented |
| Key integrity verification | *missing* | Crypto domain | ❌ Not implemented |
| Multiple key support | *missing* | Crypto domain | ❌ Not implemented |

### Domain 2 — Persistence / Vault

**Owns:** Vault file I/O, atomic writes, serialization, metadata, backup/restore.

| Responsibility | Current Location | Should Be | Status |
|---|---|---|---|
| Vault loading | `_load_vault()` | ✅ Correct domain | ⚠️ No corruption handling |
| Vault saving | `_save_vault()` | ✅ Correct domain | ❌ Not atomic |
| Directory creation | `_ensure_dir()` | ✅ Correct domain | ✅ |
| Metadata updating | Inside `_save_vault()` | ✅ Correct domain | ⚠️ Plaintext leak |
| Vault export | `cmd_export()` | ❌ Should be Vault domain fn | ⚠️ Copy-only, no verification |
| Vault import | `cmd_import()` | ❌ Should be Vault domain fn | ⚠️ No merge strategy control |
| Atomic write | *missing* | Vault domain | ❌ Not implemented |
| File locking | *missing* | Vault domain | ❌ Not implemented |
| Backup verification | *missing* | Vault domain | ❌ Not implemented |
| Corrupted vault recovery | *missing* | Vault domain | ❌ Not implemented |

### Domain 3 — CLI / Commands

**Owns:** Argument parsing, user interaction, output formatting, exit codes.

| Responsibility | Current Location | Should Be | Status |
|---|---|---|---|
| Arg parsing | `main()` | ✅ Correct domain | ✅ |
| Command dispatch | `main()` | ✅ Correct domain | ✅ |
| User output | `cmd_*()` functions | ✅ Correct domain | ⚠️ No machine-readable mode |
| Exit codes | `sys.exit(1)` scattered | ❌ Should be centralized | ⚠️ Inconsistent |
| Error formatting | Bare print + exit | ❌ Should use structured errors | ⚠️ Inconsistent |
| Password input | *missing* | CLI domain | ❌ Not implemented |
| Interactive mode | *missing* | CLI domain | ❌ Not implemented |

### Domain 4 — Entry Model / Data

**Owns:** Entry schema, validation, derived fields, search, password policy.

| Responsibility | Current Location | Should Be | Status |
|---|---|---|---|
| Entry creation | `cmd_add()` inline | ❌ Should be Entry domain fn | ⚠️ No validation |
| Entry update | `cmd_update()` inline | ❌ Should be Entry domain fn | ⚠️ No validation |
| Tag parsing | `cmd_add()` inline | ❌ Should be Entry domain fn | ✅ Works |
| Empty field stripping | `cmd_add()` inline | ❌ Should be Entry domain fn | ⚠️ Strips intentional empty strings |
| Password generation | *missing* | Entry domain | ❌ Not implemented |
| Password strength checking | *missing* | Entry domain | ❌ Not implemented |
| Entry schema validation | *missing* | Entry domain | ❌ Not implemented |
| Search/filter | *missing* | Entry domain | ❌ Not implemented |
| Rotation tracking | *missing* | Entry domain | ❌ Not implemented |
| Expiry warnings | *missing* | Entry domain | ❌ Not implemented |
| Duplicate detection | Only in `cmd_add` | Entry domain | ⚠️ Basic |

---

## Cross-Cutting Concerns (No Single Domain Owns These)

| Concern | Current Status | Required |
|---|---|---|
| Logging / Audit trail | ❌ None | Add `--verbose` flag, log rotations |
| Error handling strategy | ⚠️ Bare try/except in import only | Structured error hierarchy |
| Cross-platform compatibility | ❌ chmod 0o600 on Windows | Platform abstraction |
| Test coverage | ❌ None | Unit + integration tests |
| Configuration | ⚠️ Hardcoded paths | Config file or env vars |

---

## Proposed Domain Separation (Post-Refactor)

```
kista/
├── __init__.py
├── __main__.py            # CLI entry point
├── cli/
│   ├── __init__.py
│   ├── parser.py          # argparse setup
│   ├── commands.py        # cmd_* implementations
│   └── output.py          # Formatting helpers
├── crypto/
│   ├── __init__.py
│   ├── keys.py            # Key generation, storage, rotation
│   └── cipher.py          # Encrypt, decrypt, re-encrypt
├── vault/
│   ├── __init__.py
│   ├── store.py           # Load, save, atomic write
│   ├── backup.py          # Export, import, verify
│   └── metadata.py       # Meta file management
├── models/
│   ├── __init__.py
│   ├── entry.py           # CredentialEntry dataclass
│   └── vault.py           # Vault dataclass
├── security/
│   ├── __init__.py
│   ├── password.py        # Generation, strength checking
│   ├── permissions.py     # Cross-platform file permissions
│   └── audit.py           # Rotation tracking, expiry warnings
└── tests/
    ├── test_crypto.py
    ├── test_vault.py
    ├── test_commands.py
    └── test_models.py
```

This separation ensures each domain can be tested independently and responsibilities never bleed across boundaries.