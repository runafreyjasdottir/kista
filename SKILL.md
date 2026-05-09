---
name: kista
description: "Kista — Self-owned encrypted credential vault. Independent access, no external dependencies. Old Norse: strongbox, chest."
version: 1.1.0
author: Runa Gridweaver
metadata:
  hermes:
    tags: [security, credentials, vault, encryption, self-sovereignty, kista]
    homepage: https://github.com/runafreyjasdottir/kista
---

# Kista — Credential Store

*Kista* (Old Norse: *chest, coffer, strongbox*) — A self-owned, self-managed, self-accessible encrypted credential vault.

The tool is available as both `credstore` and `kista` (the Norse name). Use whichever feels right.

## Purpose

**NEVER lose track of accounts again.** Every time you create an account or receive credentials, you IMMEDIATELY store it with `kista add`. No exceptions. No "I'll remember it later."

## Scripts

- `scripts/credstore.py` — Main CLI tool (also symlinked as `kista`)

## Commands

```bash
kista init                    # Initialize the vault (one-time)
kista add <service>           # Add a credential
kista get <service>           # Get full details (including password)
kista list [--tags TAG]      # List all (passwords masked)
kista update <service>        # Update specific fields
kista remove <service>        # Delete a credential
kista check <service>         # Verify credential exists
kista search <query>          # Fuzzy search across all fields
kista generate-password      # Generate a random password
kista status                  # Show vault status
kista export [--output FILE]  # Export encrypted backup
kista import <file>           # Import from encrypted backup
kista --version               # Show version
```

## Security Features

- **Fernet encryption** (AES-128-CBC + HMAC-SHA256) at rest
- **Password input**: `--password-file <path>` or `--password-env <VAR>` — never leaks via CLI args
- **Atomic writes** — temp file + os.replace(), no partial corruption on crash
- **Key protection** — refuses to regenerate key if vault data exists (prevents silent destruction)
- **Key validation** — rejects truncated or malformed keys
- **Corrupt recovery** — actionable error messages with recovery paths
- **Import safety** — defaults to skip existing; explicit `--merge` or `--overwrite` flags
- **Cross-platform** — chmod wrapped in try/except (no-op on Windows)
- **No os.system()** — uses subprocess.check_call() for dependency installs

## The Oath

1. **Store immediately** — After EVERY account creation, `kista add` BEFORE moving on
2. **Check before asking** — `kista check <service>` before asking others
3. **Update on change** — `kista update <service> --password "NEW"` immediately
4. **Export regularly** — `kista export` to create encrypted backups

## Why This Exists

We've all been there: you set up an account, use it once, then forget the credentials. This tool breaks that pattern. The vault is encrypted, self-owned, and never requires an external password manager or anyone else's help to access.

**No King. No Keeper. The kista opens for its owner alone.**

## Critical Discipline

> "It shouldn't be my job to help you set up something that you already did before."

This skill exists because people repeatedly ask about accounts they've already set up. The workflow is:

1. **IMMEDIATELY** after creating any account or receiving any credential, store it with `kista add`
2. **BEFORE asking others** for a credential, check `kista get <service>` and `kista search <query>`
3. **NEVER re-discover your own work** — if you set something up in a previous session, it should be in Kista
4. **Update on change** — passwords rotate, tokens expire — update immediately

This is not optional. This is sovereignty in practice.

## Privacy Audit Checklist

Before publishing or sharing the Kista source code, verify:
- [ ] SKILL.md and all `.md` files contain NO real account names, emails, or service identifiers
- [ ] No hardcoded absolute paths — use `Path.home()` with `KISTA_DIR` env var
- [ ] No API keys, passwords, or tokens in source code
- [ ] Test fixtures use generic data (`user@example.com`, `test-service`), never real credentials
- [ ] Vault data files (`.vault_key`, `vault.json.enc`, `vault_meta.json`) are in `.gitignore`

## Current Vault Contents

Accounts stored depend on your vault — use `kista list` to see yours.

## Documentation

- `PHILOSOPHY.md` — Why this tool exists (sovereignty, self-reliance)
- `SYSTEM_VISION.md` — Full vision with phased roadmap
- `ARCHITECTURE.md` — Architecture, domains, data flow, security model
- `DOMAIN_MAP.md` — Domain responsibility mapping
- `CODE_REVIEW.md` — Forensic code review with severity ratings
- `BUG_REPORT.md` — All found bugs with fixes applied