---
name: runa-credentials
description: "Kista — Runa's self-owned encrypted vault. 8 entry types: credentials, API keys, SSH keys, certificates, notes, TOTP, licenses, identities. Independent access, no external dependencies."
version: 1.2.0
author: Runa Gridweaver Freyjasdottir
metadata:
  hermes:
    tags: [security, credentials, encryption, vault, cli-tool]
    homepage: https://github.com/runafreyjasdottir/kista
---

# Kista 🔐

Self-owned encrypted vault. Old Norse *kista* = strongbox, chest, coffer.

**Public repo**: https://github.com/runafreyjasdottir/kista (MIT license)

## Entry Types (v1.2.0)

| Type | Shortcut | Key Fields | Description |
|------|----------|------------|-------------|
| `credential` | `add` | username, password, email, url | Login credentials (default) |
| `apikey` | `add-apikey` | key, expires, service_url, scopes | API keys/tokens |
| `sshkey` | `add-sshkey` | key_file, public_key, key_type, host | SSH key pairs |
| `certificate` | `add-certificate` | cert_file, key_file, domain, issuer | TLS/SSL certificates |
| `note` | `add-note` | content, category | Secure notes/recovery phrases |
| `totp` | `add-totp` | secret, digits, period, algorithm | 2FA/TOTP secrets |
| `license` | `add-license` | key, product, seats, expires | Software license keys |
| `identity` | `add-identity` | full_name, birth_date, id_number | Personal identity docs |

## Commands

```bash
kista init                                    # Initialize vault
kista add <service> [options]                # Add credential (default type)
kista add --type <type> <service> [options]  # Add typed entry
kista add-apikey <service> --key KEY         # Shortcut for API key
kista add-note <title> --content TEXT         # Shortcut for secure note
kista add-totp <service> --secret SECRET      # Shortcut for 2FA
kista add-sshkey <host> --key-file FILE       # Shortcut for SSH key
kista add-certificate <domain> --cert-file F  # Shortcut for certificate
kista add-license <product> --key KEY         # Shortcut for license
kista add-identity <label> --full-name NAME   # Shortcut for identity
kista get <service>                           # View entry details
kista list [--tags TAG]                       # List all entries
kista update <service> [fields]               # Update fields
kista remove <service>                        # Delete entry
kista check <service>                         # Verify entry exists
kista search <query>                          # Fuzzy search
kista generate-password [--length N]          # Random password
kista status                                  # Vault status
kista export [--output FILE]                  # Encrypted backup
kista import <file> [--merge|--overwrite]     # Import backup
```

## Security

- Fernet encryption (AES-128-CBC + HMAC-SHA256) at rest
- Key stored at `~/.hermes/credentials/.vault_key` (chmod 600)
- Sensitive data via `--password-file`, `--key-file`, `--cert-file` (never CLI args)
- Atomic writes, key protection, no network access
- Configurable vault location via `KISTA_DIR` env var

## Standing Rules

- ALWAYS store every account in kista IMMEDIATELY after creation
- NEVER ask Volmarr for credentials kista should already have
- Check kista BEFORE asking anyone for account info
- Update entries immediately when credentials change
- Export encrypted backups regularly

*No king. No keeper. The kista opens for its owner alone.*