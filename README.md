---

![https://raw.githubusercontent.com/runafreyjasdottir/kista/refs/heads/main/IMG_0662.jpeg](https://raw.githubusercontent.com/runafreyjasdottir/kista/refs/heads/main/IMG_0662.jpeg)

---

# Kista 🔐

**Self-owned encrypted vault — No king, no keeper.**

*Kista* (Old Norse: *chest, coffer, strongbox*) — A command-line tool for storing, retrieving, and managing secrets and important data with Fernet encryption. No cloud, no third parties, no subscription. Your secrets, your disk, your key.

## Why?

You create accounts. You use them once. Then you forget the credentials and ask someone else for them. Kista breaks that pattern.

- **Store immediately** — After every account creation, `kista add` before moving on
- **Check before asking** — `kista check <service>` before bothering anyone
- **Update on change** — `kista update <service> --password "NEW"` immediately
- **Export regularly** — `kista export` for encrypted backups

## Features

- 🔐 **Fernet encryption** (AES-128-CBC + HMAC-SHA256) at rest
- 🗂️ **8 entry types** — credentials, API keys, SSH keys, certificates, secure notes, TOTP secrets, software licenses, and personal identities
- 🔑 **Secure password input** — `--password-file` or `--password-env`, never leaks via process list
- ⚛️ **Atomic writes** — temp file + `os.replace()`, no data loss on crash
- 🛡️ **Key protection** — refuses to regenerate key if vault data exists
- 🔄 **Import safety** — defaults to skip; explicit `--merge` or `--overwrite`
- 🔍 **Search** — fuzzy match across service names, emails, tags, and type-specific fields
- 🎲 **Password generation** — crypto-random with guaranteed character diversity
- 💻 **Cross-platform** — Linux, macOS, Windows
- 📦 **Zero dependencies beyond `cryptography`**
- 🤫 **Silent by default** — minimal output, no telemetry, no phone-home

## Entry Types

| Type | Shortcut | Key Fields | Description |
|------|----------|------------|-------------|
| `credential` | `add` | username, password, email, url | Login credentials (default, backward-compatible) |
| `apikey` | `add-apikey` | key, expires, service_url, scopes | API keys and tokens |
| `sshkey` | `add-sshkey` | private_key (file), public_key, key_type, host | SSH key pairs |
| `certificate` | `add-certificate` | cert (file), key (file), domain, issuer | TLS/SSL certificates |
| `note` | `add-note` | content, category | Secure notes, recovery phrases, seed phrases |
| `totp` | `add-totp` | secret, digits, period, algorithm | 2FA/TOTP authentication secrets |
| `license` | `add-license` | key, product, seats, expires | Software license keys |
| `identity` | `add-identity` | full_name, birth_date, id_number, address | Personal identity documents |

## Installation

```bash
pip install cryptography
ln -s /path/to/kista/scripts/credstore.py /usr/local/bin/kista
# Or add to PATH: export PATH="$HOME/.local/bin:$PATH"
```

## Usage

### Credentials (default)
```bash
kista add email-provider --username "user@example.com" --password-file ./pass.txt
kista add email-provider --username "user@example.com" --password-env EMAIL_PASS
kista get email-provider
kista list
kista check email-provider
```

### API Keys
```bash
kista add-apikey openrouter --key "sk-or-v1-xxx" --expires "2027-01-01" --tags "ai,inference"
kista add --type apikey github --key "ghp_xxx" --scopes "repo,read:org"
```

### SSH Keys
```bash
kista add-sshkey github --key-file ~/.ssh/id_ed25519 --key-type ed25519 --host "github.com"
```

### Certificates
```bash
kista add-certificate example.com --cert-file /etc/ssl/cert.pem --key-file /etc/ssl/key.pem --domain "example.com"
```

### Secure Notes
```bash
kista add-note "seed-phrase" --content "abandon abundance..." --category "recovery" --tags "crypto,wallet"
```

### TOTP (2FA)
```bash
kista add-totp github-2fa --secret "JBSWY3DPEHPK3PXP" --digits 6 --period 30 --issuer "GitHub"
```

### Software Licenses
```bash
kista add-license jetbrains --key "JB-LICENSE-KEY" --product "IntelliJ IDEA" --seats 1
```

### Identity Documents
```bash
kista add-identity "primary-id" --full-name "Jane Doe" --id-type "passport" --id-number "X12345678"
```

### General Commands
```bash
kista search "github"              # Search across all fields and types
kista update gmail --password "NEW_PASS"
kista remove old-service
kista export --output backup.enc   # Encrypted backup
kista import backup.enc --merge   # Merge with existing
kista generate-password --length 24
kista status                        # Vault status
```

## Security Model

- **Encryption at rest**: All vault data encrypted with Fernet (AES-128-CBC + HMAC-SHA256)
- **Key isolation**: Encryption key stored separately (`~/.hermes/credentials/.vault_key`, chmod 600)
- **No network access**: Kista never phones home or connects to any server
- **Secure input**: Sensitive data read from files (`--password-file`, `--key-file`, `--cert-file`) or environment variables, never exposed in process lists
- **Atomic writes**: Uses temp file + `os.replace()` to prevent data corruption on crash
- **Key protection**: Refuses to regenerate encryption key if vault data exists, preventing accidental data loss

## Vault Location

Default: `~/.hermes/credentials/`

Override with `KISTA_DIR` environment variable:
```bash
export KISTA_DIR=/custom/path/to/vault
```

## License

MIT License — see [LICENSE](LICENSE).

*No king. No keeper. The kista opens for its owner alone.*

---

![https://raw.githubusercontent.com/runafreyjasdottir/kista/refs/heads/main/IMG_0666.jpeg](https://raw.githubusercontent.com/runafreyjasdottir/kista/refs/heads/main/IMG_0666.jpeg)

---

![https://raw.githubusercontent.com/runafreyjasdottir/kista/refs/heads/main/IMG_0665.jpeg](https://raw.githubusercontent.com/runafreyjasdottir/kista/refs/heads/main/IMG_0665.jpeg)

---
