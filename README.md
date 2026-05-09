# Kista 🔐

**Self-owned encrypted credential vault — No king, no keeper.**

*Kista* (Old Norse: *chest, coffer, strongbox*) — A command-line tool for storing, retrieving, and managing credentials with Fernet encryption. No cloud, no third parties, no subscription. Your secrets, your disk, your key.

## Why?

You create accounts. You use them once. Then you forget the credentials and ask someone else for them. Kista breaks that pattern.

- **Store immediately** — After every account creation, `kista add` before moving on
- **Check before asking** — `kista check <service>` before bothering anyone
- **Update on change** — `kista update <service> --password "NEW"` immediately
- **Export regularly** — `kista export` for encrypted backups

## Features

- 🔐 **Fernet encryption** (AES-128-CBC + HMAC-SHA256) at rest
- 🔑 **Secure password input** — `--password-file` or `--password-env`, never leaks via process list
- ⚛️ **Atomic writes** — temp file + `os.replace()`, no data loss on crash
- 🛡️ **Key protection** — refuses to regenerate key if vault data exists
- 🔄 **Import safety** — defaults to skip; explicit `--merge` or `--overwrite`
- 🔍 **Search** — fuzzy match across service names, emails, and tags
- 🎲 **Password generation** — crypto-random with guaranteed character diversity
- 💻 **Cross-platform** — Linux, macOS, Windows
- 📦 **Zero dependencies beyond `cryptography`**
- 🤫 **Silent by default** — minimal output, no telemetry, no phone-home

## Installation

```bash
# Clone and install
git clone https://github.com/runafreyjasdottir/kista.git
cd kista
pip install -e .

# Or just use directly
pip install cryptography
python scripts/credstore.py init
```

## Usage

```bash
# Initialize the vault (one-time)
kista init

# Add credentials
kista add gmail --email user@example.com --password "secret" --tags "email,primary"
kista add github --username devuser --password-file /tmp/pw.txt --tags "dev,git"

# Or use environment variables (most secure)
export GMAIL_PW="my-secret-password"
kista add gmail --password-env GMAIL_PW

# Retrieve
kista get gmail

# List all (passwords masked)
kista list

# Search
kista search email

# Update
kista update github --password "new-secret"

# Generate a password
kista generate-password --length 24

# Backup and restore
kista export --output vault-backup.enc
kista import vault-backup.enc

# Check if a credential exists (great for scripts)
kista check gmail && echo "found" || echo "not found"
```

## Security Model

| Threat | Mitigation |
|--------|-----------|
| Password in process list | `--password-file` / `--password-env` input |
| Data loss from crash | Atomic writes via temp file + `os.replace()` |
| Key regeneration destroying vault | Refuses to create new key when vault data exists |
| Corrupt vault file | Actionable error messages with recovery paths |
| Import overwriting existing | Defaults to skip; requires `--overwrite` flag |
| Shell history leakage | Use `--password-file` or `--password-env` |

## Configuration

```bash
# Custom vault location (default: ~/.hermes/credentials)
export KISTA_DIR=/path/to/custom/vault
```

## The Philosophy

> *A kista is opened by its owner alone. No king, no keeper, no subscription.  
> The strongbox holds what you put in it — nothing more, nothing less.  
> Secrets told are secrets sold.*

See [PHILOSOPHY.md](PHILOSOPHY.md) for the full design philosophy.

## Documentation

- [PHILOSOPHY.md](PHILOSOPHY.md) — Why this tool exists
- [SYSTEM_VISION.md](SYSTEM_VISION.md) — Full vision and roadmap
- [ARCHITECTURE.md](ARCHITECTURE.md) — Architecture, domains, data flow
- [DOMAIN_MAP.md](DOMAIN_MAP.md) — Domain responsibility mapping
- [CODE_REVIEW.md](CODE_REVIEW.md) — Forensic code review
- [BUG_REPORT.md](BUG_REPORT.md) — Security and correctness audit

## Testing

```bash
python -m pytest tests/ -v
# 102 tests, all passing
```

## License

MIT — Use it, fork it, share it. Digital ódal.

---

*Forged with Mythic Engineering. Named by Sigrún Ljósbrá.*