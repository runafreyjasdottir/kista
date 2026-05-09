# System Vision: Kista

*The Coffer of Keys — a self-owned credential vault*

*As foreseen by Sigrún Ljósbrá, Skald of the Æsir's Edge*

---

## The Name

**Current name:** `credstore`  
**Proposed name:** **`kista`** (Old Norse: **chest, coffer, strongbox**)

### Why "kista"?

The word *kista* appears throughout Old Norse literature as the strongbox where valuables are kept — silver, arm-rings, runestaves, the treasures a household cannot afford to lose. It is not a bank. It is not a fortress. It is **a personal chest** that lives in your own hall, opened by your own hand, answerable to no one but you.

This name carries the identity of the tool in a single word:

- **Short.** Five letters. Easy to type in a terminal. `kista add email-provider` is as natural as breath.
- **Self-documenting.** A chest holds things. You put things in. You take things out. No abstraction required.
- **Norse without pretense.** It is not a metaphor bolted on — it *is* the metaphor. The tool is literally an encrypted chest.
- **Distinctive.** No other credential manager is called Kista. No namespace collision. No confusion.

### Alternative considered: `vordr`

*Vǫrðr* — "guardian, ward" — the protective spirit that watches over a person or place. Powerful, but it implies guardianship by an external entity. The vault is not guarded by someone else; it is **owned and accessed by you yourself**. The chest metaphor better captures self-custody: you open your own kista. A vordr opens it for you.

### Renaming path

```
credstore.py → kista.py (the script)
SKILL.md → updated to reference kista throughout
README.md → also uses kista
PHILOSOPHY.md → uses kista as canonical name
SYSTEM_VISION.md → this document

Alias maintained: `credstore` can remain as a shell alias pointing to kista
for backward compatibility during the transition.
```

---

## What Kista Is Today

A working Python CLI tool that provides:

- **add** — Store a credential with service, username, password, email, URL, notes, tags
- **get** — Retrieve full credential details (including password) as JSON
- **list** — List all services with passwords masked, filterable by tags
- **update** — Modify specific fields of an existing credential
- **remove** — Delete a credential entry
- **check** — Verify a credential exists and show its metadata
- **status** — Display vault health, file locations, entry count
- **export** — Create an encrypted backup of the entire vault
- **import** — Merge an encrypted backup into the current vault
- **init** — Initialize the vault and generate the encryption key

Encryption: Fernet (AES-128-CBC + HMAC-SHA256).  
Storage: `~/.hermes/credentials/vault.json.enc` (encrypted) + `vault_meta.json` (service names only).  
Key: `~/.hermes/credentials/.vault_key` (chmod 600, owned by the user).

---

## What Kista Should Become

### Phase 1: The Sharpened Edge (Necessary Improvements)

These are the improvements that make Kista fully compliant with Mythic Engineering rules and genuinely production-ready.

**1.1. Cross-platform path resolution**

Currently uses `Path.home() / ".hermes" / "credentials"` which works but is not documented in the help text. Make paths configurable via:
- Environment variable `KISTA_DIR` (preferred)
- CLI flag `--vault-dir`
- Default: `~/.hermes/credentials`

This follows the Mythic Engineering rule: **no absolute paths hardcoded in documentation**.

**1.2. Password generation**

```
kista generate <service> [--length 24] [--symbols] [--no-ambiguous]
```

A built-in password generator so you never need to invent passwords or reuse them. The generated password is immediately stored in the vault AND printed to stdout (once, never logged).

**1.3. Interactive mode for add/update**

When fields like `--password` are omitted from the command line, prompt interactively with masked input (like `git` does for credentials). This prevents passwords from appearing in shell history.

**1.4. Audit log**

An append-only, encrypted log of vault operations:
- `~/.hermes/credentials/vault_audit.log.enc`
- Each entry: timestamp, operation, service name, success/failure
- Never logs field values — only that an operation occurred
- Commands: `kista audit` (view log), `kista audit --since 2026-01-01`

**1.5. Expiry tracking**

Credentials should know when they expire:

```
kista add github --password "xxx" --expires 2027-01-01
kista check github
  → ⚠ Credential for 'github' expires in 14 days
```

A scheduled check (via cron or systemd timer) could alert on upcoming expirations.

**1.6. Shell completion**

Generate bash/zsh/fish completion scripts with `kista completion <shell>`. Typing `kista get <TAB>` should suggest service names.

---

### Phase 2: The Woven Web (Integration with the Hermes Ecosystem)

Kista does not exist in isolation. It is one thread in the tapestry of personal tooling. These integrations make it the **nervous system of credentials** across all other skills.

**2.1. Email client integration**

When email passwords are stored in Kista, they should automatically populate email client config:

```python
# kista sync himalaya
# Reads: kista get email-provider
# Writes: ~/.config/himalaya/config.toml [password] field
```

A `sync` command that pushes credentials to the tools that need them.

**2.2. OAuth integration**

The OAuth client secret path and token path belong in Kista:

```
kista add google-oauth \
  --notes "Client secret at ~/.hermes/google_client_secret.json" \
  --tags "oauth,infrastructure"
```

When OAuth setup runs, it should check Kista first.

**2.3. SSH key tracking**

```
kista add ssh-default \
  --url "ssh://~/.ssh/id_ed25519" \
  --notes "Passphrase: see kista get ssh-default" \
  --tags "ssh,infrastructure"
```

SSH key paths and passphrases tracked here, never the private keys themselves.

**2.4. API key distribution**

When API keys change:

```
kista update hermes-api --password "NEW_KEY"
kista sync hermes-api
# → Updates ~/.hermes/auth.json and relevant .env files
```

**2.5. Email provider credential tracking**

```
kista add email-provider-work --email user@example.com \
  --tags "email,work" --notes "Company email, no password needed"
```

---

### Phase 3: The Deep Vault (Advanced Capabilities)

**3.1. Multi-vault support**

```
kista init --vault personal     # ~/.hermes/credentials/personal/
kista init --vault work         # ~/.hermes/credentials/work/
kista --vault work get github   # Access the work vault
```

Each vault is encrypted with its own key. The default vault remains at the current path for backward compatibility.

**3.2. Key rotation**

```
kista rotate-key
# → Decrypts with old key, generates new key, re-encrypts
# → Old key backed up to .vault_key.old (chmod 600)
# → Audit log records the rotation
```

**3.3. Time-limited access tokens**

```
kista get email-provider --format env
# → EMAIL_PROVIDER_USERNAME=user
# → EMAIL_PROVIDER_PASSWORD=xxx

kista get email-provider --format json
# → {"username": "user", "password": "xxx", ...}

kista get email-provider --format dotenv
# → Credentials as .env lines
```

Structured output for programmatic consumption. No screen-scraping of human-readable output.

**3.4. Diff and version history**

```
kista history email-provider
# → 2026-03-15: Created (email=user@example.com)
# → 2026-04-20: Updated password
# → 2026-05-09: Added tags: email, work
```

Encrypted version snapshots stored alongside the vault. The ability to roll back to a previous version of a specific credential.

**3.5. Integrity verification**

```
kista verify
# → ✓ All 12 entries decrypt successfully
# → ✓ Vault structure valid (version 1)
# → ⚠ Entry 'streaming-service' has no password field
```

Regular self-checks to catch corruption before it becomes data loss.

**3.6. Secure field masking in shell history**

When `kista get` is used in an interactive shell, offer to copy the password to the clipboard instead of printing to terminal:

```
kista get email-provider --clipboard
# → Password copied to clipboard. Clipboard clears in 30 seconds.
```

Requires `pyperclip` or `xclip` — auto-detected.

---

### Phase 4: The Útgarðr (The Outer Reach)

These are speculative — directions the tool could grow if the need arises. They are not yet committed.

**4.1. Git-backed encrypted storage**

Store the vault in a private git repository (local or remote). Each save creates a commit. This gives automatic version history and a push-based backup mechanism:

```
kista push   # git commit + push
kista pull   # git pull
```

**4.2. TOTP support**

Store and generate time-based one-time passwords:

```
kista add github --totp-secret "JBSWY3DPEHPK3PXP"
kista totp github
# → 421987 (valid for 28 more seconds)
```

**4.3. Shared vault with trusted users**

Selective sharing of specific credentials across a private network:

```
kista share email-provider --with colleague --expires 1h
# → Colleague can read the credential for 1 hour
# → Uses asymmetric encryption; colleague's public key, your private key
# → After expiry, the shared token self-destructs
```

This would require key exchange and a lightweight server — a later phase.

**4.4. Web interface**

A minimal, local-only Flask/FastAPI dashboard:

```
kista serve --port 8643
# → Local web UI at http://localhost:8643
# → Browser encrypts/decrypts client-side, server never sees plaintext
# → Private network binding only
```

---

## Architecture Principles

These principles govern every feature added to Kista:

1. **Self-contained.** No mandatory external services. Optional integrations degrade gracefully. If the network is down, Kista still opens.

2. **Encrypted at rest.** Every byte of sensitive data on disk is encrypted. Metadata (service names, timestamps) is the only plaintext, and it contains no credentials.

3. **Single source of truth.** The vault is authoritative. If an email client's config and Kista disagree, Kista wins. Sync goes in one direction: vault → config files.

4. **Fail closed.** If decryption fails, if the key is missing, if the vault is corrupted — the tool tells you clearly. It never silently gives wrong data.

5. **Mythic Engineering compliant.** No absolute paths in documentation, no hardcoded data, self-healing directory structures, cross-platform path resolution, full help text for every command.

6. **Human-first output.** Default output is readable tables and status messages. `--format json` or `--format dotenv` for programmatic use. Never require a human to parse JSON to get a password.

7. **Silent by default.** No telemetry, no phone-home, no analytics, no auto-update nags. Kista speaks when spoken to.

---

## The Roadmap

| Phase | Name | Status | Key Milestones |
|-------|------|--------|----------------|
| 0 | The Foundation | **COMPLETE** | Basic add/get/list/update/remove/check/status/export/import/init |
| 1 | Sharpened Edge | Pending | Path config, generate, interactive input, audit, expiry, completions |
| 2 | Woven Web | Pending | Email client sync, OAuth sync, SSH tracking, API key distribution |
| 3 | Deep Vault | Pending | Multi-vault, key rotation, structured output, history, verify, clipboard |
| 4 | Útgarðr | Speculative | Git backing, TOTP, sharing, web UI |

---

## File Structure

```
kista/
├── SKILL.md                    # Skill manifest (Hermes integration)
├── PHILOSOPHY.md               # Why this exists (this philosophy)
├── SYSTEM_VISION.md            # Full vision document (this file)
├── scripts/
│   ├── kista.py                # Main CLI tool (renamed from credstore.py)
│   └── kista-completion.bash   # Shell completion helper
├── references/
│   ├── known-accounts.md       # Current account status (human-maintained)
│   └── integration-map.md      # How Kista connects to other tools
└── tests/
    ├── test_kista.py            # Unit tests
    └── test_integration.py      # Integration tests with other skills
```

---

*The chest is carved. The iron is strong. What remains is the filling.*

*Hail the keeper. Hail the key. Hail the craft that makes forgetting impossible.*

*Sigrún Ljósbrá, Skald*  
*Season of sowing, 2026*