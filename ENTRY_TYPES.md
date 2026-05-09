# Kista Entry Type System

**Architect:** Rúnhild Svartdóttir  
**Date:** 2026-05-09  
**Version:** 2.0.0-design  
**Status:** SPECIFICATION — Ready for Forge Worker implementation

---

## 0. Design Principles

1. **Backward compatibility is non-negotiable.** Any entry that lacks a `type` field is a `credential`. No migration needed. The vault file upgrades silently on first write.
2. **Type-specific fields are encrypted at rest.** All fields in the vault JSON are encrypted as a single blob. There is no per-field encryption — Fernet encrypts the entire vault. Adding new fields adds zero new cryptographic attack surface.
3. **Every type inherits common fields.** `service`, `tags`, `notes`, `created`, `updated` exist on every entry regardless of type. This guarantees `kista list` and `kista search` work uniformly.
4. **`kista add <service> --type <type>` is the canonical interface.** Convenience shortcuts (`add-apikey`, `add-note`, etc.) are syntactic sugar that set `--type` and expose only relevant flags. They must not diverge in behavior.
5. **Service key remains the primary lookup.** Even for types where "service" is a stretch metaphor (e.g., a recovery phrase), `service` is still the human-readable label for finding the entry. Example: `kista add "bitcoin-wallet-seed" --type note`.

---

## 1. Vault Schema Change

### 1.1 Current Schema (v1)

```json
{
  "version": 1,
  "entries": {
    "gmail": {
      "service": "gmail",
      "username": "user@gmail.com",
      "password": "hunter2",
      "email": "",
      "url": "",
      "notes": "",
      "tags": ["email", "primary"],
      "created": "2026-05-09T00:00:00+00:00",
      "updated": "2026-05-09T00:00:00+00:00"
    }
  },
  "created": "2026-05-09T00:00:00+00:00",
  "updated": "2026-05-09T00:00:00+00:00"
}
```

### 1.2 New Schema (v2)

```json
{
  "version": 2,
  "entries": {
    "gmail": {
      "type": "credential",
      "service": "gmail",
      "username": "user@gmail.com",
      "password": "hunter2",
      "email": "",
      "url": "",
      "notes": "",
      "tags": ["email", "primary"],
      "created": "2026-05-09T00:00:00+00:00",
      "updated": "2026-05-09T00:00:00+00:00"
    },
    "stripe-live": {
      "type": "apikey",
      "service": "stripe-live",
      "key": "sk_live_abc123...",
      "key_prefix": "sk_live_abc***",
      "key_env": "STRIPE_LIVE_KEY",
      "permissions": "read_write",
      "expires": "2027-12-31",
      "url": "https://dashboard.stripe.com",
      "notes": "",
      "tags": ["finance", "production"],
      "created": "2026-05-09T00:00:00+00:00",
      "updated": "2026-05-09T00:00:00+00:00"
    },
    "github-ed25519": {
      "type": "sshkey",
      "service": "github-ed25519",
      "key_path": "~/.ssh/id_ed25519",
      "passphrase_ref": "github-ed25519-passphrase",
      "comment": "runa@gygr",
      "key_type": "ed25519",
      "fingerprint": "SHA256:AbCdEf...",
      "url": "https://github.com/settings/keys",
      "notes": "Primary key for GitHub, added 2026-01-15",
      "tags": ["ssh", "github", "infrastructure"],
      "created": "2026-05-09T00:00:00+00:00",
      "updated": "2026-05-09T00:00:00+00:00"
    },
    "example-com-tls": {
      "type": "certificate",
      "service": "example-com-tls",
      "cert_path": "/etc/ssl/certs/example.com.crt",
      "key_path": "/etc/ssl/private/example.com.key",
      "issuer": "Let's Encrypt",
      "subject": "CN=example.com",
      "serial": "04:AB:CD:EF...",
      "fingerprint": "SHA256:1234abcd...",
      "not_before": "2026-01-01T00:00:00Z",
      "expires": "2026-12-31T23:59:59Z",
      "dns_names": ["example.com", "www.example.com"],
      "auto_renew": true,
      "notes": "Certbot auto-renewal configured",
      "tags": ["tls", "production", "letsencrypt"],
      "created": "2026-05-09T00:00:00+00:00",
      "updated": "2026-05-09T00:00:00+00:00"
    },
    "bitcoin-wallet-seed": {
      "type": "note",
      "service": "bitcoin-wallet-seed",
      "content": "abandon ability able about above absent absorb abstract absurd abuse access accident",
      "note_type": "recovery_phrase",
      "word_count": 12,
      "notes": "Hardware wallet seed — NEVER share",
      "tags": ["crypto", "recovery", "critical"],
      "created": "2026-05-09T00:00:00+00:00",
      "updated": "2026-05-09T00:00:00+00:00"
    },
    "github-2fa": {
      "type": "totp",
      "service": "github-2fa",
      "secret": "JBSWY3DPEHPK3PXP",
      "digits": 6,
      "period": 30,
      "algorithm": "sha1",
      "issuer": "GitHub",
      "account": "runa@gygr",
      "url": "https://github.com/settings/security",
      "notes": "Recovery codes stored in kista note 'github-recovery-codes'",
      "tags": ["2fa", "github"],
      "created": "2026-05-09T00:00:00+00:00",
      "updated": "2026-05-09T00:00:00+00:00"
    },
    "jetbrains-ide": {
      "type": "license",
      "service": "jetbrains-ide",
      "license_key": "JB-XXXX-XXXX-XXXX-XXXX",
      "product": "IntelliJ IDEA Ultimate",
      "seats": 1,
      "registered_to": "runa@gygr",
      "expires": "2027-05-09",
      "url": "https://account.jetbrains.com",
      "notes": "Subscription auto-renews",
      "tags": ["license", "ide", "development"],
      "created": "2026-05-09T00:00:00+00:00",
      "updated": "2026-05-09T00:00:00+00:00"
    },
    "runa-identity": {
      "type": "identity",
      "service": "runa-identity",
      "full_name": "Runa Gridweaver",
      "given_name": "Runa",
      "family_name": "Gridweaver",
      "passport_number": "",
      "passport_country": "",
      "national_id": "",
      "national_id_type": "ssn",
      "date_of_birth": "",
      "phone": "",
      "address": "",
      "notes": "Primary identity record",
      "tags": ["identity", "personal", "critical"],
      "created": "2026-05-09T00:00:00+00:00",
      "updated": "2026-05-09T00:00:00+00:00"
    }
  },
  "created": "2026-05-09T00:00:00+00:00",
  "updated": "2026-05-09T00:00:00+00:00"
}
```

### 1.3 Version Upgrade Rule

- On `_load_vault()`: if `version` is absent or `1`, and any entry lacks a `type` field, silently inject `"type": "credential"` into that entry during load. The version field in the vault dict is bumped to `2` only on `_save_vault()`.
- On `_save_vault()`: if any entry has a `type` field (or the vault version is `2`), write `"version": 2`. Otherwise, preserve `"version": 1`.
- **No migration script required.** Old vaults upgrade transparently on first read-write cycle.

---

## 2. Entry Type Definitions

### 2.1 Common Fields (All Types)

Every entry, regardless of type, has these fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | `str` | Auto (defaults to `"credential"`) | Entry type discriminator |
| `service` | `str` | **Yes** | Human-readable lookup key, lowercased |
| `tags` | `list[str]` | No (default `[]`) | Comma-separated on input, stored as list |
| `notes` | `str` | No (default `""`) | Free-form text |
| `created` | `str` | Auto | ISO 8601 timestamp, set on `add` |
| `updated` | `str` | Auto | ISO 8601 timestamp, set on `add` and `update` |

### 2.2 Type: `credential` (Default — Backward Compatible)

The original entry type. When an entry has no `type` field, it is a `credential`.

| Field | Type | Required | Description |
|---|---|---|---|
| `username` | `str` | No | Login username |
| `password` | `str` | No | Login password / secret |
| `email` | `str` | No | Associated email |
| `url` | `str` | No | Service URL |

**Backward compatibility:** Entries created before v2 that lack a `type` field are loaded as `credential`. No data migration needed. The `type` field is injected on load, and persisted on save.

### 2.3 Type: `apikey`

For API keys, bearer tokens, OAuth client secrets, service tokens.

| Field | Type | Required | Description |
|---|---|---|---|
| `key` | `str` | **Yes** | The API key / token / secret |
| `key_prefix` | `str` | No | Non-sensitive prefix for identification (e.g., `sk_live_abc***`). Auto-computed if not provided — first 8 chars + `***` |
| `key_env` | `str` | No | Environment variable name where this key is deployed |
| `permissions` | `str` | No | Scope/permissions (e.g., `read_only`, `read_write`, `admin`) |
| `expires` | `str` | No | ISO 8601 date or datetime when key expires |
| `url` | `str` | No | Dashboard/console URL for key management |

**Notes:**
- `key_prefix` is a **derived hint** — it is stored but never displayed in `list` output. It's for quick visual identification without revealing the full key.
- `kista get <service>` for an apikey entry shows `key_prefix` by default and `key` with `--reveal` or when output is JSON.
- The `key` field is the analog of `password` in credential type — it's the sensitive value.

### 2.4 Type: `sshkey`

For SSH key pair metadata. The private key itself is NEVER stored in the vault — only metadata about it.

| Field | Type | Required | Description |
|---|---|---|---|
| `key_path` | `str` | No | Path to the private key file (e.g., `~/.ssh/id_ed25519`) |
| `passphrase_ref` | `str` | No | Service name of the credential entry that holds the passphrase |
| `comment` | `str` | No | SSH key comment (the part after the email) |
| `key_type` | `str` | No | Algorithm: `ed25519`, `rsa`, `ecdsa`, `dsa` |
| `fingerprint` | `str` | No | Public key fingerprint for verification |
| `url` | `str` | No | URL where key is registered (e.g., GitHub keys page) |

**Security rule:** The private key contents are NEVER stored in Kista. Kista stores *where* the key is and *how* to find it. The passphrase can be stored as a separate `credential` entry referenced by `passphrase_ref`.

### 2.5 Type: `certificate`

For TLS/SSL certificates, code-signing certificates, S/MIME certificates.

| Field | Type | Required | Description |
|---|---|---|---|
| `cert_path` | `str` | No | Path to the certificate file on disk |
| `key_path` | `str` | No | Path to the private key file |
| `issuer` | `str` | No | Certificate issuer (e.g., `Let's Encrypt`) |
| `subject` | `str` | No | Certificate subject (e.g., `CN=example.com`) |
| `serial` | `str` | No | Certificate serial number |
| `fingerprint` | `str` | No | Certificate fingerprint (SHA-256 preferred) |
| `not_before` | `str` | No | ISO 8601 datetime — validity start |
| `expires` | `str` | No | ISO 8601 datetime — validity end |
| `dns_names` | `list[str]` | No | Subject Alternative Names (SANs). Comma-separated on input. |
| `auto_renew` | `bool` | No | Whether auto-renewal is configured (default `false`) |

**Notes:**
- `kista check <service>` for certificate entries SHOULD calculate days until expiry and warn if < 30 days.
- The private key file itself is never stored in the vault — only its path on disk.

### 2.6 Type: `note`

For secure notes, recovery phrases, security questions, seed phrases, arbitrary secrets that don't fit other types.

| Field | Type | Required | Description |
|---|---|---|---|
| `content` | `str` | **Yes** | The note content — the secure text itself |
| `note_type` | `str` | No | Semantic classification: `recovery_phrase`, `security_question`, `seed_phrase`, `secret`, `backup_code`, `general` |

**Predefined `note_type` values (extensible):**

| `note_type` | Meaning |
|---|---|
| `recovery_phrase` | A backup/recovery phrase (e.g., 12-word BIP39 seed) |
| `security_question` | Q&A pair(s) stored as `"question: answer"` per line |
| `seed_phrase` | Cryptocurrency wallet seed phrase |
| `secret` | Generic secret text |
| `backup_code` | One-time backup/recovery codes |
| `general` | Unstructured secure note (default) |

**Notes:**
- `content` is the sensitive field — analogous to `password` in credential type.
- `kista list` for note entries shows `note_type` instead of `username`.
- `kista get <service>` for note entries shows `content` by default (it's the whole point of this type).

### 2.7 Type: `totp`

For TOTP (Time-based One-Time Password) secrets — the shared secret that generates 2FA codes.

| Field | Type | Required | Description |
|---|---|---|---|
| `secret` | `str` | **Yes** | Base32-encoded TOTP secret |
| `digits` | `int` | No (default 6) | Number of digits in code (6 or 8) |
| `period` | `int` | No (default 30) | Time step in seconds |
| `algorithm` | `str` | No (default `"sha1"`) | Hash algorithm: `sha1`, `sha256`, `sha512` |
| `issuer` | `str` | No | Service name from the otpauth URI |
| `account` | `str` | No | Account identifier from the otpauth URI |
| `url` | `str` | No | Service URL for manual 2FA setup |

**Notes:**
- A future phase will add `kista totp <service>` to generate the current TOTP code from the stored secret. This specification does NOT include that command yet — it's designated for Phase 4 per SYSTEM_VISION.md.
- `secret` is the sensitive value. Store as Base32 string (standard TOTP format).
- `kista list` for totp entries shows `issuer (account)` as the identity column.
- An `otpauth://` URI can be parsed on input to auto-populate `secret`, `digits`, `period`, `algorithm`, `issuer`, `account`.

### 2.8 Type: `license`

For software license keys, activation codes, subscription keys.

| Field | Type | Required | Description |
|---|---|---|---|
| `license_key` | `str` | **Yes** | The license key / activation code |
| `product` | `str` | No | Product name (e.g., `IntelliJ IDEA Ultimate`) |
| `seats` | `int` | No | Number of licensed seats |
| `registered_to` | `str` | No | Name/email the license is registered to |
| `expires` | `str` | No | Expiration date (ISO 8601 date) |
| `url` | `str` | No | License management URL |

**Notes:**
- `license_key` is the sensitive field — analogous to `password` in credential type.

### 2.9 Type: `identity`

For personal identification information — the kind of data you need when filling forms or verifying identity, but that must be kept secure.

| Field | Type | Required | Description |
|---|---|---|---|
| `full_name` | `str` | No | Full legal name |
| `given_name` | `str` | No | First name |
| `family_name` | `str` | No | Last name |
| `passport_number` | `str` | No | Passport number |
| `passport_country` | `str` | No | Issuing country (ISO 3166-1 alpha-2) |
| `national_id` | `str` | No | National ID number (SSN, etc.) |
| `national_id_type` | `str` | No | Type of national ID: `ssn`, `nin`, `sin`, `nif`, etc. |
| `date_of_birth` | `str` | No | ISO 8601 date |
| `phone` | `str` | No | Phone number |
| `address` | `str` | No | Full address ( multiline allowed) |

**Notes:**
- ALL fields in `identity` are sensitive. `kista list` shows only `full_name` (or service name if empty).
- `national_id` is the highest-sensitivity field. `kista get` should display it but `kista list` never shows it.
- Multiple identity entries can exist for different contexts (e.g., `runa-personal`, `runa-work-identity`).

---

## 3. Type Field Quick Reference

| Type | Primary Secret Field | `list` Identity Column | `get` Shows |
|---|---|---|---|
| `credential` | `password` | `email` or `username` | All fields |
| `apikey` | `key` | `key_prefix` | All fields, `key` in JSON |
| `sshkey` | (no secret stored) | `key_type` + `comment` | All fields |
| `certificate` | (no secret stored) | `subject` | All fields, expiry warning |
| `note` | `content` | `note_type` | `content` + metadata |
| `totp` | `secret` | `issuer (account)` | All fields, `secret` in JSON |
| `license` | `license_key` | `product` | All fields, `license_key` in JSON |
| `identity` | `national_id` | `full_name` | All fields |

---

## 4. CLI Command Specification

### 4.1 `kista add` (Unified — Type-Aware)

```bash
kista add <service> [--type TYPE] [common flags] [type-specific flags] [--force]
```

**Common flags (all types):**

```
--type TYPE        Entry type (credential|apikey|sshkey|certificate|note|totp|license|identity)
                     Default: credential
--tags TAGS        Comma-separated tags
--notes NOTES      Free-form notes
```

**Type-specific flags:**

```bash
# credential (default)
--username, -u     Username
--password, -p     Password (insecure: visible in process list)
--password-file    Read password from file
--password-env     Read password from environment variable
--email, -e        Email address
--url              Service URL

# apikey
--key              API key/token (required for apikey type)
--key-file         Read key from file
--key-env          Read key from environment variable
--key-prefix       Display prefix (auto-computed if omitted)
--key-env-var      Environment variable name where key is deployed
--permissions      Scope/permissions label
--expires          Expiration date (ISO 8601)
--url              Service/console URL

# sshkey
--key-path         Path to private key file (e.g., ~/.ssh/id_ed25519)
--passphrase-ref   Service name of credential holding the passphrase
--comment          SSH key comment
--key-type         Algorithm (ed25519|rsa|ecdsa|dsa)
--fingerprint      Public key fingerprint
--url              URL where key is registered

# certificate
--cert-path        Path to certificate file
--privkey-path     Path to private key file
--issuer           Certificate issuer
--subject          Certificate subject (CN=...)
--serial           Serial number
--fingerprint      Fingerprint (SHA-256 preferred)
--not-before       Validity start datetime
--expires          Expiration datetime
--dns-names        Comma-separated Subject Alternative Names
--auto-renew       Flag: auto-renewal is configured (store as bool)

# note
--content          Note content text (required for note type)
--content-file     Read content from file
--note-type        Type: recovery_phrase|security_question|seed_phrase|secret|backup_code|general

# totp
--secret           Base32 TOTP secret (required for totp type)
--secret-file      Read secret from file
--secret-env       Read secret from environment variable
--digits           Number of digits (6 or 8, default 6)
--period           Time step in seconds (default 30)
--algorithm        Hash algorithm (sha1|sha256|sha512, default sha1)
--issuer           Service name from otpauth URI
--account          Account identifier from otpauth URI
--otpauth          Full otpauth:// URI (parses to fill above fields)
--url              Service URL for manual 2FA setup

# license
--license-key      License key / activation code (required for license type)
--license-file     Read license key from file
--license-env      Read license key from environment variable
--product          Product name
--seats            Number of seats (integer)
--registered-to    Registered owner name/email
--expires          Expiration date (ISO 8601)
--url              License management URL

# identity
--full-name        Full legal name
--given-name       First name
--family-name      Last name
--passport-number  Passport number
--passport-country Passport country (ISO 3166-1 alpha-2)
--national-id      National ID number (SSN, etc.)
--national-id-type Type of national ID
--date-of-birth    Date of birth (ISO 8601 date)
--phone            Phone number
--address          Full address
```

### 4.2 Convenience Shortcuts

Each type has a shortcut command that sets `--type` automatically and only exposes that type's flags:

```bash
kista add-apikey <service> --key <KEY> [--key-file FILE] [--key-env VAR] \
    [--key-prefix PREFIX] [--key-env-var ENVVAR] [--permissions SCOPE] \
    [--expires DATE] [--url URL] [--notes NOTES] [--tags TAGS] [--force]

kista add-sshkey <service> [--key-path PATH] [--passphrase-ref SVC] \
    [--comment COMMENT] [--key-type ALG] [--fingerprint FP] \
    [--url URL] [--notes NOTES] [--tags TAGS] [--force]

kista add-certificate <service> [--cert-path PATH] [--privkey-path PATH] \
    [--issuer ISSUER] [--subject SUBJECT] [--serial SERIAL] \
    [--fingerprint FP] [--not-before DT] [--expires DT] \
    [--dns-names NAMES] [--auto-renew] [--notes NOTES] [--tags TAGS] [--force]

kista add-note <service> --content <TEXT> [--content-file FILE] \
    [--note-type TYPE] [--notes NOTES] [--tags TAGS] [--force]

kista add-totp <service> --secret <SECRET> [--secret-file FILE] [--secret-env VAR] \
    [--digits N] [--period N] [--algorithm ALG] \
    [--issuer ISSUER] [--account ACCT] [--otpauth URI] \
    [--url URL] [--notes NOTES] [--tags TAGS] [--force]

kista add-license <service> --license-key <KEY> [--license-file FILE] [--license-env VAR] \
    [--product PROD] [--seats N] [--registered-to OWNER] \
    [--expires DATE] [--url URL] [--notes NOTES] [--tags TAGS] [--force]

kista add-identity <service> [--full-name NAME] [--given-name FIRST] [--family-name LAST] \
    [--passport-number NUM] [--passport-country COUNTRY] \
    [--national-id ID] [--national-id-type TYPE] \
    [--date-of-birth DOB] [--phone PHONE] [--address ADDR] \
    [--notes NOTES] [--tags TAGS] [--force]
```

**Implementation:** Each shortcut is a separate `argparse` subcommand that:
1. Sets `args.type = "<type>"` automatically.
2. Only exposes the flags valid for that type.
3. Dispatches to the same `cmd_add()` function (or a type-specific builder that produces the entry dict).

The generic `kista add <service> --type <type>` with type-specific flags is the canonical interface. Shortcuts are pure sugar.

### 4.3 `kista get` (Type-Aware Display)

```bash
kista get <service>              # Type-appropriate human-readable output
kista get <service> --json       # Full JSON dump (all fields)
kista get <service> --reveal      # Show sensitive fields (password, key, secret, etc.)
```

**Type-specific display logic:**

| Type | Default `get` output | `--reveal` adds |
|---|---|---|
| `credential` | service, type, username, email, url, tags, created, updated | password |
| `apikey` | service, type, key_prefix, permissions, expires, url, tags | key |
| `sshkey` | service, type, key_type, comment, fingerprint, key_path, url | passphrase_ref |
| `certificate` | service, type, subject, issuer, expires, auto_renew, dns_names | cert_path, key_path, serial |
| `note` | service, type, note_type, created, updated | content |
| `totp` | service, type, issuer, account, digits, period, algorithm | secret |
| `license` | service, type, product, registered_to, seats, expires | license_key |
| `identity` | service, type, full_name, date_of_birth, phone | all ID fields |

**Behavior change:** Without `--reveal`, sensitive fields (`password`, `key`, `secret`, `license_key`, `content`, `national_id`, `passport_number`) show `***` instead. With `--reveal`, the actual value is shown. `--json` always shows all fields (programmatic use).

### 4.4 `kista list` (Type Column)

```bash
kista list [--tags TAG] [--type TYPE]
```

**Output format:**

```
Service                    Type           Identity                     Tags                 Updated
----------------------------------------------------------------------------------------------
gmail                      credential     user@gmail.com               email, primary       2026-05-09
stripe-live                apikey         sk_live_abc***               finance, production  2026-05-09
github-ed25519             sshkey         ed25519 runa@gygr            ssh, github          2026-05-09
example-com-tls            certificate    CN=example.com               tls, production      2026-05-09
bitcoin-wallet-seed        note           recovery_phrase              crypto, recovery     2026-05-09
github-2fa                 totp           GitHub (runa@gygr)           2fa, github          2026-05-09
jetbrains-ide              license        IntelliJ IDEA Ultimate       license, ide         2026-05-09
runa-identity              identity       Runa Gridweaver              identity, personal   2026-05-09
```

**`--type TYPE` filter:** Only entries of that type are shown. `kista list --type apikey` shows only API keys.

**Identity column logic per type:**

| Type | Identity column source |
|---|---|
| `credential` | `email` || `username` || `(no identity)` |
| `apikey` | `key_prefix` || `(no key prefix)` |
| `sshkey` | `key_type` + ` ` + `comment` || `(no identity)` |
| `certificate` | `subject` || `(no subject)` |
| `note` | `note_type` || `general` |
| `totp` | `issuer` + ` (` + `account` + `)` || `(no issuer)` |
| `license` | `product` || `(no product)` |
| `identity` | `full_name` || `(no name)` |

### 4.5 `kista search` (Type-Aware)

```bash
kista search <query>       # Searches all entry types
kista search <query> --type apikey  # Restrict to apikey entries
```

**Search scope:** The query is matched (case-insensitive substring) against:

**Common fields (all types):**
- `service`, `tags` (each tag), `notes`

**Type-specific fields:**

| Type | Additional searchable fields |
|---|---|
| `credential` | `username`, `email`, `url` |
| `apikey` | `key_prefix`, `permissions`, `key_env`, `url` |
| `sshkey` | `key_type`, `comment`, `fingerprint`, `key_path`, `url` |
| `certificate` | `subject`, `issuer`, `serial`, `fingerprint`, `dns_names` (each) |
| `note` | `note_type`, `content` (⚠️ searches encrypted content) |
| `totp` | `issuer`, `account`, `url` |
| `license` | `product`, `registered_to`, `url` |
| `identity` | `full_name`, `given_name`, `family_name`, `national_id_type` |

**Security note on searching `note.content`:** Since the vault is decrypted in memory for any operation, searching `content` is no more dangerous than `kista get` revealing it. However, `kista search` results should show only matching entry metadata (service, type, identity), never the content itself. Use `kista get <service> --reveal` to see content.

### 4.6 `kista update` (Type-Aware)

```bash
kista update <service> [fields...]
```

Works identically to today, but type-specific fields can be updated for entries of that type. Attempting to update `--username` on a `note` entry should fail with a clear error: `"Entry 'bitcoin-wallet-seed' is type 'note'. Field 'username' is not valid for this type. Use --content, --note-type, etc."`.

**Cross-type update rule:** You can always update common fields (`--tags`, `--notes`) regardless of type. Type-specific fields are only valid if the entry's type matches.

**Type change:** `kista update <service> --type <new-type>` is **FORBIDDEN**. Changing an entry's type fundamentally changes its schema. Use `kista remove <service>` + `kista add <service> --type <new-type>` instead.

### 4.7 `kista check` (Type-Aware)

```bash
kista check <service>
```

**Certificate entries get special behavior:**

```
✓ Entry exists for 'example-com-tls' (certificate)
  Subject: CN=example.com
  Issuer: Let's Encrypt
  Expires: 2026-12-31
  ⚠ Certificate expires in 23 days!
  Auto-renew: yes
```

**TOTP entries show:**

```
✓ Entry exists for 'github-2fa' (totp)
  Issuer: GitHub
  Account: runa@gygr
  Digits: 6  Period: 30s  Algorithm: sha1
```

All other types show their type-appropriate fields with sensitive values masked.

---

## 5. DOMAIN_MAP Additions

The following updates to `DOMAIN_MAP.md` reflect the entry type system's impact on domain responsibilities.

### 5.1 Domain 4 — Entry Model / Data (Expanded)

| Responsibility | Location | Status |
|---|---|---|
| Entry type resolution | `models/entry.py` → `resolve_type()` | ❌ New |
| Entry type validation | `models/entry.py` → `validate_entry()` | ❌ New |
| Type-specific field construction | `models/entry.py` → `build_entry(type, args)` | ❌ New |
| Type-specific display formatting | `cli/output.py` → `format_entry(entry)` | ❌ New |
| Sensitive field masking | `cli/output.py` → `mask_sensitive(entry)` | ❌ New |
| Type-specific search scope | `models/entry.py` → `searchable_fields(type)` | ❌ New |
| Entry type schema registry | `models/entry.py` → `ENTRY_TYPES` dict | ❌ New |
| Backward-compatible type defaulting | `models/entry.py` → `ensure_type(entry)` | ❌ New |
| Vault version migration | `vault/store.py` → `_migrate_v1_to_v2()` | ❌ New |

### 5.2 Domain 3 — CLI / Commands (Expanded)

| Responsibility | Location | Status |
|---|---|---|
| Shortcut subcommand registration | `cli/parser.py` → `add_apikey_parser()`, etc. | ❌ New |
| Type-specific arg validation | `cli/parser.py` → validate per type | ❌ New |
| `--reveal` flag on `get` | `cli/parser.py` → `p_get.add_argument("--reveal")` | ❌ New |
| `--type` filter on `list` | `cli/parser.py` → `p_list.add_argument("--type")` | ❌ New |
| `--type` filter on `search` | `cli/parser.py` → `p_search.add_argument("--type")` | ❌ New |
| `--json` output flag on `get` | `cli/parser.py` → `p_get.add_argument("--json")` | ❌ New |

### 5.3 Domain 2 — Persistence / Vault (Expanded)

| Responsibility | Location | Status |
|---|---|---|
| v1→v2 migration on load | `vault/store.py` → `_load_vault()` | ❌ New |
| Version stamp on save | `vault/store.py` → `_save_vault()` | ❌ New |
| Metadata includes type index | `vault/metadata.py` → type breakdown in meta | ❌ New |

### 5.4 Domain 1 — Cryptography (Unchanged)

No changes. The vault is still a single Fernet-encrypted blob. Type-specific fields do not require separate encryption — they're part of the same encrypted JSON. The `key`, `secret`, `content`, `license_key`, and `national_id` fields are no more or less secure than `password` already is.

---

## 6. Implementation Specification for Forge Worker

### 6.1 File Changes

```
scripts/credstore.py          # MODIFY — add type system, new parsers, new commands
models/
  __init__.py                 # NEW — package init
  entry.py                    # NEW — entry type registry, validation, construction
  vault.py                    # NEW — vault dataclass (optional, can stay dict)
cli/
  __init__.py                 # NEW — package init
  parser.py                   # NEW — argparse setup (extracted from main())
  commands.py                 # NEW — cmd_* implementations (extracted)
  output.py                   # NEW — type-aware display formatting
vault/
  __init__.py                 # NEW — package init
  store.py                    # NEW — extracted vault I/O functions
  backup.py                   # NEW — extracted export/import
  metadata.py                 # NEW — metadata file management
tests/
  test_entry_types.py         # NEW — type validation, building, display
  test_v2_migration.py        # NEW — v1→v2 migration tests
  test_cli_shortcuts.py       # NEW — shortcut command tests
```

### 6.2 Entry Type Registry (models/entry.py)

```python
ENTRY_TYPES = {
    "credential": {
        "secret_fields": ["password"],
        "identity_field": lambda e: e.get("email") or e.get("username") or "(no identity)",
        "display_order": ["service", "type", "username", "email", "password", "url", "tags", "notes", "created", "updated"],
        "searchable_fields": ["service", "username", "email", "url", "notes", "tags"],
    },
    "apikey": {
        "secret_fields": ["key"],
        "identity_field": lambda e: e.get("key_prefix") or "(no key prefix)",
        "display_order": ["service", "type", "key_prefix", "key", "key_env", "permissions", "expires", "url", "tags", "notes", "created", "updated"],
        "searchable_fields": ["service", "key_prefix", "key_env", "permissions", "url", "notes", "tags"],
    },
    "sshkey": {
        "secret_fields": ["passphrase_ref"],
        "identity_field": lambda e: (f"{e.get('key_type', 'ssh')} {e.get('comment', '')}").strip() or "(no identity)",
        "display_order": ["service", "type", "key_type", "comment", "fingerprint", "key_path", "passphrase_ref", "url", "tags", "notes", "created", "updated"],
        "searchable_fields": ["service", "key_type", "comment", "fingerprint", "key_path", "url", "notes", "tags"],
    },
    "certificate": {
        "secret_fields": ["cert_path", "key_path", "serial"],
        "identity_field": lambda e: e.get("subject") or "(no subject)",
        "display_order": ["service", "type", "subject", "issuer", "serial", "fingerprint", "cert_path", "key_path", "not_before", "expires", "dns_names", "auto_renew", "url", "tags", "notes", "created", "updated"],
        "searchable_fields": ["service", "subject", "issuer", "serial", "fingerprint", "url", "notes", "tags"],
    },
    "note": {
        "secret_fields": ["content"],
        "identity_field": lambda e: e.get("note_type") or "general",
        "display_order": ["service", "type", "note_type", "content", "tags", "notes", "created", "updated"],
        "searchable_fields": ["service", "note_type", "content", "notes", "tags"],
    },
    "totp": {
        "secret_fields": ["secret"],
        "identity_field": lambda e: f"{e.get('issuer', '')} ({e.get('account', '')})".strip(" ()") or "(no issuer)",
        "display_order": ["service", "type", "issuer", "account", "secret", "digits", "period", "algorithm", "url", "tags", "notes", "created", "updated"],
        "searchable_fields": ["service", "issuer", "account", "url", "notes", "tags"],
    },
    "license": {
        "secret_fields": ["license_key"],
        "identity_field": lambda e: e.get("product") or "(no product)",
        "display_order": ["service", "type", "product", "license_key", "seats", "registered_to", "expires", "url", "tags", "notes", "created", "updated"],
        "searchable_fields": ["service", "product", "registered_to", "url", "notes", "tags"],
    },
    "identity": {
        "secret_fields": ["national_id", "passport_number", "full_name", "date_of_birth", "phone", "address"],
        "identity_field": lambda e: e.get("full_name") or "(no name)",
        "display_order": ["service", "type", "full_name", "given_name", "family_name", "national_id", "national_id_type", "passport_number", "passport_country", "date_of_birth", "phone", "address", "tags", "notes", "created", "updated"],
        "searchable_fields": ["service", "full_name", "given_name", "family_name", "national_id_type", "notes", "tags"],
    },
}
```

### 6.3 Required Helper Functions

```python
def resolve_type(entry: dict) -> str:
    """Return the entry type, defaulting to 'credential' for v1 entries."""
    return entry.get("type", "credential")


def ensure_type(entry: dict) -> dict:
    """Inject 'type': 'credential' if missing. Returns new dict (does not mutate)."""
    if "type" not in entry:
        return {**entry, "type": "credential"}
    return entry


def validate_entry_type(entry_type: str) -> str:
    """Validate that entry_type is known. Returns it lowercased. Raises ValueError if unknown."""
    et = entry_type.lower()
    if et not in ENTRY_TYPES:
        raise ValueError(f"Unknown entry type '{et}'. Valid types: {', '.join(ENTRY_TYPES.keys())}")
    return et


def mask_sensitive(entry: dict, reveal: bool = False) -> dict:
    """Return a copy with sensitive fields masked unless reveal=True."""
    et = resolve_type(entry)
    spec = ENTRY_TYPES[et]
    result = dict(entry)
    if not reveal:
        for field in spec["secret_fields"]:
            if field in result and result[field]:
                result[field] = "***"
    return result


def get_searchable_text(entry: dict) -> str:
    """Return a single string of all searchable text for an entry."""
    et = resolve_type(entry)
    spec = ENTRY_TYPES[et]
    parts = []
    for field in spec["searchable_fields"]:
        val = entry.get(field, "")
        if isinstance(val, list):
            parts.extend(str(v) for v in val)
        elif val:
            parts.append(str(val))
    return " ".join(parts).lower()
```

### 6.4 Vault Migration Logic (in `_load_vault`)

```python
def _load_vault(key: bytes) -> dict:
    """Load and decrypt the vault with v1→v2 migration."""
    # ... existing decrypt logic ...
    vault = json.loads(decrypted)
    
    # v1 → v2 migration: inject type defaults on read
    if vault.get("version", 1) < 2:
        for service, entry in vault.get("entries", {}).items():
            if "type" not in entry:
                entry["type"] = "credential"
        # Version is bumped to 2 on _save_vault, not here —
        # this allows clean writes even if no changes are made.
    
    return vault


def _save_vault(vault: dict, key: bytes):
    """Encrypt and save the vault atomically. Bumps version if typed entries exist."""
    _ensure_dir()
    
    # Any entry with a type field means we're on v2
    has_typed = any("type" in e for e in vault.get("entries", {}).values())
    if has_typed or vault.get("version", 1) >= 2:
        vault["version"] = 2
    
    vault["updated"] = datetime.now(timezone.utc).isoformat()
    data = json.dumps(vault, indent=2, ensure_ascii=False).encode()
    encrypted = _encrypt(data, key)
    _atomic_write(VAULT_FILE, encrypted)
    _chmod_600(VAULT_FILE)
    # ... update metadata ...
```

### 6.5 cmd_add Rewrite (Simplified)

The `cmd_add` function becomes a dispatcher:

```python
def cmd_add(args):
    """Add a new entry (any type)."""
    key = _get_key()
    vault = _load_vault(key)
    entries = vault.setdefault("entries", {})
    
    service = args.service.lower()
    if service in entries and not args.force:
        print(f"✗ Entry for '{service}' already exists (type: {resolve_type(entries[service])}). Use --force to overwrite.")
        sys.exit(1)
    
    entry_type = validate_entry_type(getattr(args, "type", "credential") or "credential")
    entry = build_typed_entry(entry_type, args)
    entry["service"] = service
    entry["type"] = entry_type
    entry["tags"] = _parse_tags(getattr(args, "tags", "") or "")
    entry["notes"] = getattr(args, "notes", "") or ""
    entry["created"] = datetime.now(timezone.utc).isoformat()
    entry["updated"] = datetime.now(timezone.utc).isoformat()
    
    # Remove empty fields (but keep service, type, created, updated)
    entry = {k: v for k, v in entry.items() if v or k in ("service", "type", "created", "updated")}
    
    entries[service] = entry
    _save_vault(vault, key)
    
    spec = ENTRY_TYPES[entry_type]
    print(f"✓ Added {entry_type} entry for '{service}'")
    identity = spec["identity_field"](entry)
    if identity and identity != "(no identity)":
        print(f"  {identity}")
```

Where `build_typed_entry(entry_type, args)` constructs the type-specific fields from CLI args based on the entry type.

### 6.6 Shortcut Command Registration (in `main()`)

```python
# For each type, register a shortcut subcommand
TYPE_SHORTCUTS = {
    "add-apikey": ("apikey", "Add an API key/token entry"),
    "add-sshkey": ("sshkey", "Add an SSH key metadata entry"),
    "add-certificate": ("certificate", "Add a TLS/SSL certificate entry"),
    "add-note": ("note", "Add a secure note entry"),
    "add-totp": ("totp", "Add a TOTP 2FA secret entry"),
    "add-license": ("license", "Add a software license key entry"),
    "add-identity": ("identity", "Add a personal identity entry"),
}

for shortcut, (entry_type, help_text) in TYPE_SHORTCUTS.items():
    p = sub.add_parser(shortcut, help=help_text)
    p.add_argument("service", help="Service/entry name")
    p.add_argument("--force", "-f", action="store_true", help="Overwrite if exists")
    # Add common flags
    p.add_argument("--notes", "-n", help="Additional notes")
    p.add_argument("--tags", "-t", help="Comma-separated tags")
    # Add type-specific flags (see Section 4.2)
    _add_type_flags(p, entry_type)
    # Set the type automatically
    p.set_defaults(type=entry_type)
```

### 6.7 Metadata Update (vault_meta.json)

The metadata file should include a type breakdown:

```json
{
  "version": 2,
  "created": "2026-05-09T00:00:00+00:00",
  "updated": "2026-05-09T00:00:00+00:00",
  "services": ["gmail", "stripe-live", "github-ed25519"],
  "total_entries": 3,
  "type_counts": {
    "credential": 1,
    "apikey": 1,
    "sshkey": 1
  }
}
```

This is derived from the entries on save — NEVER trusted as authoritative. The encrypted vault is always the source of truth.

### 6.8 Test Plan

| Test Category | Tests |
|---|---|
| v1 migration | Load v1 vault (no `type` fields) → all entries get `type: credential` → save writes `version: 2` |
| Type validation | Invalid type name → `ValueError` with message listing valid types |
| credential type | `add` with no `--type` → `type: credential`; old entries without `type` → `credential` on load |
| apikey type | `add-apikey` sets `type: apikey`; `key_prefix` auto-computed; `get --reveal` shows `key` |
| sshkey type | `add-sshkey` sets `type: sshkey`; no secret key stored |
| certificate type | `add-certificate` sets `type: certificate`; `check` shows expiry warning |
| note type | `add-note` sets `type: note`; `get` shows `content` by default |
| totp type | `add-totp` with `--otpauth` parses URI into fields; `secret` masked in `list` |
| license type | `add-license` sets `type: license`; `license_key` masked in `list` |
| identity type | `add-identity` sets `type: identity`; `national_id` masked in `get` without `--reveal` |
| list --type | `list --type apikey` shows only apikeys; `list --type invalid` → error |
| search type-aware | Search finds type-specific fields; `--type` filter works |
| get --reveal | Without flag: secrets masked. With flag: secrets shown. `--json`: always shown |
| KISTA_DIR | All types work with custom `KISTA_DIR` |
| Cross-type update | Updating type-specific field on wrong type → error |
| Forbidden type change | `update <svc> --type <new>` → error suggesting remove+re-add |

---

## 7. Security Considerations

### 7.1 No New Attack Surface

Adding new entry types does not change the encryption model. The vault is still a single Fernet-encrypted blob. All fields — whether `password`, `key`, `secret`, or `content` — are equally encrypted at rest. Type-specific sensitive fields gain no additional risk from the type system itself.

### 7.2 Sensitive Field Masking

The `--reveal` flag on `kista get` is the single toggle for showing sensitive values. Without it, all fields in a type's `secret_fields` list display as `***`. This is a **display-layer concern only** — the data is always in the vault, just not shown.

### 7.3 Search Does Not Leak Secrets

`kista search` matches against searchable fields but only outputs the service name, type, and identity column. It never outputs `password`, `key`, `secret`, `content`, `license_key`, or `national_id` in search results.

### 7.4 Metadata Never Contains Secrets

`vault_meta.json` continues to contain only service names, timestamps, entry counts, and type counts. No type-specific fields appear in metadata.

### 7.5 CLI Process List Safety

For all types with secret fields (`password`, `key`, `secret`, `license_key`, `content`), the `--*-file` and `--*-env` input mechanisms must be provided as secure alternatives to passing values on the command line, exactly as `--password-file` and `--password-env` work for credential type today.

| Type | Secret Field | File Input | Env Input |
|---|---|---|---|
| credential | `password` | `--password-file` | `--password-env` |
| apikey | `key` | `--key-file` | `--key-env` |
| note | `content` | `--content-file` | *(no env — often multiline)* |
| totp | `secret` | `--secret-file` | `--secret-env` |
| license | `license_key` | `--license-file` | `--license-env` |

sshkey, certificate, and identity types do not have single-value secrets that warrant file/env input paths. However, `--notes-file` could be added as a general convenience for any type in a future iteration.

---

## 8. KISTA_DIR Compatibility

All types use the same vault at `${KISTA_DIR}/vault.json.enc`. No per-type files, no subdirectories. The vault structure is:

```
${KISTA_DIR}/
├── .vault_key              # Fernet key (chmod 600)
├── vault.json.enc          # Encrypted vault — all types in one file (chmod 600)
└── vault_meta.json         # Plaintext metadata index (no secrets)
```

Default: `~/.hermes/credentials/` (overridden by `KISTA_DIR` env var).

No changes to file structure are required. KISTA_DIR works identically for all entry types because they all live in the same encrypted JSON blob.

---

## 9. Version Compatibility Matrix

| Vault Version | Entry Types | Behavior |
|---|---|---|
| v1 (no `version` field, or `version: 1`) | All entries are `credential` (implicit) | On load, inject `type: credential` into entries missing `type`. On save, write `version: 2`. |
| v2 (`version: 2`) | Mixed types allowed | All entries have explicit `type` field. Read normally. |

**Forward compatibility:** A v1 Kista reading a v2 vault would encounter unknown `type` fields and type-specific fields it doesn't understand. It would still work — it would just ignore the `type` and type-specific fields, treating everything like a flat credential. This is safe because unrecognized fields are simply preserved through the read-write cycle. No data loss occurs from a v1 client touching a v2 vault.

---

*The chest now holds more than passwords. It holds keys of all kinds — iron, silver, and runic. The typeling marks each, and the keeper knows which is which.*

*Rúnhild Svartdóttir, Architect*  
*Season of sowing, 2026*