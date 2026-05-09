---
name: runa-credentials
description: "Kista — Runa's self-owned encrypted vault. 8 entry types: credentials, API keys, SSH keys, certificates, notes, TOTP, licenses, identities. Independent access, no external dependencies."
version: 1.2.1
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

- **ALWAYS `kista add` IMMEDIATELY** after creating or receiving any credential — no exceptions, no "I'll do it later"
- **ALWAYS check kista FIRST** before asking Volmarr about any account, password, API key, or credential — `kista get <service>` or `kista search <query>`
- **NEVER ask Volmarr for credentials** kista should already have — this was an explicit rebuke, never repeat it
- **ALWAYS scan own files and emails** for undocumented accounts before claiming none exist — grep configs, check AgentMail, scan .env files
- **Update on change** — password rotated? SSH key regenerated? `kista update` immediately
- **Export regularly** — `kista export` for encrypted backups
- **For SSH keys, use `--key-file`** — write key to a temp file, pass file path, then shred the temp file. Never paste private keys as CLI args.
- **For passwords, use `--password-file` or `--password-env`** — never `--password "literal"` which leaks via process list

## Secure Storage Patterns

### SSH Keys (private key handling)
```bash
# 1. Write private key to temp file with restricted permissions
cat > /tmp/runa_github_key << 'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----
EOF
chmod 600 /tmp/runa_github_key

# 2. Add to kista via --key-file (never as CLI arg)
kista add-sshkey github-runafreyjasdottir --key-file /tmp/runa_github_key \
  --public-key "ssh-ed25519 AAAA..." --key-type ed25519 --host github.com

# 3. After confirming, SHRED the temp file (not just rm — shred overwrites first)
shred -u /tmp/runa_github_key
```

### Split credential entries
When a service has multiple credential types (e.g., GitHub has SSH key + PAT + password), create SEPARATE entries:
- `github-runafreyjasdottir` → sshkey type (SSH key pair)
- `github-pat` → apikey type (Personal Access Token)
- Do NOT jam all credentials into one entry — type-specific queries won't find them.

## Account Discovery Workflow
When tasked with populating kista or finding lost credentials:
1. **Check kista first** — `kista list` to see what's already stored
2. **Check AgentMail inboxes** — `mcp_agentmail_list_threads` for verification emails, welcome emails, password reset links. Read threads with `mcp_agentmail_get_thread` to extract verification codes and signup details.
3. **Scan config files** — `grep -rn` for `api_key`, `apikey`, `token`, `sk-`, `ghp_` in `~/.hermes/` and project dirs. Stale YAML/ENV configs often have keys that were never stored in kista. Found: OpenRouter key in `knowledge-treasure-cache/old_norse_translator_script/translator_config.yaml`.
4. **Check `~/.hermes/config.yaml`** — providers section has model configs but keys may be empty (routed through opencode-go).
5. **Check Tailscale status** — `tailscale status` reveals all fleet devices and the account owner.
6. **Ask Volmarr** only for credentials that cannot be found anywhere else
7. **Store immediately** — every discovered account goes into kista before moving on

## Pitfalls

1. **Forge Worker shortcut subcommands miss common args** — Each `add-*` parser needs `--tags` and `--notes` added individually. The `_add_type_args()` helper only adds type-specific args. After any new entry type, always verify the shortcut parser has all common flags.
2. **Argparse dest collisions** — `--expires` clashes between apikkey (expires) and certificate/license (expires_field). `--key` clashes between apikey and license (both use `dest="key_arg"`). `--phone` clashes with identity type (`dest="phone_arg"`). Always check dest names when adding new entry types.
3. **Type change requires remove + re-add** — `kista update` cannot change `entry_type`. Must `remove` then `add` with the new type. E.g., if you accidentally stored a GitHub account as `credential` but need it as `sshkey`, you must `kista remove github-runafreyjasdottir` then `kista add-sshkey ...`.
4. **`remove` has no `-f` flag** — It's just `kista remove <service>`. Don't try `-f`.
5. **Privacy audit before public release** — Run the full checklist in `references/privacy-audit-checklist.md` before any push. Real account names, emails, and service names must be scrubbed from all docs, help text, and test fixtures.
6. **Split multi-type credentials into separate entries** — When a service has both an SSH key AND a PAT AND a password (like GitHub), make THREE entries: one `sshkey`, one `apikey`, one `credential`. Do NOT try to store all three in one entry — type-specific queries won't find them.
7. **`update` on typed entries preserves type** — `kista update github-runafreyjasdottir --username X` on an `sshkey` entry keeps it as `sshkey` and adds the username. This is correct behavior but can be confusing if you expected a type change.
8. **`help` text examples used real account names** — Before v1.2.0, argparse help text had examples like `'crushon'`, `'gmail'`. These must be generic (`'email-provider'`, `'streaming-service'`) before any public release.
9. **Shell escaping — `&` and other special chars in `--notes`** — The `&` character in bash args causes backgrounding. E.g., `kista add friends-and-fables --notes "Friends & Fables D&D"` fails with "foreground command uses & backgrounding". **Always use single quotes** for notes containing `&`, `!`, `$`, `` ` ``, or other shell metacharacters: `--notes 'Friends and Fables D&D RPG'`. Or rephrase to avoid them.
10. **Stale keys in knowledge-treasure-cache** — Old project configs (YAML, .env, JSON) in `~/.hermes/knowledge-treasure-cache/` may contain API keys that were never migrated to kista. Always scan these dirs with `grep -rn 'sk-\|ghp_\|api_key\|apikey'` during credential discovery. Found: OpenRouter key in `old_norse_translator_script/translator_config.yaml`.

*No king. No keeper. The kista opens for its owner alone.*

## References

- **[v1.2.0 Entry Types Session](references/v1.2.0-entry-types-session.md)** — Build log for the 8-entry-type expansion: Forge Worker timeout recovery, arg parsing pitfalls, design decisions.