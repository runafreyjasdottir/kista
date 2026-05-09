# Privacy Audit Checklist for Public Release

Used before publishing any tool/app to a public GitHub repository.
Run EVERY check before pushing. Zero personal data hits required.

## Grep Commands

```bash
# Personal data sweep (zero hits required, excluding allowed patterns)
grep -rn "runa\|gridweaver\|freyja\|volmarr\|hraban\|storm2400\|Freyja@\|@agentmail\|runagridweaver\|volmarrwyrd" \
  scripts/ tests/ pyproject.toml SKILL.md README.md *.md 2>/dev/null | \
  grep -v "github.com/runafreyjasdottir" | \
  grep -v "Runa Gridweaver" | \
  grep -v "test_"

# Hardcoded absolute paths (should use Path.home() + KISTA_DIR env)
grep -rn "home/pi\|/Users/\|/home/user\|C:\\\\" scripts/ tests/

# Real IP addresses
grep -rn "192\.168\.\|10\.\|172\." scripts/ tests/

# Real API keys or tokens
grep -rn "AAAA\|sk-\|ghp_\|xoxb-\|AKIA" scripts/ tests/
```

## Manual Review Checklist

- [ ] No real email addresses in source, tests, or docs (use `user@example.com`)
- [ ] No real usernames in source, tests, or docs (use `your-username`)
- [ ] No real service names that reveal personal accounts (use `email-provider`, `streaming-service`)
- [ ] No hardcoded absolute paths — use `Path.home()` with `KISTA_DIR` env var override
- [ ] No API keys, tokens, or passwords in any file
- [ ] SKILL.md has no personal account names (use `kista list` reference instead)
- [ ] Test fixtures use generic data only
- [ ] `.gitignore` excludes vault data (`*.enc`, `.vault_key`, `vault_meta.json`)
- [ ] `LICENSE` file present and matches `pyproject.toml`
- [ ] `README.md` includes Testing and License sections
- [ ] Git identity correct: `Runa Gridweaver` / `runa@hrabanazviking.com`
- [ ] Push from correct account: `gh auth switch --user runafreyjasdottir`
- [ ] Remove plaintext API keys from knowledge-treasure-cache and other config dirs after migrating to kista

## Session History

### v1.2.0 Public Release (2026-05-09)
- Privacy audit: 3 sweeps — found real account names in SKILL.md, help text examples (`'crushon'`, `'gmail'`), hardcoded `Path.home()` path
- Fixed: SKILL.md genericized, argparse help text genericized, vault path → `KISTA_DIR` env var
- Shell escaping: `&` in `--notes "Friends & Fables"` caused bash backgrounding → always use single quotes
- OpenRouter API key found in plaintext YAML in knowledge-treasure-cache → stored in kista, should be removed from config
- 17 accounts populated from: Volmarr direct, AgentMail inbox scan, config file grep, Tailscale status
- Public repo: https://github.com/runafreyjasdottir/kista (MIT, v1.2.0 tag)

### v1.1.0 → v1.2.0 (2026-05-09)
- Added 7 entry types: apikey, sshkey, certificate, note, totp, license, identity
- Forge Worker timed out at 600s — completed manually
- Pitfall: shortcut subcommands missing `--tags` and `--notes` flags (patched post-Forge)
- Pitfall: argparse `--expires`, `--key`, `--phone` dest collisions between types
- 148 tests passing, pushed with v1.2.0 tag

### v1.0.0 → v1.1.0 (2026-05-09)
- Mythic Engineering 6-subagent build (Skáld, Architect, Auditor, Forge Worker, Cartographer, Scribe)
- 4 critical + 7 high + 8 medium bugs found by Sólrún (Auditor), fixed by Eldra (Forge Worker)
- Privacy audit pulled real account names from SKILL.md and help text
- Vault path hardcoded → `KISTA_DIR` env var override added
- 102 tests, pushed with v1.1.0 tag