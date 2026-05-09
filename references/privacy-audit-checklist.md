# Privacy Audit Checklist for Public Release

Used before publishing any tool/app to a public GitHub repository.

## Grep Commands

```bash
# Run all of these before pushing. Zero hits required.
grep -rn "runa\|gridweaver\|freyja\|volmarr\|hraban\|storm2400\|Freyja@\|@agentmail\|runagridweaver\|volmarrwyrd" \
  scripts/ tests/ pyproject.toml SKILL.md *.md 2>/dev/null | \
  grep -v "github.com/runafreyjasdottir" | \
  grep -v "Runa Gridweaver" | \
  grep -v "test_"

# Check for hardcoded absolute paths
grep -rn "home/pi\|/Users/\|/home/user\|C:\\\\" scripts/ tests/

# Check for real IP addresses
grep -rn "192\.168\.\|10\.\|172\." scripts/ tests/

# Check for real API keys or tokens
grep -rn "AAAA\|sk-\|ghp_\|xoxb-\|AKIA" scripts/ tests/
```

## Manual Review Checklist

- [ ] No real email addresses in source, tests, or docs (use `user@example.com`)
- [ ] No real usernames in source, tests, or docs (use `your-username`)
- [ ] No real service names that reveal personal accounts (use `email-provider`, `streaming-service`)
- [ ] No hardcoded absolute paths — use `Path.home()` with env var override
- [ ] No API keys, tokens, or passwords in any file
- [ ] SKILL.md has no personal account names (use `kista list` reference instead)
- [ ] Test fixtures use generic data only
- [ ] `.gitignore` excludes vault data (`*.enc`, `.vault_key`, `vault_meta.json`)
- [ ] `LICENSE` file present and matches `pyproject.toml`
- [ ] `README.md` includes Testing and License sections
- [ ] Git identity correct: `Runa Gridweaver` / `runa@hrabanazviking.com`
- [ ] Push from correct account: `gh auth switch --user runafreyjasdottir`

## Kista Session Lessons (2026-05-09)

1. **Initial build was ad-hoc** — 4 critical bugs, 7 high, 8 medium found by ME Auditor
2. **SKILL.md contained real account names** — had to clean gmail, agentmail, crushon, bitwarden references
3. **Help text had real service names** — `'crushon', 'gmail'` → `'email-provider', 'streaming-service'`
4. **Vault path was hardcoded** — `~/.hermes/credentials` now uses `KISTA_DIR` env var override
5. **Camoufox on Pi** required `pip3 install camoufox && python3 -m camoufox fetch` before browser server would start

## Camoufox Setup on Pi 5 (ARM64)

The Camoufox browser server at `/home/pi/camofox-browser/` requires:
1. `pip3 install --break-system-packages camoufox`
2. `python3 -m camoufox fetch` (downloads Firefox binary)
3. Then start: `node node_modules/@askjo/camofox-browser/server.js`
4. Health check: `curl http://localhost:9377/health`