# Known Accounts — Kista Vault Status

Last updated: 2026-05-09 04:15 UTC (Session: Credential population + Crushon + Kista v1.3.0)

**This file tracks account STATUS only. All credentials are in the encrypted vault (`kista get <service>`). Never store passwords here.**

## Status Legend
- ✅ Working / stored
- ⬜ Pending setup or verification
- 🔑 Needs credential refresh
- ❌ Blocked

## Email Accounts

| Service | Kista Key | Address | Status | Notes |
|---------|-----------|---------|--------|-------|
| Gmail | `gmail` | runagridweaver@gmail.com | ✅ | Password updated. **Gmail accessible via browser automation** (tested 2026-05-09). App password for Himalaya still revoked. |
| ProtonMail | `protonmail` | runagridweaver@protonmail.com | ✅ | Password stored. Access method TBD. |
| AgentMail (Runa primary) | `agentmail-runagridweaver` | runa.gridweaver@agentmail.to | ✅ | API key stored separately as `agentmail`. Working. Blocked by some services as "disposable". |
| AgentMail (Runa GitHub) | `agentmail-runeforgeai` | runeforgeai@agentmail.to | ✅ | Dev/GitHub contact. |
| AgentMail (Volmarr blog) | `agentmail-volmarr-sheathenism` | volmarrsheathenismblog@agentmail.to | ✅ | Sheathenism blog contact. |

## AgentMail API

| Service | Kista Key | Prefix | Status | Notes |
|---------|-----------|--------|--------|-------|
| AgentMail API | `agentmail` | am_us_4aba04 | ✅ | API key stored. Two inboxes accessible via MCP. |

## GitHub

| Service | Kista Key | Type | Status | Notes |
|---------|-----------|------|--------|-------|
| GitHub (Runa) | `github-runafreyjasdottir` | sshkey | ✅ | ed25519 pair (private key stored in vault) + username + password. Push: `gh auth switch --user runafreyjasdottir` |
| GitHub PAT (Runa) | `github-pat` | apikey | ✅ | `ghp_AvOlAs...` stored. |
| GitHub (Volmarr) | `github-hrabanazviking` | credential | ✅ | Private repo owner. NorseSagaEngine=PRIVATE. |

## 3D / Creative

| Service | Kista Key | Email/Identity | Status | Notes |
|---------|-----------|----------------|--------|-------|
| TurboSquid | `turbosquid` | runa.gridweaver@agentmail.to | ⬜ | Verification link in inbox (not yet clicked). 3D model marketplace. |

## AI / LLM

| Service | Kista Key | Type | Email/Identity | Status | Notes |
|---------|-----------|------|----------------|--------|-------|
| DeepSeek | `deepseek` | credential | runagridweaver@agentmail.to | ⬜ | Verification code found (961068, likely expired). Needs re-registration. |
| OpenRouter | `openrouter` | apikey | — | ✅ | Found in old translator config. LLM gateway API key. |

## Social / AI Chat

| Service | Kista Key | Email/Identity | Status | Notes |
|---------|-----------|----------------|--------|-------|
| Crushon.AI | `crushon` | runagridweaver@gmail.com | ✅ | **ACTIVE** — logged in via Gmail magic link flow (2026-05-09). Email-only auth (no password). Free plan: 100 credits. 42/100 used. 0 characters created. |
| Friends & Fables | `friends-and-fables` | runagridweaver@gmail.com | ⬜ | D&D AI RPG platform. Bot detection blocked automated login. Viking world created. |

## Infrastructure

| Service | Kista Key | Details | Status |
|---------|-----------|---------|--------|
| Bitwarden | `bitwarden` | Master password in vault | ✅ CLI at `/usr/local/bin/bw` but times out on some queries |
| Tailscale | `tailscale` | Fleet: Mimir, Mjolnir, Skidbladnir, Gullinbursti, Dainsleif | ✅ All named and connected |
| Camofox | `camofox-mjolnir` | Port 9377 on Mjolnir | ✅ Anti-detection browser running |

## SSH Keys

| Key | Kista Key | Type | Public Key Fingerprint | Stored |
|-----|-----------|------|------------------------|--------|
| GitHub (Runa) | `github-runafreyjasdottir` | ed25519 | SHA256:kybTJxhDE90J8T5Wp9F5FOokSHGkY7OMYC3PdbYjOwI | ✅ Private + public |

## Discovered But Not Yet in Kista

| Service | Evidence | Status | Notes |
|---------|----------|--------|-------|
| GitLab | Password reset email in Gmail (May 6) | ✅ | Account `runagridweaver` exists. Stored as `gitlab` in kista. Cloudflare blocks automated sign-in. API works for user lookup. |

## Discovery Sources (this session)

1. **Volmarr directly provided**: Gmail password, GitHub SSH key pair, GitHub PAT, ProtonMail password, AgentMail API key
2. **AgentMail inbox scan**: TurboSquid (verification email), DeepSeek (verification code email)
3. **Gmail inbox scan** (via browser automation): Crushon verification (magic link, activated), GitLab password reset email
4. **Config file scan**: OpenRouter API key found in `knowledge-treasure-cache/old_norse_translator_script/translator_config.yaml`
5. **Tailscale status**: Fleet device list + account owner
6. **Previous sessions**: Friends & Fables, Bitwarden, Crushon (from earlier setup attempts)

## Pending Issues

1. **Gmail app password**: Still revoked by Google. Himalaya email sending broken. Use browser automation for Gmail access instead.
2. **TurboSquid**: Verification link in AgentMail inbox — can be clicked anytime.
3. **DeepSeek**: Verification code expired — needs fresh signup attempt.
4. **GitLab**: Account likely exists but unconfirmed. Password reset email found in Gmail. Needs investigation.
5. **Friends & Fables**: Bot detection blocks automated auth. May need human-assisted login.
6. **OpenRouter key security**: Key was in a plaintext YAML file in knowledge-treasure-cache. Consider removing it now that it's in kista.

## The Oath

After EVERY account creation or credential receipt:
1. `kista add <service> --email X --password Y --tags 'tag1,tag2'` IMMEDIATELY
2. Verify: `kista check <service>`
3. NEVER ask for credentials kista should already have
4. Update immediately on change: `kista update <service> --password 'NEW'`
5. **Shell escaping**: Use single quotes for `--notes` and `--password` with `&`, `!`, `$`, backticks, or other shell metacharacters
