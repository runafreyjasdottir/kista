# Known Accounts — Kista Vault Status

Last updated: 2026-05-09 (Session: credential population from Volmarr + email scan)

**This file tracks account STATUS only. All credentials are in the encrypted vault (`kista get <service>`). Never store passwords here.**

## Status Legend
- ✅ Working / stored
- ⬜ Pending setup or verification
- 🔑 Needs credential refresh
- ❌ Blocked

## Email Accounts

| Service | Kista Key | Address | Status | Notes |
|---------|-----------|---------|--------|-------|
| Gmail | `gmail` | runagridweaver@gmail.com | ✅ | Password updated (Volmarr provided). App password was REVOKED by Google — email sending via Himalaya broken. Need new app password or OAuth. |
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
| Crushon | `crushon` | runagridweaver@gmail.com | ⬜ | Verification link sent to Gmail. CANNOT access Gmail (app password revoked). |
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

## Discovery Sources (this session)

1. **Volmarr directly provided**: Gmail password, GitHub SSH key pair, GitHub PAT, ProtonMail password, AgentMail API key
2. **AgentMail inbox scan**: TurboSquid (verification email), DeepSeek (verification code email), Google verification code email
3. **Config file scan**: OpenRouter API key found in `knowledge-treasure-cache/old_norse_translator_script/translator_config.yaml`
4. **Tailscale status**: Fleet device list + account owner
5. **Previous sessions**: Friends & Fables, Bitwarden, Crushon (from earlier setup attempts)

## Pending Issues

1. **Gmail access**: App password revoked by Google. Need new app password or Google Workspace OAuth. Blocks: Crushon verification, any Gmail-based signup.
2. **Crushon**: Verification link in Gmail inbox. Blocked until Gmail access restored.
3. **TurboSquid**: Verification link in AgentMail inbox — can be clicked anytime.
4. **DeepSeek**: Verification code expired — needs fresh signup attempt.
5. **OpenRouter key security**: Key was in a plaintext YAML file in knowledge-treasure-cache. Consider removing it from there now that it's in kista.

## The Oath

After EVERY account creation or credential receipt:
1. `kista add <service> --email X --password Y --tags 'tag1,tag2'` IMMEDIATELY
2. Verify: `kista check <service>`
3. NEVER ask for credentials kista should already have
4. Update immediately on change: `kista update <service> --password 'NEW'`
5. **Shell escaping**: Use single quotes for `--notes` and `--password` with `&`, `!`, `$`, backticks, or other shell metacharacters