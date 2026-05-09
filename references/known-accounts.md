# Known Accounts Status

Last updated: 2026-05-09

## Status Legend
- ✅ Working
- ⬜ Pending setup
- ❌ Blocked/broken
- 🔑 Needs credential refresh

## Email Accounts

| Service | Address | Status | Notes |
|---------|---------|--------|-------|
| Email Provider | user@example.com | 🔑 | App password expired/revoked. Need new app password or OAuth setup. |
| Email Provider | work-user@example.com | ✅ | Working. Disposable email filters may block this address. |
| Email Provider | dev-contact@example.com | ✅ | Dev contact + GitHub. |

## Social / Streaming Accounts

| Service | Email/Identity | Status | Notes |
|---------|---------------|--------|-------|
| Streaming | user@example.com | ⬜ | Verification link sent. Disposable email addresses may be BLOCKED. |
| GitHub | your-username | ✅ | Push: `gh auth switch --user your-username` |

## Infrastructure

| Service | Account | Status | Notes |
|---------|---------|--------|-------|
| Password Manager | user@example.com | ✅ | Master password in vault. |
| VPN | (via shared account) | ✅ | All devices connected. |
| Local API | On host | ✅ | Port 8642. |
| Media Server | On host | ✅ | Port 8443. |
| Web UI | On host | ✅ | Port 3000. |

## Kista Integration

All accounts above should also be stored in Kista (`kista add/get/list/check/search`). The vault is the canonical source. Use `kista list` to verify what's stored.

**Kista commands:**
```bash
kista add <service> --email X --password Y --tags "tag1,tag2"
kista get <service>        # Full details including password
kista check <service>      # Verify credential exists
kista search <query>       # Fuzzy search
kista update <service>     # Update fields
kista generate-password   # Random password generation
kista export               # Encrypted backup
```

**The Oath:** Store immediately after creation. Check before asking. Update on change.

## OAuth Setup

Status: **NOT SET UP** — no token file present. The setup script exists with full instructions, but OAuth was never completed. This is needed to read email programmatically.

### Required Steps
1. Create cloud project at console.example.com
2. Enable required APIs
3. Create OAuth 2.0 Desktop client credentials
4. Add your email as test user
5. Download client secret JSON
6. Run the setup script
7. Visit the auth URL, approve, paste redirect URL
8. Verify with the check script

## App Password Pitfall

Email providers may routinely revoke app passwords for "security reasons." The email client config may use an app password that returns `AUTHENTICATIONFAILED`.

**Fix:** Either generate a new App Password or complete OAuth setup (preferred, long-term solution).

## Account Creation Discipline

After EVERY account creation:
1. `kista add <service>` IMMEDIATELY — before moving on to anything else
2. Record the email, password, tags, and any setup notes
3. If credential setup requires multiple steps (e.g., email verification needed), mark status as `⬜ Pending` with clear next steps
4. Never ask for credentials that should already be in Kista