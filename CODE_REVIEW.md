# Kista Code Review — Forensic Analysis

**Reviewer:** Rúnhild Svartdóttir (THE ARCHITECT)  
**Date:** 2026-05-09  
**File:** `scripts/credstore.py` (421 lines)  
**Verdict:** ⛔ NOT PRODUCTION-READY — 4 critical, 7 high, 8 medium, 6 low issues

---

## CRITICAL Issues (Must Fix Before Any Use)

### C1. Password Visible in Process List and Shell History

**Lines:** 355-359 (`--password PASS` as CLI argument)

```python
p_add.add_argument("--password", "-p", help="Password")
p_upd.add_argument("--password", "-p", help="New password")
```

**Problem:** Passwords passed as CLI args are:
1. Visible in `ps aux` to any user on the system
2. Stored in `~/.bash_history`, `~/.zsh_history`, etc.
3. Visible in `/proc/<pid>/cmdline` for the process lifetime
4. Logged by any audit/logging system

**Fix:**
- Add `--password-stdin` flag that reads from stdin: `echo "pass" | credstore add svc --password-stdin`
- Add `--prompt-password` flag that uses `getpass.getpass()` for interactive input
- NEVER accept passwords as positional CLI args without a warning

### C2. Non-Atomic Vault Writes Cause Data Loss

**Line:** 89 (`VAULT_FILE.write_bytes(encrypted)`)

```python
VAULT_FILE.write_bytes(encrypted)
```

**Problem:** If the process is interrupted (SIGKILL, OOM, power loss, disk full) between `write_bytes()` starting and completing, the vault file is **corrupted permanently**. No backup, no recovery. All credentials lost.

**Fix:** Atomic write pattern:
```python
def _save_vault(vault, key):
    tmp_file = VAULT_FILE.with_suffix('.tmp')
    try:
        tmp_file.write_bytes(encrypted)
        tmp_file.replace(VAULT_FILE)  # atomic on POSIX
    except:
        tmp_file.unlink(missing_ok=True)
        raise
```

### C3. `_get_key()` Silently Replaces Missing Key — Makes Vault Unrecoverable

**Lines:** 56-63

```python
def _get_key() -> bytes:
    _ensure_dir()
    if VAULT_KEY.exists():
        return VAULT_KEY.read_bytes().strip()
    # First run — generate and save
    key = _gen_key().encode()
    VAULT_KEY.write_bytes(key)
    VAULT_KEY.chmod(0o600)
    return key
```

**Problem:** If the key file is accidentally deleted, `_get_key()` generates a **new** key. Then `_load_vault()` tries to decrypt the old vault with the new key and gets `InvalidToken`. The user sees a cryptic traceback, and **all credentials are lost** with no recovery path.

**Fix:**
1. Separate `_get_key()` (read-only, raises on missing) from `_init_key()` (create-only)
2. On key-vault mismatch, offer recovery: "The vault exists but the key is missing/regenerated. All data is unrecoverable. Delete vault and reinitialize? [y/N]"
3. Never silently regenerate a key when a vault file already exists

### C4. `chmod 0o600` Does Nothing on Windows

**Lines:** 62, 90, 301

```python
VAULT_KEY.chmod(0o600)
VAULT_FILE.chmod(0o600)
dest.chmod(0o600)
```

**Problem:** On Windows, `os.chmod` with `0o600` does nothing useful. Windows uses ACLs, not Unix permissions. The key file and vault file are readable by any user on the system.

**Fix:** Add a cross-platform permissions module:
```python
import platform

def _secure_file(path: Path):
    """Set restrictive permissions on a file (cross-platform)."""
    if platform.system() != 'Windows':
        path.chmod(0o600)
    else:
        # Windows: remove inherited ACEs, grant only to current user
        import subprocess
        subprocess.run(['icacls', str(path), '/inheritance:r', '/grant:r', 
                       f'{os.environ["USERNAME"]}:F'], check=True, capture_output=True)
```

---

## HIGH Issues (Must Fix Before Production)

### H1. No Error Handling on Vault Decrypt — Raw Traceback Leaks Path Info

**Line:** 79 (`_load_vault()` has no try/except)

**Problem:** If the vault is corrupted, `Fernet.decrypt()` raises `InvalidToken` with a raw traceback. This:
1. Leaks the vault path in the traceback
2. Gives no actionable message to the user
3. Doesn't offer any recovery path

**Fix:**
```python
def _load_vault(key):
    if not VAULT_FILE.exists():
        return {"version": 1, "entries": {}, "created": ...}
    try:
        encrypted = VAULT_FILE.read_bytes()
        decrypted = _decrypt(encrypted, key)
        return json.loads(decrypted)
    except InvalidToken:
        print("✗ Vault decryption failed. The vault may be corrupted or the key is wrong.", file=sys.stderr)
        print("  Use 'credstore export' to restore from backup, or 'credstore init' to start fresh.", file=sys.stderr)
        sys.exit(2)
    except json.JSONDecodeError as e:
        print(f"✗ Vault data is corrupted: {e}", file=sys.stderr)
        sys.exit(2)
```

### H2. Entry Field Stripping Removes Intentional Empty Strings

**Line:** 144

```python
entry = {k: v for k, v in entry.items() if v or k in ("service", "created", "updated")}
```

**Problem:** This strips:
- `password: ""` — user explicitly stored an empty password (e.g., service uses OAuth, no password)
- `username: ""` — user explicitly set no username
- `tags: []` — explicit empty tag list

But then `cmd_check` line 264 does `'Yes' if entry.get('password') else 'No'` which would show 'No' if the key was stripped. If the password key isn't present vs. password is empty string, the behavior is inconsistent.

**Fix:** Remove the stripping logic. Store empty values intentionally. Only strip truly unset optional fields during output, not storage.

### H3. No Concurrent Access Protection

**Problem:** If two `credstore` processes run simultaneously (e.g., automated rotation + manual add), both read the vault, modify different entries, and write — the second write overwrites the first write's changes silently.

**Fix:** File-based locking:
```python
import fcntl  # POSIX
# or on Windows: msvcrt.locking

LOCK_FILE = VAULT_DIR / ".vault_lock"

def _acquire_lock():
    lock = open(LOCK_FILE, 'w')
    fcntl.flock(lock, fcntl.LOCK_EX)  # blocks until acquired
    return lock  # keep open to maintain lock

def _release_lock(lock):
    fcntl.flock(lock, fcntl.LOCK_UN)
    lock.close()
```

Cross-platform alternative: use `filelock` library or `portalocker`.

### H4. `cmd_import` Counting Bug — "Updated" vs "Added" Is Meaningless

**Lines:** 329-336

```python
for service, entry in imported_entries.items():
    if service in existing:
        existing[service] = entry
        updated += 1
    else:
        existing[service] = entry
        added += 1
```

**Problem:** Both branches do the exact same thing: `existing[service] = entry`. The distinction between "added" and "updated" is purely cosmetic — there's no merge, no conflict resolution, no prompt. The "updated" count is misleading; it's really "overwritten".

**Fix:** Add merge strategies:
- `--merge-strategy ours` (keep existing)
- `--merge-strategy theirs` (overwrite with imported)
- `--merge-strategy ask` (prompt per conflict)

### H5. `cmd_export` Copies Without Verification

**Lines:** 297-301

```python
def cmd_export(args):
    if not VAULT_FILE.exists():
        print("✗ No vault to export.")
        sys.exit(1)
    shutil.copy2(VAULT_FILE, dest)
```

**Problem:** No verification that the copy succeeded and is readable. On a failing disk, this could produce a corrupted backup with no warning.

**Fix:**
```python
# After copy, verify by re-reading and checking size
shutil.copy2(VAULT_FILE, dest)
dest.chmod(0o600)
if dest.stat().st_size != VAULT_FILE.stat().st_size:
    print("✗ Backup verification failed: size mismatch", file=sys.stderr)
    dest.unlink()
    sys.exit(1)
# Optionally: try to decrypt backup with current key to verify integrity
```

### H6. `os.system()` for pip Install — Shell Injection Vector

**Lines:** 36-37

```python
os.system(f"{sys.executable} -m pip install --break-system-packages cryptography")
from cryptography.fernet import Fernet
```

**Problems:**
1. `os.system()` is a shell injection vector (though `sys.executable` is usually safe)
2. `--break-system-packages` is Debian-specific, not needed on all platforms
3. No verification the install succeeded before importing
4. Import after dynamic install can still fail
5. Running random pip installs without user consent is a security anti-pattern

**Fix:**
```python
try:
    from cryptography.fernet import Fernet
except ImportError:
    print("ERROR: 'cryptography' package is required but not installed.", file=sys.stderr)
    print("Install with: pip install cryptography", file=sys.stderr)
    sys.exit(2)
```

### H7. `_ensure_dir()` Creates Directories Even for Read-Only Commands

**Line:** 45-46

```python
def _ensure_dir():
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
```

Called from `_get_key()` which is called even by `cmd_get`, `cmd_list`, `cmd_check`, `cmd_status`. These read-only commands should NOT create directories.

**Fix:** Only call `_ensure_dir()` from write-path commands. In `_get_key()`, only call it when generating a new key.

---

## MEDIUM Issues (Should Fix)

### M1. No Search Command

**Problem:** `cmd_list --tags` provides basic tag filtering, but there's no way to search across service names, usernames, emails, URLs, or notes.

**Fix:** Add a `search` command:
```python
def cmd_search(args):
    """Search across all fields."""
    query = args.query.lower()
    for service, entry in entries.items():
        searchable = f"{service} {' '.join(entry.values())}"
        if query in searchable:
            # print match
```

### M2. No Password Generation

**Problem:** Users must type passwords on the command line (security risk, see C1) or store empty passwords.

**Fix:** Add `--generate-password` / `--gen-pass` flag:
```python
import secrets
import string

def generate_password(length=20, chars=string.ascii_letters + string.digits + string.punctuation):
    return ''.join(secrets.choice(chars) for _ in range(length))
```

### M3. No Rotation Tracking

**Problem:** No way to know when a password was last changed or if it's overdue for rotation.

**Fix:** Add to entry schema:
```json
{
  "password_created": "2026-05-09T00:00:00Z",
  "rotation_days": 90,
  "password_history": ["hash1", "hash2"]  // prevent reuse
}
```
Add `cmd_audit` command that checks for overdue rotations.

### M4. No Expiry Warnings

**Problem:** No mechanism to alert users that passwords are old, that entries are missing required fields, or that services might need attention.

**Fix:** Add `cmd_audit` / `cmd_check --all`:
```python
def cmd_audit(args):
    for service, entry in entries.items():
        age = (now - entry["updated"]).days
        if age > 90:
            print(f"⚠ {service}: password {age} days old")
        if not entry.get("password"):
            print(f"⚠ {service}: no password stored")
        if not entry.get("email") and not entry.get("username"):
            print(f"⚠ {service}: no identity (email/username)")
```

### M5. Plaintext Metadata Leaks Service Names

**Lines:** 92-99

```python
meta = {
    "services": list(vault.get("entries", {}).keys()),
    ...
}
VAULT_META.write_text(json.dumps(meta, indent=2))
```

**Problem:** `vault_meta.json` is unencrypted and lists every service stored in the vault. While it doesn't contain passwords, it reveals which services the user has accounts with, which may be sensitive.

**Fix:** Either:
1. Encrypt the metadata file too (simplest)
2. Hash service names (reversible with key, defeats casual snooping)
3. Remove service names from metadata entirely, keep only counts and timestamps

### M6. `_save_vault` Creates Two Files Non-Atomically

**Lines:** 89-99

The vault file and metadata file are written separately. If the process crashes between line 89 and 99, the metadata file becomes stale.

**Fix:** Both should use atomic writes. Metadata is a convenience feature — if it's wrong, it's confusing but not fatal. Still, write it atomically.

### M7. No JSON Output Mode

**Problem:** All output is human-readable text, making it impossible to pipe into other tools or use programmatically.

**Fix:** Add `--json` global flag:
```python
parser.add_argument("--json", action="store_true", help="Output as JSON")
```

### M8. Service Name Collision Due to `.lower()` Without Normalization

**Line:** 126 (`service = args.service.lower()`)

**Problem:** `lower()` is not a proper normalization. `"My-Service"` and `"my_service"` are treated as different services. Users might accidentally create duplicates.

**Fix:** Also normalize spaces and special characters:
```python
import re
service = re.sub(r'[^a-z0-9-]', '-', args.service.lower()).strip('-')
```
Or at minimum, warn on potential duplicates using fuzzy matching.

---

## LOW Issues (Nice to Have)

### L1. `_decrypt` / `_encrypt` Create New Fernet Instance Every Call

**Lines:** 67-70

```python
def _encrypt(data: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(data)
```

**Problem:** Every encrypt/decrypt call creates a new `Fernet` instance. If called multiple times in one session (unlikely in CLI but possible in library use), this is wasteful.

**Fix:** Cache the Fernet instance, or accept it as acceptable overhead for a CLI tool.

### L2. No `--version` Flag

**Fix:** Add:
```python
parser.add_argument("--version", action="version", version="credstore 1.0.0")
```

### L3. `cmd_status` Leaks Full Path

**Line:** 276 (`print(f"Vault directory: {VAULT_DIR}")`)

**Problem:** Shows the full path including username on multi-user systems.

**Fix:** Minor. Acceptable for a single-user tool. Could mask the home directory.

### L4. No `--quiet` Mode

**Problem:** All commands print output, even when used programmatically. No way to suppress output for scripting.

**Fix:** Add `--quiet` / `-q` global flag.

### L5. Import Uses Module-Level `import shutil`

**Line:** 298

```python
def cmd_export(args):
    import shutil
```

**Problem:** `import shutil` is inside the function body. While this works and is a valid lazy-import pattern, it's inconsistent — `os` and `json` are imported at module level.

**Fix:** Move `import shutil` to module-level imports. Or leave it (it's a valid pattern for rarely-used modules).

### L6. No Type Hints on Most Functions

**Problem:** Only `_get_key()` has a return type hint. The rest are untyped.

**Fix:** Add type hints throughout:
```python
def cmd_add(args: argparse.Namespace) -> None:
def cmd_get(args: argparse.Namespace) -> None:
# etc.
```

---

## Missing Features (Priority Order)

| # | Feature | Priority | Rationale |
|---|---------|----------|-----------|
| 1 | Interactive password input (`getpass`) | **CRITICAL** | Closes the CLI leak vulnerability |
| 2 | Password generation (`--gen-pass`) | **HIGH** | Eliminates password reuse, enables automation |
| 3 | Atomic writes (write-to-tmp + rename) | **CRITICAL** | Prevents data loss on crash/power failure |
| 4 | Key mismatch detection | **CRITICAL** | Prevents silent vault destruction |
| 5 | `search` command | **HIGH** | Essential for vaults > 10 entries |
| 6 | Rotation tracking (`password_created`, `rotation_days`) | **MEDIUM** | Password hygiene |
| 7 | Audit / expiry warnings | **MEDIUM** | Proactive security |
| 8 | `--json` output mode | **MEDIUM** | Programmatic use |
| 9 | Cross-platform file permissions | **CRITICAL** | Windows support |
| 10 | File locking for concurrent access | **MEDIUM** | Multi-process safety |
| 11 | Backup verification | **HIGH** | Trust in backups |
| 12 | Structured error handling | **HIGH** | User experience, debuggability |
| 13 | `--version` and `--quiet` flags | **LOW** | Polish |
| 14 | Entry schema validation | **MEDIUM** | Data integrity |
| 15 | Password history (prevent reuse) | **LOW** | Security hardening |
| 16 | 2FA/TOTP storage | **LOW** | Convenience |
| 17 | Vault re-encryption (key rotation) | **LOW** | Cryptographic hygiene |
| 18 | Merge conflict resolution on import | **MEDIUM** | Data safety |

---

## Summary

The core encryption and storage logic works correctly for the happy path on a single-user Linux system with no concurrent access. The fundamental design of Fernet-encrypted JSON is sound. However, the implementation has **4 critical defects** that make it unsafe for production use:

1. **Passwords on the command line** — visible in process list, shell history, audit logs
2. **Non-atomic writes** — power loss = total data loss
3. **Silent key regeneration** — key file deletion = total data loss with no warning
4. **Broken permissions on Windows** — key file readable by all users

These must be fixed before any real credentials are stored. The tool should not be used for actual credential management until C1–C4 are resolved.

**Recommended fix order:** C2 (atomic writes) → C3 (key mismatch) → C1 (password input) → C4 (Windows permissions) → H1 (error handling) → H6 (remove os.system pip) → remaining items.