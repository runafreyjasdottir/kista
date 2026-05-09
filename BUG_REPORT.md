# BUG_REPORT.md — Kista Security & Correctness Audit

**Auditor:** Sólrún Hvítmynd  
**Date:** 2026-05-09  
**Target:** `scripts/credstore.py` (421 lines, v1.0.0)  
**Platform:** Linux ARM64

---

## 1. SECURITY BUGS

### BUG-SEC-01: Passwords Exposed in Process Command Line (CRITICAL)
**Lines:** 353–359 (`--password`, `--username`, `--email`)

All sensitive fields are passed as CLI arguments. On Linux, any local user can see `/proc/<pid>/cmdline` while the command runs. This leaks passwords to any user on the system, and they persist in shell history, `~/.bash_history`, and process accounting logs.

**Impact:** Any process on the system can read user passwords in cleartext.
**Fix:** Accept sensitive fields via `--password-file <path>` or `-p -` (stdin), or use environment variables, or open `$EDITOR` with a temp file.

### BUG-SEC-02: Import Overwrites Without Confirmation (HIGH)
**Lines:** 329–335

`cmd_import` silently overwrites existing entries when the imported vault contains the same service name. There is no `--dry-run`, no confirmation prompt, and no merge strategy. The `updated` counter is misleading: it counts overwrites, not actual user-confirmed updates.

**Impact:** Cannot recover overwritten credentials without a separate backup.
**Fix:** Add `--merge` (skip existing) / `--overwrite` flag and require explicit opt-in for overwrite. At minimum, warn and require `--force`.

### BUG-SEC-03: Export Copies Ciphertext Without Integrity Check (MEDIUM)
**Lines:** 298–301

`cmd_export` does a raw `shutil.copy2` of the encrypted vault file without any integrity verification. There is no checksum, no signature, no verification that the file was written completely before copying. A partial write (from a concurrent process or crash) produces a corrupt backup with no warning.

**Impact:** Corrupt backups can be silently created.
**Fix:** Verify the vault can be decrypted before export; add a SHA-256 checksum file alongside the export.

### BUG-SEC-04: Vault Metadata Leaks Service Names in Cleartext (MEDIUM)
**Lines:** 92–99

`vault_meta.json` is stored unencrypted and contains every service name and the total entry count. This metadata reveals which services the user uses, which is valuable intelligence for an attacker.

**Impact:** Violates the principle that the vault should reveal nothing without the key.
**Fix:** Encrypt the metadata file with the same key, or remove it entirely (it's a convenience, not a requirement).

### BUG-SEC-05: No Key Derivation — Raw Fernet Key on Disk (MEDIUM)
**Lines:** 49–63

The Fernet key is stored as raw bytes on disk. If an attacker obtains the key file, they can decrypt the entire vault immediately. There is no key derivation function (PBKDF2, Argon2, scrypt) that would require a passphrase to derive the key. The `chmod 600` protection is trivially bypassed by root or by physical access to the storage device.

**Impact:** Key theft = total vault compromise with no passphrase barrier.
**Fix:** Derive the Fernet key from a passphrase using PBKDF2 or Argon2, or at minimum support an optional passphrase layer.

### BUG-SEC-06: `os.system()` for pip install — Command Injection Vector (HIGH)
**Line:** 36

```python
os.system(f"{sys.executable} -m pip install --break-system-packages cryptography")
```

`os.system` passes the command through a shell, which is a command injection risk if `sys.executable` is ever manipulated. The `--break-system-packages` flag is also a footgun on system Python.

**Impact:** Shell injection if `sys.executable` contains metacharacters (unlikely but possible in container environments). Degrades system package integrity.
**Fix:** Use `subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])` and consider a virtual environment requirement instead.

### BUG-SEC-07: No Secure Memory Handling (LOW)
Throughout the code, passwords are stored as plain Python strings. Python doesn't zero memory on deallocation. A long-running process may retain password strings in memory that can be recovered from core dumps or `/proc/<pid>/mem`.

**Impact:** Password residue in memory after operations.
**Fix:** Acceptable for this threat model, but worth noting. In a high-security context, use `bytearray` with explicit `del` and consider `mlock()`.

---

## 2. MISSING ERROR HANDLING PATHS

### BUG-ERR-01: Corrupt Vault File — No Recovery, Silent Failure (HIGH)
**Lines:** 74–80 (`_load_vault`)

If `vault.json.enc` is truncated, corrupted, or contains invalid ciphertext, `_decrypt` raises `cryptography.fernet.InvalidToken` which propagates as an unhandled exception with a raw traceback. No useful error message, no suggestion of recovery, no backup restoration path.

**Fix:** Catch `InvalidToken` and `json.JSONDecodeError`; provide actionable error messages; offer to restore from the most recent export.

### BUG-ERR-02: Permission Errors on Key/Vault Files — Unhandled (MEDIUM)
**Lines:** 58, 61, 89, 99

`read_bytes()`, `write_bytes()`, `write_text()`, and `chmod()` all raise `PermissionError` if the files have wrong ownership or the process lacks write permission. These are never caught.

**Fix:** Catch `PermissionError` and print a message with the expected ownership/permissions and how to fix them.

### BUG-ERR-03: Disk Full — Silent Data Loss (MEDIUM)
**Lines:** 89 (`VAULT_FILE.write_bytes`)

On systems with limited storage, `write_bytes` can fail due to `OSError: [Errno 28] No space left on device`. Because the write happens _before_ any integrity check, a partial write could leave the vault in a corrupt state (the previous content is already gone if Python's buffered write partially flushed).

**Fix:** Write to a temporary file first, then atomically rename (`os.rename`) over the target. This also fixes the race condition (BUG-RACE-01).

### BUG-ERR-04: Key File Truncation = Total Data Loss (HIGH)
**Lines:** 58–63

If `VAULT_KEY.read_bytes()` returns an empty or truncated key (e.g., from a partial write crash), `.strip()` on empty bytes returns `b''`. `Fernet(b'')` will raise an opaque `ValueError`. The vault data is still intact, but the "key" file is corrupted and the data is permanently inaccessible.

**Fix:** Validate the key length (Fernet keys are exactly 44 URL-safe base64-encoded bytes). If invalid, refuse to overwrite and warn about potential data loss.

### BUG-ERR-05: Missing `argparse` Subcommand = Silent Exit (LOW)
**Line:** 401–403

If the user mistypes a command (e.g., `credstore.py ad email-provider`), argparse prints help and exits 0 (success), which could be misinterpreted by scripts as "operation succeeded."

**Fix:** Exit with code 1 or 2 for unknown/missing subcommands.

### BUG-ERR-06: No Validation of Imported JSON Structure (MEDIUM)
**Lines:** 316 (`json.loads(decrypted)`)

The import result is assumed to be a dict with `"entries"`. If the imported file decrypts but contains `{"entries": null}` or a completely different structure, the loop at line 329 will raise `AttributeError` or `TypeError`.

**Fix:** Validate the structure: `if not isinstance(imported, dict) or "entries" not in imported: ...`

### BUG-ERR-07: Empty `.strip()` on Tags Produces `[\"\"]` (LOW)
**Line:** 138, 225

When `args.tags` is provided but contains only whitespace or commas (e.g., `--tags ",,"` or `--tags "  "`), the comprehension `[t.strip() for t in args.tags.split(",")]` produces `["", "", ""]` or `["a"]`. These empty strings are stored as tags and pollute tag filtering in `cmd_list`.

**Fix:** Filter out empty strings: `[t.strip() for t in args.tags.split(",") if t.strip()]`

---

## 3. CROSS-PLATFORM COMPATIBILITY ISSUES

### BUG-XPLAT-01: `Path.chmod(0o600)` Ignores umask Masking (LOW)
**Lines:** 62, 90, 301

On some Linux configurations and NFS mounts, `chmod(0o600)` may not behave as expected due to POSIX ACLs, umask interference, or filesystem restrictions. On default ext4, this works fine, but it's not robust.

**Fix:** Verify the permissions after setting them with `os.chmod` and `os.stat`, or use `os.open`/`os.fdopen` with mode flags.

### BUG-XPLAT-02: `os.system` Is Platform-Dependent (LOW)
**Line:** 36

`os.system` uses `/bin/sh`, which differs between distributions (dash vs bash). The pip install command may fail on minimal containers.

**Fix:** Already noted in BUG-SEC-06; use `subprocess` instead.

### BUG-XPLAT-03: No Windows Compatibility (INFORMATIONAL)
`Path.home()` and `Path` operations work cross-platform, but `chmod(0o600)` is a no-op on Windows (FAT32/NTFS), and the `.vault_key` dot-file convention is Unix-specific. This is irrelevant for Linux deployments but noted for completeness.

---

## 4. RACE CONDITIONS & CONCURRENT ACCESS

### BUG-RACE-01: TOCTOU — Read-Modify-Write Without Locking (CRITICAL)
**Lines:** All mutation commands (`add`, `update`, `remove`, `import`)

Every mutation follows: `(1) load vault → (2) modify in memory → (3) save vault`. If two processes run simultaneously (e.g., one user adds a credential while a script updates another), the second write overwrites the first's changes.

**Impact:** Data loss under concurrent use.
**Fix:** Use `fcntl.flock` (Linux file locking) or a `.lock` file with PID-based contention resolution.

### BUG-RACE-02: Non-Atomic Write (HIGH)
**Line:** 89 (`VAULT_FILE.write_bytes(encrypted)`)

`write_bytes` is not atomic. A crash or power loss during write leaves either the old data (if Python hasn't flushed) or a corrupt partial file (if it has). With `ensure_ascii=False` and long passwords, the encrypted blob can be several KB.

**Fix:** Write to `vault.json.enc.tmp`, then `os.rename()` (atomic on same filesystem).

### BUG-RACE-03: Key File Non-Atomic Write (MEDIUM)
**Line:** 61 (`VAULT_KEY.write_bytes(key)`)

Same non-atomic write problem as BUG-RACE-02 for the key file, with the added risk that a partial key makes the vault permanently undecryptable.

**Fix:** Same — write-then-rename pattern.

---

## 5. INPUT VALIDATION GAPS

### BUG-VAL-01: No Validation on Service Names (MEDIUM)
**Line:** 126 (`service = args.service.lower()`)

A service name can be empty string (`credstore.py add ""`), contain newlines, null bytes, path traversal sequences (`../../etc/passwd`), or extremely long strings. The `.lower()` conversion means services differing only by case (`GMail` vs `gmail`) silently collide.

**Fix:** Validate: non-empty, max length (e.g., 128 chars), no path separators or null bytes, alphanumeric + `_-.` only.

### BUG-VAL-02: No Length Limit on Passwords or Other Fields (LOW)
**Lines:** 131–137

There's no upper bound on field lengths. A 10 MB password string will be encrypted and stored, bloating the vault and potentially causing memory issues.

**Fix:** Enforce reasonable length limits (e.g., 4096 chars per field).

### BUG-VAL-03: No Email/URL Format Validation (LOW)
**Lines:** 135–136

`--email` and `--url` accept arbitrary strings. While not dangerous, it means typographic errors are silently stored.

**Fix:** Optional basic validation (contains `@`, starts with `http`).

### BUG-VAL-04: Tags Not Lowercased (LOW)
**Line:** 138, 225

Service names are `.lower()`-ed but tags are not. `--tags "Email"` and `--tags "email"` are stored as different tags, and the `cmd_list` tag filter lowercases the _filter_ but not the _stored tags_, causing case-sensitive mismatches.

**Fix:** Lowercase tags on storage: `[t.strip().lower() for t in ...]`

### BUG-VAL-05: `--force` Flag on `add` Silently Overwrites (MEDIUM)
**Line:** 127–128

`--force` on `add` completely replaces an existing entry, deleting all fields not re-specified. There is no warning, no diff display, no confirmation prompt.

**Fix:** Show the old entry and require confirmation, or merge fields instead of replacing.

---

## 6. ENCRYPTION WEAKNESSES

### BUG-ENC-01: No Integrity Verification Beyond Fernet's HMAC (LOW)
Fernet includes HMAC-SHA256 for tamper detection, which is good. However, there is no separate key-rotation mechanism. If a key is compromised, there is no way to re-encrypt the vault with a new key.

**Fix:** Add a `rotate-key` command that decrypts with the old key and re-encrypts with a new key.

### BUG-ENC-02: No Key Stretching (MEDIUM)
As noted in BUG-SEC-05, the key is raw — no PBKDF2, no salt, no iterations. This means the key is exactly as strong as its entropy source (32 bytes from `os.urandom`). This is adequate but there is no defense-in-depth against key file theft.

### BUG-ENC-03: No Version Negotiation on Import (LOW)
**Line:** 316

When importing, the version field is not checked. If a future version changes the vault schema, importing a v2 vault into a v1 tool would silently misinterpret data.

**Fix:** Check `imported.get("version", 1) <= vault.get("version", 1)` and warn or reject on version mismatch.

---

## 7. MISSING TEST COVERAGE

The project has **zero tests**. No `tests/` directory exists. The following areas require test coverage:

| Area | Status |
|---|---|
| `cmd_init` — fresh and re-init | ❌ None |
| `cmd_add` — normal, duplicate, force, empty fields | ❌ None |
| `cmd_get` — found, not found, case insensitive | ❌ None |
| `cmd_list` — empty, filtered, unfiltered | ❌ None |
| `cmd_update` — single field, multiple fields, nonexistent | ❌ None |
| `cmd_remove` — found, not found | ❌ None |
| `cmd_check` — found, not found, partial entry | ❌ None |
| `cmd_status` — initialized, uninitialized | ❌ None |
| `cmd_export` — normal, no vault | ❌ None |
| `cmd_import` — merge, conflict, corrupt file, wrong key | ❌ None |
| Corrupt vault file | ❌ None |
| Corrupt/missing key file | ❌ None |
| Unicode/emoji in passwords | ❌ None |
| Empty vault operations | ❌ None |
| Very long passwords | ❌ None |
| Concurrent access | ❌ None |
| Permission errors | ❌ None |

---

## Summary

| Severity | Count |
|---|---|
| CRITICAL | 2 (BUG-SEC-01, BUG-RACE-01) |
| HIGH | 5 (BUG-SEC-02, BUG-SEC-06, BUG-ERR-01, BUG-ERR-04, BUG-RACE-02) |
| MEDIUM | 8 (BUG-SEC-03, BUG-SEC-04, BUG-ERR-02, BUG-ERR-03, BUG-ERR-06, BUG-VAL-01, BUG-VAL-05, BUG-ENC-02) |
| LOW | 11 (BUG-SEC-07, BUG-ERR-05, BUG-ERR-07, BUG-VAL-02, BUG-VAL-03, BUG-VAL-04, BUG-XPLAT-01, BUG-XPLAT-02, BUG-XPLAT-03, BUG-ENC-01, BUG-ENC-03) |

**Total findings: 30**

The two most urgent fixes are:
1. **Prevent password leakage via CLI arguments** (BUG-SEC-01)
2. **Add file locking and atomic writes** (BUG-RACE-01, BUG-RACE-02)