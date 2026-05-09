#!/usr/bin/env python3
"""
Runa's Credential Store — Self-owned, self-managed, self-accessible.
Encrypted credential vault that Runa can access independently.
No dependency on external password managers or Volmarr's help.

Also installable as 'kista' (Old Norse: strongbox/chest).

Usage:
  credstore.py add <service> [--username USER] [--password PASS] [--password-file FILE] [--password-env VAR]
                           [--email EMAIL] [--url URL] [--notes NOTES] [--tags TAGS]
  credstore.py get <service>            # Returns JSON with all fields
  credstore.py list [--tags TAG]        # List all services (passwords masked)
  credstore.py update <service> [fields...]  # Update specific fields
  credstore.py remove <service>         # Delete a credential entry
  credstore.py check <service>          # Verify credential exists and is valid
  credstore.py search <query>           # Fuzzy search across services and fields
  credstore.py export                   # Export all as encrypted backup
  credstore.py import <file> [--merge|--overwrite]  # Import from encrypted backup
  credstore.py init                     # Initialize the vault with a key
  credstore.py status                    # Show vault status
  credstore.py generate-password [--length N]  # Generate a random password
  credstore.py --version                # Show version

The encryption key is stored at ~/.hermes/credentials/.vault_key
This file is chmod 600 — only the pi user can read it.
Runa controls her own keys. No external dependencies.
"""

import argparse
import json
import os
import secrets
import string
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Fernet for symmetric encryption
try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    print("Installing cryptography package...")
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "cryptography"]
    )
    from cryptography.fernet import Fernet, InvalidToken

__version__ = "1.1.0"

VAULT_DIR = Path(os.environ.get("KISTA_DIR", str(Path.home() / ".hermes" / "credentials")))
VAULT_KEY = VAULT_DIR / ".vault_key"
VAULT_FILE = VAULT_DIR / "vault.json.enc"
VAULT_META = VAULT_DIR / "vault_meta.json"


def _ensure_dir():
    VAULT_DIR.mkdir(parents=True, exist_ok=True)


def _chmod_600(path: Path):
    """Set file permissions to 600 (owner read/write only), cross-platform safe."""
    try:
        path.chmod(0o600)
    except (OSError, NotImplementedError):
        # On Windows or restricted filesystems, chmod may fail or be a no-op
        pass


def _gen_key():
    """Generate a new Fernet encryption key."""
    return Fernet.generate_key().decode()


def _validate_key(key_bytes: bytes) -> bytes:
    """Validate that a key looks like a valid Fernet key.

    Fernet keys are 32 bytes of entropy, base64url-encoded to 44 characters.
    A truncated or empty key would make the vault permanently inaccessible.
    """
    stripped = key_bytes.strip()
    if len(stripped) != 44:
        raise ValueError(
            f"Invalid vault key: expected 44 bytes (base64url-encoded Fernet key), "
            f"got {len(stripped)} bytes. The key file may be truncated or corrupted. "
            f"Your vault data is still intact — do NOT regenerate the key or you will "
            f"lose access permanently. Check if the key file was partially written."
        )
    # Verify it decodes properly
    try:
        import base64
        decoded = base64.urlsafe_b64decode(stripped)
        if len(decoded) != 32:
            raise ValueError("Key does not decode to 32 bytes of entropy")
    except Exception as exc:
        raise ValueError(
            f"Vault key is corrupt and cannot be used. "
            f"Your vault data is still intact — do NOT regenerate the key. "
            f"Error: {exc}"
        ) from exc
    return stripped


def _get_key() -> bytes:
    """Get the vault encryption key, creating if needed.

    IMPORTANT: Never regenerates a key if vault data exists.
    If the key file is missing but the vault file exists, this is an error
    (vault data would be unrecoverable without the key).
    """
    _ensure_dir()
    if VAULT_KEY.exists():
        raw = VAULT_KEY.read_bytes()
        return _validate_key(raw)
    # No key file exists — check if vault data exists
    if VAULT_FILE.exists():
        # Vault data exists but key is missing — cannot recover
        print(
            f"✗ CRITICAL: Vault data exists at {VAULT_FILE} but the key file "
            f"{VAULT_KEY} is missing. Without the key, the vault data is "
            f"permanently inaccessible. If you have a key backup, restore it to "
            f"{VAULT_KEY}. Otherwise, you must re-initialize (this will destroy "
            f"the existing vault data).",
            file=sys.stderr,
        )
        sys.exit(1)
    # First run — no key and no vault data, safe to generate
    key = _gen_key().encode()
    VAULT_KEY.write_bytes(key)
    _chmod_600(VAULT_KEY)
    return key


def _encrypt(data: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(data)


def _decrypt(data: bytes, key: bytes) -> bytes:
    return Fernet(key).decrypt(data)


def _load_vault(key: bytes) -> dict:
    """Load and decrypt the vault with error recovery."""
    if not VAULT_FILE.exists():
        return {"version": 1, "entries": {}, "created": datetime.now(timezone.utc).isoformat()}
    encrypted = VAULT_FILE.read_bytes()
    try:
        decrypted = _decrypt(encrypted, key)
    except InvalidToken:
        print(
            f"✗ Cannot decrypt vault: the key does not match the encrypted data.\n"
            f"  This usually means the vault was encrypted with a different key.\n"
            f"  If you've recently re-initialized, your old vault data is lost.\n"
            f"  To start fresh, move {VAULT_FILE} aside and run 'init'.",
            file=sys.stderr,
        )
        sys.exit(1)
    try:
        return json.loads(decrypted)
    except json.JSONDecodeError as exc:
        print(
            f"✗ Vault data is corrupt (invalid JSON: {exc}).\n"
            f"  The decryption key is correct, but the data inside is not valid JSON.\n"
            f"  This may indicate a truncated write. If you have a backup, restore it.\n"
            f"  Vault file: {VAULT_FILE}",
            file=sys.stderr,
        )
        sys.exit(1)


def _atomic_write(path: Path, data: bytes):
    """Write data to a file atomically using temp file + os.replace().

    This prevents corruption from crashes during write and avoids the
    TOCTOU race condition (BUG-RACE-02).
    """
    _ensure_dir()
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp_path.write_bytes(data)
        os.replace(str(tmp_path), str(path))
    except BaseException:
        # Clean up tmp on any failure
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _save_vault(vault: dict, key: bytes):
    """Encrypt and save the vault atomically."""
    _ensure_dir()
    vault["updated"] = datetime.now(timezone.utc).isoformat()
    data = json.dumps(vault, indent=2, ensure_ascii=False).encode()
    encrypted = _encrypt(data, key)
    _atomic_write(VAULT_FILE, encrypted)
    _chmod_600(VAULT_FILE)
    # Update metadata (unencrypted — just service names and timestamps)
    meta = {
        "version": vault.get("version", 1),
        "created": vault.get("created", ""),
        "updated": vault.get("updated", ""),
        "services": list(vault.get("entries", {}).keys()),
        "total_entries": len(vault.get("entries", {})),
    }
    _atomic_write(VAULT_META, json.dumps(meta, indent=2).encode())


def _parse_tags(tags_str: str) -> list:
    """Parse comma-separated tags, filtering empty strings and lowering case."""
    if not tags_str:
        return []
    return [t.strip().lower() for t in tags_str.split(",") if t.strip()]


def _has_password_source(args) -> bool:
    """Check if any password source was explicitly provided."""
    return bool(
        (hasattr(args, "password_file") and args.password_file)
        or (hasattr(args, "password_env") and args.password_env)
        or (hasattr(args, "password") and args.password)
    )


def _resolve_password(args) -> str:
    """Resolve password from --password-file, --password-env, --password, or stdin.

    Priority: --password-file > --password-env > --password > stdin prompt (add only)
    Returns empty string if no password source provided (for update, this means "don't change").
    """
    if hasattr(args, "password_file") and args.password_file:
        try:
            return Path(args.password_file).read_text().strip()
        except (OSError, FileNotFoundError) as exc:
            print(f"✗ Cannot read password file: {exc}", file=sys.stderr)
            sys.exit(1)
    if hasattr(args, "password_env") and args.password_env:
        pw = os.environ.get(args.password_env)
        if pw is None:
            print(
                f"✗ Environment variable '{args.password_env}' is not set.",
                file=sys.stderr,
            )
            sys.exit(1)
        return pw
    if hasattr(args, "password") and args.password:
        return args.password
    # No password provided via any method — prompt for 'add' command only
    if getattr(args, "command", None) == "add" and sys.stdin.isatty():
        try:
            import getpass
            pw = getpass.getpass("Password (input hidden): ")
            return pw
        except (EOFError, KeyboardInterrupt):
            print("", file=sys.stderr)
            sys.exit(1)
    return ""


def cmd_init(args):
    """Initialize the vault."""
    _ensure_dir()
    if VAULT_KEY.exists() and VAULT_FILE.exists():
        print(f"✓ Vault already exists at {VAULT_DIR}")
        print(f"  Key: {VAULT_KEY}")
        print(f"  Data: {VAULT_FILE}")
        key = _get_key()
        vault = _load_vault(key)
        print(f"  Entries: {len(vault.get('entries', {}))}")
        return
    key = _get_key()
    vault = {"version": 1, "entries": {}, "created": datetime.now(timezone.utc).isoformat()}
    _save_vault(vault, key)
    print(f"✓ Vault initialized at {VAULT_DIR}")
    print(f"  Key: {VAULT_KEY} (chmod 600, owned by you)")


def cmd_add(args):
    """Add a new credential."""
    key = _get_key()
    vault = _load_vault(key)
    entries = vault.setdefault("entries", {})

    service = args.service.lower()
    if service in entries and not args.force:
        print(f"✗ Credential for '{service}' already exists. Use --force to overwrite or 'update' to modify.")
        sys.exit(1)

    password = _resolve_password(args)

    entry = {
        "service": service,
        "username": args.username or "",
        "password": password,
        "email": args.email or "",
        "url": args.url or "",
        "notes": args.notes or "",
        "tags": _parse_tags(args.tags) if args.tags else [],
        "created": datetime.now(timezone.utc).isoformat(),
        "updated": datetime.now(timezone.utc).isoformat(),
    }

    # Remove empty fields
    entry = {k: v for k, v in entry.items() if v or k in ("service", "created", "updated")}

    entries[service] = entry
    _save_vault(vault, key)
    print(f"✓ Added credential for '{service}'")
    if entry.get("email"):
        print(f"  Email: {entry['email']}")
    if entry.get("username"):
        print(f"  Username: {entry['username']}")


def cmd_get(args):
    """Get a credential (full details including password)."""
    key = _get_key()
    vault = _load_vault(key)
    entries = vault.get("entries", {})

    service = args.service.lower()
    if service not in entries:
        print(f"✗ No credential found for '{service}'")
        print(f"  Available: {', '.join(entries.keys()) or '(empty)'}")
        sys.exit(1)

    entry = entries[service]
    print(json.dumps(entry, indent=2, ensure_ascii=False))


def cmd_list(args):
    """List all credentials (passwords masked)."""
    key = _get_key()
    vault = _load_vault(key)
    entries = vault.get("entries", {})

    if not entries:
        print("No credentials stored yet. Use 'add' to create one.")
        return

    tag_filter = args.tags.lower() if args.tags else None

    print(f"{'Service':<25} {'Username/Email':<35} {'Tags':<20} {'Updated'}")
    print("-" * 100)

    for service, entry in sorted(entries.items()):
        tags = ", ".join(entry.get("tags", []))
        if tag_filter and tag_filter not in tags:
            continue
        identity = entry.get("email") or entry.get("username") or "(no identity)"
        updated = entry.get("updated", "?")[:10]
        print(f"{service:<25} {identity:<35} {tags:<20} {updated}")


def cmd_update(args):
    """Update specific fields of a credential."""
    key = _get_key()
    vault = _load_vault(key)
    entries = vault.get("entries", {})

    service = args.service.lower()
    if service not in entries:
        print(f"✗ No credential found for '{service}'")
        sys.exit(1)

    entry = entries[service]
    updated = False

    if args.username:
        entry["username"] = args.username
        updated = True
    # Resolve password from any source (--password-file, --password-env, --password, stdin)
    if _has_password_source(args):
        entry["password"] = _resolve_password(args)
        updated = True
    if args.email:
        entry["email"] = args.email
        updated = True
    if args.url:
        entry["url"] = args.url
        updated = True
    if args.notes:
        entry["notes"] = args.notes
        updated = True
    if args.tags:
        entry["tags"] = _parse_tags(args.tags)
        updated = True

    if updated:
        entry["updated"] = datetime.now(timezone.utc).isoformat()
        _save_vault(vault, key)
        print(f"✓ Updated credential for '{service}'")
    else:
        print("No fields specified to update.")


def cmd_remove(args):
    """Remove a credential."""
    key = _get_key()
    vault = _load_vault(key)
    entries = vault.get("entries", {})

    service = args.service.lower()
    if service not in entries:
        print(f"✗ No credential found for '{service}'")
        sys.exit(1)

    del entries[service]
    _save_vault(vault, key)
    print(f"✓ Removed credential for '{service}'")


def cmd_check(args):
    """Check if a credential exists and show status."""
    key = _get_key()
    vault = _load_vault(key)
    entries = vault.get("entries", {})

    service = args.service.lower()
    if service in entries:
        entry = entries[service]
        print(f"✓ Credential exists for '{service}'")
        print(f"  Email: {entry.get('email', '(not set)')}")
        print(f"  Username: {entry.get('username', '(not set)')}")
        print(f"  Has password: {'Yes' if entry.get('password') else 'No'}")
        print(f"  URL: {entry.get('url', '(not set)')}")
        print(f"  Tags: {', '.join(entry.get('tags', [])) or '(none)'}")
        print(f"  Created: {entry.get('created', '?')[:10]}")
        print(f"  Updated: {entry.get('updated', '?')[:10]}")
    else:
        print(f"✗ No credential found for '{service}'")


def cmd_status(args):
    """Show vault status."""
    _ensure_dir()
    print(f"Vault directory: {VAULT_DIR}")
    print(f"Key file: {VAULT_KEY} ({'exists' if VAULT_KEY.exists() else 'MISSING'})")
    print(f"Data file: {VAULT_FILE} ({'exists' if VAULT_FILE.exists() else 'empty'})")

    if VAULT_FILE.exists() and VAULT_KEY.exists():
        key = _get_key()
        vault = _load_vault(key)
        entries = vault.get("entries", {})
        print(f"Entries: {len(entries)}")
        print(f"Services: {', '.join(entries.keys()) or '(none)'}")
        print(f"Created: {vault.get('created', '?')}")
        print(f"Updated: {vault.get('updated', '?')}")
    else:
        print("Vault not initialized. Run 'init' to create.")


def cmd_search(args):
    """Fuzzy search across services and fields."""
    key = _get_key()
    vault = _load_vault(key)
    entries = vault.get("entries", {})

    query = args.query.lower()

    results = []
    for service, entry in entries.items():
        # Check service name
        if query in service:
            results.append(service)
            continue
        # Check all string fields
        searchable = " ".join(str(v) for v in entry.values() if isinstance(v, str))
        if query in searchable.lower():
            results.append(service)
            continue
        # Check tags
        tags = entry.get("tags", [])
        if any(query in t for t in tags):
            results.append(service)

    if not results:
        print(f"No matches for '{query}'")
    else:
        print(f"Found {len(results)} match(es):")
        for svc in sorted(results):
            entry = entries[svc]
            identity = entry.get("email") or entry.get("username") or "(no identity)"
            tags = ", ".join(entry.get("tags", []))
            print(f"  {svc:<25} {identity:<35} {tags}")


def cmd_generate_password(args):
    """Generate a random password."""
    length = args.length if hasattr(args, "length") and args.length else 20
    alphabet = string.ascii_letters + string.digits + string.punctuation
    # Ensure at least one of each character class
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        has_lower = any(c in string.ascii_lowercase for c in password)
        has_upper = any(c in string.ascii_uppercase for c in password)
        has_digit = any(c in string.digits for c in password)
        has_symbol = any(c in string.punctuation for c in password)
        if has_lower and has_upper and has_digit and has_symbol:
            break
    print(password)


def cmd_export(args):
    """Export all credentials as encrypted backup."""
    if not VAULT_FILE.exists():
        print("✗ No vault to export.")
        sys.exit(1)
    # Verify vault can be decrypted before exporting (BUG-SEC-03)
    key = _get_key()
    try:
        _load_vault(key)
    except (SystemExit, Exception) as exc:
        print(f"✗ Cannot export a corrupt vault. {exc}", file=sys.stderr)
        sys.exit(1)
    import shutil
    dest = Path(args.output) if args.output else VAULT_DIR / "vault_backup.enc"
    shutil.copy2(VAULT_FILE, dest)
    _chmod_600(dest)
    print(f"✓ Exported encrypted vault to {dest}")


def cmd_import(args):
    """Import credentials from encrypted backup."""
    src = Path(args.file)
    if not src.exists():
        print(f"✗ File not found: {src}")
        sys.exit(1)
    key = _get_key()
    # Try to decrypt with our key
    try:
        data = src.read_bytes()
        decrypted = _decrypt(data, key)
        imported = json.loads(decrypted)
    except InvalidToken:
        print(
            "✗ Failed to decrypt: the backup was encrypted with a different key.\n"
            "  You must import into a vault that shares the same encryption key.",
            file=sys.stderr,
        )
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(
            f"✗ Backup file decrypted but contains invalid JSON: {exc}\n"
            "  The file may be corrupted.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Validate imported structure
    if not isinstance(imported, dict):
        print("✗ Invalid backup format: expected a JSON object.", file=sys.stderr)
        sys.exit(1)
    imported_entries = imported.get("entries")
    if imported_entries is None:
        # Handle null/missing entries — treat as empty
        imported_entries = {}
    if not isinstance(imported_entries, dict):
        print("✗ Invalid backup format: 'entries' must be an object.", file=sys.stderr)
        sys.exit(1)

    # Merge with existing vault based on --merge/--overwrite flags
    vault = _load_vault(key) if VAULT_FILE.exists() else {"version": 1, "entries": {}}
    existing = vault.setdefault("entries", {})

    # Default behavior: skip existing entries (safe)
    merge_mode = getattr(args, "merge", False)
    overwrite_mode = getattr(args, "overwrite", False)

    added = 0
    skipped = 0
    updated = 0
    for service, entry in imported_entries.items():
        if service in existing:
            if overwrite_mode:
                existing[service] = entry
                updated += 1
            elif merge_mode:
                # Merge: update only missing fields
                for field, value in entry.items():
                    if field not in existing[service] or not existing[service].get(field):
                        existing[service][field] = value
                updated += 1
            else:
                # Default: skip existing
                skipped += 1
        else:
            existing[service] = entry
            added += 1

    _save_vault(vault, key)
    print(f"✓ Imported {added} new + {updated} updated" +
          (f", {skipped} skipped (use --overwrite to replace or --merge to fill blanks)" if skipped else ""))


def main():
    parser = argparse.ArgumentParser(
        description="Runa's Credential Store — Self-owned encrypted vault",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="command")

    # init
    sub.add_parser("init", help="Initialize the vault")

    # add
    p_add = sub.add_parser("add", help="Add a new credential")
    p_add.add_argument("service", help="Service name (e.g., 'email-provider', 'streaming-service')")
    p_add.add_argument("--username", "-u", help="Username")
    p_add.add_argument("--password", "-p", help="Password (insecure: visible in process list)")
    p_add.add_argument("--password-file", help="Read password from file (secure)")
    p_add.add_argument("--password-env", help="Read password from environment variable (secure)")
    p_add.add_argument("--email", "-e", help="Email address")
    p_add.add_argument("--url", help="Service URL")
    p_add.add_argument("--notes", "-n", help="Additional notes")
    p_add.add_argument("--tags", "-t", help="Comma-separated tags")
    p_add.add_argument("--force", "-f", action="store_true", help="Overwrite if exists")

    # get
    p_get = sub.add_parser("get", help="Get credential details")
    p_get.add_argument("service", help="Service name")

    # list
    p_list = sub.add_parser("list", help="List all credentials")
    p_list.add_argument("--tags", "-t", help="Filter by tag")

    # update
    p_upd = sub.add_parser("update", help="Update credential fields")
    p_upd.add_argument("service", help="Service name")
    p_upd.add_argument("--username", "-u", help="New username")
    p_upd.add_argument("--password", "-p", help="New password (insecure)")
    p_upd.add_argument("--password-file", help="Read password from file (secure)")
    p_upd.add_argument("--password-env", help="Read password from environment variable (secure)")
    p_upd.add_argument("--email", "-e", help="New email")
    p_upd.add_argument("--url", help="New URL")
    p_upd.add_argument("--notes", "-n", help="New notes")
    p_upd.add_argument("--tags", "-t", help="New comma-separated tags")

    # remove
    p_rm = sub.add_parser("remove", help="Remove a credential")
    p_rm.add_argument("service", help="Service name")

    # check
    p_chk = sub.add_parser("check", help="Check credential status")
    p_chk.add_argument("service", help="Service name")

    # search
    p_search = sub.add_parser("search", help="Fuzzy search across services and fields")
    p_search.add_argument("query", help="Search term")

    # generate-password
    p_gen = sub.add_parser("generate-password", help="Generate a random password")
    p_gen.add_argument("--length", "-l", type=int, default=20, help="Password length (default: 20)")

    # status
    sub.add_parser("status", help="Show vault status")

    # export
    p_exp = sub.add_parser("export", help="Export encrypted backup")
    p_exp.add_argument("--output", "-o", help="Output file path")

    # import
    p_imp = sub.add_parser("import", help="Import from encrypted backup")
    p_imp.add_argument("file", help="Backup file path")
    imp_mutex = p_imp.add_mutually_exclusive_group()
    imp_mutex.add_argument("--merge", action="store_true",
                           help="Merge: fill in blank fields for existing entries")
    imp_mutex.add_argument("--overwrite", action="store_true",
                           help="Overwrite: replace existing entries with imported versions")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    commands = {
        "init": cmd_init,
        "add": cmd_add,
        "get": cmd_get,
        "list": cmd_list,
        "update": cmd_update,
        "remove": cmd_remove,
        "check": cmd_check,
        "search": cmd_search,
        "generate-password": cmd_generate_password,
        "status": cmd_status,
        "export": cmd_export,
        "import": cmd_import,
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()