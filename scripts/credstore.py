#!/usr/bin/env python3
"""
Runa's Credential Store — Self-owned, self-managed, self-accessible.
Encrypted credential vault that Runa can access independently.
No dependency on external password managers or Volmarr's help.

Also installable as 'kista' (Old Norse: strongbox/chest).

Usage:
  credstore.py add <service> [--type TYPE] [--username USER] [--password PASS] [--password-file FILE] [--password-env VAR]
                           [--email EMAIL] [--url URL] [--notes NOTES] [--tags TAGS]
                           [--key KEY] [--key-file FILE] [--expires DATE] [--service-url URL]
                           [--rate-limit LIMIT] [--scopes SCOPES] [--public-key KEY]
                           [--passphrase PHRASE] [--key-type TYPE] [--host HOST]
                           [--cert-file FILE] [--cert CERT] [--domain DOMAIN] [--issuer ISSUER]
                           [--chain CHAIN] [--content TEXT] [--category CAT]
                           [--secret SECRET] [--digits N] [--period N] [--algorithm ALGO]
                           [--product PROD] [--seats N] [--order-id ID]
                           [--full-name NAME] [--birth-date DATE] [--id-number NUM]
                           [--id-type TYPE] [--address ADDR] [--phone PHONE] [--national-id ID]
  credstore.py add-apikey <service> [apikey-specific flags]  # shortcut
  credstore.py add-sshkey <service> [sshkey-specific flags]  # shortcut
  credstore.py add-certificate <service> [cert-specific flags]  # shortcut
  credstore.py add-note <service> [note-specific flags]  # shortcut
  credstore.py add-totp <service> [totp-specific flags]  # shortcut
  credstore.py add-license <service> [license-specific flags]  # shortcut
  credstore.py add-identity <service> [identity-specific flags]  # shortcut
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

__version__ = "1.2.0"

VAULT_DIR = Path(os.environ.get("KISTA_DIR", str(Path.home() / ".hermes" / "credentials")))
VAULT_KEY = VAULT_DIR / ".vault_key"
VAULT_FILE = VAULT_DIR / "vault.json.enc"
VAULT_META = VAULT_DIR / "vault_meta.json"

# Entry type schemas: field name -> (required, default)
# Required fields must be provided when adding; defaults are filled in automatically.
ENTRY_TYPE_SCHEMAS = {
    "credential": {
        # Original fields — no required fields, backward-compatible
        "username": (False, ""),
        "password": (False, ""),
        "email": (False, ""),
        "url": (False, ""),
    },
    "apikey": {
        "key": (True, None),
        "expires": (False, ""),
        "service_url": (False, ""),
        "rate_limit": (False, ""),
        "scopes": (False, ""),
    },
    "sshkey": {
        "private_key": (True, None),  # via --key-file
        "public_key": (False, ""),
        "passphrase": (False, ""),
        "key_type": (False, ""),
        "host": (False, ""),
    },
    "certificate": {
        "cert": (True, None),  # via --cert-file
        "key": (False, ""),     # via --key-file for cert-type entries
        "domain": (False, ""),
        "issuer": (False, ""),
        "expires": (False, ""),
        "chain": (False, ""),
    },
    "note": {
        "content": (True, None),
        "category": (False, ""),
    },
    "totp": {
        "secret": (True, None),
        "digits": (False, 6),
        "period": (False, 30),
        "algorithm": (False, "SHA1"),
        "issuer": (False, ""),
    },
    "license": {
        "key": (True, None),
        "product": (False, ""),
        "seats": (False, ""),
        "expires": (False, ""),
        "order_id": (False, ""),
    },
    "identity": {
        "full_name": (False, ""),
        "birth_date": (False, ""),
        "id_number": (False, ""),
        "id_type": (False, ""),
        "address": (False, ""),
        "phone": (False, ""),
        "national_id": (False, ""),
    },
}

# Types that use --key-file for sensitive data (not a password file)
SENSITIVE_FILE_TYPES = {"sshkey", "certificate"}


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
    """Load and decrypt the vault with error recovery.

    Automatically upgrades old entries by adding entry_type='credential' if missing.
    """
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
        vault = json.loads(decrypted)
    except json.JSONDecodeError as exc:
        print(
            f"✗ Vault data is corrupt (invalid JSON: {exc}).\n"
            f"  The decryption key is correct, but the data inside is not valid JSON.\n"
            f"  This may indicate a truncated write. If you have a backup, restore it.\n"
            f"  Vault file: {VAULT_FILE}",
            file=sys.stderr,
        )
        sys.exit(1)

    # Backward compatibility: add entry_type to entries that lack it
    entries = vault.get("entries", {})
    for service, entry in entries.items():
        if isinstance(entry, dict) and "entry_type" not in entry:
            entry["entry_type"] = "credential"

    return vault


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


def _read_file_content(filepath: str) -> str:
    """Read file content, stripping trailing newlines. Used for --key-file, --cert-file."""
    path = Path(filepath)
    try:
        return path.read_text()
    except (OSError, FileNotFoundError) as exc:
        print(f"✗ Cannot read file '{filepath}': {exc}", file=sys.stderr)
        sys.exit(1)


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
    """Add a new entry (of any type)."""
    key = _get_key()
    vault = _load_vault(key)
    entries = vault.setdefault("entries", {})

    service = args.service.lower()
    if service in entries and not getattr(args, "force", False):
        print(f"✗ Entry for '{service}' already exists. Use --force to overwrite or 'update' to modify.")
        sys.exit(1)

    entry_type = getattr(args, "entry_type", "credential") or "credential"
    # If entry_type is still "credential" but command is a type shortcut, infer the type
    if entry_type == "credential":
        _SHORTCUT_TYPES = {
            "add-apikey": "apikey",
            "add-sshkey": "sshkey",
            "add-certificate": "certificate",
            "add-note": "note",
            "add-totp": "totp",
            "add-license": "license",
            "add-identity": "identity",
        }
        cmd = getattr(args, "command", None)
        if cmd in _SHORTCUT_TYPES:
            entry_type = _SHORTCUT_TYPES[cmd]
    if entry_type not in ENTRY_TYPE_SCHEMAS:
        print(f"✗ Unknown entry type '{entry_type}'. Valid types: {', '.join(ENTRY_TYPE_SCHEMAS.keys())}")
        sys.exit(1)

    entry = {
        "service": service,
        "entry_type": entry_type,
        "created": datetime.now(timezone.utc).isoformat(),
        "updated": datetime.now(timezone.utc).isoformat(),
    }

    # Add common fields (present for all types)
    password = _resolve_password(args)
    entry["username"] = getattr(args, "username", None) or ""
    entry["password"] = password
    entry["email"] = getattr(args, "email", None) or ""
    entry["url"] = getattr(args, "url", None) or ""
    entry["notes"] = getattr(args, "notes", None) or ""
    entry["tags"] = _parse_tags(getattr(args, "tags", None)) if getattr(args, "tags", None) else []

    # Add type-specific fields
    if entry_type == "apikey":
        entry["key"] = getattr(args, "key_arg", None) or ""
        entry["expires"] = getattr(args, "expires", None) or ""
        entry["service_url"] = getattr(args, "service_url", None) or ""
        entry["rate_limit"] = getattr(args, "rate_limit", None) or ""
        entry["scopes"] = getattr(args, "scopes", None) or ""

    elif entry_type == "sshkey":
        # private_key is required and read from --key-file for security
        key_file = getattr(args, "key_file", None)
        if key_file:
            entry["private_key"] = _read_file_content(key_file)
        else:
            entry["private_key"] = ""
        entry["public_key"] = getattr(args, "public_key", None) or ""
        entry["passphrase"] = getattr(args, "passphrase", None) or ""
        entry["key_type"] = getattr(args, "key_type", None) or ""
        entry["host"] = getattr(args, "host", None) or ""

    elif entry_type == "certificate":
        # cert is required and read from --cert-file for security
        cert_file = getattr(args, "cert_file", None)
        if cert_file:
            entry["cert"] = _read_file_content(cert_file)
        else:
            entry["cert"] = ""
        # optional --key-file for certificate private key
        key_file = getattr(args, "key_file", None)
        if key_file:
            entry["key"] = _read_file_content(key_file)
        else:
            entry["key"] = ""
        entry["domain"] = getattr(args, "domain", None) or ""
        entry["issuer"] = getattr(args, "issuer", None) or ""
        entry["expires"] = getattr(args, "expires", None) or getattr(args, "expires_field", None) or ""
        entry["chain"] = getattr(args, "chain", None) or ""

    elif entry_type == "note":
        entry["content"] = getattr(args, "content", None) or ""
        entry["category"] = getattr(args, "category", None) or ""

    elif entry_type == "totp":
        entry["secret"] = getattr(args, "secret", None) or ""
        entry["digits"] = getattr(args, "digits", None) or 6
        entry["period"] = getattr(args, "period", None) or 30
        entry["algorithm"] = getattr(args, "algorithm", None) or "SHA1"
        entry["issuer"] = getattr(args, "issuer", None) or ""

    elif entry_type == "license":
        entry["key"] = getattr(args, "key_arg", None) or ""
        entry["product"] = getattr(args, "product", None) or ""
        entry["seats"] = getattr(args, "seats", None) or ""
        entry["expires"] = getattr(args, "expires", None) or getattr(args, "expires_field", None) or ""
        entry["order_id"] = getattr(args, "order_id", None) or ""

    elif entry_type == "identity":
        entry["full_name"] = getattr(args, "full_name", None) or ""
        entry["birth_date"] = getattr(args, "birth_date", None) or ""
        entry["id_number"] = getattr(args, "id_number", None) or ""
        entry["id_type"] = getattr(args, "id_type", None) or ""
        entry["address"] = getattr(args, "address", None) or ""
        entry["phone"] = getattr(args, "phone", None) or getattr(args, "phone_arg", None) or ""
        entry["national_id"] = getattr(args, "national_id", None) or ""

    # Validate required fields
    schema = ENTRY_TYPE_SCHEMAS[entry_type]
    for field_name, (required, default) in schema.items():
        if required:
            val = entry.get(field_name)
            if not val:
                print(f"✗ Required field '{field_name}' missing for type '{entry_type}'.")
                sys.exit(1)

    # Remove empty fields (but keep required timestamps and service)
    entry = {k: v for k, v in entry.items()
             if v or k in ("service", "created", "updated", "entry_type")}

    entries[service] = entry
    _save_vault(vault, key)
    print(f"✓ Added {entry_type} for '{service}'")


def cmd_get(args):
    """Get an entry (full details)."""
    key = _get_key()
    vault = _load_vault(key)
    entries = vault.get("entries", {})

    service = args.service.lower()
    if service not in entries:
        print(f"✗ No entry found for '{service}'")
        print(f"  Available: {', '.join(entries.keys()) or '(empty)'}")
        sys.exit(1)

    entry = entries[service]
    entry_type = entry.get("entry_type", "credential")

    # Display type-appropriate fields, hiding very large fields
    display_entry = dict(entry)
    # For sshkey and certificate, show truncated versions of large fields in terminal
    # but the full JSON output includes everything
    print(json.dumps(entry, indent=2, ensure_ascii=False))


def cmd_list(args):
    """List all entries (passwords and sensitive fields masked)."""
    key = _get_key()
    vault = _load_vault(key)
    entries = vault.get("entries", {})

    if not entries:
        print("No entries stored yet. Use 'add' to create one.")
        return

    tag_filter = args.tags.lower() if args.tags else None

    print(f"{'Service':<20} {'Type':<13} {'Identity':<30} {'Tags':<20} {'Updated'}")
    print("-" * 105)

    for service, entry in sorted(entries.items()):
        tags = ", ".join(entry.get("tags", []))
        if tag_filter and tag_filter not in tags:
            continue
        entry_type = entry.get("entry_type", "credential")
        # Identity display varies by type
        if entry_type == "credential":
            identity = entry.get("email") or entry.get("username") or "(no identity)"
        elif entry_type == "apikey":
            identity = entry.get("service_url") or "(no URL)"
        elif entry_type == "sshkey":
            identity = f"{entry.get('key_type', '?')}@{entry.get('host', '?')}"
        elif entry_type == "certificate":
            identity = entry.get("domain") or "(no domain)"
        elif entry_type == "note":
            identity = entry.get("category") or "(no category)"
        elif entry_type == "totp":
            identity = entry.get("issuer") or "(no issuer)"
        elif entry_type == "license":
            identity = entry.get("product") or "(no product)"
        elif entry_type == "identity":
            identity = entry.get("full_name") or "(no name)"
        else:
            identity = "(unknown)"
        updated = entry.get("updated", "?")[:10]
        print(f"{service:<20} {entry_type:<13} {identity:<30} {tags:<20} {updated}")


def cmd_update(args):
    """Update specific fields of an entry."""
    key = _get_key()
    vault = _load_vault(key)
    entries = vault.get("entries", {})

    service = args.service.lower()
    if service not in entries:
        print(f"✗ No entry found for '{service}'")
        sys.exit(1)

    entry = entries[service]
    entry_type = entry.get("entry_type", "credential")
    updated = False

    # Common fields (available for all types)
    if getattr(args, "username", None):
        entry["username"] = args.username
        updated = True
    if _has_password_source(args):
        entry["password"] = _resolve_password(args)
        updated = True
    if getattr(args, "email", None):
        entry["email"] = args.email
        updated = True
    if getattr(args, "url", None):
        entry["url"] = args.url
        updated = True
    if getattr(args, "notes", None):
        entry["notes"] = args.notes
        updated = True
    if getattr(args, "tags", None):
        entry["tags"] = _parse_tags(args.tags)
        updated = True

    # Type-specific field updates
    if entry_type == "apikey":
        if getattr(args, "key_arg", None):
            entry["key"] = args.key_arg
            updated = True
        if getattr(args, "expires", None):
            entry["expires"] = args.expires
            updated = True
        if getattr(args, "service_url", None):
            entry["service_url"] = args.service_url
            updated = True
        if getattr(args, "rate_limit", None):
            entry["rate_limit"] = args.rate_limit
            updated = True
        if getattr(args, "scopes", None):
            entry["scopes"] = args.scopes
            updated = True

    elif entry_type == "sshkey":
        if getattr(args, "key_file", None):
            entry["private_key"] = _read_file_content(args.key_file)
            updated = True
        if getattr(args, "public_key", None):
            entry["public_key"] = args.public_key
            updated = True
        if getattr(args, "passphrase", None):
            entry["passphrase"] = args.passphrase
            updated = True
        if getattr(args, "key_type", None):
            entry["key_type"] = args.key_type
            updated = True
        if getattr(args, "host", None):
            entry["host"] = args.host
            updated = True

    elif entry_type == "certificate":
        if getattr(args, "cert_file", None):
            entry["cert"] = _read_file_content(args.cert_file)
            updated = True
        if getattr(args, "key_file", None):
            entry["key"] = _read_file_content(args.key_file)
            updated = True
        if getattr(args, "domain", None):
            entry["domain"] = args.domain
            updated = True
        if getattr(args, "issuer", None):
            entry["issuer"] = args.issuer
            updated = True
        if getattr(args, "expires_field", None):  # --expires for certificates
            entry["expires"] = args.expires_field
            updated = True
        if getattr(args, "chain", None):
            entry["chain"] = args.chain
            updated = True

    elif entry_type == "note":
        if getattr(args, "content", None):
            entry["content"] = args.content
            updated = True
        if getattr(args, "category", None):
            entry["category"] = args.category
            updated = True

    elif entry_type == "totp":
        if getattr(args, "secret", None):
            entry["secret"] = args.secret
            updated = True
        if getattr(args, "digits", None) is not None:
            entry["digits"] = args.digits
            updated = True
        if getattr(args, "period", None) is not None:
            entry["period"] = args.period
            updated = True
        if getattr(args, "algorithm", None):
            entry["algorithm"] = args.algorithm
            updated = True
        if getattr(args, "issuer", None):
            entry["issuer"] = args.issuer
            updated = True

    elif entry_type == "license":
        if getattr(args, "key_arg", None):
            entry["key"] = args.key_arg
            updated = True
        if getattr(args, "product", None):
            entry["product"] = args.product
            updated = True
        if getattr(args, "seats", None):
            entry["seats"] = args.seats
            updated = True
        if getattr(args, "expires_field", None):
            entry["expires"] = args.expires_field
            updated = True
        if getattr(args, "order_id", None):
            entry["order_id"] = args.order_id
            updated = True

    elif entry_type == "identity":
        if getattr(args, "full_name", None):
            entry["full_name"] = args.full_name
            updated = True
        if getattr(args, "birth_date", None):
            entry["birth_date"] = args.birth_date
            updated = True
        if getattr(args, "id_number", None):
            entry["id_number"] = args.id_number
            updated = True
        if getattr(args, "id_type", None):
            entry["id_type"] = args.id_type
            updated = True
        if getattr(args, "address", None):
            entry["address"] = args.address
            updated = True
        if getattr(args, "phone_arg", None):
            entry["phone"] = args.phone_arg
            updated = True
        if getattr(args, "national_id", None):
            entry["national_id"] = args.national_id
            updated = True

    if updated:
        entry["updated"] = datetime.now(timezone.utc).isoformat()
        _save_vault(vault, key)
        print(f"✓ Updated {entry_type} for '{service}'")
    else:
        print("No fields specified to update.")


def cmd_remove(args):
    """Remove an entry."""
    key = _get_key()
    vault = _load_vault(key)
    entries = vault.get("entries", {})

    service = args.service.lower()
    if service not in entries:
        print(f"✗ No entry found for '{service}'")
        sys.exit(1)

    del entries[service]
    _save_vault(vault, key)
    print(f"✓ Removed entry for '{service}'")


def cmd_check(args):
    """Check if an entry exists and show status."""
    key = _get_key()
    vault = _load_vault(key)
    entries = vault.get("entries", {})

    service = args.service.lower()
    if service in entries:
        entry = entries[service]
        entry_type = entry.get("entry_type", "credential")
        print(f"✓ Entry exists for '{service}' (type: {entry_type})")

        # Show type-appropriate summary fields
        if entry_type == "credential":
            print(f"  Email: {entry.get('email', '(not set)')}")
            print(f"  Username: {entry.get('username', '(not set)')}")
            print(f"  Has password: {'Yes' if entry.get('password') else 'No'}")
            print(f"  URL: {entry.get('url', '(not set)')}")
        elif entry_type == "apikey":
            print(f"  Has key: {'Yes' if entry.get('key') else 'No'}")
            print(f"  Service URL: {entry.get('service_url', '(not set)')}")
            print(f"  Expires: {entry.get('expires', '(not set)')}")
        elif entry_type == "sshkey":
            print(f"  Key type: {entry.get('key_type', '(not set)')}")
            print(f"  Host: {entry.get('host', '(not set)')}")
            print(f"  Has private key: {'Yes' if entry.get('private_key') else 'No'}")
        elif entry_type == "certificate":
            print(f"  Domain: {entry.get('domain', '(not set)')}")
            print(f"  Issuer: {entry.get('issuer', '(not set)')}")
            print(f"  Expires: {entry.get('expires', '(not set)')}")
        elif entry_type == "note":
            print(f"  Category: {entry.get('category', '(not set)')}")
        elif entry_type == "totp":
            print(f"  Issuer: {entry.get('issuer', '(not set)')}")
            print(f"  Digits: {entry.get('digits', 6)}")
            print(f"  Period: {entry.get('period', 30)}s")
        elif entry_type == "license":
            print(f"  Product: {entry.get('product', '(not set)')}")
            print(f"  Expires: {entry.get('expires', '(not set)')}")
        elif entry_type == "identity":
            print(f"  Name: {entry.get('full_name', '(not set)')}")

        print(f"  Tags: {', '.join(entry.get('tags', [])) or '(none)'}")
        print(f"  Created: {entry.get('created', '?')[:10]}")
        print(f"  Updated: {entry.get('updated', '?')[:10]}")
    else:
        print(f"✗ No entry found for '{service}'")


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
        # Count by type
        type_counts = {}
        for entry in entries.values():
            et = entry.get("entry_type", "credential")
            type_counts[et] = type_counts.get(et, 0) + 1
        for et, count in sorted(type_counts.items()):
            print(f"  {et}: {count}")
        print(f"Services: {', '.join(entries.keys()) or '(none)'}")
        print(f"Created: {vault.get('created', '?')}")
        print(f"Updated: {vault.get('updated', '?')}")
    else:
        print("Vault not initialized. Run 'init' to create.")


def cmd_search(args):
    """Fuzzy search across services and all fields (including type-specific)."""
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
            entry_type = entry.get("entry_type", "credential")
            if entry_type == "credential":
                identity = entry.get("email") or entry.get("username") or "(no identity)"
            elif entry_type == "apikey":
                identity = entry.get("service_url") or "(no URL)"
            elif entry_type == "note":
                identity = entry.get("category") or "(no category)"
            else:
                identity = entry.get("full_name") or entry.get("domain") or entry.get("host") or "(no identity)"
            tags = ", ".join(entry.get("tags", []))
            print(f"  {svc:<25} [{entry_type}] {identity:<30} {tags}")


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

    # Upgrade imported entries to have entry_type
    for svc, entry in imported_entries.items():
        if isinstance(entry, dict) and "entry_type" not in entry:
            entry["entry_type"] = "credential"

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


def _add_type_args(parser, entry_type):
    """Add type-specific arguments to an argparse subparser."""
    if entry_type == "apikey":
        parser.add_argument("--key", dest="key_arg", help="API key value (required)")
        parser.add_argument("--expires", help="Expiration date/time")
        parser.add_argument("--service-url", dest="service_url", help="Service URL for the API")
        parser.add_argument("--rate-limit", dest="rate_limit", help="Rate limit info")
        parser.add_argument("--scopes", help="Comma-separated permission scopes")

    elif entry_type == "sshkey":
        parser.add_argument("--key-file", help="Path to SSH private key file (required, secure)")
        parser.add_argument("--public-key", dest="public_key", help="Public key content")
        parser.add_argument("--passphrase", help="Key passphrase")
        parser.add_argument("--key-type", dest="key_type", choices=["rsa", "ed25519", "ecdsa"],
                            help="SSH key type")
        parser.add_argument("--host", help="Associated host")

    elif entry_type == "certificate":
        parser.add_argument("--cert-file", help="Path to certificate file (required, secure)")
        parser.add_argument("--key-file", help="Path to private key file for the certificate")
        parser.add_argument("--domain", help="Certificate domain")
        parser.add_argument("--issuer", help="Certificate issuer")
        parser.add_argument("--expires", dest="expires_field", help="Expiration date")
        parser.add_argument("--chain", help="Certificate chain")

    elif entry_type == "note":
        parser.add_argument("--content", help="Note content (required)")
        parser.add_argument("--category", help="Note category")

    elif entry_type == "totp":
        parser.add_argument("--secret", help="TOTP secret (required)")
        parser.add_argument("--digits", type=int, default=None, help="Number of digits (default: 6)")
        parser.add_argument("--period", type=int, default=None, help="Time period in seconds (default: 30)")
        parser.add_argument("--algorithm", help="Algorithm (default: SHA1)")
        parser.add_argument("--issuer", help="TOTP issuer")

    elif entry_type == "license":
        parser.add_argument("--key", dest="key_arg", help="License key (required)")
        parser.add_argument("--product", help="Product name")
        parser.add_argument("--seats", help="Number of seats")
        parser.add_argument("--expires", dest="expires_field", help="Expiration date")
        parser.add_argument("--order-id", dest="order_id", help="Order ID")

    elif entry_type == "identity":
        parser.add_argument("--full-name", dest="full_name", help="Full legal name")
        parser.add_argument("--birth-date", dest="birth_date", help="Date of birth")
        parser.add_argument("--id-number", dest="id_number", help="ID number")
        parser.add_argument("--id-type", dest="id_type", help="ID type (passport, driver_license, etc.)")
        parser.add_argument("--address", help="Address")
        parser.add_argument("--phone", dest="phone_arg", help="Phone number")
        parser.add_argument("--national-id", dest="national_id", help="National ID number")


def main():
    parser = argparse.ArgumentParser(
        description="Runa's Credential Store — Self-owned encrypted vault (kista)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="command")

    # init
    sub.add_parser("init", help="Initialize the vault")

    # add (general, with --type)
    p_add = sub.add_parser("add", help="Add a new entry")
    p_add.add_argument("service", help="Service name (e.g., 'email-provider', 'streaming-service')")
    p_add.add_argument("--type", dest="entry_type", default="credential",
                       choices=list(ENTRY_TYPE_SCHEMAS.keys()),
                       help="Entry type (default: credential)")
    p_add.add_argument("--username", "-u", help="Username")
    p_add.add_argument("--password", "-p", help="Password (insecure: visible in process list)")
    p_add.add_argument("--password-file", help="Read password from file (secure)")
    p_add.add_argument("--password-env", help="Read password from environment variable (secure)")
    p_add.add_argument("--email", "-e", help="Email address")
    p_add.add_argument("--url", help="Service URL")
    p_add.add_argument("--notes", "-n", help="Additional notes")
    p_add.add_argument("--tags", "-t", help="Comma-separated tags")
    p_add.add_argument("--force", "-f", action="store_true", help="Overwrite if exists")
    # Type-specific args for 'add' (merged from all types)
    p_add.add_argument("--key", dest="key_arg", help="API key / License key")
    p_add.add_argument("--key-file", help="Path to private key file (sshkey/certificate)")
    p_add.add_argument("--cert-file", help="Path to certificate file")
    p_add.add_argument("--expires", help="Expiration date")
    p_add.add_argument("--service-url", dest="service_url", help="Service URL (apikey)")
    p_add.add_argument("--rate-limit", dest="rate_limit", help="Rate limit (apikey)")
    p_add.add_argument("--scopes", help="Comma-separated scopes (apikey)")
    p_add.add_argument("--public-key", dest="public_key", help="Public key content (sshkey)")
    p_add.add_argument("--passphrase", help="Passphrase (sshkey)")
    p_add.add_argument("--key-type", dest="key_type", choices=["rsa", "ed25519", "ecdsa"],
                        help="SSH key type")
    p_add.add_argument("--host", help="Associated host (sshkey)")
    p_add.add_argument("--domain", help="Domain (certificate)")
    p_add.add_argument("--issuer", help="Issuer (certificate/totp)")
    p_add.add_argument("--chain", help="Certificate chain (certificate)")
    p_add.add_argument("--content", help="Note content (note)")
    p_add.add_argument("--category", help="Category (note)")
    p_add.add_argument("--secret", help="Secret (totp)")
    p_add.add_argument("--digits", type=int, default=None, help="Digits (totp, default: 6)")
    p_add.add_argument("--period", type=int, default=None, help="Period in seconds (totp, default: 30)")
    p_add.add_argument("--algorithm", help="Algorithm (totp, default: SHA1)")
    p_add.add_argument("--product", help="Product name (license)")
    p_add.add_argument("--seats", help="Number of seats (license)")
    p_add.add_argument("--order-id", dest="order_id", help="Order ID (license)")
    p_add.add_argument("--full-name", dest="full_name", help="Full name (identity)")
    p_add.add_argument("--birth-date", dest="birth_date", help="Birth date (identity)")
    p_add.add_argument("--id-number", dest="id_number", help="ID number (identity)")
    p_add.add_argument("--id-type", dest="id_type", help="ID type (identity)")
    p_add.add_argument("--address", help="Address (identity)")
    p_add.add_argument("--phone", dest="phone_arg", help="Phone (identity)")
    p_add.add_argument("--national-id", dest="national_id", help="National ID (identity)")

    # Convenience shortcuts for add (each auto-sets --type)
    p_add_apikey = sub.add_parser("add-apikey", help="Add an API key entry")
    p_add_apikey.add_argument("service", help="Service name")
    p_add_apikey.add_argument("--key", dest="key_arg", help="API key value (required)")
    p_add_apikey.add_argument("--expires", help="Expiration date/time")
    p_add_apikey.add_argument("--service-url", dest="service_url", help="Service URL for the API")
    p_add_apikey.add_argument("--rate-limit", dest="rate_limit", help="Rate limit info")
    p_add_apikey.add_argument("--scopes", help="Comma-separated permission scopes")
    p_add_apikey.add_argument("--tags", "-t", help="Comma-separated tags")
    p_add_apikey.add_argument("--notes", "-n", help="Additional notes")
    p_add_apikey.add_argument("--force", "-f", action="store_true", help="Overwrite if exists")

    p_add_sshkey = sub.add_parser("add-sshkey", help="Add an SSH key entry")
    p_add_sshkey.add_argument("service", help="Service/host name")
    p_add_sshkey.add_argument("--key-file", help="Path to SSH private key file (required, secure)")
    p_add_sshkey.add_argument("--public-key", dest="public_key", help="Public key content")
    p_add_sshkey.add_argument("--passphrase", help="Key passphrase")
    p_add_sshkey.add_argument("--key-type", dest="key_type", choices=["rsa", "ed25519", "ecdsa"],
                               help="SSH key type")
    p_add_sshkey.add_argument("--host", help="Associated host")
    p_add_sshkey.add_argument("--tags", "-t", help="Comma-separated tags")
    p_add_sshkey.add_argument("--notes", "-n", help="Additional notes")
    p_add_sshkey.add_argument("--force", "-f", action="store_true", help="Overwrite if exists")

    p_add_cert = sub.add_parser("add-certificate", help="Add a certificate entry")
    p_add_cert.add_argument("service", help="Service/domain name")
    p_add_cert.add_argument("--cert-file", help="Path to certificate file (required, secure)")
    p_add_cert.add_argument("--key-file", help="Path to private key file")
    p_add_cert.add_argument("--domain", help="Certificate domain")
    p_add_cert.add_argument("--issuer", help="Certificate issuer")
    p_add_cert.add_argument("--expires", dest="expires_field", help="Expiration date")
    p_add_cert.add_argument("--chain", help="Certificate chain")
    p_add_cert.add_argument("--tags", "-t", help="Comma-separated tags")
    p_add_cert.add_argument("--notes", "-n", help="Additional notes")
    p_add_cert.add_argument("--force", "-f", action="store_true", help="Overwrite if exists")

    p_add_note = sub.add_parser("add-note", help="Add a note entry")
    p_add_note.add_argument("service", help="Note title/identifier")
    p_add_note.add_argument("--content", help="Note content (required)")
    p_add_note.add_argument("--category", help="Note category")
    p_add_note.add_argument("--tags", "-t", help="Comma-separated tags")
    p_add_note.add_argument("--force", "-f", action="store_true", help="Overwrite if exists")

    p_add_totp = sub.add_parser("add-totp", help="Add a TOTP entry")
    p_add_totp.add_argument("service", help="Service name")
    p_add_totp.add_argument("--secret", help="TOTP secret (required)")
    p_add_totp.add_argument("--digits", type=int, default=None, help="Number of digits (default: 6)")
    p_add_totp.add_argument("--period", type=int, default=None, help="Time period in seconds (default: 30)")
    p_add_totp.add_argument("--algorithm", help="Algorithm (default: SHA1)")
    p_add_totp.add_argument("--issuer", help="TOTP issuer")
    p_add_totp.add_argument("--tags", "-t", help="Comma-separated tags")
    p_add_totp.add_argument("--notes", "-n", help="Additional notes")
    p_add_totp.add_argument("--force", "-f", action="store_true", help="Overwrite if exists")

    p_add_license = sub.add_parser("add-license", help="Add a license entry")
    p_add_license.add_argument("service", help="Product/service name")
    p_add_license.add_argument("--key", dest="key_arg", help="License key (required)")
    p_add_license.add_argument("--product", help="Product name")
    p_add_license.add_argument("--seats", help="Number of seats")
    p_add_license.add_argument("--expires", dest="expires_field", help="Expiration date")
    p_add_license.add_argument("--order-id", dest="order_id", help="Order ID")
    p_add_license.add_argument("--tags", "-t", help="Comma-separated tags")
    p_add_license.add_argument("--notes", "-n", help="Additional notes")
    p_add_license.add_argument("--force", "-f", action="store_true", help="Overwrite if exists")

    p_add_identity = sub.add_parser("add-identity", help="Add an identity entry")
    p_add_identity.add_argument("service", help="Identity label/name")
    p_add_identity.add_argument("--full-name", dest="full_name", help="Full legal name")
    p_add_identity.add_argument("--birth-date", dest="birth_date", help="Date of birth")
    p_add_identity.add_argument("--id-number", dest="id_number", help="ID number")
    p_add_identity.add_argument("--id-type", dest="id_type", help="ID type")
    p_add_identity.add_argument("--address", help="Address")
    p_add_identity.add_argument("--phone", dest="phone_arg", help="Phone number")
    p_add_identity.add_argument("--national-id", dest="national_id", help="National ID number")
    p_add_identity.add_argument("--tags", "-t", help="Comma-separated tags")
    p_add_identity.add_argument("--notes", "-n", help="Additional notes")
    p_add_identity.add_argument("--force", "-f", action="store_true", help="Overwrite if exists")

    # get
    p_get = sub.add_parser("get", help="Get entry details")
    p_get.add_argument("service", help="Service name")

    # list
    p_list = sub.add_parser("list", help="List all entries")
    p_list.add_argument("--tags", "-t", help="Filter by tag")

    # update
    p_upd = sub.add_parser("update", help="Update entry fields")
    p_upd.add_argument("service", help="Service name")
    p_upd.add_argument("--username", "-u", help="New username")
    p_upd.add_argument("--password", "-p", help="New password (insecure)")
    p_upd.add_argument("--password-file", help="Read password from file (secure)")
    p_upd.add_argument("--password-env", help="Read password from environment variable (secure)")
    p_upd.add_argument("--email", "-e", help="New email")
    p_upd.add_argument("--url", help="New URL")
    p_upd.add_argument("--notes", "-n", help="New notes")
    p_upd.add_argument("--tags", "-t", help="New comma-separated tags")
    # Type-specific update fields
    p_upd.add_argument("--key", dest="key_arg", help="API/License key")
    p_upd.add_argument("--key-file", help="Path to private key file (sshkey/certificate)")
    p_upd.add_argument("--cert-file", help="Path to certificate file")
    p_upd.add_argument("--expires", dest="expires_field", help="Expiration date")
    p_upd.add_argument("--service-url", dest="service_url", help="Service URL (apikey)")
    p_upd.add_argument("--rate-limit", dest="rate_limit", help="Rate limit (apikey)")
    p_upd.add_argument("--scopes", help="Scopes (apikey)")
    p_upd.add_argument("--public-key", dest="public_key", help="Public key (sshkey)")
    p_upd.add_argument("--passphrase", help="Passphrase (sshkey)")
    p_upd.add_argument("--key-type", dest="key_type", choices=["rsa", "ed25519", "ecdsa"],
                        help="SSH key type")
    p_upd.add_argument("--host", help="Host (sshkey)")
    p_upd.add_argument("--domain", help="Domain (certificate)")
    p_upd.add_argument("--issuer", help="Issuer (certificate/totp)")
    p_upd.add_argument("--chain", help="Certificate chain (certificate)")
    p_upd.add_argument("--content", help="Note content (note)")
    p_upd.add_argument("--category", help="Category (note)")
    p_upd.add_argument("--secret", help="Secret (totp)")
    p_upd.add_argument("--digits", type=int, default=None, help="Digits (totp)")
    p_upd.add_argument("--period", type=int, default=None, help="Period (totp)")
    p_upd.add_argument("--algorithm", help="Algorithm (totp)")
    p_upd.add_argument("--product", help="Product (license)")
    p_upd.add_argument("--seats", help="Seats (license)")
    p_upd.add_argument("--order-id", dest="order_id", help="Order ID (license)")
    p_upd.add_argument("--full-name", dest="full_name", help="Full name (identity)")
    p_upd.add_argument("--birth-date", dest="birth_date", help="Birth date (identity)")
    p_upd.add_argument("--id-number", dest="id_number", help="ID number (identity)")
    p_upd.add_argument("--id-type", dest="id_type", help="ID type (identity)")
    p_upd.add_argument("--address", help="Address (identity)")
    p_upd.add_argument("--phone", dest="phone_arg", help="Phone (identity)")
    p_upd.add_argument("--national-id", dest="national_id", help="National ID (identity)")

    # remove
    p_rm = sub.add_parser("remove", help="Remove an entry")
    p_rm.add_argument("service", help="Service name")

    # check
    p_chk = sub.add_parser("check", help="Check entry status")
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

    # Map shortcut commands to 'add' with entry_type
    TYPE_SHORTCUTS = {
        "add-apikey": "add",
        "add-sshkey": "add",
        "add-certificate": "add",
        "add-note": "add",
        "add-totp": "add",
        "add-license": "add",
        "add-identity": "add",
    }
    TYPE_MAP = {
        "add-apikey": "apikey",
        "add-sshkey": "sshkey",
        "add-certificate": "certificate",
        "add-note": "note",
        "add-totp": "totp",
        "add-license": "license",
        "add-identity": "identity",
    }

    command = args.command
    if command in TYPE_SHORTCUTS:
        command = TYPE_SHORTCUTS[command]
        args.entry_type = TYPE_MAP[args.command]

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

    commands[command](args)


if __name__ == "__main__":
    main()