"""Optional local credential storage.

API keys are optional in VIGIL — it runs fully without any. This module
exists only so an analyst does not have to re-export environment variables
in every shell.

DESIGN CONSTRAINTS (these are deliberate, not incidental):

  * Keys are NEVER written to ``config.yaml``. That file is documented as
    secret-free, ships in the repository, and is the kind of thing people
    commit by accident. Credentials live in a separate file.
  * The store is ``~/.vigil/credentials`` — outside the project tree, so it
    cannot be captured by ``git add .``.
  * The file is created with mode 0600 (owner read/write only) on POSIX.
  * **Environment variables always win.** A key exported in the shell
    overrides the stored one, so CI and ephemeral sessions behave predictably
    and a stored key can always be bypassed without deleting it.
  * Values are never printed, logged, or included in reports or errors. The
    display helpers here emit a masked fingerprint only.

No network access. Local file I/O only.
"""

from __future__ import annotations

import os
import stat
from typing import Optional

CREDENTIALS_DIR = os.path.join(os.path.expanduser("~"), ".vigil")
CREDENTIALS_PATH = os.path.join(CREDENTIALS_DIR, "credentials")

# The only keys VIGIL recognizes, with what each unlocks.
KNOWN_KEYS: dict[str, str] = {
    "VT_API_KEY": "VirusTotal hash lookups",
    "ABUSEIPDB_API_KEY": "AbuseIPDB IP reputation",
    "ANTHROPIC_API_KEY": "AI-written verdict explanations",
}


def mask(value: Optional[str]) -> str:
    """Render a key for display without disclosing it."""
    if not value:
        return "(not set)"
    v = value.strip()
    if len(v) <= 8:
        return "*" * len(v)
    return f"{v[:4]}{'*' * 8}{v[-4:]}  (len {len(v)})"


def load_file(path: Optional[str] = None) -> dict[str, str]:
    """Read stored credentials. A missing or unreadable file is not an error;
    VIGIL simply behaves as though no keys were configured."""
    path = path or CREDENTIALS_PATH
    creds: dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                name, _, value = line.partition("=")
                name, value = name.strip(), value.strip().strip('"').strip("'")
                if name in KNOWN_KEYS and value:
                    creds[name] = value
    except OSError:
        return {}
    return creds


def get(name: str, path: Optional[str] = None) -> Optional[str]:
    """Resolve one key. Environment first, stored file second."""
    path = path or CREDENTIALS_PATH
    from_env = os.environ.get(name)
    if from_env:
        return from_env
    return load_file(path).get(name)


def source_of(name: str, path: Optional[str] = None) -> str:
    """Where a key is coming from: 'environment', 'file', or 'unset'."""
    path = path or CREDENTIALS_PATH
    if os.environ.get(name):
        return "environment"
    if name in load_file(path):
        return "file"
    return "unset"


def save(creds: dict[str, str], path: Optional[str] = None) -> tuple[bool, str]:
    """Merge ``creds`` into the store, 0600. Returns (ok, message).

    An empty value removes that key. Never raises.
    """
    path = path or CREDENTIALS_PATH
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        existing = load_file(path)
        for name, value in creds.items():
            if value:
                existing[name] = value
            else:
                existing.pop(name, None)

        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write("# VIGIL credentials. Keep this file private.\n")
            fh.write("# Environment variables of the same name take precedence.\n")
            fh.write("# Delete a line to remove that key.\n")
            for name in KNOWN_KEYS:
                if name in existing:
                    fh.write(f"{name}={existing[name]}\n")
        _restrict(tmp)
        os.replace(tmp, path)
        _restrict(path)
    except OSError as exc:
        return False, f"could not write {path}: {exc}"

    note = ""
    if os.name == "nt":
        note = ("  NOTE: on Windows, file permissions are not restricted the "
                "way chmod 600 does on Linux/macOS. Anyone who can read your "
                "user profile can read this file.")
    return True, f"saved to {path}{chr(10) + note if note else ''}"


def _restrict(path: str) -> None:
    """Owner-only permissions. A no-op on platforms that ignore POSIX mode."""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    except OSError:
        pass


def permissions_warning(path: Optional[str] = None) -> Optional[str]:
    """Return a warning if the store is readable by group or others."""
    path = path or CREDENTIALS_PATH
    if os.name == "nt" or not os.path.isfile(path):
        return None
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return None
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        return (f"{path} is readable by other users; "
                f"run: chmod 600 {path}")
    return None
