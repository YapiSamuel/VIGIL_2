"""File ingestion: validation, type detection by magic bytes, hashing, and
safe archive extraction.

This module reads bytes and writes extracted bytes to a temp directory. It
never executes, evaluates, or imports anything derived from the input, and
it makes no network calls. Everything here is a pure byte transform plus
guarded filesystem I/O.
"""

from __future__ import annotations

import hashlib
import os
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from typing import Optional

# Hard caps. A junior analyst dropping a 500 MB "script" on us is almost
# certainly a mistake or an attack; refuse rather than exhaust memory.
MAX_FILE_SIZE = 25 * 1024 * 1024          # 25 MB per input file
MAX_TOTAL_UNCOMPRESSED = 100 * 1024 * 1024  # 100 MB across an archive
MAX_ARCHIVE_ENTRIES = 2000
MAX_COMPRESSION_RATIO = 200               # uncompressed:compressed per entry
READ_CHUNK = 1024 * 1024

SUPPORTED_SCRIPT_TYPES = ("script:sh", "script:ps1", "script:py")
ARCHIVE_TYPES = ("archive:zip", "archive:targz")


class IngestError(Exception):
    """Raised when a file cannot be safely ingested."""


@dataclass
class ExtractedMember:
    name: str            # original name inside the archive
    path: str            # path on disk where it was safely written
    size: int
    detected_type: str


@dataclass
class IngestResult:
    path: str            # resolved real path of the input
    original_path: str   # what the caller passed in
    detected_type: str
    size: int
    md5: str
    sha1: str
    sha256: str
    is_archive: bool = False
    members: list[ExtractedMember] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# --- hashing --------------------------------------------------------------

def hash_bytes(data: bytes) -> tuple[str, str, str]:
    """Return (md5, sha1, sha256) hex digests for ``data``."""
    return (
        hashlib.md5(data).hexdigest(),
        hashlib.sha1(data).hexdigest(),
        hashlib.sha256(data).hexdigest(),
    )


def hash_file(path: str) -> tuple[str, str, str]:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(READ_CHUNK)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


# --- type detection -------------------------------------------------------

def _looks_like_text(data: bytes) -> bool:
    if not data:
        return True
    if b"\x00" in data[:4096]:
        return False
    sample = data[:4096]
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        pass
    # A few high bytes are fine (latin-1 scripts); mostly-binary is not.
    printable = sum(1 for b in sample if 9 <= b <= 13 or 32 <= b <= 126)
    return printable / len(sample) >= 0.85


def _classify_script(data: bytes, ext_hint: str) -> tuple[str, list[str]]:
    """Classify a text blob into a script type. Content wins over the
    extension, which is only used to break genuine ties (with a note)."""
    notes: list[str] = []
    head = data[:512].decode("utf-8", errors="replace")
    lowered = head.lower()
    stripped = head.lstrip()

    if stripped.startswith("#!"):
        shebang = stripped.splitlines()[0].lower()
        if "python" in shebang:
            return "script:py", notes
        if "pwsh" in shebang or "powershell" in shebang:
            return "script:ps1", notes
        if any(s in shebang for s in ("bash", "/sh", "zsh", "dash", "ksh")):
            return "script:sh", notes

    # PowerShell has no shebang; look for load-bearing syntax.
    ps_markers = ("param(", "$psversiontable", "-encodedcommand",
                  "invoke-expression", "new-object", "[system.")
    if any(m in lowered for m in ps_markers):
        return "script:ps1", notes

    py_markers = ("import ", "def ", "print(", "__name__")
    if any(m in head for m in py_markers):
        return "script:py", notes

    if ext_hint in (".sh", ".bash", ".ps1", ".py"):
        mapping = {".sh": "script:sh", ".bash": "script:sh",
                   ".ps1": "script:ps1", ".py": "script:py"}
        notes.append(
            f"type inferred from extension {ext_hint!r}; content gave no "
            "definitive signal"
        )
        return mapping[ext_hint], notes

    notes.append("text file of undetermined script type")
    return "text", notes


def detect_type(data: bytes, ext_hint: str = "") -> tuple[str, list[str]]:
    """Detect a file's type from its bytes. ``ext_hint`` is a lowercase
    extension used only as a last-resort tiebreaker."""
    if data[:4] == b"PK\x03\x04" or data[:4] == b"PK\x05\x06":
        return "archive:zip", []
    if data[:2] == b"\x1f\x8b":
        # gzip; could wrap a tar (.tar.gz) or a single file (.gz)
        return "archive:targz", []
    if len(data) > 262 and data[257:263] == b"ustar\x00":
        return "archive:tar", []
    if _looks_like_text(data):
        return _classify_script(data, ext_hint)
    return "binary", []


# --- path validation ------------------------------------------------------

def _validate_input_path(path: str) -> str:
    if not os.path.exists(path):
        raise IngestError(f"no such file: {path}")
    if os.path.islink(path):
        raise IngestError(f"refusing to follow symlink: {path}")
    if not os.path.isfile(path):
        raise IngestError(f"not a regular file: {path}")
    real = os.path.realpath(path)
    size = os.path.getsize(real)
    if size == 0:
        raise IngestError(f"file is empty: {path}")
    if size > MAX_FILE_SIZE:
        raise IngestError(
            f"file too large: {size} bytes exceeds {MAX_FILE_SIZE} limit"
        )
    return real


# --- safe archive extraction ---------------------------------------------

def _safe_join(dest_dir: str, name: str) -> str:
    """Resolve ``name`` under ``dest_dir``, refusing zip-slip escapes."""
    dest_dir = os.path.realpath(dest_dir)
    # Normalize separators and strip any leading drive/root.
    candidate = os.path.normpath(os.path.join(dest_dir, name))
    real_candidate = os.path.realpath(candidate)
    if real_candidate != dest_dir and not real_candidate.startswith(
        dest_dir + os.sep
    ):
        raise IngestError(f"archive entry escapes extraction dir: {name!r}")
    return candidate


def _extract_zip(path: str, dest_dir: str, notes: list[str]) -> list[ExtractedMember]:
    members: list[ExtractedMember] = []
    total = 0
    with zipfile.ZipFile(path) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_ARCHIVE_ENTRIES:
            raise IngestError(
                f"archive has {len(infos)} entries, exceeds "
                f"{MAX_ARCHIVE_ENTRIES} limit"
            )
        for info in infos:
            if info.is_dir():
                continue
            name = info.filename
            # zipfile has no symlink concept in the API, but unix mode bits
            # can encode one; refuse those.
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise IngestError(f"archive contains a symlink: {name!r}")
            if info.file_size > MAX_TOTAL_UNCOMPRESSED:
                raise IngestError(f"entry too large: {name!r}")
            if info.compress_size > 0:
                ratio = info.file_size / info.compress_size
                if ratio > MAX_COMPRESSION_RATIO:
                    raise IngestError(
                        f"entry {name!r} compression ratio {ratio:.0f}:1 "
                        "looks like a decompression bomb"
                    )
            total += info.file_size
            if total > MAX_TOTAL_UNCOMPRESSED:
                raise IngestError("archive exceeds total uncompressed limit")

            target = _safe_join(dest_dir, name)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            # Stream with a hard cap so a lying header can't overrun.
            written = 0
            with zf.open(info) as src, open(target, "wb") as dst:
                while True:
                    chunk = src.read(READ_CHUNK)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > MAX_TOTAL_UNCOMPRESSED:
                        raise IngestError(
                            f"entry {name!r} exceeded declared size while "
                            "extracting"
                        )
                    dst.write(chunk)
            with open(target, "rb") as fh:
                data = fh.read(4096)
            dtype, _ = detect_type(data, os.path.splitext(name)[1].lower())
            members.append(ExtractedMember(name, target, written, dtype))
    return members


def _extract_tar(path: str, dest_dir: str, notes: list[str]) -> list[ExtractedMember]:
    members: list[ExtractedMember] = []
    total = 0
    # gzip/tar streaming; tarfile handles the gzip layer via "r:*".
    with tarfile.open(path, "r:*") as tf:
        count = 0
        for member in tf:
            count += 1
            if count > MAX_ARCHIVE_ENTRIES:
                raise IngestError(
                    f"archive exceeds {MAX_ARCHIVE_ENTRIES} entries"
                )
            if member.issym() or member.islnk():
                raise IngestError(
                    f"archive contains a link: {member.name!r}"
                )
            if member.isdir():
                continue
            if not member.isfile():
                # devices, fifos, etc. have no place in a script bundle
                raise IngestError(
                    f"archive contains a non-regular file: {member.name!r}"
                )
            if member.size > MAX_TOTAL_UNCOMPRESSED:
                raise IngestError(f"entry too large: {member.name!r}")
            total += member.size
            if total > MAX_TOTAL_UNCOMPRESSED:
                raise IngestError("archive exceeds total uncompressed limit")

            target = _safe_join(dest_dir, member.name)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                continue
            written = 0
            with open(target, "wb") as dst:
                while True:
                    chunk = src.read(READ_CHUNK)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > MAX_TOTAL_UNCOMPRESSED:
                        raise IngestError(
                            f"entry {member.name!r} exceeded size while "
                            "extracting"
                        )
                    dst.write(chunk)
            with open(target, "rb") as fh:
                data = fh.read(4096)
            dtype, _ = detect_type(data, os.path.splitext(member.name)[1].lower())
            members.append(ExtractedMember(member.name, target, written, dtype))
    return members


def extract_archive(path: str, detected_type: str, dest_dir: Optional[str] = None
                    ) -> tuple[str, list[ExtractedMember], list[str]]:
    """Safely extract an archive. Returns (dest_dir, members, notes).

    The caller owns ``dest_dir`` cleanup. If not provided, a temp dir is
    created under the system temp root.
    """
    notes: list[str] = []
    if dest_dir is None:
        dest_dir = tempfile.mkdtemp(prefix="vigil_extract_")
    os.makedirs(dest_dir, exist_ok=True)
    if detected_type == "archive:zip":
        members = _extract_zip(path, dest_dir, notes)
    elif detected_type in ("archive:targz", "archive:tar"):
        members = _extract_tar(path, dest_dir, notes)
    else:
        raise IngestError(f"not an extractable archive type: {detected_type}")
    if not members:
        notes.append("archive contained no regular files")
    return dest_dir, members, notes


# --- top-level entry ------------------------------------------------------

def ingest(path: str, extract: bool = True, dest_dir: Optional[str] = None
           ) -> IngestResult:
    """Validate, hash, and type a file. If it is an archive and ``extract``
    is set, safely extract its members too."""
    real = _validate_input_path(path)
    size = os.path.getsize(real)
    with open(real, "rb") as fh:
        head = fh.read(4096)
    ext_hint = os.path.splitext(path)[1].lower()
    detected_type, notes = detect_type(head, ext_hint)
    md5, sha1, sha256 = hash_file(real)

    result = IngestResult(
        path=real, original_path=path, detected_type=detected_type,
        size=size, md5=md5, sha1=sha1, sha256=sha256, notes=list(notes),
    )

    if detected_type in ARCHIVE_TYPES or detected_type == "archive:tar":
        result.is_archive = True
        if extract:
            _, members, ex_notes = extract_archive(real, detected_type, dest_dir)
            result.members = members
            result.notes.extend(ex_notes)
    return result
