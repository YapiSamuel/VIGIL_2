import json
import os
import stat

import pytest

from vigil import credentials as c


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in c.KNOWN_KEYS:
        monkeypatch.delenv(k, raising=False)


def _p(tmp_path):
    return str(tmp_path / "credentials")


# --- precedence: environment always wins -----------------------------------

def test_environment_takes_precedence_over_file(tmp_path, monkeypatch):
    p = _p(tmp_path)
    c.save({"VT_API_KEY": "from-file"}, path=p)
    assert c.get("VT_API_KEY", path=p) == "from-file"
    monkeypatch.setenv("VT_API_KEY", "from-env")
    assert c.get("VT_API_KEY", path=p) == "from-env"
    assert c.source_of("VT_API_KEY", path=p) == "environment"


def test_source_of_reports_accurately(tmp_path, monkeypatch):
    p = _p(tmp_path)
    assert c.source_of("VT_API_KEY", path=p) == "unset"
    c.save({"VT_API_KEY": "k"}, path=p)
    assert c.source_of("VT_API_KEY", path=p) == "file"
    monkeypatch.setenv("VT_API_KEY", "e")
    assert c.source_of("VT_API_KEY", path=p) == "environment"


# --- storage round-trip -----------------------------------------------------

def test_save_and_load_roundtrip(tmp_path):
    p = _p(tmp_path)
    ok, _msg = c.save({"VT_API_KEY": "abc123", "ANTHROPIC_API_KEY": "xyz789"},
                      path=p)
    assert ok
    loaded = c.load_file(p)
    assert loaded["VT_API_KEY"] == "abc123"
    assert loaded["ANTHROPIC_API_KEY"] == "xyz789"


def test_save_merges_rather_than_replacing(tmp_path):
    p = _p(tmp_path)
    c.save({"VT_API_KEY": "one"}, path=p)
    c.save({"ABUSEIPDB_API_KEY": "two"}, path=p)
    loaded = c.load_file(p)
    assert loaded["VT_API_KEY"] == "one"
    assert loaded["ABUSEIPDB_API_KEY"] == "two"


def test_empty_value_removes_a_key(tmp_path):
    p = _p(tmp_path)
    c.save({"VT_API_KEY": "gone-soon"}, path=p)
    c.save({"VT_API_KEY": ""}, path=p)
    assert "VT_API_KEY" not in c.load_file(p)


def test_unknown_keys_are_ignored(tmp_path):
    p = _p(tmp_path)
    with open(p, "w") as fh:
        fh.write("SOME_OTHER_SECRET=nope\nVT_API_KEY=yes\n")
    loaded = c.load_file(p)
    assert loaded == {"VT_API_KEY": "yes"}


# --- security properties ----------------------------------------------------

@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions only")
def test_file_is_owner_readable_only(tmp_path):
    p = _p(tmp_path)
    c.save({"VT_API_KEY": "secret"}, path=p)
    mode = os.stat(p).st_mode
    assert not (mode & stat.S_IRWXG), "group can access the credential file"
    assert not (mode & stat.S_IRWXO), "others can access the credential file"


def test_mask_never_reveals_the_key():
    secret = "sk-ant-verysecretvalue1234567890"
    masked = c.mask(secret)
    assert secret not in masked
    assert masked.startswith("sk-a")
    assert "*" in masked


def test_mask_handles_short_and_empty_values():
    assert c.mask(None) == "(not set)"
    assert c.mask("") == "(not set)"
    assert "short" not in c.mask("short")


def test_credentials_path_is_outside_the_project(tmp_path):
    """Keys must not live anywhere `git add .` could reach."""
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    assert not os.path.abspath(c.CREDENTIALS_PATH).startswith(repo + os.sep)


def test_config_yaml_is_never_used_for_secrets():
    """config.yaml ships in the repo and is documented secret-free."""
    assert "config" not in os.path.basename(c.CREDENTIALS_PATH)
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cfg = os.path.join(repo, "config.yaml")
    if os.path.isfile(cfg):
        body = open(cfg, encoding="utf-8").read()
        for key in c.KNOWN_KEYS:
            # the name may be mentioned in a comment, but never assigned
            assert f"{key}:" not in body and f"{key}=" not in body


# --- graceful degradation ---------------------------------------------------

def test_missing_file_is_not_an_error(tmp_path):
    assert c.load_file(str(tmp_path / "nope")) == {}
    assert c.get("VT_API_KEY", path=str(tmp_path / "nope")) is None


def test_malformed_file_is_tolerated(tmp_path):
    p = _p(tmp_path)
    with open(p, "w") as fh:
        fh.write("garbage line\n\n# comment\n=novalue\nVT_API_KEY=ok\n")
    assert c.load_file(p) == {"VT_API_KEY": "ok"}


def test_save_to_unwritable_path_returns_false(tmp_path):
    d = tmp_path / "creds"
    d.mkdir()
    ok, msg = c.save({"VT_API_KEY": "x"}, path=str(d))
    assert ok is False and msg
