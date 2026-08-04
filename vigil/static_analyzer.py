"""Static detection over every deobfuscation layer.

Two engines run over each layer's text:

  1. A built-in pattern set (always available) covering persistence,
     anti-forensics, credential access, execution, and C2 behaviors.
  2. YARA, if ``yara-python`` is installed and rule files are present.
     YARA is optional: its absence degrades to pattern-only detection
     with a note, never a crash. This keeps "runs with zero config."

Every finding returns the rule/pattern name, the matched substring, the
category, an ATT&CK technique id where known, and the id + technique of the
layer it was found in, so the report can always show its work.

Pure text matching. No execution of input, no network, no eval.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Optional

from .deobfuscator import Layer, flatten

try:  # optional dependency
    import yara  # type: ignore
    _YARA_AVAILABLE = True
except Exception:  # pragma: no cover - depends on host
    yara = None  # type: ignore
    _YARA_AVAILABLE = False


@dataclass
class Finding:
    name: str            # rule or pattern id
    engine: str          # "pattern" | "yara"
    category: str        # persistence | anti_forensics | credential_access | execution | c2 | download
    matched: str         # the substring that matched (truncated)
    layer_id: int
    layer_technique: str
    attack_id: Optional[str] = None
    severity: str = "medium"  # low | medium | high


@dataclass
class AnalysisResult:
    findings: list[Finding] = field(default_factory=list)
    yara_used: bool = False
    notes: list[str] = field(default_factory=list)


# --- built-in pattern set -------------------------------------------------
# Each entry: (name, category, attack_id, severity, compiled regex).
# Patterns are intentionally behavior-focused, not string-blocklists.

def _p(pattern: str) -> "re.Pattern[str]":
    return re.compile(pattern, re.IGNORECASE)


_PATTERNS: list[tuple[str, str, Optional[str], str, "re.Pattern[str]"]] = [
    # --- execution ---
    ("powershell_iex", "execution", "T1059.001", "high",
     _p(r"\b(?:iex|invoke-expression)\b")),
    ("powershell_encoded", "execution", "T1027", "high",
     _p(r"-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,}")),
    ("powershell_hidden_bypass", "execution", "T1059.001", "high",
     _p(r"-(?:windowstyle\s+hidden|w\s+hidden|nop|noprofile|ep\s+bypass|executionpolicy\s+bypass)")),
    ("shell_eval", "execution", "T1059.004", "high",
     _p(r"\beval\s*\(|\bexec\s*\(|\bsystem\s*\(")),
    ("python_dynamic_exec", "execution", "T1059.006", "high",
     _p(r"\b(?:exec|eval)\s*\(|__import__\s*\(|compile\s*\(")),
    # --- download / staging ---
    ("net_webclient_download", "download", "T1105", "high",
     _p(r"net\.webclient|downloadstring|downloadfile|invoke-webrequest|invoke-restmethod")),
    ("curl_wget_pipe_shell", "download", "T1105", "high",
     _p(r"(?:curl|wget)\b[^\n|]*\|\s*(?:ba)?sh")),
    ("python_url_fetch", "download", "T1105", "medium",
     _p(r"urllib\.request|requests\.get|urlretrieve")),
    # --- persistence ---
    ("scheduled_task", "persistence", "T1053.005", "high",
     _p(r"\bschtasks\b|register-scheduledtask|new-scheduledtask")),
    ("cron_persistence", "persistence", "T1053.003", "medium",
     _p(r"\bcrontab\b|/etc/cron\.|/etc/crontab")),
    ("registry_run_key", "persistence", "T1547.001", "high",
     _p(r"(?:hklm|hkcu|hkey_[a-z_]+)\\[^\n]*\\(?:run|runonce)\b|reg\s+add")),
    ("systemd_service_persistence", "persistence", "T1543.002", "medium",
     _p(r"/etc/systemd/system/|systemctl\s+enable")),
    ("bashrc_persistence", "persistence", "T1546.004", "medium",
     _p(r"~?/?\.bashrc|~?/?\.bash_profile|~?/?\.profile")),
    # --- anti-forensics ---
    ("clear_windows_logs", "anti_forensics", "T1070.001", "high",
     _p(r"clear-eventlog|wevtutil\s+cl|remove-eventlog")),
    ("clear_shell_history", "anti_forensics", "T1070.003", "medium",
     _p(r"history\s+-c|unset\s+HISTFILE|rm\s+[^\n]*\.bash_history|/var/log")),
    ("timestomp", "anti_forensics", "T1070.006", "medium",
     _p(r"\btouch\s+-[amt]|set-itemproperty[^\n]*lastwritetime")),
    ("disable_defender", "anti_forensics", "T1562.001", "high",
     _p(r"set-mppreference|add-mppreference|disable(?:realtimemonitoring|antispyware)")),
    # --- credential access ---
    ("credential_dumping", "credential_access", "T1003", "high",
     _p(r"\bmimikatz\b|sekurlsa|lsass|comsvcs\.dll[^\n]*minidump")),
    ("unix_credential_files", "credential_access", "T1003.008", "high",
     _p(r"/etc/shadow|/etc/passwd\b")),
    ("browser_credential_theft", "credential_access", "T1555.003", "medium",
     _p(r"login\s+data|\\google\\chrome\\user\s+data|logins\.json|key4\.db")),
    # --- c2 ---
    ("reverse_shell_bash", "c2", "T1071", "high",
     _p(r"/dev/tcp/|/dev/udp/|bash\s+-i\s*>&")),
    ("reverse_shell_nc", "c2", "T1071", "high",
     _p(r"\bnc(?:at)?\b[^\n]*(?:-e|-c)\b|mkfifo[^\n]*\|\s*(?:ba)?sh")),
    ("socket_backconnect", "c2", "T1095", "medium",
     _p(r"socket\.socket|new-object\s+[^\n]*sockets\.tcpclient")),
    # --- obfuscation self-evidence ---
    ("base64_decode_call", "execution", "T1140", "medium",
     _p(r"frombase64string|base64\s+-d|base64\.b64decode|::frombase64")),
]


def _pattern_scan(text: str, layer: Layer) -> list[Finding]:
    findings: list[Finding] = []
    for name, category, attack_id, severity, rx in _PATTERNS:
        m = rx.search(text)
        if m:
            matched = m.group()
            if len(matched) > 120:
                matched = matched[:117] + "..."
            findings.append(Finding(
                name=name, engine="pattern", category=category,
                matched=matched, layer_id=layer.id,
                layer_technique=layer.technique, attack_id=attack_id,
                severity=severity,
            ))
    return findings


# --- YARA -----------------------------------------------------------------

def _default_rules_dir() -> str:
    # repo_root/rules
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(here, "rules")


def compile_yara(rules_dir: Optional[str] = None):
    """Compile all ``*.yar`` / ``*.yara`` files in ``rules_dir``. Returns a
    compiled ruleset or None if YARA is unavailable or no rules compile."""
    if not _YARA_AVAILABLE:
        return None
    rules_dir = rules_dir or _default_rules_dir()
    if not os.path.isdir(rules_dir):
        return None
    filepaths = {}
    for fname in sorted(os.listdir(rules_dir)):
        if fname.endswith((".yar", ".yara")):
            filepaths[os.path.splitext(fname)[0]] = os.path.join(rules_dir, fname)
    if not filepaths:
        return None
    try:
        return yara.compile(filepaths=filepaths)
    except Exception:
        return None


def _yara_scan(text: str, layer: Layer, rules) -> list[Finding]:
    findings: list[Finding] = []
    try:
        matches = rules.match(data=text.encode("utf-8", errors="replace"))
    except Exception:
        return findings
    for match in matches:
        meta = getattr(match, "meta", {}) or {}
        matched_str = ""
        strings = getattr(match, "strings", [])
        if strings:
            try:
                # yara-python >= 4.3 returns StringMatch objects
                first = strings[0]
                inst = getattr(first, "instances", None)
                if inst:
                    matched_str = inst[0].matched_data.decode(
                        "utf-8", errors="replace")
                else:  # older tuple form (offset, identifier, data)
                    matched_str = first[2].decode("utf-8", errors="replace")
            except Exception:
                matched_str = ""
        if len(matched_str) > 120:
            matched_str = matched_str[:117] + "..."
        findings.append(Finding(
            name=match.rule, engine="yara",
            category=str(meta.get("category", "yara")),
            matched=matched_str, layer_id=layer.id,
            layer_technique=layer.technique,
            attack_id=meta.get("attack_id"),
            severity=str(meta.get("severity", "medium")),
        ))
    return findings


# --- top-level ------------------------------------------------------------

def analyze(root: Layer, rules_dir: Optional[str] = None,
            use_yara: bool = True) -> AnalysisResult:
    """Run pattern (and, if available, YARA) detection over every layer."""
    result = AnalysisResult()
    rules = compile_yara(rules_dir) if use_yara else None
    if use_yara and rules is None:
        if not _YARA_AVAILABLE:
            result.notes.append(
                "yara-python not installed; ran pattern detection only"
            )
        else:
            result.notes.append(
                "no YARA rules compiled; ran pattern detection only"
            )
    result.yara_used = rules is not None

    for layer in flatten(root):
        result.findings.extend(_pattern_scan(layer.text, layer))
        if rules is not None:
            result.findings.extend(_yara_scan(layer.text, layer, rules))

    return result
