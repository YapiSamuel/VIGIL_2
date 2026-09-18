# VIGIL

[![tests](https://github.com/YapiSamuel/VIGIL_2/actions/workflows/tests.yml/badge.svg)](https://github.com/YapiSamuel/VIGIL_2/actions/workflows/tests.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

**Pre-execution malware triage for scripts.** VIGIL answers one question
fast: *is this script safe to hand off, or should I escalate it now?*

It is built for a junior analyst in a mixed Linux/Windows SOC who has a
suspicious `.sh`, `.ps1`, or `.py` and needs a structured, explainable answer
in under 30 seconds — without a sandbox platform running.

```
$ vigil scan suspicious.sh

  VERDICT: MALICIOUS  (100/100)  -> ESCALATE NOW
  confidence: medium - multiple strong local signals, no external confirmation

  Why  [template]
    Risk band MALICIOUS (score 100/100). Primary evidence: c2 finding (high)
    [pattern:reverse_shell_bash [T1095]]; download finding (high)
    [pattern:curl_wget_pipe_shell [T1105]] ...

  Static findings (3)
      high  reverse_shell_bash [T1095]  (layer 0/source)
      high  curl_wget_pipe_shell [T1105]  (layer 1/base64)   <-- found INSIDE a base64 blob
```

## What VIGIL does

```
file in
  -> ingestor        validate path, magic bytes, hashes, safe archive extraction
  -> cache           SQLite keyed by SHA256; skip re-analysis
  -> deobfuscator    recursive layer unwrapping
  -> static_analyzer YARA + pattern detection over EVERY layer
  -> ioc_extractor   IPs, domains, URLs over every layer (with provenance)
  -> intel clients   VirusTotal + AbuseIPDB + URLhaus, parallel, hash-first
  -> scorer          deterministic risk score from collected signals
  -> verdict          plain-English explanation (AI narrates; it never judges)
  -> reporter        terminal summary + JSON
```

The deobfuscator recursively unwraps base64, hex, `\x`/`\u` escapes, URL
encoding, decimal char arrays, string concatenation, ROT13, reversal, and
gzip/zlib/bz2 — including PowerShell `-EncodedCommand` (UTF-16LE). Detection
and IOC extraction then run over **every decoded layer**, so a C2 address
three levels deep is caught exactly like plaintext.

## Install & run

VIGIL runs on the **standard library alone**. With zero config and no API
keys it performs full local analysis; optional extras add capability and
degrade gracefully (with a printed note, never a crash) when absent.

```bash
python -m vigil scan suspicious.sh          # local-only, zero config
python -m vigil scan bundle.tar.gz          # archives are extracted safely
python -m vigil scan suspicious.ps1 --json  # machine-readable report
python -m vigil setup                        # write a config template, show key status

# Regulated data (CUI / PHI): zero egress + a tamper-evident audit trail
python -m vigil scan suspicious.sh --offline --audit-log ~/.vigil/audit.jsonl
python -m vigil verify-audit ~/.vigil/audit.jsonl
```

`--offline` disables threat intel **and** AI narration and blocks upload
regardless of any other flag, including `--upload`. Analysis stays fully
functional — only external corroboration and AI-written prose are lost. It can
also be enforced centrally via `policy.offline: true` in `config.yaml`, so it
does not depend on an analyst remembering a flag.

Exit code is `1` when the verdict says escalate, `0` otherwise — so VIGIL
drops into a shell pipeline.

Optional extras (`pip install -r requirements.txt`):

| Extra          | Unlocks                                  | Without it |
|----------------|------------------------------------------|------------|
| `PyYAML`       | reading `config.yaml`                    | built-in defaults |
| `yara-python`  | YARA rule matching over every layer      | pattern detection only |
| `anthropic`    | AI-written verdict narration             | deterministic explanation |

### API keys (optional, environment variables only)

Secrets are read **only** from the environment — never from config, never
logged, never in reports.

| Variable            | Enables                          |
|---------------------|----------------------------------|
| `VT_API_KEY`        | VirusTotal hash lookups          |
| `ABUSEIPDB_API_KEY` | AbuseIPDB IP reputation          |
| `ANTHROPIC_API_KEY` | AI-written verdict explanations  |

URLhaus (abuse.ch) needs no key and works out of the box.

## Safety model

- **Nothing is ever executed.** VIGIL is static analysis only. Every operation
  is a pure text or byte transform. VIGIL does not detonate; it tells you
  whether you should.
- **Exactly two modules make network calls:** `intel/` (threat-intel lookups)
  and `verdict.py` (AI narration, only when an Anthropic key is set). Every
  other module is offline and pure. Neither path ever transmits the file or
  its contents — but `verdict.py` does send extracted IOCs (URLs, domains,
  public IPs) as evidence. **Use `--offline` to disable both**, which is the
  correct mode for CUI, PHI, or other regulated data. See
  [THREAT_MODEL.md](THREAT_MODEL.md) and [COMPLIANCE.md](COMPLIANCE.md).
- **Hash-first.** VIGIL looks up your file by SHA256. It never uploads the
  file itself to VirusTotal unless you pass `--upload`, which prints a warning
  and prompts first — because uploaded files become retrievable by VT's paid
  customers, and uploading a sample containing customer data or credentials
  can be a compliance violation.
- **The AI never decides the verdict.** `scorer.py` produces the risk score
  deterministically from collected signals. `verdict.py` only *explains*
  evidence already collected, and every claim cites a specific signal (rule
  name, decoded layer id, VT engine count, IOC). If it cannot cite, it does
  not say it.
- **Every finding carries provenance.** "Why does it think this is malicious?"
  is always already answered in the report: rule name, matched string, layer
  id, source.
- **Graceful degradation.** Missing keys, rate limits, and network failures
  produce a partial report with a clear note, never a crash. The VirusTotal
  free tier (4 req/min, 500/day) is respected via rate limiting and bounded
  IOC fan-out.

## What VIGIL cannot do

A tool that states its limits is more trustworthy than one that oversells.
VIGIL is static analysis, and static analysis has hard blind spots:

- **Obfuscation built at runtime.** If a payload is assembled from pieces only
  at execution time, there is no static blob to decode.
- **XOR / encryption with an execution-time key.** VIGIL unwraps *encodings*
  (base64, hex, ...), not *encryption* whose key exists only at runtime.
- **Environment-dependent decoding.** Payloads that decode differently based
  on hostname, date, or a C2 response cannot be resolved without running them.
- **Intent.** A base64 blob is a base64 blob whether it is a dropper or a
  legitimate installer. VIGIL scores *behaviors and reputation*, not purpose.
- **Windows PE binaries (`.exe`).** Explicitly out of scope. Dynamic analysis
  of Windows binaries is not possible here, and shallow PE header reading is
  weak signal. VIGIL says so and declines rather than guessing.
- **A clean verdict is not a guarantee.** "No signals collected" means exactly
  that — absence of evidence, not proof of safety.

VIGIL is not a sandbox, not a PE analyzer, not a SIEM or case manager, and not
a new category of tool. It is a focused, honest, well-engineered triage aid.

## Development

```bash
pip install -r requirements.txt
python -m pytest            # full suite, incl. hostile-input tests per module
```

Every module ships with unit tests alongside it, including malformed and
hostile input (zip-slip, decompression bombs, decode bombs, malformed
encodings, broken caches, rate-limit and network failures).

See [THREAT_MODEL.md](THREAT_MODEL.md) for the adversary model and the
guarantees each module is responsible for, and [COMPLIANCE.md](COMPLIANCE.md)
for control mappings to NIST SP 800-171/800-53, CIS Controls v8.1, and
ISO/IEC 27001:2022 — including an honest gaps section.

## License

Licensed under the [Apache License 2.0](LICENSE).

You may use, modify, and distribute this software, including commercially.
The license includes an express patent grant, and it grants no rights to the
VIGIL name or marks. Derivative works must retain the copyright notice, include
the [NOTICE](NOTICE) file, and state what they changed.
