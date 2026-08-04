# VIGIL v2.0.0

**Pre-execution malware triage for scripts.** VIGIL answers one question fast:
*is this script safe to hand off, or should I escalate it now?* — in under 30
seconds, with no sandbox and no cloud dependency.

Built for a junior analyst in a mixed Linux/Windows SOC who has a suspicious
`.sh`, `.ps1`, or `.py` (or an archive of them) and needs a structured,
explainable answer now.

> ⚠️ **Work in progress.** This is a complete, tested release, but the project
> is still evolving. Expect rough edges and breaking changes before a stable
> line. Feedback and issues are very welcome.

## Highlights

- **Recursive deobfuscation, then analysis over *every* layer.** Unwraps
  base64, hex, `\x`/`\u` escapes, URL encoding, decimal char arrays, string
  concatenation, ROT13, reversal, and gzip/zlib/bz2 — including PowerShell
  `-EncodedCommand` (UTF-16LE). A C2 address three decodes deep is caught
  exactly like plaintext.
- **Explainable by construction.** Every finding carries its provenance — rule
  name, matched string, decoded layer id, and source — and every claim in the
  verdict cites a specific signal.
- **Deterministic scoring; AI narrates but never decides.** `scorer.py`
  produces the risk band from collected signals with a documented weighting
  table. The AI layer only explains evidence already collected.
- **Runs with zero config and no API keys**, degrading to full local analysis.

## Pipeline

```
ingestor -> cache -> deobfuscator -> static_analyzer -> ioc_extractor
         -> intel (VirusTotal + AbuseIPDB + URLhaus) -> scorer -> verdict -> reporter
```

## Safety model

- **Nothing is ever executed.** Static analysis only; every operation is a pure
  text/byte transform.
- **Network egress is confined to `vigil/intel/`.** Every other module is
  offline and pure — the "can this leak my sample?" question is answered by
  reading one directory.
- **Hash-first.** Files are looked up by SHA256; the sample is never uploaded
  to VirusTotal unless you pass `--upload`, which prints a warning and prompts.
- **Graceful degradation.** Missing keys, rate limits, and network failures
  produce a partial report with a clear note, never a crash.

## Install & run

VIGIL runs on the Python **standard library alone**.

```bash
python -m vigil scan suspicious.sh          # local-only, zero config
python -m vigil scan bundle.tar.gz          # archives extracted safely
python -m vigil scan suspicious.ps1 --json  # machine-readable report
python -m vigil setup                        # config template + key status
```

Optional extras (`pip install -r requirements.txt`): `PyYAML` (config),
`yara-python` (YARA rules), `anthropic` (AI-written verdicts). API keys are
read from environment variables only.

## What VIGIL cannot do (by design)

Runtime-built obfuscation, execution-time XOR/encryption keys,
environment-dependent decoding, intent, and Windows PE (`.exe`) binaries are
out of scope. A SAFE verdict means "no signals found," not "proven benign" —
and the tool says so. See `README.md` and `THREAT_MODEL.md`.

## Testing

110 unit tests across every module, including hostile input: zip-slip,
decompression bombs, decode bombs, malformed encodings, broken caches, and
rate-limit / network failures.

---

🤖 Built with [Claude Code](https://claude.com/claude-code)
