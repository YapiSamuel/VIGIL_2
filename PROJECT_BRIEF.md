# VIGIL — Project Brief

Paste this as your first message to Claude Code. Keep it in the repo root as
`PROJECT_BRIEF.md` and point Claude Code at it in later sessions.

---

## Role

You are helping me build VIGIL, a pre-execution malware triage CLI. I am a
junior SOC analyst / student. Explain your reasoning as you go — I am building
this to learn, not just to have it finished. Push back when I ask for something
that is a bad idea, and tell me when something I want is harder or less
valuable than I think.

## What VIGIL is

A command-line triage tool that answers one question fast: **is this script
safe to hand off, or should I escalate it now?**

Target user: a junior analyst in a mixed Linux/Windows SOC who has a suspicious
script and needs a structured answer in under 30 seconds, without a sandbox
platform running.

## What VIGIL is NOT — do not let scope creep back in

- **Not a sandbox.** v1.0 performs **static analysis only**. Nothing is ever
  executed. Docker containers share the host kernel and are not an isolation
  boundary; we are not pretending otherwise. Position: "we don't detonate, we
  tell you whether you should."
- **Not a PE analyzer.** `.exe` is out of scope for v1.0. We cannot dynamically
  analyze Windows binaries on Linux, and shallow PE header reading is weak
  signal.
- **Not a SIEM or case manager.** That is TheHive's and Elastic's job.
- **Not novel.** Code Insight, Any.run, IntelOwl, Assemblyline exist. We are
  building a focused, honest, well-engineered tool — not a new category.

If I ask for watch mode, a GUI, offline mode, or PyPI packaging before v1.0 is
finished and tested, remind me they are deferred.

## Scope for v1.0

**File types:** `.sh`, `.ps1`, `.py`, and archives (`.zip`, `.tar.gz`)
containing them.

**Pipeline:**

```
file in
  → ingestor        validate path, magic bytes, hashes, safe archive extraction
  → cache           SQLite keyed by SHA256; skip re-analysis
  → deobfuscator    recursive layer unwrapping                    [DONE]
  → static_analyzer YARA + pattern detection over every layer
  → ioc_extractor   IPs, domains, URLs over every layer
  → intel clients   VT + AbuseIPDB + URLhaus, parallel, hash-first
  → scorer          deterministic risk score from collected signals
  → verdict         Anthropic API writes plain-English explanation
  → reporter        terminal summary + JSON
```

## Hard engineering rules

These are non-negotiable. Enforce them even if I forget.

1. **Nothing is executed, evaluated, `eval`'d, or imported from analyzed input.**
   Every operation is a pure text or byte transformation.
2. **Only the intel client modules make network calls.** Every other module is
   offline and pure. This is what makes the safety story auditable — if someone
   asks "can this tool leak data," the answer is in two files.
3. **Hash-lookup first. Never upload a file to VirusTotal without an explicit
   `--upload` flag plus a printed warning.** Files uploaded to VT become
   accessible to VT's paid customers; in a corporate SOC, uploading a file
   containing customer data or credentials is a compliance violation. This
   default is what makes the tool deployable instead of banned on day one.
4. **The AI never decides the verdict.** `scorer.py` produces the risk score
   deterministically from collected signals. `verdict.py` only explains
   evidence that was already collected, and every claim it makes must cite a
   specific signal (YARA rule name, decoded layer id, VT engine count, IOC).
   If it cannot cite, it does not say it. A confident wrong verdict handed to a
   junior analyst is worse than no verdict.
5. **Every finding carries provenance.** When I ask "why does it think this is
   malicious," the answer must already be in the report — rule name, matched
   string, layer id, source. Tools that cannot explain themselves get abandoned
   after the first false positive.
6. **Graceful degradation.** Missing API keys, rate limits, and network
   failures must produce a partial report with a clear note, never a crash.
   VT free tier is 4 req/min, 500/day — respect it.
7. **Secrets from environment variables or config only.** Never logged, never
   in reports, never in error messages.
8. **Tests alongside each module, not after.** Every module ships with unit
   tests including malformed and hostile input.

## Repo layout

```
VIGIL/
├── vigil/
│   ├── __init__.py
│   ├── main.py
│   ├── ingestor.py
│   ├── deobfuscator.py        [DONE]
│   ├── static_analyzer.py
│   ├── ioc_extractor.py
│   ├── intel/
│   │   ├── vt_client.py
│   │   ├── abuseipdb_client.py
│   │   └── urlhaus_client.py
│   ├── scorer.py
│   ├── verdict.py
│   ├── cache.py
│   └── reporter.py
├── rules/                      YARA rules
├── tests/
├── reports/
├── PROJECT_BRIEF.md
├── THREAT_MODEL.md
├── config.yaml
├── requirements.txt
└── README.md
```

## Current state

`vigil/deobfuscator.py` is written and tested. It:

- Recursively unwraps base64 (standard + urlsafe), hex, `\x` and `\u` escapes,
  URL encoding, decimal char arrays, string concatenation, ROT13, and reversed
  text, plus gzip/zlib/bz2 and UTF-16LE post-processing.
- Handles PowerShell `-EncodedCommand` correctly — that base64 always decodes
  to UTF-16LE, and missing this misses the most common Windows obfuscation.
- Bounds recursion by depth (8), layer count (200), and blob size (2 MB), with
  SHA256 cycle detection so a decode bomb cannot exhaust memory.
- Filters noise with a keyword `likeness()` score — without it, every git hash,
  JWT, and minified bundle becomes a bogus layer. Keywords are counted once per
  family so a loop printing `curl` 500 times does not outrank a real payload.
- Suppresses sibling layers whose text is a substring of a longer sibling,
  which removes partial re-decodes of the same blob.
- Exposes `flatten(root)` as the seam: YARA and IOC extraction run over
  **every** layer, so a C2 address three levels deep is caught like plaintext.

Verified against a three-stage nested sample (base64 → base64 → payload, plus a
hex fallback URL and a UTF-16LE PowerShell blob) and against a benign script
that correctly produced zero layers.

## Build order

Build one module at a time. Do not start the next until the current one has
passing tests and I have reviewed it.

1. `ingestor.py` — path validation (reject traversal and symlinks), magic-byte
   type detection (never trust the extension), hashes, **safe archive
   extraction** (zip-slip protection, decompression-bomb limits on ratio, entry
   count, and total uncompressed size).
2. `cache.py` — SQLite keyed by SHA256, storing analysis results with a TTL.
3. `ioc_extractor.py` — consumes `flatten()`; extracts IPs, domains, URLs with
   defanging support and private/reserved-range filtering. Reports which layer
   each IOC came from.
4. `static_analyzer.py` — YARA over every layer, plus pattern detection for
   persistence, anti-forensics, credential access, and C2. Every match returns
   the rule name and matched string.
5. `intel/` clients — parallel lookups, shared rate-limit handling, hash-first
   by default.
6. `scorer.py` — deterministic risk score with a documented weighting table.
   Layer depth is itself a signal: three levels of encoding is meaningful.
7. `verdict.py` — Anthropic API. Evidence-bound prompt, cited claims, ATT&CK
   technique IDs, confidence level with stated basis.
8. `reporter.py` — terminal summary plus JSON.
9. `main.py` — CLI wiring, config loading, first-run setup.

## Definition of done for v1.0

- `vigil scan suspicious.sh` produces a verdict in under 30 seconds
- Runs with zero config and no API keys, degrading to local-only analysis
- Every finding traceable to its source signal and originating layer
- Test suite covering each module, including hostile input
- README that states plainly what the tool cannot do — obfuscation built at
  runtime, XOR with an execution-time key, environment-dependent decoding, and
  intent (a base64 blob is a base64 blob whether it is a dropper or an
  installer). A project that states its limits reads as more mature than one
  that oversells.

## How to work with me

Before writing a module, state its contract: inputs, outputs, failure modes,
and what it must never do. Then write it. Then write its tests. Then stop and
let me review before moving on.
