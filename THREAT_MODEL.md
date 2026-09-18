# VIGIL — Threat Model

VIGIL analyzes files that are assumed hostile. The input is the adversary.
This document states what VIGIL defends against, what it deliberately does
not, and which module owns each guarantee.

## Adversary

The file under analysis is attacker-controlled and may be crafted
specifically to attack the analysis tool, not just the eventual victim. We
assume the adversary knows VIGIL's design.

Attacker goals VIGIL must resist:

1. **Code execution in the analyst's environment** via the act of analysis.
2. **Resource exhaustion** (memory, CPU, disk) to crash or hang the tool.
3. **Filesystem escape** during archive extraction (writing outside the
   extraction directory, overwriting the analyst's files).
4. **Data exfiltration** — tricking VIGIL into sending the sample or its
   contents somewhere the analyst did not intend.
5. **Evasion** — hiding behavior from static detection.

## Guarantees and where they live

### 1. No execution of input — *every module*

The single most important property: **nothing derived from the input is ever
executed, evaluated, `eval`'d, `exec`'d, imported, or deserialized into
code.** Every operation is a pure text or byte transform.

- The deobfuscator decodes with `base64`, `bytes.fromhex`, `codecs`, etc. —
  never `eval`, never `pickle`, never `marshal`.
- The static analyzer matches patterns and YARA rules against input as
  **data**. YARA rules are compiled from VIGIL's own `rules/` directory, never
  from the sample.
- The AI verdict layer receives a closed list of already-collected evidence as
  text; the model cannot cause code execution and cannot change the score.

### 2. Network egress is confined to two modules — *architectural*

**Exactly two components open a socket.** Every other module is offline and
pure, so the exfiltration question is answerable by reading two files.

**a. `vigil/intel/`** — threat-intel lookups. All outbound HTTP funnels
through `intel/base.py::http_json`.

- **Hash-first.** The file is looked up by SHA256. The file itself is uploaded
  only when the caller passes `--upload`, which prints a warning and prompts.
- Missing keys / rate limits / network errors degrade to noted partial
  results; they never crash the scan and never retry unboundedly.

**b. `vigil/verdict.py`** — AI narration, when `ANTHROPIC_API_KEY` is set and
`--no-ai` is not passed. This path transmits the assembled **evidence list**
to the Anthropic API. That list contains signal identifiers, rule names,
point values, and **extracted IOC values (URLs, domains, public IPs)** — see
`verdict.py::_build_evidence`. It does **not** transmit the file, its bytes,
or decoded layer text.

> ⚠️ **Regulated-data warning.** Extracted URLs retain their full path and
> query string, so an internal URL in the analyzed file can leave the host via
> this path. Private/reserved IP ranges are filtered out by the IOC extractor,
> but internal *hostnames* and URL parameters are not. **When analyzing files
> that may contain CUI, PHI, or other regulated data, run with `--offline`,**
> which disables both egress paths and hard-blocks upload regardless of any
> other flag.

### 3. Resource-exhaustion resistance — *ingestor, deobfuscator, intel*

| Vector | Control | Where |
|--------|---------|-------|
| Huge input file | 25 MB hard cap | `ingestor.MAX_FILE_SIZE` |
| Decompression bomb (archive) | per-entry ratio, entry count, total-size caps, streamed with a hard write cap | `ingestor._extract_zip/_extract_tar` |
| Decode bomb (recursive decode) | depth cap (8), layer cap (200), 2 MB per-layer cap | `deobfuscator.MAX_DEPTH/MAX_LAYERS/MAX_BLOB_SIZE` |
| Decode cycle (A->B->A) | global SHA256 dedup of layer content | `deobfuscator._State.seen_hashes` |
| IOC flood -> intel flood | bounded IOC fan-out (10 IPs/URLs/domains) | `intel.MAX_IPS/MAX_URLS/MAX_DOMAINS` |
| Rate-limit abuse | minimum-interval limiter, shared across VT calls | `intel.base.RateLimiter` |

### 4. Filesystem-escape resistance — *ingestor*

- **Input path**: symlinks are refused; the path is `realpath`-resolved;
  non-regular files and empty files are rejected.
- **Archive entries**: every extracted path is resolved and confirmed to stay
  within the extraction directory (zip-slip / path-traversal defense);
  symlink and hardlink entries are refused; device/fifo entries in tars are
  refused. Extraction streams to disk with a hard byte cap so a lying header
  cannot overrun.

### 5. Secret hygiene — *config + intel*

API keys are read **only** from environment variables, never from config
files, never logged, and never written into reports or error messages.
`config.yaml` is documented as secret-free.

## Out of scope (by design)

These are not defended against because they are **not VIGIL's job** in this release,
and pretending otherwise would give false confidence:

- **Runtime-only obfuscation, execution-time XOR/encryption keys, and
  environment-dependent decoding.** Static analysis cannot resolve payloads
  that only exist when run. VIGIL reports the encoded blob and its depth as a
  signal, and says plainly what it could not decode.
- **Windows PE (`.exe`) analysis.** Dynamic analysis of Windows binaries is
  not possible in this context and shallow header parsing is weak signal.
  VIGIL declines rather than guessing.
- **Intent classification.** VIGIL scores behavior and reputation, not whether
  a given behavior is authorized in your environment. A base64 blob is a
  base64 blob whether dropper or installer.
- **Sandboxing / isolation.** VIGIL does not execute anything, so it needs no
  isolation boundary — and it does not pretend a container would provide one.
  (A Docker container shares the host kernel and is not an isolation boundary
  for hostile code; VIGIL's safety comes from never executing input at all.)

## Residual risks

- **False negatives** from any out-of-scope evasion above. A SAFE verdict is
  "no signals found," not "proven benign," and the report says so.
- **Parser vulnerabilities** in the Python standard library (`zipfile`,
  `tarfile`, `gzip`, `zlib`, `bz2`) or in `yara-python`. VIGIL relies on these
  being memory-safe; it adds the policy limits above on top of them.
- **Third-party intel accuracy.** VT/AbuseIPDB/URLhaus verdicts are treated as
  corroborating signals, not ground truth, and are always attributed to their
  source in the report.
