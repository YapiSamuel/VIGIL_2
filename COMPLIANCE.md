# VIGIL — Control Alignment

## Scope and honest framing

**No security tool can be "CMMC compliant," "ISO 27001 certified," or
"NIST compliant."** Those standards assess *organizations*:

- **ISO/IEC 27001** certifies an Information Security Management System (ISMS).
- **CMMC** certifies a defense contractor against **NIST SP 800-171**.
- **CIS Controls** and **NIST SP 800-53** are organizational control sets.

What a *tool* can do is **support** an organization in satisfying specific
controls, and be deployable without violating others. This document maps
VIGIL to the controls it supports, and — equally important — states plainly
which it does **not** address.

> This is a **self-assessment by the author**. It has not been independently
> audited, assessed by a C3PAO, or validated by any third party. Treat it as
> a starting point for your own control mapping, not as evidence of
> compliance.

---

## 1. NIST SP 800-171 Rev. 2 (basis for CMMC Level 2)

| Control | Requirement | VIGIL's contribution | Status |
|---|---|---|---|
| **3.1.3** | Control the flow of CUI | **Hash-first by default**: the file is queried by SHA256; the sample is never uploaded without explicit `--upload` + warning + prompt. `--offline` disables all egress. | ✅ Supports |
| **3.3.1** | Create and retain audit records | `--audit-log` writes append-only JSONL records of every scan | ✅ Supports |
| **3.3.2** | Trace actions to individual users | Audit records capture operator, host, timestamp, target hash, verdict, and egress paths used | ✅ Supports |
| **3.6.1** | Operational incident-handling capability | Provides the *triage* step of detection & analysis | ✅ Supports |
| **3.6.2** | Track, document, report incidents | JSON reports are durable, machine-readable IR artifacts with full provenance | ✅ Supports |
| **3.13.1** | Monitor and control communications at boundaries | Egress confined to two auditable modules; `--offline` enforces zero egress | ✅ Supports |
| **3.13.11** | FIPS-validated cryptography for CUI | ⚠️ See *Cryptographic posture* below — MD5/SHA1 are used as **malware identifiers**, not security functions | ⚠️ Qualified |
| **3.14.2** | Malicious code protection | Pre-execution triage layer; complements, does not replace, endpoint AV | ✅ Supports |
| **3.14.5** | Scan files from external sources as downloaded/opened | **This is VIGIL's core use case** — analysis *before* the file is opened | ✅ Supports |
| **3.1.1 / 3.1.2** | Limit system access to authorized users | VIGIL has no authentication layer; it inherits the OS account's rights | ❌ Not addressed |
| **3.4.x** | Configuration management / baselines | Out of scope | ❌ Not addressed |

---

## 2. NIST SP 800-53 Rev. 5

| Control | VIGIL's contribution |
|---|---|
| **AC-4** Information Flow Enforcement | Hash-first default; `--offline` hard switch |
| **AU-2** Event Logging | Audit log records scan events |
| **AU-3** Content of Audit Records | Records who, what, when, where, outcome, and egress used |
| **AU-9** Protection of Audit Information | **Hash-chained records** — each entry embeds the previous entry's hash, making deletion or alteration detectable (`audit.verify()`) |
| **IR-4 / IR-5** Incident Handling / Monitoring | Structured triage output feeding IR workflow |
| **SI-3** Malicious Code Protection | Pre-execution static triage |
| **SI-4** System Monitoring | JSON output is SIEM-ingestible |
| **SA-11** Developer Testing | 110+ unit tests including adversarial input |

---

## 3. NIST Cybersecurity Framework 2.0

| Function / Category | Alignment |
|---|---|
| **DE.AE** — Adverse Event Analysis | Core function: analyze a suspicious artifact and characterize it |
| **DE.CM** — Continuous Monitoring | Supports file-level inspection at ingress |
| **RS.AN** — Incident Analysis | Provenance-carrying findings support root-cause work |
| **PR.DS** — Data Security | Hash-first and offline mode prevent sample disclosure |
| **GV.SC** — Supply Chain Risk Mgmt | Triage of scripts received from external parties |

---

## 4. NIST AI Risk Management Framework (AI 100-1)

**This is VIGIL's strongest alignment**, and it is architectural rather than
procedural.

| AI RMF Characteristic | How VIGIL implements it |
|---|---|
| **Valid and Reliable** | The verdict is produced by a deterministic scorer with a documented weighting table. Identical input yields an identical verdict — the AI cannot alter it. |
| **Accountable and Transparent** | Every finding carries rule name, matched string, originating decode layer, and source. The report states which component decided what. |
| **Explainable and Interpretable** | The AI's *only* role is explanation, and every claim must cite a specific signal id. If it cannot cite, it does not say it. |
| **Safe** | ATT&CK technique IDs come from a human-authored mapping table, **not** model inference — so a technique attribution cannot be hallucinated. |
| **Secure and Resilient** | The model receives a closed evidence list; it cannot cause code execution, and failure of the AI path degrades to a deterministic template. |

The governing principle: **a confident, fluent, wrong verdict handed to a
junior analyst is worse than no verdict.** The scorer/narrator separation
exists to make that failure mode structurally impossible.

---

## 5. CIS Controls v8.1

| Control | Safeguard | VIGIL's contribution |
|---|---|---|
| **3** Data Protection | 3.1, 3.3 | Hash-first default; `--offline` prevents regulated data egress |
| **8** Audit Log Management | 8.2, 8.5 | Append-only, hash-chained audit log with detailed records |
| **10** Malware Defenses | 10.1 | Pre-execution triage of files from external sources |
| **13** Network Monitoring & Defense | 13.x | Extracted IOCs (with layer provenance) feed blocklists and hunts |
| **16** Application Software Security | 16.1, 16.14 | Documented threat model, adversarial test suite, secure-by-design constraints |
| **17** Incident Response Management | 17.x | Structured, reproducible triage artifacts |

---

## 6. ISO/IEC 27001:2022 — Annex A

| Annex A Control | Title | VIGIL's contribution |
|---|---|---|
| **A.5.7** | Threat intelligence | Integrates VirusTotal, AbuseIPDB, URLhaus; attributes every verdict to its source |
| **A.5.25** | Assessment and decision on information security events | Deterministic escalate / do-not-escalate decision with documented basis |
| **A.5.26** | Response to information security incidents | JSON artifacts support response workflow |
| **A.8.7** | Protection against malware | Pre-execution triage layer |
| **A.8.12** | Data leakage prevention | **Hash-first default and `--offline`** — the sample never leaves the host unless explicitly authorized |
| **A.8.15** | Logging | Operator audit log |
| **A.8.16** | Monitoring activities | SIEM-ingestible output |
| **A.8.25** | Secure development life cycle | Threat model authored before implementation |
| **A.8.28** | Secure coding | Hard rule: nothing derived from input is executed, evaluated, or imported |
| **A.8.29** | Security testing in development | Adversarial test suite: zip-slip, decompression bombs, decode bombs, malformed encodings |

---

## Cryptographic posture (read this before a CUI deployment)

VIGIL computes **MD5, SHA1, and SHA256** for each file.

- **SHA256** is the primary identifier and the cache key.
- **MD5 and SHA1** are computed **solely because threat-intel services and
  IOC feeds are keyed on them.** They are used as *lookup identifiers*, never
  as integrity or authentication controls.

Under **NIST SP 800-171 3.13.11** and **FIPS 140-3**, MD5 and SHA1 are not
approved for security functions. VIGIL does not use them for a security
function, but an assessor may flag their presence. Document this distinction
in your SSP. The audit log's chain integrity uses **SHA256 only**.

---

## Gaps — what VIGIL does *not* provide

State these plainly in any assessment rather than letting an assessor find them:

1. **No authentication or authorization.** Single-user CLI; it inherits the
   invoking OS account's privileges. The entire AC family is unaddressed.
2. **No FIPS-validated cryptographic module.** Python's `hashlib` is used
   as provided by the host.
3. **External services are not FedRAMP-authorized.** VirusTotal, AbuseIPDB,
   and Anthropic are commercial SaaS. **Use `--offline` in environments where
   that matters.**
4. **No SBOM is published** (an EO 14028 / NIST SP 800-218 expectation),
   though the dependency surface is the Python standard library plus three
   optional packages.
5. **Audit log is tamper-*evident*, not tamper-*proof*.** An attacker with
   write access can rewrite the entire chain. Forward it to a WORM store or
   SIEM for the stronger property.
6. **No independent assessment.** Nothing here has been validated by a third
   party.
7. **Detection coverage is finite.** The ATT&CK mapping covers only the
   behaviors explicitly enumerated in `static_analyzer.py`. A technique not in
   that table receives **no** ID rather than a guessed one.

---

## Recommended configuration for regulated environments

```bash
# CUI / PHI / regulated data — zero egress, full audit trail
python -m vigil scan suspicious.sh \
  --offline \
  --audit-log /var/log/vigil/audit.jsonl \
  --json
```

`--offline` disables threat intel *and* AI narration and hard-blocks upload
**regardless of any other flag**, including `--upload`. Analysis remains fully
functional: deobfuscation, YARA, pattern detection, IOC extraction, and
deterministic scoring are all local. Only external corroboration and AI-written
prose are lost, and the report says so in its notes.

Verify audit-log integrity at any time:

```python
from vigil import audit
ok, checked, bad_line = audit.verify("/var/log/vigil/audit.jsonl")
```
