# VIGIL — Evaluation Methodology

A plan for measuring whether VIGIL works, rather than asserting that it does.

This document is written to be executed. It defines research questions,
corpus construction, metrics, experiments, and threats to validity. It is
deliberately conservative: every claim it produces should survive an
adversarial reader.

---

## 0. Why this exists

VIGIL currently rests on assertion. It detects the behaviors its pattern table
enumerates, and the risk bands were calibrated by judgment rather than data.
Two questions are therefore open:

1. **Does it detect malicious scripts at a useful rate, without drowning an
   analyst in false positives?**
2. **Are the band thresholds (`SAFE`/`LOW`/`SUSPICIOUS`/`HIGH`/`MALICIOUS`)
   set where the data says they should be?**

Neither can be answered by adding features. Both require a corpus.

---

## 1. Research questions

**RQ1 — Detection performance.** What are VIGIL's precision, recall, and
false-positive rate on a labeled corpus of benign and malicious scripts,
across `.sh`, `.ps1`, and `.py`?

**RQ2 — Threshold calibration.** Where should the band boundaries sit to
maximize utility for triage? The current thresholds are hand-chosen; an ROC
analysis over the continuous 0–100 score can place them empirically.

**RQ3 — Layered obfuscation.** Does analyzing every decoded layer measurably
improve detection over analyzing only the source text? This isolates the
project's central design decision and is directly measurable by re-running the
corpus with recursion disabled.

**RQ4 — Precision/recall tradeoff on downloaders.** Bare download-to-file
patterns (`wget -O`, `curl -o`, `curl >`) are currently undetected, because
matching them naively would fire on most legitimate installer scripts. What
is the actual cost, in false positives against real-world benign installers,
of adding them? *(This question exists because the synthetic corpus surfaced
the gap; it is the first concrete experiment to run.)*

**RQ5 — Analyst decision quality (stretch, requires IRB).** Does constraining
an LLM to *explanation only* — rather than letting it assess — measurably
change the accuracy of escalation decisions made by inexperienced analysts?

RQ1–RQ4 are achievable within a capstone timeline and need no human subjects.
RQ5 is the novel research contribution and is scoped separately in §7.

---

## 2. Corpus construction

The corpus is the experiment. A weak corpus invalidates everything downstream,
and **the benign half is harder and matters more** than the malicious half.

### 2.1 Malicious samples

| Source | Notes |
|---|---|
| **MalwareBazaar** (abuse.ch) | Free API, filterable by file type; the primary source for script-family samples |
| **theZoo** | Curated repository, live samples — handle with the same care |
| **Published IR reports / CISA advisories** | Scripts quoted in advisories come with authoritative labels and ATT&CK context |

**Target: ≥ 300 malicious samples**, stratified across `.sh`, `.ps1`, `.py`.

**Handling rules.** Download only inside an isolated VM with no shared folders
and host-only networking. Never execute a sample — VIGIL performs static
analysis and never needs a working payload. Store samples encrypted and
password-protected at rest. Confirm your institution's acceptable-use policy
before downloading live malware on a university network.

### 2.2 Benign samples — the part that decides the result

False positives are what get tools abandoned, and they come from software that
*legitimately* behaves suspiciously. A benign corpus of hand-written "hello
world" scripts proves nothing. It must contain scripts that download, decode,
elevate, and write to system paths — because real ones do.

| Source | Why it matters |
|---|---|
| **Package manager install scripts** — Homebrew formulas, Debian `postinst`, RPM `%post` | Routinely `curl`, `chmod +x`, write to `/usr/local` |
| **npm `postinstall` hooks** | Frequently fetch and execute |
| **Chocolatey packages, PowerShell Gallery modules** | Windows equivalents; use `DownloadString`, `-ExecutionPolicy Bypass` |
| **Popular GitHub repos** (high-star, `.sh`/`.py`/`.ps1`) | General-purpose baseline |
| **CI/CD scripts** — GitHub Actions, GitLab CI | Base64 secrets handling, remote fetches |
| **Vendor install one-liners** (`curl … \| sh` installers) | **The adversarial case.** Legitimate software that looks exactly like a dropper |

**Target: ≥ 700 benign samples.** The imbalance is deliberate: in a real SOC
queue, benign vastly outnumbers malicious, and precision under class imbalance
is what determines whether the tool is usable.

### 2.3 Labeling

- **Malicious** = sourced from a malware feed with corroborating detections
  (e.g. ≥ 5 VirusTotal engines), or quoted as malicious in a published report.
- **Benign** = sourced from a reputable distribution channel **and** clean on
  VirusTotal.
- **Discard** anything ambiguous. A contaminated label is worse than a smaller
  corpus. Record the discard count and reasons.

Record for every sample: SHA256, source, label, label basis, file type, date
acquired. Publish this manifest — **not the samples** — so the corpus is
reconstructible without redistributing malware.

---

## 3. Metrics

Report the full confusion matrix, never accuracy alone (under 70/30 imbalance,
"always benign" scores 70% accuracy while catching nothing).

| Metric | Definition | Why |
|---|---|---|
| **Recall (TPR)** | TP / (TP + FN) | Missed malware is the catastrophic error |
| **Precision** | TP / (TP + FP) | Low precision means alert fatigue and abandonment |
| **FPR** | FP / (FP + TN) | The number that decides deployability |
| **F1** | harmonic mean | Single summary figure |
| **ROC / AUC** | across all thresholds | Threshold-independent discrimination (RQ2) |
| **PR-AUC** | precision-recall | More informative than ROC under class imbalance |

**Report per file type** (`.sh` / `.ps1` / `.py`) as well as overall. Aggregate
numbers hide that PowerShell coverage may be far stronger than Python.

**Also report:**
- **Per-technique recall** — which ATT&CK techniques are reliably caught and
  which are not. This is more useful to a practitioner than a single figure.
- **Runtime distribution** — median and p95 wall-clock per sample. The project
  claims "under 30 seconds"; that claim should be measured, not assumed.
- **Truncation rate** — how often `INCOMPLETE ANALYSIS` fires, and whether
  those samples are disproportionately malicious.

---

## 4. Experiments

### E1 — Baseline performance (RQ1)
Run VIGIL over the full corpus with `--offline --json`, collect scores, compute
all metrics in §3. This is the headline result.

### E2 — Threshold calibration (RQ2)
Using the continuous scores from E1, plot ROC and PR curves and identify the
threshold maximizing F1, and separately the threshold holding FPR below 5%.
Compare to the current hand-set boundaries. **If the data disagrees with the
current thresholds, change them and say so** — that is a finding, not a defect.

### E3 — Layer analysis ablation (RQ3)
Re-run the corpus with recursive deobfuscation disabled (analyze source text
only) and compare recall. This isolates the contribution of the project's
central design decision. Expected result: a meaningful recall gain on obfuscated
samples and no change on plaintext ones. **If there is no gain, that is a
publishable negative result** and it should be reported.

### E4 — Downloader precision tradeoff (RQ4)
Add candidate patterns for `wget -O`, `curl -o`, and `curl >`. Measure the
change in recall **and** the change in false positives against the benign
installer subset specifically. Report the tradeoff curve rather than a verdict.
This experiment directly answers whether the current conservative choice is
correct.

### E5 — Comparative baseline
Compare VIGIL against at least one independent tool on the same corpus:

- **ClamAV** — freely available, script signatures, easy to automate
- **YARA with a public ruleset** — isolates what VIGIL's pipeline adds over
  rules alone
- **VirusTotal aggregate** (hash lookup only) — an upper bound reference

The honest framing: VIGIL is not expected to beat a multi-engine aggregate. The
question is whether it provides useful signal *locally, without upload*, which
is the deployment scenario it targets.

---

## 5. Threats to validity

State these explicitly; a reviewer will find them regardless.

1. **Corpus bias.** Samples from a single feed share family characteristics.
   Stratify by source and report per-source results.
2. **Temporal bias.** Recent samples may resemble each other. Record first-seen
   dates and, if feasible, evaluate on a time-held-out split.
3. **Label noise.** VirusTotal consensus is a proxy for ground truth, not
   ground truth. Report the label basis and discard rate.
4. **Benign corpus realism.** If the benign set lacks aggressive installer
   scripts, the false-positive rate will be optimistic. This is the most likely
   way to accidentally overstate results.
5. **Self-evaluation.** The tool's author designed both the patterns and the
   corpus. Mitigate by sourcing benign samples programmatically rather than by
   hand-picking, and by pre-registering thresholds before seeing results.
6. **Static-analysis ceiling.** Runtime-constructed payloads and
   execution-time encryption are undetectable by design. Quantify how much of
   the corpus falls into this category rather than treating those as ordinary
   misses.

---

## 6. Reproducibility

- Publish the **sample manifest** (hashes + sources), never the samples.
- Publish the evaluation harness as `tools/evaluate.py`, emitting a CSV of
  `sha256, label, score, band, elapsed, findings, bounds_hit`.
- Pin the VIGIL commit hash used for each run.
- Publish the analysis notebook producing every figure.

A reader with feed access should be able to reconstruct the corpus and
reproduce every number.

---

## 7. RQ5 — The analyst decision study (stretch)

This is the novel contribution, and the only part requiring human subjects.

**Design.** Between-subjects, three conditions. Participants (students or
junior analysts) triage a fixed set of ~20 scripts and decide escalate / do
not escalate:

| Condition | What the participant sees |
|---|---|
| **A — Raw** | The script only |
| **B — Constrained AI** | Script + VIGIL's evidence-bound explanation |
| **C — Unconstrained AI** | Script + an LLM freely assessing the file |

**Measures:** decision accuracy against ground truth, time to decision, and
self-reported confidence (to detect *overconfidence* in condition C — the
specific harm the architecture is designed to prevent).

**Hypothesis.** B improves accuracy over A. C may improve speed but produces
higher confidence on incorrect decisions than B — the failure mode that
motivates the whole scorer/narrator separation.

**Requirements.** IRB approval, informed consent, a power analysis to size the
sample, and pre-registration of the hypothesis before data collection.

**Sequencing.** Begin IRB paperwork early — approval commonly takes 4–8 weeks —
and run E1–E4 while it is pending. If IRB approval does not arrive in time,
RQ1–RQ4 still constitute a complete, defensible capstone.

---

## 8. Suggested sequence

| Phase | Work | Output |
|---|---|---|
| 1 | Build corpus + manifest; write `tools/evaluate.py` | Reproducible harness |
| 2 | E1, E2 | Headline metrics; calibrated thresholds |
| 3 | E3, E4 | Design-decision evidence |
| 4 | E5 | Comparative context |
| 5 | Write up; submit IRB for RQ5 in parallel | Capstone / paper draft |

Phases 1–4 are the capstone. Phase 5 is the paper.

---

## 9. What an honest result looks like

The goal is not to show VIGIL is good. It is to find out where it is good and
where it is not, and to say so precisely.

A result of the form *"recall 0.78 on PowerShell, 0.61 on Python, FPR 4.2%,
with misses concentrated in runtime-constructed payloads"* is more valuable —
and far more credible — than a single inflated accuracy figure. Negative
results on RQ3 or RQ4 are publishable and should be reported as readily as
positive ones.

A tool that documents where it fails is more trustworthy than one that claims
it does not.
