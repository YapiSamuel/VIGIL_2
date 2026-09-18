#!/usr/bin/env python3
"""Evaluation harness for VIGIL — turns EVALUATION.md into numbers.

Scans a labeled corpus, writes per-sample results to CSV, and reports the
metrics that matter for a triage tool: precision, recall, false-positive
rate, F1, ROC-AUC, and a threshold sweep for calibrating the band
boundaries empirically (EVALUATION.md, RQ2).

Standard library only, to match the rest of the project. No sklearn, no
pandas — the statistics here are simple enough to compute honestly and
to audit by reading.

LABELS
------
Two ways to label a corpus:

  --labels filename   (default) infer from a `<label>__name.ext` prefix,
                      which is what tools/make_samples.py produces.
                      safe_/benign_ -> benign; everything else -> malicious.

  --labels manifest   read a CSV with columns `path,label`, where label is
                      one of benign/malicious. Use this for a real corpus,
                      and keep the manifest in version control while keeping
                      the samples out of it.

USAGE
-----
    python3 tools/make_samples.py
    python3 tools/evaluate.py --corpus samples/ --out results.csv

    python3 tools/evaluate.py --manifest corpus.csv --out results.csv --jobs 8

Every run is pinned to a VIGIL commit; the harness records it in the CSV so
a result can always be tied to the code that produced it.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Optional

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENIGN_PREFIXES = ("safe", "benign", "clean")


@dataclass
class Result:
    path: str
    label: str                 # "benign" | "malicious"
    score: int = 0
    band: str = ""
    escalate: bool = False
    file_type: str = ""
    sha256: str = ""
    elapsed: float = 0.0
    n_findings: int = 0
    n_iocs: int = 0
    max_depth: int = 0
    bounds_hit: str = ""
    techniques: str = ""
    error: str = ""


# --- running the tool -------------------------------------------------------

def _label_from_filename(path: str) -> str:
    base = os.path.basename(path)
    prefix = base.split("__")[0].lower() if "__" in base else ""
    return "benign" if prefix in BENIGN_PREFIXES else "malicious"


def scan_one(path: str, label: str, timeout: int = 120) -> Result:
    """Run VIGIL once, offline and uncached, and parse its JSON report."""
    r = Result(path=path, label=label)
    start = time.time()
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "vigil", "scan", path,
             "--offline", "--no-cache", "--no-color", "--json"],
            capture_output=True, text=True, timeout=timeout, cwd=REPO_ROOT,
        )
    except subprocess.TimeoutExpired:
        r.error = f"timeout after {timeout}s"
        r.elapsed = time.time() - start
        return r
    r.elapsed = time.time() - start

    out = proc.stdout
    if "{" not in out:
        r.error = (proc.stderr or "no JSON emitted").strip().splitlines()[:1]
        r.error = r.error[0] if r.error else "no JSON emitted"
        return r
    try:
        report = json.loads(out[out.index("{"):])
    except json.JSONDecodeError as exc:
        r.error = f"unparseable JSON: {exc}"
        return r

    v = report.get("verdict", {}) or {}
    f = report.get("file", {}) or {}
    r.score = int(v.get("score", 0))
    r.band = str(v.get("band", ""))
    r.escalate = bool(v.get("escalate", False))
    r.file_type = str(f.get("detected_type", ""))
    r.sha256 = str(f.get("sha256", ""))

    findings = report.get("findings") or []
    r.n_findings = len(findings)
    r.techniques = ";".join(sorted({
        str(x.get("attack_id")) for x in findings if x.get("attack_id")}))
    r.n_iocs = len(report.get("iocs") or [])
    layers = report.get("layers")
    if isinstance(layers, dict):
        r.max_depth = int(layers.get("max_depth", 0) or 0)
    r.bounds_hit = ";".join(report.get("bounds_hit") or [])
    notes = " ".join(str(n) for n in (report.get("notes") or []))
    if not r.bounds_hit and "INCOMPLETE ANALYSIS" in notes:
        r.bounds_hit = "reported_in_notes"
    return r


# --- metrics ----------------------------------------------------------------

@dataclass
class Confusion:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def fpr(self) -> float:
        d = self.fp + self.tn
        return self.fp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def confusion_at(results: list[Result], threshold: int) -> Confusion:
    """A sample is flagged when score >= threshold."""
    c = Confusion()
    for r in results:
        if r.error:
            continue
        flagged = r.score >= threshold
        malicious = r.label == "malicious"
        if flagged and malicious:
            c.tp += 1
        elif flagged and not malicious:
            c.fp += 1
        elif not flagged and malicious:
            c.fn += 1
        else:
            c.tn += 1
    return c


def roc_auc(results: list[Result]) -> float:
    """ROC-AUC via the rank-sum (Mann-Whitney U) identity, which handles
    ties correctly and needs no curve interpolation."""
    pos = [r.score for r in results if not r.error and r.label == "malicious"]
    neg = [r.score for r in results if not r.error and r.label == "benign"]
    if not pos or not neg:
        return float("nan")
    # average ranks over the combined, sorted scores
    combined = sorted([(s, 1) for s in pos] + [(s, 0) for s in neg])
    ranks: list[float] = [0.0] * len(combined)
    i = 0
    while i < len(combined):
        j = i
        while j + 1 < len(combined) and combined[j + 1][0] == combined[i][0]:
            j += 1
        avg = (i + j) / 2.0 + 1.0            # 1-indexed average rank for ties
        for k in range(i, j + 1):
            ranks[k] = avg
        i = j + 1
    rank_sum_pos = sum(rk for rk, (_s, lab) in zip(ranks, combined) if lab == 1)
    n_pos, n_neg = len(pos), len(neg)
    u = rank_sum_pos - n_pos * (n_pos + 1) / 2.0
    return u / (n_pos * n_neg)


# --- reporting --------------------------------------------------------------

def _pct(x: float) -> str:
    return "n/a" if x != x else f"{x * 100:5.1f}%"


def print_report(results: list[Result], default_threshold: int) -> None:
    ok = [r for r in results if not r.error]
    errs = [r for r in results if r.error]
    n_mal = sum(1 for r in ok if r.label == "malicious")
    n_ben = sum(1 for r in ok if r.label == "benign")

    print("=" * 72)
    print("VIGIL EVALUATION")
    print("=" * 72)
    print(f"samples evaluated : {len(ok)}  ({n_mal} malicious, {n_ben} benign)")
    if errs:
        print(f"errors            : {len(errs)}")
        for r in errs[:5]:
            print(f"    {os.path.basename(r.path)}: {r.error}")

    if not n_mal or not n_ben:
        print("\n!! Corpus has only one class. Precision/recall/AUC are")
        print("   undefined. Add samples of the missing class before drawing")
        print("   any conclusion (EVALUATION.md section 2).")
        return

    c = confusion_at(ok, default_threshold)
    print(f"\n--- performance at score >= {default_threshold} ---")
    print(f"  TP {c.tp:<5} FP {c.fp:<5} TN {c.tn:<5} FN {c.fn}")
    print(f"  precision {_pct(c.precision)}   recall {_pct(c.recall)}")
    print(f"  FPR       {_pct(c.fpr)}   F1     {c.f1:.3f}")
    print(f"  ROC-AUC   {roc_auc(ok):.3f}")

    # --- RQ2: threshold sweep ---
    print("\n--- threshold sweep (RQ2: where should the bands sit?) ---")
    print(f"  {'thr':>4}  {'precision':>9}  {'recall':>7}  {'FPR':>6}  {'F1':>6}")
    best_f1 = (0.0, 0)
    best_under_5 = None
    for t in range(0, 101, 5):
        cc = confusion_at(ok, t)
        if cc.f1 > best_f1[0]:
            best_f1 = (cc.f1, t)
        if cc.fpr <= 0.05 and best_under_5 is None and cc.recall > 0:
            best_under_5 = (t, cc)
        print(f"  {t:>4}  {_pct(cc.precision):>9}  {_pct(cc.recall):>7}  "
              f"{_pct(cc.fpr):>6}  {cc.f1:>6.3f}")
    print(f"\n  best F1          : {best_f1[0]:.3f} at threshold {best_f1[1]}")
    if best_under_5:
        t, cc = best_under_5
        print(f"  lowest threshold holding FPR <= 5%: {t} "
              f"(recall {_pct(cc.recall)})")
    else:
        print("  no threshold holds FPR <= 5% with non-zero recall")

    # --- per file type ---
    print("\n--- recall by file type ---")
    types = sorted({r.file_type for r in ok if r.file_type})
    for ft in types:
        sub = [r for r in ok if r.file_type == ft]
        cc = confusion_at(sub, default_threshold)
        n_m = sum(1 for r in sub if r.label == "malicious")
        if n_m:
            print(f"  {ft:<14} recall {_pct(cc.recall)}  "
                  f"({cc.tp}/{n_m} malicious caught, {cc.fp} FP)")
        else:
            print(f"  {ft:<14} {len(sub)} benign only, {cc.fp} FP")

    # --- misses, the most useful section for improving the tool ---
    misses = [r for r in ok if r.label == "malicious"
              and r.score < default_threshold]
    if misses:
        print(f"\n--- false negatives ({len(misses)}) ---")
        for r in sorted(misses, key=lambda x: x.score)[:15]:
            print(f"  {r.score:>3}  {r.band:<11} {os.path.basename(r.path)}")
    fps = [r for r in ok if r.label == "benign"
           and r.score >= default_threshold]
    if fps:
        print(f"\n--- false positives ({len(fps)}) ---")
        for r in sorted(fps, key=lambda x: -x.score)[:15]:
            print(f"  {r.score:>3}  {r.band:<11} {os.path.basename(r.path)}")

    # --- truncation rate ---
    trunc = [r for r in ok if r.bounds_hit]
    if trunc:
        tm = sum(1 for r in trunc if r.label == "malicious")
        print(f"\n--- incomplete analysis ---")
        print(f"  {len(trunc)}/{len(ok)} samples hit a decode bound "
              f"({tm} malicious, {len(trunc) - tm} benign)")

    # --- runtime ---
    times = sorted(r.elapsed for r in ok)
    if times:
        p95 = times[int(len(times) * 0.95) - 1] if len(times) > 1 else times[0]
        print(f"\n--- runtime ---")
        print(f"  median {times[len(times)//2]:.2f}s   p95 {p95:.2f}s   "
              f"max {times[-1]:.2f}s")
        over = [t for t in times if t > 30]
        if over:
            print(f"  !! {len(over)} sample(s) exceeded the 30s target")


def _vigil_commit() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, cwd=REPO_ROOT)
        return out.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--corpus", help="directory of samples to evaluate")
    src.add_argument("--manifest", help="CSV with columns path,label")
    ap.add_argument("--labels", choices=["filename", "manifest"],
                    default="filename",
                    help="how to label --corpus samples (default: filename)")
    ap.add_argument("--out", default="results.csv", help="per-sample CSV out")
    ap.add_argument("--threshold", type=int, default=50,
                    help="score at/above which a sample counts as flagged")
    ap.add_argument("--jobs", type=int, default=4, help="parallel scans")
    ap.add_argument("--timeout", type=int, default=120, help="per-sample seconds")
    args = ap.parse_args()

    targets: list[tuple[str, str]] = []
    if args.manifest:
        with open(args.manifest, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                p, lab = row.get("path"), (row.get("label") or "").lower()
                if not p or lab not in ("benign", "malicious"):
                    continue
                targets.append((p, lab))
    else:
        for name in sorted(os.listdir(args.corpus)):
            p = os.path.join(args.corpus, name)
            if os.path.isfile(p):
                targets.append((p, _label_from_filename(p)))

    if not targets:
        print("no samples found", file=sys.stderr)
        return 2

    commit = _vigil_commit()
    print(f"evaluating {len(targets)} sample(s) at vigil commit {commit} "
          f"with {args.jobs} job(s)...\n")

    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(
            lambda t: scan_one(t[0], t[1], args.timeout), targets))

    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["path", "label", "score", "band", "escalate", "file_type",
                    "sha256", "elapsed_s", "n_findings", "n_iocs",
                    "max_depth", "bounds_hit", "attack_ids", "error",
                    "vigil_commit"])
        for r in results:
            w.writerow([r.path, r.label, r.score, r.band, r.escalate,
                        r.file_type, r.sha256, f"{r.elapsed:.3f}",
                        r.n_findings, r.n_iocs, r.max_depth, r.bounds_hit,
                        r.techniques, r.error, commit])

    print_report(results, args.threshold)
    print(f"\nper-sample results written to {args.out}")
    print("\nNOTE: a synthetic corpus measures wiring, not real-world")
    print("performance. Numbers are only meaningful on a corpus built per")
    print("EVALUATION.md section 2 - especially the benign half.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
