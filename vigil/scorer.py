"""Deterministic risk scoring.

This module, not the AI, decides the verdict. Given the signals every other
module collected, it produces a number and a band by a fixed, documented
weighting table. The same inputs always produce the same score, and every
point is attributed to a named signal so the report can show exactly why a
file landed where it did.

`verdict.py` may later *explain* this score in prose, but it can never
change it. A confident wrong verdict handed to a junior analyst is worse
than no verdict; keeping the decision deterministic and auditable is the
whole point.

Pure and offline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .ioc_extractor import IOC
from .static_analyzer import Finding

# ---------------------------------------------------------------------------
# Weighting table. These are the knobs. They are here, in one place, on
# purpose — so the scoring policy is reviewable rather than scattered.
# ---------------------------------------------------------------------------

# Points per static finding, by severity.
FINDING_SEVERITY_POINTS = {"low": 5, "medium": 12, "high": 25}

# Some categories are strong intent signals; give them a bump on top of
# severity. This is calibrated so a single unambiguous behavior escalates on
# its own: a reverse shell or a credential dump is not ambiguous, and a
# junior analyst should be told to escalate it without needing a second
# signal. Weaker-on-their-own behaviors (persistence, download) need
# corroboration to cross the escalate line.
CATEGORY_BONUS = {
    "c2": 45,               # 25 + 45 = 70 -> HIGH -> escalate on its own
    "credential_access": 45,  # same: dumping creds escalates alone
    "anti_forensics": 25,   # 25 + 25 = 50 -> SUSPICIOUS
    "persistence": 15,      # weaker alone (admins use schtasks/cron too)
    "download": 10,
    "execution": 5,
}

# Obfuscation depth is itself a signal: benign scripts are rarely wrapped
# three layers deep. Points scale with the deepest layer that produced a
# child, capped so a decode bomb can't dominate the score.
DEPTH_POINTS_PER_LEVEL = 8
DEPTH_POINTS_CAP = 32

# Intel is high-confidence external corroboration.
INTEL_VT_HIT = 45            # any VT engine detections
INTEL_VT_PER_ENGINE = 2      # additional per detecting engine, capped
INTEL_VT_ENGINE_CAP = 30
INTEL_ABUSEIPDB_HIT = 25     # IP over abuse threshold
INTEL_URLHAUS_HIT = 35       # URL/host listed as malicious

# Defanged IOCs are a mild signal — someone deliberately neutered an address,
# which benign automation rarely does.
DEFANGED_IOC_POINTS = 5
DEFANGED_IOC_CAP = 15

# Band thresholds over a 0..100 clamp.
BAND_THRESHOLDS = [
    (0, "SAFE"),
    (20, "LOW"),
    (45, "SUSPICIOUS"),
    (70, "HIGH"),
    (85, "MALICIOUS"),
]

MAX_SCORE = 100


@dataclass
class ScoreItem:
    points: int
    reason: str
    signal: str          # the concrete signal cited (rule name, engine, etc.)
    source: str          # "static" | "obfuscation" | "intel" | "ioc"


@dataclass
class Score:
    value: int
    band: str
    escalate: bool
    items: list[ScoreItem] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def contributions_by_source(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for item in self.items:
            out[item.source] = out.get(item.source, 0) + item.points
        return out


def _band_for(value: int) -> str:
    band = "SAFE"
    for threshold, name in BAND_THRESHOLDS:
        if value >= threshold:
            band = name
    return band


def score(findings: list[Finding], iocs: list[IOC], max_layer_depth: int,
          intel_results: Optional[list] = None) -> Score:
    """Compute the deterministic risk score.

    ``intel_results`` is a list of :class:`vigil.intel.base.IntelResult`;
    kept as a loose type to avoid importing the network package here.
    """
    items: list[ScoreItem] = []

    # --- static findings ---
    # De-duplicate by (rule name) so the same rule firing in five layers does
    # not quintuple its weight; note the multiplicity instead.
    seen_rules: dict[str, int] = {}
    for f in findings:
        seen_rules[f.name] = seen_rules.get(f.name, 0) + 1
    counted: set[str] = set()
    for f in findings:
        if f.name in counted:
            continue
        counted.add(f.name)
        base = FINDING_SEVERITY_POINTS.get(f.severity, 8)
        bonus = CATEGORY_BONUS.get(f.category, 0)
        pts = base + bonus
        mult = seen_rules[f.name]
        reason = f"{f.category} finding ({f.severity})"
        if mult > 1:
            reason += f", seen in {mult} layers"
        items.append(ScoreItem(
            points=pts, reason=reason,
            signal=f"{f.engine}:{f.name}" + (f" [{f.attack_id}]" if f.attack_id else ""),
            source="static",
        ))

    # --- obfuscation depth ---
    if max_layer_depth > 0:
        pts = min(max_layer_depth * DEPTH_POINTS_PER_LEVEL, DEPTH_POINTS_CAP)
        items.append(ScoreItem(
            points=pts,
            reason=f"content was obfuscated {max_layer_depth} layer(s) deep",
            signal=f"deobfuscation_depth={max_layer_depth}",
            source="obfuscation",
        ))

    # --- defanged IOCs ---
    defanged = [i for i in iocs if i.defanged]
    if defanged:
        pts = min(len(defanged) * DEFANGED_IOC_POINTS, DEFANGED_IOC_CAP)
        items.append(ScoreItem(
            points=pts,
            reason=f"{len(defanged)} defanged indicator(s) present",
            signal="defanged_iocs=" + ",".join(i.value for i in defanged[:3]),
            source="ioc",
        ))

    # --- intel ---
    for r in (intel_results or []):
        if not getattr(r, "malicious", False):
            continue
        if r.source == "virustotal":
            pts = INTEL_VT_HIT
            if r.score:
                pts += min(r.score * INTEL_VT_PER_ENGINE, INTEL_VT_ENGINE_CAP)
            items.append(ScoreItem(
                points=pts, reason="VirusTotal detections",
                signal=f"virustotal:{r.indicator} ({r.note})", source="intel",
            ))
        elif r.source == "abuseipdb":
            items.append(ScoreItem(
                points=INTEL_ABUSEIPDB_HIT,
                reason="AbuseIPDB flagged the destination IP",
                signal=f"abuseipdb:{r.indicator} ({r.note})", source="intel",
            ))
        elif r.source == "urlhaus":
            items.append(ScoreItem(
                points=INTEL_URLHAUS_HIT,
                reason="URLhaus listed the URL/host as malicious",
                signal=f"urlhaus:{r.indicator} ({r.note})", source="intel",
            ))

    raw = sum(i.points for i in items)
    value = max(0, min(MAX_SCORE, raw))
    band = _band_for(value)

    result = Score(value=value, band=band, escalate=band in ("HIGH", "MALICIOUS"),
                   items=sorted(items, key=lambda x: x.points, reverse=True))

    if not items:
        result.notes.append(
            "no suspicious signals collected; score reflects absence of "
            "evidence, not proof of safety"
        )
    if raw > MAX_SCORE:
        result.notes.append(f"raw score {raw} clamped to {MAX_SCORE}")
    return result
