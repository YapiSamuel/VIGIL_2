"""Plain-English verdict explanation.

The AI here is a *narrator*, never a judge. `scorer.py` has already decided
the band; this module turns the collected evidence into an explanation a
junior analyst can act on. Two hard constraints:

  1. It may only reference signals that were actually collected. The prompt
     ships the evidence as a closed list and forbids claims outside it. If a
     claim can't cite a signal, it isn't made.
  2. It never changes the score or the band. Those come from the scorer and
     are passed through verbatim.

Without an ANTHROPIC_API_KEY (or without the ``anthropic`` package), this
degrades to a deterministic, template-built explanation that cites the same
evidence — so the tool is fully usable offline, just less fluent.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Optional

from .scorer import Score

DEFAULT_MODEL = "claude-sonnet-5"
MAX_EVIDENCE_ITEMS = 40

_SYSTEM_PROMPT = (
    "You are the explanation layer of VIGIL, a malware triage tool used by "
    "junior SOC analysts. You do NOT decide whether a file is malicious — a "
    "deterministic scorer already did that, and its verdict is fixed. Your "
    "only job is to explain the provided evidence clearly.\n\n"
    "HARD RULES:\n"
    "- You may ONLY reference signals in the EVIDENCE list. Never invent "
    "IOCs, rule names, engine counts, or behaviors.\n"
    "- Every claim must cite the specific signal id it rests on, in "
    "brackets, e.g. [pattern:reverse_shell_bash].\n"
    "- If the evidence does not support a statement, do not make it. It is "
    "correct and expected to say the evidence is thin when it is.\n"
    "- Do not contradict the given band or score.\n"
    "- Be concise: 3-6 sentences. Write for someone deciding whether to "
    "escalate in the next 30 seconds."
)


@dataclass
class Verdict:
    band: str
    score: int
    escalate: bool
    explanation: str
    confidence: str          # "low" | "medium" | "high"
    confidence_basis: str
    attack_ids: list[str] = field(default_factory=list)
    source: str = "template"  # "anthropic" | "template"
    notes: list[str] = field(default_factory=list)


def _collect_attack_ids(findings) -> list[str]:
    ids = []
    for f in findings or []:
        aid = getattr(f, "attack_id", None)
        if aid and aid not in ids:
            ids.append(aid)
    return ids


def _confidence(score: Score, intel_results) -> tuple[str, str]:
    """Confidence is about how well-corroborated the verdict is, stated with
    its basis — not a second opinion on the verdict itself."""
    has_intel = any(getattr(r, "malicious", False) for r in (intel_results or []))
    static_pts = score.contributions_by_source().get("static", 0)
    if has_intel and score.value >= 70:
        return "high", "external threat intel corroborates local findings"
    if score.value >= 70 or (static_pts >= 40):
        return "medium", "multiple strong local signals, no external confirmation"
    if score.value == 0:
        return "low", "no suspicious signals were collected; absence of evidence only"
    return "low", "few or weak signals; treat as inconclusive"


def _build_evidence(score: Score, findings, iocs, intel_results) -> list[dict]:
    evidence: list[dict] = []
    for item in score.items:
        evidence.append({
            "signal": item.signal,
            "points": item.points,
            "why": item.reason,
            "source": item.source,
        })
    # Include concrete IOCs so the narrator can name destinations, each tagged
    # with the layer it came from for provenance.
    for ioc in (iocs or [])[:15]:
        layers = ",".join(str(h.layer_id) for h in ioc.hits)
        evidence.append({
            "signal": f"ioc:{ioc.ioc_type}:{ioc.value}",
            "why": f"{ioc.ioc_type} indicator found in layer(s) {layers}"
                   + (" (defanged)" if ioc.defanged else ""),
            "source": "ioc",
        })
    return evidence[:MAX_EVIDENCE_ITEMS]


# --- deterministic fallback ----------------------------------------------

def _template_explanation(score: Score, iocs, confidence: str,
                          confidence_basis: str) -> str:
    if not score.items:
        return (
            "No suspicious signals were collected from this file across any "
            "decoded layer. That is not proof of safety: obfuscation built "
            "at runtime, environment-dependent decoding, or purely novel "
            "logic can evade static analysis, but nothing here warrants "
            "escalation on its own. Confidence: "
            f"{confidence} ({confidence_basis})."
        )
    top = score.items[:4]
    bullet = "; ".join(f"{it.reason} [{it.signal}]" for it in top)
    dest = ""
    named = [i for i in (iocs or []) if i.ioc_type in ("url", "domain", "ipv4", "ipv6")]
    if named:
        dest = " Network indicators: " + ", ".join(
            i.value for i in named[:5]) + "."
    return (
        f"Risk band {score.band} (score {score.value}/100). "
        f"Primary evidence: {bullet}.{dest} "
        f"Confidence: {confidence} ({confidence_basis})."
    )


# --- anthropic path -------------------------------------------------------

def _anthropic_explanation(evidence: list[dict], score: Score, model: str,
                           api_key: str) -> Optional[str]:
    try:
        import anthropic  # type: ignore
    except Exception:
        return None
    try:
        client = anthropic.Anthropic(api_key=api_key)
        user_content = (
            f"VERDICT (fixed, do not change): band={score.band}, "
            f"score={score.value}/100, escalate={score.escalate}.\n\n"
            "EVIDENCE (the only facts you may cite):\n"
            + json.dumps(evidence, indent=2)
            + "\n\nWrite the explanation now, citing signal ids in brackets."
        )
        resp = client.messages.create(
            model=model,
            max_tokens=400,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_content}],
        )
        parts = [b.text for b in resp.content if getattr(b, "type", "") == "text"]
        text = "\n".join(parts).strip()
        return text or None
    except Exception:
        return None


# --- top-level ------------------------------------------------------------

def explain(score: Score, findings=None, iocs=None, intel_results=None,
            model: str = DEFAULT_MODEL, api_key: Optional[str] = None,
            use_ai: bool = True) -> Verdict:
    """Produce a :class:`Verdict`. Never raises; falls back to a template
    whenever the AI path is unavailable or errors."""
    confidence, basis = _confidence(score, intel_results)
    attack_ids = _collect_attack_ids(findings)
    evidence = _build_evidence(score, findings, iocs, intel_results)

    verdict = Verdict(
        band=score.band, score=score.value, escalate=score.escalate,
        explanation="", confidence=confidence, confidence_basis=basis,
        attack_ids=attack_ids,
    )

    from .credentials import get as _cred
    key = api_key or _cred("ANTHROPIC_API_KEY")
    if use_ai and key:
        text = _anthropic_explanation(evidence, score, model, key)
        if text:
            verdict.explanation = text
            verdict.source = "anthropic"
            return verdict
        verdict.notes.append(
            "AI narration unavailable; used deterministic explanation"
        )
    elif use_ai and not key:
        verdict.notes.append(
            "no ANTHROPIC_API_KEY; used deterministic explanation"
        )

    verdict.explanation = _template_explanation(score, iocs, confidence, basis)
    verdict.source = "template"
    return verdict
