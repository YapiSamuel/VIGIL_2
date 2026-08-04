"""Report assembly and rendering.

Two outputs from one assembled report:
  * ``to_dict`` / ``to_json`` — the machine-readable record (for pipelines,
    case tickets, or the cache).
  * ``render_terminal`` — the human summary a junior analyst reads in the
    30-second triage window.

Every finding and IOC is rendered with its provenance (which layer, which
signal) because a tool that cannot explain itself gets abandoned after the
first false positive.
"""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Optional

from .deobfuscator import Layer, flatten

VIGIL_VERSION = "1.0.0"

# --- ANSI helpers (degrade to plain text when color is off) ---------------

_COLORS = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
}

_BAND_COLOR = {
    "SAFE": "green", "LOW": "green", "SUSPICIOUS": "yellow",
    "HIGH": "red", "MALICIOUS": "red",
}

TEXT_PREVIEW = 160

# Glyphs, with ASCII fallbacks for consoles that can't encode them (e.g. a
# Windows cp1252 terminal — a real case in a mixed Linux/Windows SOC).
_GLYPHS = {
    True:  {"arrow": "→", "branch": "↳", "ok": "✓", "bad": "✗", "bullet": "•"},
    False: {"arrow": "->", "branch": "\\_", "ok": "[ok]", "bad": "[X]", "bullet": "*"},
}


def _c(text: str, color: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{_COLORS.get(color, '')}{text}{_COLORS['reset']}"


def supports_unicode(stream) -> bool:
    """True if ``stream`` can encode our glyphs. Defaults to True when the
    encoding is unknown."""
    enc = getattr(stream, "encoding", None)
    if not enc:
        return False
    try:
        "→↳✓✗•".encode(enc)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def _serialize(obj):
    if is_dataclass(obj):
        return {k: _serialize(v) for k, v in asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_serialize(v) for v in obj]
    return obj


def _layer_summary(root: Layer) -> list[dict]:
    out = []
    for layer in flatten(root):
        text = layer.text
        out.append({
            "id": layer.id,
            "technique": layer.technique,
            "depth": layer.depth,
            "parent_id": layer.parent_id,
            "sha256": layer.sha256,
            "length": len(text),
            "preview": (text[:TEXT_PREVIEW] + "...") if len(text) > TEXT_PREVIEW else text,
        })
    return out


def max_depth(root: Layer) -> int:
    return max((l.depth for l in flatten(root)), default=0)


def to_dict(*, ingest, layer_root: Layer, analysis, iocs, intel, score,
            verdict, elapsed_seconds: float, notes: Optional[list] = None,
            cache_hit: bool = False) -> dict:
    """Assemble the full machine-readable report."""
    return {
        "vigil_version": VIGIL_VERSION,
        "elapsed_seconds": round(elapsed_seconds, 3),
        "cache_hit": cache_hit,
        "file": {
            "path": ingest.original_path,
            "detected_type": ingest.detected_type,
            "size": ingest.size,
            "md5": ingest.md5,
            "sha1": ingest.sha1,
            "sha256": ingest.sha256,
            "is_archive": ingest.is_archive,
            "members": [_serialize(m) for m in ingest.members],
        },
        "verdict": {
            "band": verdict.band,
            "score": verdict.score,
            "escalate": verdict.escalate,
            "confidence": verdict.confidence,
            "confidence_basis": verdict.confidence_basis,
            "explanation": verdict.explanation,
            "explanation_source": verdict.source,
            "attack_ids": verdict.attack_ids,
        },
        "score_breakdown": [_serialize(i) for i in score.items],
        "layers": _layer_summary(layer_root),
        "findings": [_serialize(f) for f in analysis.findings],
        "iocs": [_serialize(i) for i in iocs],
        "intel": [_serialize(r) for r in intel.results],
        "notes": _collect_notes(ingest, analysis, intel, score, verdict, notes),
    }


def _collect_notes(ingest, analysis, intel, score, verdict, extra) -> list[str]:
    notes: list[str] = []
    notes.extend(ingest.notes)
    notes.extend(analysis.notes)
    notes.extend(intel.notes)
    notes.extend(score.notes)
    notes.extend(verdict.notes)
    if extra:
        notes.extend(extra)
    # de-dupe, preserve order
    seen = set()
    out = []
    for n in notes:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def to_json(report: dict, indent: int = 2) -> str:
    import json
    return json.dumps(report, indent=indent, default=str)


# --- terminal rendering ---------------------------------------------------

def render_terminal(report: dict, color: bool = True,
                    unicode_ok: bool = True) -> str:
    g = _GLYPHS[bool(unicode_ok)]
    lines: list[str] = []
    v = report["verdict"]
    f = report["file"]
    band = v["band"]
    band_color = _BAND_COLOR.get(band, "yellow")

    lines.append(_c(f"VIGIL {report['vigil_version']}", "bold", color)
                 + _c(f"  ({report['elapsed_seconds']}s"
                      + (", cache hit" if report["cache_hit"] else "") + ")",
                      "dim", color))
    lines.append("")
    verdict_line = f"  VERDICT: {band}  ({v['score']}/100)"
    lines.append(_c(verdict_line, band_color, color) + (
        _c(f"  {g['arrow']} ESCALATE NOW", "red", color) if v["escalate"] else
        _c(f"  {g['arrow']} safe to hand off", "green", color) if band in ("SAFE", "LOW") else
        _c(f"  {g['arrow']} review before handing off", "yellow", color)))
    dash = "—" if unicode_ok else "-"
    lines.append(_c(f"  confidence: {v['confidence']} {dash} {v['confidence_basis']}",
                    "dim", color))
    lines.append("")

    lines.append(_c("  File", "bold", color))
    lines.append(f"    {f['path']}")
    lines.append(f"    type: {f['detected_type']}   size: {f['size']} bytes")
    lines.append(f"    sha256: {f['sha256']}")
    if f["is_archive"]:
        lines.append(f"    archive members: {len(f['members'])}")
    lines.append("")

    lines.append(_c("  Why", "bold", color) + _c(f"  [{v['explanation_source']}]", "dim", color))
    for chunk in _wrap(v["explanation"], 72):
        lines.append(f"    {chunk}")
    lines.append("")

    breakdown = report["score_breakdown"]
    if breakdown:
        lines.append(_c("  Evidence (top signals)", "bold", color))
        for item in breakdown[:8]:
            pts = _c(f"+{item['points']:>3}", band_color, color)
            lines.append(f"    {pts}  {item['reason']}")
            lines.append(_c(f"          {g['branch']} {item['signal']}", "dim", color))
        lines.append("")

    findings = report["findings"]
    if findings:
        lines.append(_c(f"  Static findings ({len(findings)})", "bold", color))
        for fd in findings[:10]:
            aid = f" [{fd['attack_id']}]" if fd.get("attack_id") else ""
            lines.append(
                f"    {fd['severity']:>6}  {fd['name']}{aid}"
                + _c(f"  (layer {fd['layer_id']}/{fd['layer_technique']})", "dim", color))
        if len(findings) > 10:
            lines.append(_c(f"    ... and {len(findings) - 10} more", "dim", color))
        lines.append("")

    iocs = report["iocs"]
    if iocs:
        lines.append(_c(f"  IOCs ({len(iocs)})", "bold", color))
        for ioc in iocs[:12]:
            layers = ",".join(str(h["layer_id"]) for h in ioc["hits"])
            tag = _c(" (defanged)", "yellow", color) if ioc.get("defanged") else ""
            lines.append(f"    {ioc['ioc_type']:>6}  {ioc['value']}{tag}"
                         + _c(f"  (layer {layers})", "dim", color))
        if len(iocs) > 12:
            lines.append(_c(f"    ... and {len(iocs) - 12} more", "dim", color))
        lines.append("")

    intel = report["intel"]
    shown_intel = [r for r in intel if r["status"] in ("found", "clean", "not_found")]
    if shown_intel:
        lines.append(_c("  Threat intel", "bold", color))
        for r in shown_intel[:10]:
            mark = _c(g["bad"], "red", color) if r["malicious"] else _c(g["ok"], "green", color)
            lines.append(f"    {mark} {r['source']:>11}  {r['indicator'][:48]}"
                         + _c(f"  {r['note']}", "dim", color))
        lines.append("")

    if v["attack_ids"]:
        lines.append(_c("  ATT&CK techniques", "bold", color)
                     + "  " + ", ".join(v["attack_ids"]))
        lines.append("")

    notes = report["notes"]
    if notes:
        lines.append(_c("  Notes", "bold", color))
        for n in notes:
            lines.append(_c(f"    {g['bullet']} {n}", "dim", color))
        lines.append("")

    return "\n".join(lines)


def _wrap(text: str, width: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    cur = ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            if cur:
                lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines or [""]
