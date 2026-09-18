"""VIGIL command-line entry point and pipeline orchestration.

Wires the modules into the pipeline described in PROJECT_BRIEF.md:

    file in
      -> ingestor        validate, type by magic bytes, hash, safe extract
      -> cache           SQLite by SHA256; skip re-analysis
      -> deobfuscator    recursive layer unwrapping
      -> static_analyzer YARA + pattern detection over every layer
      -> ioc_extractor   IPs/domains/URLs over every layer
      -> intel clients   VT + AbuseIPDB + URLhaus, parallel, hash-first
      -> scorer          deterministic risk score
      -> verdict         plain-English explanation (AI narrates, never judges)
      -> reporter        terminal summary + JSON

Runs with zero config and no API keys, degrading to local-only analysis.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

from . import audit
from . import credentials
from . import ingestor
from . import reporter
from . import scorer
from . import static_analyzer
from . import verdict as verdict_mod
from .cache import Cache
from .deobfuscator import MAX_DEPTH, deobfuscate
from .intel import IntelConfig, gather
from .ioc_extractor import extract as extract_iocs

DEFAULT_CACHE_PATH = os.path.join(os.path.expanduser("~"), ".vigil", "cache.db")
DEFAULT_CONFIG_PATHS = ["config.yaml", os.path.join(
    os.path.expanduser("~"), ".vigil", "config.yaml")]

READABLE_TYPES = ("script:sh", "script:ps1", "script:py", "text")


# --- configuration --------------------------------------------------------

@dataclass
class Config:
    cache_path: str = DEFAULT_CACHE_PATH
    cache_ttl_hours: int = 24
    use_cache: bool = True
    enable_vt: bool = True
    enable_abuseipdb: bool = True
    enable_urlhaus: bool = True
    enable_intel: bool = True
    enable_ai: bool = True
    ai_model: str = verdict_mod.DEFAULT_MODEL
    enable_yara: bool = True
    yara_rules_dir: Optional[str] = None
    allow_upload: bool = False
    color: bool = True
    # Offline mode disables every outbound path in one switch (intel clients
    # AND the AI narrator) and hard-blocks upload. This is the mode to use
    # when analyzing files that may contain CUI, PHI, or regulated data.
    offline: bool = False
    audit_log: Optional[str] = None
    notes: list[str] = field(default_factory=list)


def load_config(path: Optional[str] = None) -> Config:
    """Load config from YAML if available. Secrets are never read from here —
    only from environment variables. Missing config is not an error."""
    cfg = Config()
    candidates = [path] if path else DEFAULT_CONFIG_PATHS
    chosen = next((p for p in candidates if p and os.path.isfile(p)), None)
    if not chosen:
        return cfg
    try:
        import yaml  # type: ignore
    except Exception:
        cfg.notes.append(
            f"found {chosen} but PyYAML is not installed; using defaults"
        )
        return cfg
    try:
        with open(chosen, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except Exception as exc:
        cfg.notes.append(f"could not parse {chosen}: {exc}; using defaults")
        return cfg

    cache = data.get("cache", {}) or {}
    cfg.cache_path = os.path.expanduser(cache.get("path", cfg.cache_path))
    cfg.cache_ttl_hours = int(cache.get("ttl_hours", cfg.cache_ttl_hours))

    intel = data.get("intel", {}) or {}
    cfg.enable_vt = bool(intel.get("enable_virustotal", cfg.enable_vt))
    cfg.enable_abuseipdb = bool(intel.get("enable_abuseipdb", cfg.enable_abuseipdb))
    cfg.enable_urlhaus = bool(intel.get("enable_urlhaus", cfg.enable_urlhaus))

    ai = data.get("ai", {}) or {}
    cfg.enable_ai = bool(ai.get("enable", cfg.enable_ai))
    cfg.ai_model = str(ai.get("model", cfg.ai_model))

    ycfg = data.get("yara", {}) or {}
    cfg.enable_yara = bool(ycfg.get("enable", cfg.enable_yara))
    if ycfg.get("rules_dir"):
        cfg.yara_rules_dir = os.path.expanduser(ycfg["rules_dir"])

    # Policy settings. `offline: true` is how an organization enforces "nothing
    # leaves this machine" centrally, rather than relying on an analyst to
    # remember --offline on every invocation. Config can only ever *enable*
    # offline; there is deliberately no way to switch it back off from the CLI.
    policy = data.get("policy", {}) or {}
    if bool(policy.get("offline", False)):
        cfg.offline = True
        cfg.enable_intel = False
        cfg.enable_ai = False
        cfg.allow_upload = False
        cfg.notes.append(f"offline mode enforced by policy in {chosen}")
    if policy.get("audit_log"):
        cfg.audit_log = os.path.expanduser(str(policy["audit_log"]))

    return cfg


# --- core analysis --------------------------------------------------------

def _analyze_blob(ingest_like, text: str, config: Config,
                  vt_limiter=None, cache: Optional[Cache] = None,
                  cache_hit: bool = False) -> dict:
    """Run deobfuscate -> static -> ioc -> intel -> score -> verdict ->
    report for one text blob and its file metadata."""
    start = time.time()

    root = deobfuscate(text)
    analysis = static_analyzer.analyze(
        root, rules_dir=config.yara_rules_dir, use_yara=config.enable_yara)
    iocs = extract_iocs(root)

    if config.enable_intel:
        intel_cfg = IntelConfig(
            enable_vt=config.enable_vt,
            enable_abuseipdb=config.enable_abuseipdb,
            enable_urlhaus=config.enable_urlhaus,
            allow_upload=config.allow_upload,
        )
        intel = gather(ingest_like.sha256, iocs, intel_cfg, vt_limiter=vt_limiter)
    else:
        from .intel import IntelBundle
        intel = IntelBundle(notes=["intel lookups disabled by flag"])

    depth = reporter.max_depth(root)
    the_score = scorer.score(analysis.findings, iocs, depth, intel.results,
                             bounds_hit=root.bounds_hit)
    if root.bounds_hit:
        _BOUND_NOTES = {
            "max_depth": (f"obfuscation nested deeper than the decode limit "
                          f"(MAX_DEPTH={MAX_DEPTH}); content below it was "
                          "NOT analyzed"),
            "max_layers": ("layer budget exhausted; some decoded content was "
                           "not analyzed"),
            "max_blob_size": ("a decoded layer exceeded the size limit and "
                              "was not analyzed"),
        }
        for b in root.bounds_hit:
            analysis.notes.append(
                "INCOMPLETE ANALYSIS: " + _BOUND_NOTES.get(b, b))
    the_verdict = verdict_mod.explain(
        the_score, findings=analysis.findings, iocs=iocs,
        intel_results=intel.results, model=config.ai_model,
        use_ai=config.enable_ai)

    elapsed = time.time() - start
    return reporter.to_dict(
        ingest=ingest_like, layer_root=root, analysis=analysis, iocs=iocs,
        intel=intel, score=the_score, verdict=the_verdict,
        elapsed_seconds=elapsed, cache_hit=cache_hit)


def _read_text(path: str) -> str:
    with open(path, "rb") as fh:
        data = fh.read()
    return data.decode("utf-8", errors="replace")


def run_scan(path: str, config: Config) -> dict:
    """Full pipeline for one input path. Returns a report dict (for archives,
    a wrapper with per-member reports)."""
    from .intel.base import RateLimiter
    vt_limiter = RateLimiter(min_interval=15.0)

    ingest = ingestor.ingest(path, extract=True)

    cache: Optional[Cache] = None
    if config.use_cache:
        os.makedirs(os.path.dirname(config.cache_path) or ".", exist_ok=True)
        cache = Cache(config.cache_path, ttl_seconds=config.cache_ttl_hours * 3600)
        cached = cache.get(ingest.sha256)
        if cached is not None:
            cached["cache_hit"] = True
            cache.close()
            return cached

    if ingest.is_archive:
        report = _scan_archive(ingest, config, vt_limiter, cache)
    else:
        if ingest.detected_type not in READABLE_TYPES:
            # Unsupported type (e.g. a PE): honest refusal, not a crash.
            report = _unsupported_report(ingest)
        else:
            text = _read_text(ingest.path)
            report = _analyze_blob(ingest, text, config, vt_limiter, cache)

    if cache is not None:
        cache.put(ingest.sha256, report)
        cache.close()
    return report


def _scan_archive(ingest, config: Config, vt_limiter, cache) -> dict:
    member_reports = []
    for member in ingest.members:
        if member.detected_type not in READABLE_TYPES:
            continue
        try:
            text = _read_text(member.path)
        except OSError:
            continue
        md5, sha1, sha256 = ingestor.hash_file(member.path)
        member_ingest = ingestor.IngestResult(
            path=member.path, original_path=f"{ingest.original_path}!{member.name}",
            detected_type=member.detected_type, size=member.size,
            md5=md5, sha1=sha1, sha256=sha256,
        )
        member_reports.append(_analyze_blob(member_ingest, text, config, vt_limiter))

    if not member_reports:
        return {
            "vigil_version": reporter.VIGIL_VERSION,
            "cache_hit": False,
            "file": {
                "path": ingest.original_path,
                "detected_type": ingest.detected_type,
                "size": ingest.size, "sha256": ingest.sha256,
                "is_archive": True, "members": [],
                "md5": ingest.md5, "sha1": ingest.sha1,
            },
            "verdict": {
                "band": "SAFE", "score": 0, "escalate": False,
                "confidence": "low",
                "confidence_basis": "archive contained no analyzable scripts",
                "explanation": "The archive contained no .sh/.ps1/.py scripts "
                               "to analyze.",
                "explanation_source": "template", "attack_ids": [],
            },
            "score_breakdown": [], "layers": [], "findings": [], "iocs": [],
            "intel": [], "notes": ingest.notes + ["no analyzable members found"],
            "archive_members": [],
        }

    worst = max(member_reports, key=lambda r: r["verdict"]["score"])
    wrapper = dict(worst)  # headline verdict = worst member
    wrapper["file"] = {
        "path": ingest.original_path,
        "detected_type": ingest.detected_type,
        "size": ingest.size, "sha256": ingest.sha256,
        "md5": ingest.md5, "sha1": ingest.sha1,
        "is_archive": True,
        "members": [reporter._serialize(m) for m in ingest.members],
    }
    wrapper["archive_members"] = member_reports
    wrapper["notes"] = list(ingest.notes) + wrapper.get("notes", []) + [
        f"archive: reporting worst of {len(member_reports)} analyzed member(s)"
    ]
    return wrapper


def _unsupported_report(ingest) -> dict:
    return {
        "vigil_version": reporter.VIGIL_VERSION,
        "elapsed_seconds": 0.0,
        "cache_hit": False,
        "file": {
            "path": ingest.original_path,
            "detected_type": ingest.detected_type,
            "size": ingest.size, "md5": ingest.md5, "sha1": ingest.sha1,
            "sha256": ingest.sha256, "is_archive": False, "members": [],
        },
        "verdict": {
            "band": "SAFE", "score": 0, "escalate": False, "confidence": "low",
            "confidence_basis": "file type is out of scope for this release",
            "explanation": (
                f"VIGIL does not analyze {ingest.detected_type} files. "
                "Scope is .sh/.ps1/.py scripts and archives of them. "
                "Windows PE analysis is explicitly out of scope — shallow "
                "header reading is weak signal and dynamic analysis is not "
                "possible here."),
            "explanation_source": "template", "attack_ids": [],
        },
        "score_breakdown": [], "layers": [], "findings": [], "iocs": [],
        "intel": [],
        "notes": ingest.notes + [f"unsupported type: {ingest.detected_type}"],
    }


# --- CLI ------------------------------------------------------------------

_CONFIG_TEMPLATE = """\
# VIGIL configuration. Secrets are NEVER stored here — set API keys as
# environment variables instead:
#   VT_API_KEY, ABUSEIPDB_API_KEY, ANTHROPIC_API_KEY

cache:
  path: ~/.vigil/cache.db
  ttl_hours: 24

intel:
  enable_virustotal: true
  enable_abuseipdb: true
  enable_urlhaus: true

ai:
  enable: true
  model: claude-sonnet-5

yara:
  enable: true
  # rules_dir: rules
"""


def _cmd_verify_audit(args) -> int:
    """Verify the audit log's hash chain. Exit 0 intact, 1 broken, 2 unreadable.

    Tamper-*evidence*, not tamper-proofing: an attacker with write access can
    rebuild the whole chain. Forward to a WORM store or SIEM for the stronger
    property. See COMPLIANCE.md.
    """
    if not os.path.isfile(args.path):
        sys.stderr.write(f"no such audit log: {args.path}\n")
        return 2
    ok, checked, bad_line = audit.verify(args.path)
    if ok:
        print(f"audit chain INTACT - {checked} record(s) verified in {args.path}")
        return 0
    if bad_line is None:
        sys.stderr.write(f"could not read audit log: {args.path}\n")
        return 2
    sys.stderr.write(
        f"audit chain BROKEN at line {bad_line} of {args.path} "
        f"({checked} record(s) verified before the break).\n"
        "A record was altered, deleted, or reordered after it was written.\n")
    return 1


def _cmd_setup(args) -> int:
    target_dir = os.path.join(os.path.expanduser("~"), ".vigil")
    os.makedirs(target_dir, exist_ok=True)
    cfg_path = os.path.join(target_dir, "config.yaml")
    if os.path.exists(cfg_path) and not args.force:
        print(f"config already exists at {cfg_path} (use --force to overwrite)")
    else:
        with open(cfg_path, "w", encoding="utf-8") as fh:
            fh.write(_CONFIG_TEMPLATE)
        print(f"wrote config template to {cfg_path}")
    print("\nOptional API keys - current status:")
    for var, what in credentials.KNOWN_KEYS.items():
        src = credentials.source_of(var)
        shown = credentials.mask(credentials.get(var))
        print(f"  {var:<20} {what:<34} [{src}] {shown}")

    warn = credentials.permissions_warning()
    if warn:
        sys.stderr.write(f"\nWARNING: {warn}\n")

    print("\nVIGIL runs fully without any of these, degrading to local-only "
          "analysis. Keys only add external corroboration and AI-written prose;"
          "\nthe verdict itself is always computed locally.")

    if args.keys:
        return _prompt_for_keys()

    # Offer the prompt rather than hiding it behind a flag. Only when there is
    # a real terminal: piping `vigil setup` into something must not block
    # waiting for input that will never come.
    if not args.no_keys and sys.stdin.isatty() and sys.stdout.isatty():
        try:
            answer = input("\nConfigure API keys now? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if answer in ("y", "yes"):
            return _prompt_for_keys()
        print("Skipped. You can run this again any time with: "
              f"{_prog()} setup --keys")
        return 0

    print(f"\nTo store keys locally, run:  {_prog()} setup --keys")
    print("Or export them as environment variables, which always take "
          "precedence.")
    return 0


def _prompt_for_keys() -> int:
    """Interactively collect API keys and store them 0600 outside the repo."""
    import getpass

    print("\n" + "=" * 68)
    print("API KEY SETUP")
    print("=" * 68)
    print(f"Keys are stored in {credentials.CREDENTIALS_PATH}")
    print("  - NOT in config.yaml, and NOT inside the project directory,")
    print("    so they cannot be committed to git by accident.")
    print("  - Owner-read-only (chmod 600) on Linux and macOS.")
    print("  - Environment variables of the same name still take precedence.")
    print("\nInput is hidden. Press Enter to skip a key, or type '-' to "
          "remove a stored one.\n")

    if not sys.stdin.isatty():
        sys.stderr.write("setup --keys needs an interactive terminal.\n")
        return 2

    collected: dict[str, str] = {}
    for var, what in credentials.KNOWN_KEYS.items():
        current = credentials.source_of(var)
        hint = f" [currently: {current}]" if current != "unset" else ""
        try:
            value = getpass.getpass(f"  {var} ({what}){hint}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\naborted; nothing was written.")
            return 2
        if value == "-":
            collected[var] = ""          # explicit removal
            print(f"    {var} will be removed")
        elif value:
            collected[var] = value
            print(f"    stored {credentials.mask(value)}")
        else:
            print("    skipped")

    if not collected:
        print("\nNothing entered; no changes made.")
        return 0

    ok, msg = credentials.save(collected)
    print(f"\n{'OK' if ok else 'FAILED'}: {msg}")
    if not ok:
        return 2

    print("\nVerifying:")
    for var in credentials.KNOWN_KEYS:
        print(f"  {var:<20} [{credentials.source_of(var)}] "
              f"{credentials.mask(credentials.get(var))}")
    print("\nKeys are never printed in reports, logs, or error messages.")
    print("Remember: any key means network egress. Use --offline when "
          "analyzing regulated data.")
    return 0


def _prog() -> str:
    return "vigil" if os.path.basename(sys.argv[0]) == "vigil" else "python -m vigil"


def _cmd_scan(args) -> int:
    config = load_config(args.config)
    if args.no_cache:
        config.use_cache = False
    if args.no_intel:
        config.enable_intel = False
    if args.no_ai:
        config.enable_ai = False
    if args.no_yara:
        config.enable_yara = False
    if args.no_color:
        config.color = False
    if args.upload:
        config.allow_upload = True
    if args.audit_log:
        config.audit_log = args.audit_log

    # Offline is a hard switch and deliberately wins over every other flag,
    # including --upload. If an operator OR a config policy says "nothing
    # leaves this machine", no combination of other options may override it.
    # Note this is evaluated after the flags above, so a config-enforced
    # offline still clears allow_upload set by --upload.
    if args.offline:
        config.offline = True
    if config.offline:
        config.enable_intel = False
        config.enable_ai = False
        config.allow_upload = False
        if args.upload:
            sys.stderr.write(
                "note: offline mode overrides --upload; no data will be sent.\n")
        config.notes.append(
            "offline mode: all network egress disabled (intel + AI narration)")

    if args.upload and not config.offline:
        # Hard rule 3: an explicit, printed warning before any upload path.
        sys.stderr.write(
            "WARNING: --upload will send the FILE ITSELF to VirusTotal. "
            "Uploaded files become retrievable by VT's paid customers. Do NOT "
            "upload files containing customer data, credentials, or anything "
            "your policy forbids sharing.\n")
        if not args.yes:
            sys.stderr.write("Proceed? [y/N] ")
            sys.stderr.flush()
            answer = sys.stdin.readline().strip().lower()
            if answer not in ("y", "yes"):
                sys.stderr.write("aborted; no upload performed.\n")
                return 2

    try:
        report = run_scan(args.path, config)
    except ingestor.IngestError as exc:
        sys.stderr.write(f"ingest error: {exc}\n")
        return 2
    except Exception as exc:  # last-resort guard; a scan should not crash
        sys.stderr.write(f"unexpected error: {exc}\n")
        return 3

    for n in config.notes:
        report.setdefault("notes", []).append(n)

    if config.audit_log:
        f = report.get("file", {}) or {}
        v = report.get("verdict", {}) or {}
        ok = audit.write(config.audit_log, audit.build_record(
            event="scan",
            target={"path": f.get("path"), "sha256": f.get("sha256"),
                    "size": f.get("size"), "type": f.get("detected_type")},
            verdict={"band": v.get("band"), "score": v.get("score"),
                     "escalate": v.get("escalate"),
                     "explanation_source": v.get("explanation_source")},
            egress={"intel": config.enable_intel, "ai": config.enable_ai,
                    "upload": config.allow_upload, "offline": config.offline},
            vigil_version=reporter.VIGIL_VERSION,
        ))
        if not ok:
            report.setdefault("notes", []).append(
                f"could not write audit log to {config.audit_log}")

    if args.json:
        print(reporter.to_json(report))
    else:
        unicode_ok = reporter.supports_unicode(sys.stdout)
        color = config.color and sys.stdout.isatty()
        rendered = reporter.render_terminal(report, color=color,
                                            unicode_ok=unicode_ok)
        # Last-resort guard: if the console still rejects a character, emit an
        # ASCII-safe version rather than crashing the whole scan on output.
        try:
            print(rendered)
        except UnicodeEncodeError:
            enc = sys.stdout.encoding or "ascii"
            sys.stdout.write(rendered.encode(enc, "replace").decode(enc) + "\n")

    # exit code encodes the verdict for scripting: 0 safe, 1 escalate.
    return 1 if report["verdict"]["escalate"] else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vigil",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "VIGIL - pre-execution malware triage for scripts.\n\n"
            "Answers one question fast: is this script safe to hand off, or\n"
            "should it be escalated now? Analyzes .sh, .ps1, .py files and\n"
            "archives of them in under 30 seconds, with no sandbox required.\n\n"
            "Nothing is ever executed. Every operation is a pure text or byte\n"
            "transform. VIGIL does not detonate; it tells you whether you\n"
            "should.\n\n"
            "Obfuscation is recursively unwrapped (base64, hex, ROT13, URL and\n"
            "\\x escapes, gzip/zlib/bz2, PowerShell -EncodedCommand), and every\n"
            "decoded layer is analyzed - so a C2 address three layers deep is\n"
            "caught exactly like plaintext.\n\n"
            "The verdict is computed locally by a deterministic scorer. The AI\n"
            "layer, when enabled, only explains evidence already collected; it\n"
            "never decides the verdict and cannot invent findings."),
        epilog=(
            "EXIT CODES\n"
            "  0  no escalation needed        2  input/usage error\n"
            "  1  escalate (or audit broken)  3  unexpected internal error\n"
            "\n"
            "EXAMPLES\n"
            "  vigil scan suspicious.sh\n"
            "      Local analysis with zero configuration.\n\n"
            "  vigil scan bundle.tar.gz\n"
            "      Archives are extracted safely (zip-slip and bomb limits).\n\n"
            "  vigil scan payload.ps1 --json > report.json\n"
            "      Machine-readable output for a SIEM or case system.\n\n"
            "  vigil scan sample.sh --offline --audit-log ~/.vigil/audit.jsonl\n"
            "      Zero network egress plus a tamper-evident audit trail.\n"
            "      Use this for CUI, PHI, or any regulated data.\n\n"
            "  vigil verify-audit ~/.vigil/audit.jsonl\n"
            "      Confirm no audit record was altered, deleted, or reordered.\n\n"
            "  vigil setup --keys\n"
            "      Store optional API keys (never in config.yaml, never in the\n"
            "      project directory).\n"
            "\n"
            "API KEYS ARE OPTIONAL\n"
            "  VIGIL runs fully without any key. Keys add external\n"
            "  corroboration (VirusTotal, AbuseIPDB) and AI-written prose.\n"
            "  They never affect the verdict, which is always computed locally.\n"
            "  Any key means network egress: use --offline for sensitive files.\n"
            "\n"
            "WHAT VIGIL CANNOT DO\n"
            "  Runtime-built obfuscation, execution-time encryption keys,\n"
            "  environment-dependent decoding, intent, and Windows PE binaries\n"
            "  are out of scope. A SAFE verdict means no signals were found -\n"
            "  not proof that a file is benign.\n"
            "\n"
            "Docs: README.md  THREAT_MODEL.md  COMPLIANCE.md  EVALUATION.md"))
    parser.add_argument("--version", action="version",
                        version=f"vigil {reporter.VIGIL_VERSION}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    scan = sub.add_parser("scan", help="analyze a script or archive")
    scan.add_argument("path", help="path to the file to analyze")
    scan.add_argument("--json", action="store_true", help="emit JSON report")
    scan.add_argument("--config", help="path to a config file")
    scan.add_argument("--no-cache", action="store_true", help="ignore the cache")
    scan.add_argument("--no-intel", action="store_true",
                      help="skip all network intel lookups")
    scan.add_argument("--no-ai", action="store_true",
                      help="skip AI narration; use deterministic explanation")
    scan.add_argument("--no-yara", action="store_true", help="skip YARA")
    scan.add_argument("--offline", action="store_true",
                      help="disable ALL network egress (intel + AI) and block "
                           "upload; use for CUI/regulated data")
    scan.add_argument("--audit-log", metavar="PATH",
                      help="append an operator audit record to PATH (JSONL)")
    scan.add_argument("--no-color", action="store_true", help="disable color")
    scan.add_argument("--upload", action="store_true",
                      help="upload the file to VirusTotal (prints a warning)")
    scan.add_argument("--yes", action="store_true",
                      help="skip the --upload confirmation prompt")
    scan.set_defaults(func=_cmd_scan)

    va = sub.add_parser("verify-audit",
                        help="verify the integrity of an audit log chain")
    va.add_argument("path", help="path to the audit log (JSONL)")
    va.set_defaults(func=_cmd_verify_audit)

    setup = sub.add_parser("setup", help="first-run setup: write a config template")
    setup.add_argument("--keys", action="store_true",
                       help="go straight to entering API keys")
    setup.add_argument("--no-keys", action="store_true",
                       help="show status only; never prompt for keys")
    setup.add_argument("--force", action="store_true",
                       help="overwrite an existing config")
    setup.set_defaults(func=_cmd_setup)

    return parser


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
