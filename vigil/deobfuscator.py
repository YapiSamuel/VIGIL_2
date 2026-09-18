"""Recursive layer unwrapping for obfuscated script content.

Pure text/byte transforms only. Nothing here executes, evaluates, or
imports anything derived from the input. Network and filesystem access are
out of scope for this module entirely.
"""

from __future__ import annotations

import base64
import binascii
import bz2
import codecs
import gzip
import hashlib
import re
import zlib
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import unquote

MAX_DEPTH = 8
MAX_LAYERS = 200
MAX_BLOB_SIZE = 2 * 1024 * 1024  # 2 MB, applied to decoded child candidates

_PRINTABLE_EXTRA = "\n\r\t"
_PRINTABLE_RATIO_THRESHOLD = 0.80

# Keyword families for likeness(). Each family counts at most once per text,
# regardless of how many times its keywords repeat, so a loop that prints
# "curl" 500 times can't outscore a payload that touches five distinct
# suspicious behaviors once each.
_KEYWORD_FAMILIES: dict[str, tuple[str, ...]] = {
    "web_download": (
        "downloadstring", "downloadfile", "invoke-webrequest",
        "net.webclient", "urlretrieve", "requests.get", "curl ", "wget ",
    ),
    "execution": (
        "invoke-expression", "iex ", "iex(", "eval(", "exec(",
        "os.system", "subprocess", "system(", "shellexecute",
    ),
    "shell_indicators": (
        "powershell", "/bin/bash", "/bin/sh", "cmd.exe", "cmd /c",
    ),
    "network_protocol": (
        "http://", "https://", "ftp://",
    ),
    "obfuscation_flags": (
        "-encodedcommand", "-enc ", "frombase64string", "-bypass",
        "-windowstyle hidden", "-noni", "-nop ",
    ),
    "persistence": (
        "schtasks", "reg add", "registry", "crontab", "hklm\\", "hkcu\\",
    ),
    "credential_access": (
        "mimikatz", "lsass", "/etc/passwd", "/etc/shadow", "credential",
        "keylogger",
    ),
    "c2_networking": (
        "socket(", "reverse shell", "bind shell", "nc -e", "ncat ",
        "/dev/tcp/",
    ),
    "anti_forensics": (
        "clear-eventlog", "wevtutil", "history -c", "rm -rf /var/log",
        "remove-item -force",
    ),
}


def likeness(text: str) -> int:
    """Count distinct suspicious keyword families present in ``text``."""
    lowered = text.lower()
    return sum(
        1
        for keywords in _KEYWORD_FAMILIES.values()
        if any(k in lowered for k in keywords)
    )


@dataclass
class Layer:
    id: int
    technique: str
    depth: int
    text: str
    sha256: str
    parent_id: Optional[int] = None
    children: list["Layer"] = field(default_factory=list)
    # True when this layer still contained decodable content that a bound
    # stopped us from following. Such a layer is never pruned: "we stopped
    # here with more to decode" is itself a signal the analyst must see.
    truncated: bool = False
    # Populated on the root only: which bounds were hit anywhere in the tree.
    bounds_hit: list[str] = field(default_factory=list)


@dataclass
class _State:
    next_id: int = 0
    layer_count: int = 0
    seen_hashes: set = field(default_factory=set)
    bounds_hit: set = field(default_factory=set)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    good = sum(1 for c in s if c.isprintable() or c in _PRINTABLE_EXTRA)
    return good / len(s)


def _bytes_to_text(b: bytes) -> Optional[str]:
    if not b:
        return None
    candidates = []
    try:
        candidates.append(b.decode("utf-8"))
    except UnicodeDecodeError:
        pass
    if len(b) % 2 == 0:
        try:
            candidates.append(b.decode("utf-16-le"))
        except UnicodeDecodeError:
            pass
    if not candidates:
        return None
    best = max(candidates, key=_printable_ratio)
    if _printable_ratio(best) < _PRINTABLE_RATIO_THRESHOLD:
        return None
    return best


def _try_decompress(b: bytes) -> Optional[tuple[str, bytes]]:
    try:
        if b[:2] == b"\x1f\x8b":
            return "gzip", gzip.decompress(b)
        if b[:3] == b"BZh":
            return "bz2", bz2.decompress(b)
        if len(b) >= 2 and b[0] == 0x78 and b[1] in (
            0x01, 0x5E, 0x9C, 0xDA, 0x20, 0x7D, 0xBB, 0xF9,
        ):
            return "zlib", zlib.decompress(b)
    except Exception:
        return None
    return None


def _decode_base64(match_text: str, urlsafe: bool) -> Optional[bytes]:
    padding = (-len(match_text)) % 4
    padded = match_text + ("=" * padding)
    try:
        if urlsafe:
            return base64.urlsafe_b64decode(padded)
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None


def _decode_hex(match_text: str) -> Optional[bytes]:
    cleaned = match_text[2:] if match_text.lower().startswith("0x") else match_text
    if len(cleaned) % 2 != 0:
        return None
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return None


def _decode_xesc(match_text: str) -> Optional[bytes]:
    hexvals = re.findall(r"\\x([0-9a-fA-F]{2})", match_text)
    try:
        return bytes(int(h, 16) for h in hexvals)
    except ValueError:
        return None


def _decode_uesc(match_text: str) -> Optional[str]:
    hexvals = re.findall(r"\\u([0-9a-fA-F]{4})", match_text)
    try:
        return "".join(chr(int(h, 16)) for h in hexvals)
    except ValueError:
        return None


def _decode_urlenc(match_text: str) -> Optional[str]:
    try:
        decoded = unquote(match_text, errors="strict")
    except Exception:
        return None
    return decoded if decoded != match_text else None


def _decode_decimal_array(match_text: str) -> Optional[str]:
    nums_str = re.findall(r"\d{1,3}", match_text)
    if len(nums_str) < 4:
        return None
    nums = [int(n) for n in nums_str]
    if any(n > 255 for n in nums):
        return None
    return "".join(chr(n) for n in nums)


_QUOTED_RE = re.compile(r"(['\"])((?:\\.|(?!\1).)*?)\1")
_CONCAT_OP_RE = re.compile(r"\s*[+.&]\s*")


def _find_string_concat(text: str) -> list[tuple[int, int, str]]:
    results = []
    pos = 0
    n = len(text)
    while pos < n:
        m = _QUOTED_RE.match(text, pos)
        if not m:
            pos += 1
            continue
        start = m.start()
        parts = [m.group(2)]
        end = m.end()
        while True:
            op_m = _CONCAT_OP_RE.match(text, end)
            if not op_m:
                break
            nm = _QUOTED_RE.match(text, op_m.end())
            if not nm:
                break
            parts.append(nm.group(2))
            end = nm.end()
        if len(parts) >= 2:
            results.append((start, end, "".join(parts)))
            pos = end
        else:
            pos = m.end()
    return results


_PS_ENC_RE = re.compile(
    r"(?<![\w-])-(?:e|en|enc|encodedcommand)\s+([A-Za-z0-9+/=]{16,})(?![A-Za-z0-9+/=])",
    re.IGNORECASE,
)
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_BASE64URL_RE = re.compile(r"[A-Za-z0-9_-]{20,}={0,2}")
_HEX_RE = re.compile(r"(?:0x)?(?:[0-9a-fA-F]{2}){8,}")
_XESC_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
_UESC_RE = re.compile(r"(?:\\u[0-9a-fA-F]{4}){4,}")
_URLENC_TOKEN_RE = re.compile(r"%[0-9a-fA-F]{2}")
_DECIMAL_ARR_RE = re.compile(r"\[?\s*\d{1,3}(?:\s*,\s*\d{1,3}){3,}\s*\]?")


def _collect_candidates(text: str) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    seen_spans: set[tuple[int, int]] = set()

    for m in _PS_ENC_RE.finditer(text):
        raw = _decode_base64(m.group(1), urlsafe=False)
        if raw is None:
            continue
        try:
            decoded = raw.decode("utf-16-le")
        except UnicodeDecodeError:
            continue
        candidates.append(("powershell_encodedcommand", decoded))
        seen_spans.add(m.span(1))

    for m in _BASE64_RE.finditer(text):
        if m.span() in seen_spans:
            continue
        raw = _decode_base64(m.group(), urlsafe=False)
        if raw is None:
            continue
        decomp = _try_decompress(raw)
        technique, payload = ("base64+" + decomp[0], decomp[1]) if decomp else ("base64", raw)
        decoded = _bytes_to_text(payload)
        if decoded:
            candidates.append((technique, decoded))

    for m in _BASE64URL_RE.finditer(text):
        if not re.search(r"[-_]", m.group()):
            continue  # pure alnum runs are already covered by _BASE64_RE
        raw = _decode_base64(m.group(), urlsafe=True)
        if raw is None:
            continue
        decomp = _try_decompress(raw)
        technique, payload = ("base64url+" + decomp[0], decomp[1]) if decomp else ("base64url", raw)
        decoded = _bytes_to_text(payload)
        if decoded:
            candidates.append((technique, decoded))

    for m in _HEX_RE.finditer(text):
        raw = _decode_hex(m.group())
        if raw is None:
            continue
        decomp = _try_decompress(raw)
        technique, payload = ("hex+" + decomp[0], decomp[1]) if decomp else ("hex", raw)
        decoded = _bytes_to_text(payload)
        if decoded:
            candidates.append((technique, decoded))

    for m in _XESC_RE.finditer(text):
        raw = _decode_xesc(m.group())
        if raw is None:
            continue
        decoded = _bytes_to_text(raw)
        if decoded:
            candidates.append(("x_escape", decoded))

    for m in _UESC_RE.finditer(text):
        decoded = _decode_uesc(m.group())
        if decoded:
            candidates.append(("u_escape", decoded))

    if len(_URLENC_TOKEN_RE.findall(text)) >= 3:
        decoded = _decode_urlenc(text)
        if decoded:
            candidates.append(("url_encoding", decoded))

    for m in _DECIMAL_ARR_RE.finditer(text):
        decoded = _decode_decimal_array(m.group())
        if decoded:
            candidates.append(("decimal_char_array", decoded))

    for _start, _end, decoded in _find_string_concat(text):
        candidates.append(("string_concat", decoded))

    rot13 = codecs.decode(text, "rot13")
    if rot13 != text:
        candidates.append(("rot13", rot13))

    reversed_text = text[::-1]
    if reversed_text != text:
        candidates.append(("reversed", reversed_text))

    return candidates


def _suppress_substrings(layers: list[Layer]) -> list[Layer]:
    keep = []
    for i, layer in enumerate(layers):
        if not layer.text:
            continue
        shadowed = any(
            i != j and len(layer.text) < len(other.text) and layer.text in other.text
            for j, other in enumerate(layers)
        )
        if not shadowed:
            keep.append(layer)
    return keep


def _build(
    text: str, depth: int, technique: str, parent_id: Optional[int], state: _State
) -> Optional[Layer]:
    digest = _sha256(text)
    if digest in state.seen_hashes:
        return None
    if state.layer_count >= MAX_LAYERS:
        return None
    state.seen_hashes.add(digest)
    layer_id = state.next_id
    state.next_id += 1
    state.layer_count += 1
    layer = Layer(
        id=layer_id, technique=technique, depth=depth, text=text,
        sha256=digest, parent_id=parent_id,
    )
    if depth < MAX_DEPTH:
        layer.children = _find_children(text, depth + 1, layer_id, state)
    elif _collect_candidates(text):
        # We are at the depth cap and this layer STILL decodes further. Say so
        # rather than silently returning a clean-looking tree: a payload buried
        # below the cap would otherwise be reported as nothing at all.
        layer.truncated = True
        state.bounds_hit.add("max_depth")
    return layer


def _find_children(
    text: str, depth: int, parent_id: int, state: _State
) -> list[Layer]:
    if state.layer_count >= MAX_LAYERS:
        state.bounds_hit.add("max_layers")
        return []
    children = []
    for technique, decoded in _collect_candidates(text):
        if not decoded or decoded == text:
            continue
        if len(decoded.encode("utf-8", errors="replace")) > MAX_BLOB_SIZE:
            state.bounds_hit.add("max_blob_size")
            continue
        child = _build(decoded, depth, technique, parent_id, state)
        if child is not None:
            children.append(child)
        if state.layer_count >= MAX_LAYERS:
            state.bounds_hit.add("max_layers")
            break
    return _suppress_substrings(children)


def _prune(layer: Layer) -> Optional[Layer]:
    layer.children = [
        pruned for pruned in (_prune(child) for child in layer.children)
        if pruned is not None
    ]
    # A truncated layer is kept even with no keyword hits and no surviving
    # children: it is the evidence that analysis stopped short.
    if likeness(layer.text) > 0 or layer.children or layer.truncated:
        return layer
    return None


def deobfuscate(source: str) -> Layer:
    """Recursively unwrap obfuscation layers in ``source``.

    Returns the root Layer (depth 0, technique="source", the original
    text unchanged). Children are pruned to drop dead-end decodes that
    hit no suspicious keyword family and led nowhere further (git hashes,
    JWTs, minified bundles); the root itself is always kept, including
    when it has zero children.
    """
    state = _State()
    root = _build(source, depth=0, technique="source", parent_id=None, state=state)
    assert root is not None  # first call on a fresh state can't collide
    root.children = [
        pruned for pruned in (_prune(child) for child in root.children)
        if pruned is not None
    ]
    root.bounds_hit = sorted(state.bounds_hit)
    return root


def flatten(root: Layer) -> list[Layer]:
    """Flatten the layer tree into a list, root first, depth-first."""
    result: list[Layer] = []
    stack = [root]
    while stack:
        node = stack.pop()
        result.append(node)
        stack.extend(reversed(node.children))
    return result
