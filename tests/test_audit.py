import json
import os

from vigil import audit


def _rec(**kw):
    kw.setdefault("event", "scan")
    kw.setdefault("vigil_version", "2.0.0")
    return audit.build_record(**kw)


# --- record construction ---------------------------------------------------

def test_record_has_accountability_fields():
    r = _rec(target={"sha256": "a" * 64}, verdict={"band": "SAFE"})
    for key in ("ts", "event", "operator", "host", "vigil_version",
                "target", "verdict", "egress", "schema"):
        assert key in r, key
    assert r["ts"].endswith("Z")


def test_record_never_contains_file_contents_or_secrets():
    # The caller could only leak by passing evidence in; build_record itself
    # must not reach for anything beyond what it is given.
    r = _rec(target={"path": "x.sh", "sha256": "b" * 64})
    blob = json.dumps(r).lower()
    for forbidden in ("api_key", "apikey", "password", "secret", "token",
                      "layer_text", "matched"):
        assert forbidden not in blob


# --- chaining and verification ---------------------------------------------

def test_write_and_verify_single_record(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    assert audit.write(p, _rec()) is True
    ok, checked, bad = audit.verify(p)
    assert (ok, checked, bad) == (True, 1, None)


def test_first_record_chains_from_genesis(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    audit.write(p, _rec())
    body = json.loads(open(p).readline())
    assert body["prev_hash"] == audit.GENESIS_HASH
    assert len(body["record_hash"]) == 64


def test_chain_links_across_records(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    for i in range(5):
        audit.write(p, _rec(target={"sha256": str(i) * 64}))
    lines = [json.loads(l) for l in open(p)]
    assert len(lines) == 5
    for prev, cur in zip(lines, lines[1:]):
        assert cur["prev_hash"] == prev["record_hash"]
    ok, checked, bad = audit.verify(p)
    assert ok and checked == 5 and bad is None


def test_tampering_with_a_record_is_detected(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    for i in range(4):
        audit.write(p, _rec(verdict={"band": "MALICIOUS", "score": 90 + i}))
    lines = open(p).read().splitlines()
    r = json.loads(lines[2])
    r["verdict"]["score"] = 0          # hide a malicious verdict
    lines[2] = json.dumps(r)
    open(p, "w").write("\n".join(lines) + "\n")

    ok, _checked, bad = audit.verify(p)
    assert ok is False
    assert bad == 3                    # 1-indexed


def test_deleting_a_record_is_detected(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    for i in range(4):
        audit.write(p, _rec(target={"sha256": str(i) * 64}))
    lines = open(p).read().splitlines()
    del lines[1]                       # excise an inconvenient scan
    open(p, "w").write("\n".join(lines) + "\n")

    ok, _checked, bad = audit.verify(p)
    assert ok is False
    assert bad == 2


def test_corrupt_json_line_is_detected(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    audit.write(p, _rec())
    with open(p, "a") as fh:
        fh.write("{not valid json\n")
    ok, _checked, bad = audit.verify(p)
    assert ok is False and bad == 2


# --- graceful degradation ---------------------------------------------------

def test_write_creates_parent_directories(tmp_path):
    p = str(tmp_path / "nested" / "deeper" / "audit.jsonl")
    assert audit.write(p, _rec()) is True
    assert os.path.isfile(p)


def test_empty_path_returns_false_without_raising():
    assert audit.write("", _rec()) is False


def test_unwritable_path_returns_false_without_raising(tmp_path):
    # A directory where a file is expected: write must fail, not explode.
    d = tmp_path / "audit.jsonl"
    d.mkdir()
    assert audit.write(str(d), _rec()) is False


def test_verify_missing_file_returns_false_without_raising(tmp_path):
    ok, checked, bad = audit.verify(str(tmp_path / "nope.jsonl"))
    assert ok is False and checked == 0


def test_unserializable_payload_does_not_raise(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    r = _rec(extra={"obj": object()})
    # default=str makes this serializable rather than fatal
    assert audit.write(p, r) is True
    ok, _c, _b = audit.verify(p)
    assert ok is True


def test_blank_lines_are_tolerated(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    audit.write(p, _rec())
    with open(p, "a") as fh:
        fh.write("\n\n")
    audit.write(p, _rec())
    ok, checked, bad = audit.verify(p)
    assert ok is True and checked == 2 and bad is None
