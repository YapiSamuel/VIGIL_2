from vigil.cache import Cache, DEFAULT_TTL_SECONDS


class FakeClock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def test_put_and_get_roundtrip(tmp_path):
    clock = FakeClock()
    c = Cache(str(tmp_path / "c.db"), clock=clock)
    assert c.get("abc") is None
    assert c.put("abc", {"band": "HIGH", "n": 1})
    assert c.get("abc") == {"band": "HIGH", "n": 1}


def test_ttl_expiry(tmp_path):
    clock = FakeClock()
    c = Cache(str(tmp_path / "c.db"), ttl_seconds=100, clock=clock)
    c.put("k", {"v": 1})
    clock.t += 50
    assert c.get("k") == {"v": 1}
    clock.t += 60  # now 110 > 100 ttl
    assert c.get("k") is None


def test_purge_expired(tmp_path):
    clock = FakeClock()
    c = Cache(str(tmp_path / "c.db"), ttl_seconds=100, clock=clock)
    c.put("a", {"v": 1})
    clock.t += 200
    c.put("b", {"v": 2})
    removed = c.purge_expired()
    assert removed == 1
    assert c.get("a") is None
    assert c.get("b") == {"v": 2}


def test_persists_across_reopen(tmp_path):
    path = str(tmp_path / "c.db")
    clock = FakeClock()
    c1 = Cache(path, clock=clock)
    c1.put("x", {"v": 9})
    c1.close()
    c2 = Cache(path, clock=clock)
    assert c2.get("x") == {"v": 9}


def test_broken_db_degrades_to_miss(tmp_path):
    # Point the cache at a directory path — sqlite cannot open it as a db.
    c = Cache(str(tmp_path))
    assert c.get("anything") is None
    assert c.put("anything", {"v": 1}) is False


def test_schema_version_mismatch_is_a_miss(tmp_path):
    import sqlite3
    path = str(tmp_path / "c.db")
    clock = FakeClock()
    c = Cache(path, clock=clock)
    c.put("k", {"v": 1})
    c.close()
    # tamper the stored schema version
    conn = sqlite3.connect(path)
    conn.execute("UPDATE analysis_cache SET schema_version = 999")
    conn.commit()
    conn.close()
    c2 = Cache(path, clock=clock)
    assert c2.get("k") is None
