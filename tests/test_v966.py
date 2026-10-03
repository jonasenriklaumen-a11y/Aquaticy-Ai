"""Tempo, Cache-Datenschutz und getrennte Laufdaten fuer 9.6.6 Luna."""

from __future__ import annotations

import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

import pytest

from aquaticy import privacy, tools, web
from aquaticy.cache import SCHEMA, Cache
from aquaticy.models import PageResult, SearchResult
from tests.test_v965 import parallel_site as parallel_site


def test_cache_encrypts_payload_and_query_and_migrates_existing_rows(tmp_path):
    path = tmp_path / "cache.sqlite3"
    with sqlite3.connect(path) as conn:
        conn.executescript(SCHEMA)
        conn.execute(
            "INSERT INTO cache VALUES ('old', 'search', 'Privater Arzt', ?, 1, 9999999999)",
            ('{"adresse": "Geheimstraße"}',),
        )
        conn.execute("INSERT INTO privacy_state VALUES ('chats', '1')")
    cache = Cache(path)
    assert b"Privater Arzt" not in path.read_bytes()
    assert "Geheimstraße".encode() not in path.read_bytes()
    cache.set("new", {"frage": "Private Diagnose"}, label="Arzttermin")
    assert cache.get("old") == {"adresse": "Geheimstraße"}
    assert cache.get("new") == {"frage": "Private Diagnose"}
    with sqlite3.connect(path) as conn:
        rows = conn.execute("SELECT payload, label FROM cache").fetchall()
    assert all(
        p.startswith(privacy.TEXT_PREFIX) and label.startswith(privacy.TEXT_PREFIX)
        for p, label in rows
    )
    assert Cache(path).get("old") == cache.get("old")


def test_cache_ciphertext_cannot_be_read_in_another_profile_or_column(tmp_path):
    first = Cache(tmp_path / "users" / ("a" * 32) / "cache.sqlite3")
    second = Cache(tmp_path / "users" / ("b" * 32) / "cache.sqlite3")
    first.set("key", {"secret": "private"}, label="private label")
    with sqlite3.connect(first.db_path) as conn:
        row = conn.execute("SELECT payload, label FROM cache WHERE key=?", ("key",)).fetchone()
    second.set("key", {})
    with sqlite3.connect(second.db_path) as conn:
        conn.execute("UPDATE cache SET payload=?", (row[0],))
    assert second.get("key") is None
    with sqlite3.connect(first.db_path) as conn:
        conn.execute("UPDATE cache SET payload=?", (row[1],))
    assert first.get("key") is None


def test_recent_chats_use_one_query_and_search_stops_at_limit(tmp_path, monkeypatch):
    cache = Cache(tmp_path / "cache.sqlite3")
    for i in range(50):
        cache.add_history(str(i), f"Frage {i}", "gesuchtes Stichwort")
    cache.rename_chat("49", "Eigener Titel")
    cache.mark_unread("49")
    statements = []
    original_connect = cache._connect

    @contextmanager
    def traced():
        with original_connect() as conn:
            conn.set_trace_callback(statements.append)
            yield conn

    monkeypatch.setattr(cache, "_connect", traced)
    listed = cache.recent_chats(40)
    assert len(listed) == 40 and listed[0]["title"] == "Eigener Titel"
    assert listed[0]["unread"]
    assert len([s for s in statements if s.lstrip().upper().startswith("SELECT")]) == 1
    opened = []
    original_open = cache._open

    def counted(value, column):
        opened.append(column)
        return original_open(value, column)

    monkeypatch.setattr(cache, "_open", counted)
    result = cache.search_chats("Stichwort", limit=2)
    assert [chat["session_id"] for chat in result] == ["49", "48"]
    assert opened.count("history.answer") == 2
    assert "Stichwort" in result[0]["snippet"]
    assert result[0]["unread"]
    assert cache.search_chats("Stichwort", limit=0) == cache.recent_chats(0) == []


def test_search_preserves_oldest_snippet_and_all_turns(tmp_path):
    cache = Cache(tmp_path / "cache.sqlite3")
    cache.add_history("old", "Stichwort alt", "Erste Antwort")
    cache.add_history("new", "Andere Frage", "Stichwort neuer Chat")
    cache.add_history("old", "Stichwort zweite Frage", "Zweite Antwort")
    result = cache.search_chats("Stichwort")
    assert [c["session_id"] for c in result] == ["old", "new"]
    assert result[0]["turns"] == 2 and "Stichwort alt" in result[0]["snippet"]
    assert "zweite Frage" not in result[0]["snippet"]
    cache.rename_chat("new", "Titel mit reinem Namensfund")
    assert cache.search_chats("Namensfund")[0]["snippet"] == ""


def test_casefold_search_shows_snippet_including_expanded_characters(tmp_path):
    cache = Cache(tmp_path / "cache.sqlite3")
    cache.add_history("one", "Straße in Köln", "Eine schöne Straße")
    result = cache.search_chats("STRASSE")
    assert result and "Straße" in result[0]["snippet"]


def test_parallel_page_misses_share_fetch_but_keep_independent_checks(
    settings, tmp_path, monkeypatch
):
    cache = Cache(tmp_path / "cache.sqlite3")
    started = threading.Event()
    release = threading.Event()
    waiting = threading.Event()
    fetched = []
    fill = cache.filling

    @contextmanager
    def observed(key):
        if started.is_set():
            waiting.set()
        with fill(key):
            yield

    monkeypatch.setattr(cache, "filling", observed)

    class Fetcher:
        def fetch(self, url, **kwargs):
            fetched.append(url)
            started.set()
            assert release.wait(5)
            return PageResult(url=url, ok=True, text="Oeffentlicher Text", via="http")

    boxes = [tools.Toolbox(settings, cache=cache, fetcher=Fetcher()) for _ in range(2)]
    checks = []
    for i, box in enumerate(boxes):
        original_gate = box._leak_gate
        monkeypatch.setattr(
            box,
            "_leak_gate",
            lambda name, args, i=i, gate=original_gate: checks.append(i) or gate(name, args),
        )
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(boxes[0].call, "fetch_page", {"url": "https://example.org/page"})
        try:
            assert started.wait(5)
            second = pool.submit(boxes[1].call, "fetch_page", {"url": "https://example.org/page"})
            assert waiting.wait(5)
        finally:
            release.set()
        results = [first.result(), second.result()]
    assert len(fetched) == 1 and sorted(checks) == [0, 1]
    assert [r["via"] for r in results] == ["http", "cache"]
    assert all(box.untrusted_seen for box in boxes)
    assert all("Oeffentlicher Text" in r["text"] for r in results)
    assert not cache._fills


def test_different_cache_keys_and_profiles_do_not_block_each_other(tmp_path):
    first = Cache(tmp_path / "a" / "cache.sqlite3")
    second = Cache(tmp_path / "b" / "cache.sqlite3")
    with first.filling("page-a"), ThreadPoolExecutor(max_workers=2) as pool:

        def fill(cache, key):
            with cache.filling(key):
                return True

        assert pool.submit(fill, first, "page-b").result(timeout=2)
        assert pool.submit(fill, second, "page-a").result(timeout=2)
    with pytest.raises(RuntimeError), first.filling("failure"):
        raise RuntimeError("missing page")
    assert not first._fills
    with first.filling("failure"):
        pass


def test_changing_searxng_instance_does_not_reuse_previous_results(settings, tmp_path, monkeypatch):
    cache = Cache(tmp_path / "cache.sqlite3")
    monkeypatch.setattr(
        tools, "search_broadly", lambda wanted, count, runner: (runner(wanted[0], count), wanted)
    )
    calls = []

    def search(query, **kwargs):
        calls.append(kwargs["instance_url"])
        return [SearchResult(title=kwargs["instance_url"], url="https://example.org/page")]

    monkeypatch.setattr(tools, "search_web", search)
    settings.search_backend = "searxng"
    settings.searxng_url = "https://first.example"
    box = tools.Toolbox(settings, cache=cache)
    try:
        first = box.web_search("Recherche")
        settings.searxng_url = "https://second.example"
        second = box.web_search("Recherche")
        third = box.web_search("Recherche")
        assert first["results"][0]["title"] != second["results"][0]["title"]
        assert calls == ["https://first.example", "https://second.example"]
        assert third["cached"]
    finally:
        box.close()


@pytest.mark.parametrize("action", ["new", "open", "command"])
def test_reused_session_does_not_expose_previous_chats_run(parallel_site, action):
    client, _, _, _, account, _ = parallel_site
    current = client.get("/api/chats").json()["current"]
    assert client.post("/api/chat", json={"message": "Vorherige Antwort"}).status_code == 200
    state = client.get("/api/runstate").json()
    assert state["question"] == "Vorherige Antwort" and not state["resume"]
    if action == "new":
        selected = client.post("/api/clear").json()["current"]
    elif action == "open":
        settings = web.SESSIONS.get(account).settings()
        Cache(settings.db_path).add_history("saved", "Gespeicherter Chat", "Antwort")
        selected = client.post("/api/open", json={"session_id": "saved"}).json()["session_id"]
    else:
        assert client.post("/api/command", json={"line": "/clear"}).status_code == 200
        selected = client.get("/api/chats").json()["current"]
    assert selected != current
    headers = {"X-Aquaticy-Chat": selected}
    assert client.get("/api/runstate", headers=headers).json() == {
        "running": False,
        "resume": False,
    }
    assert client.get("/api/run", params={"id": state["id"]}, headers=headers).status_code == 404


def test_cache_migration_cleans_replaced_overflow_pages_and_is_concurrent(tmp_path):
    path = tmp_path / "cache.sqlite3"
    secret = "Privater-Arzttermin"
    with sqlite3.connect(path) as conn:
        conn.executescript(SCHEMA)
        conn.execute("INSERT INTO privacy_state VALUES ('chats', '1')")
        conn.executemany(
            "INSERT INTO cache VALUES (?, ?, ?, ?, 1, 9999999999)",
            [(str(i), "search", secret, '"' + secret * 250 + '"') for i in range(50)],
        )
    with ThreadPoolExecutor(max_workers=2) as pool:
        caches = list(pool.map(lambda _: Cache(path), range(2)))
    assert all(cache.get("0") == secret * 250 for cache in caches)
    assert secret.encode() not in path.read_bytes()


def test_migration_retries_pending_cleanup_without_changing_ciphertext(tmp_path):
    path = tmp_path / "cache.sqlite3"
    cache = Cache(path)
    cache.set("key", {"value": "privat"})
    with sqlite3.connect(path) as conn:
        before = conn.execute("SELECT payload FROM cache").fetchone()[0]
        conn.execute("UPDATE privacy_state SET value='1' WHERE name='cache'")
    resumed = Cache(path)
    assert resumed.get("key") == {"value": "privat"}
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT payload FROM cache").fetchone()[0] == before
        assert (
            conn.execute("SELECT value FROM privacy_state WHERE name='cache'").fetchone()[0] == "2"
        )


def test_migration_at_storage_limit_discards_only_cache(tmp_path, monkeypatch):
    from aquaticy import budget

    path = tmp_path / "cache.sqlite3"
    upload = tmp_path / "uploads" / "photo.png"
    upload.parent.mkdir()
    upload.write_bytes(b"Keep uploaded photo")
    with sqlite3.connect(path) as conn:
        conn.executescript(SCHEMA)
        conn.execute("INSERT INTO cache VALUES ('key', 'search', 'privat', '{}', 1, 9999999999)")
    monkeypatch.setattr(budget, "fits", lambda folder, size: False)
    cache = Cache(path)
    assert cache.get("key") is None
    assert upload.read_bytes() == b"Keep uploaded photo"
    assert b"privat" not in path.read_bytes()


def test_cache_budget_counts_encryption_and_label_overhead(tmp_path, monkeypatch):
    from aquaticy import budget

    cache = Cache(tmp_path / "cache.sqlite3")
    measured = []
    monkeypatch.setattr(budget, "fits", lambda folder, size: measured.append(size) or False)
    cache.set("key", "x", label="L" * 100)
    assert cache.get("key") is None
    assert measured and measured[0] > 150


def test_empty_legacy_cache_payload_remains_a_miss_after_migration(tmp_path):
    path = tmp_path / "cache.sqlite3"
    with sqlite3.connect(path) as conn:
        conn.executescript(SCHEMA)
        conn.execute("INSERT INTO cache VALUES ('empty', 'search', '', '', 1, 9999999999)")
        conn.execute("INSERT INTO cache VALUES ('labeled', 'search', 'privat', '', 1, 9999999999)")
    cache = Cache(path)
    assert cache.get("empty") is None and cache.get("labeled") is None
    assert b"privat" not in path.read_bytes()


@pytest.mark.parametrize(
    "message", ["unknown storage-opt", "Filesystem does not support, or has not enabled quotas"]
)
def test_known_unsupported_docker_quota_keeps_isolation_and_disk_monitor(monkeypatch, message):
    import subprocess

    from aquaticy import sandbox

    box = sandbox.Sandbox()
    box.runtime = sandbox.Runtime("docker", "docker", "Docker")
    attempts = []

    def run(binary, *args, **kwargs):
        attempts.append(args)
        return subprocess.CompletedProcess(
            args, 1 if len(attempts) == 1 else 0, "", message if len(attempts) == 1 else ""
        )

    monkeypatch.setattr(sandbox, "_runs", run)
    box._start_container()
    assert not box._quota_ok and len(attempts) == 2
    initial = list(attempts[0])
    index = initial.index("--storage-opt")
    del initial[index : index + 2]
    assert list(attempts[1]) == initial
    assert "--read-only" in initial
    assert initial[initial.index("--network") + 1] == "none"
    assert initial[initial.index("--cap-drop") + 1] == "ALL"
    monkeypatch.setattr(box, "usage_gb", lambda: box.disk_gb + 1)
    box._check_quota(sandbox.RunResult(exit_code=0, stdout="", stderr="", seconds=0))
    with pytest.raises(ValueError, match="voll"):
        box._refuse_if_full()


def test_other_docker_errors_do_not_trigger_quota_fallback(monkeypatch):
    import subprocess

    from aquaticy import sandbox

    box = sandbox.Sandbox()
    box.runtime = sandbox.Runtime("docker", "docker", "Docker")
    attempts = []

    def run(binary, *args, **kwargs):
        attempts.append(args)
        return subprocess.CompletedProcess(args, 1, "", "permission denied")

    monkeypatch.setattr(sandbox, "_runs", run)
    with pytest.raises(sandbox.SandboxUnavailable, match="permission denied"):
        box._start_container()
    assert len(attempts) == 1 and box._quota_ok


def test_plaintext_query_starting_with_encryption_prefix_is_also_migrated(tmp_path):
    path = tmp_path / "cache.sqlite3"
    label = "enc2:Privater Arzt"
    with sqlite3.connect(path) as conn:
        conn.executescript(SCHEMA)
        conn.execute("INSERT INTO cache VALUES ('key', 'search', ?, '{}', 1, 9999999999)", (label,))
    cache = Cache(path)
    with sqlite3.connect(path) as conn:
        stored = conn.execute("SELECT label FROM cache").fetchone()[0]
    assert cache._open(stored, "cache.label") == label
    assert label.encode() not in path.read_bytes()
