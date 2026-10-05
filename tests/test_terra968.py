"""Deterministic races, origin changes and bounded model arguments for Terra."""

from __future__ import annotations

import errno
import json
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import httpx
import pytest

from aquaticy import agent, auth, memory, netguard, subagents, web
from aquaticy.auth import AuthStore
from aquaticy.jsonutil import MAX_DEPTH, JsonDepthError, raw_decode
from tests.test_v965 import parallel_site as parallel_site

OLD, NEW = "old-password-123", "new-password-456"


def account(store):
    return store.register("race@example.org", OLD, "normal", username="Race",
                          terms_accepted=True, terms_version="1")


def test_verified_old_password_cannot_open_a_session_after_change(tmp_path):
    store = AuthStore(tmp_path, "TESTCODE")
    registered = account(store)
    verified = store.authenticate(registered.email, OLD)
    another_process = AuthStore(tmp_path, "TESTCODE")
    another_process.change_password(registered, OLD, NEW)
    with pytest.raises(ValueError, match="inzwischen"):
        store.create_session(verified, "late-device", "127.0.0.1")
    fresh = store.authenticate(registered.email, NEW)
    token = store.create_session(fresh, "fresh-device", "127.0.0.1")
    assert store.session_account(token, "fresh-device").id == registered.id


def test_competing_password_changes_across_stores_have_one_winner(tmp_path, monkeypatch):
    stores = [AuthStore(tmp_path, "TESTCODE"), AuthStore(tmp_path, "TESTCODE")]
    registered = account(stores[0])
    keep = stores[0].create_session(registered, "keep", "127.0.0.1")
    other = stores[0].create_session(registered, "other", "127.0.0.1")
    original = auth._argon_hash
    barrier = threading.Barrier(2)
    candidates = ("first-new-password-123", "second-new-password-456")

    def hash_password(password, *args):
        if password in candidates and len(args) == 2:
            barrier.wait(timeout=10)
        return original(password, *args)

    monkeypatch.setattr(auth, "_argon_hash", hash_password)

    def change(index):
        try:
            stores[index].change_password(registered, OLD, candidates[index], keep)
        except ValueError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as pool:
        won = list(pool.map(change, range(2)))
    assert sum(won) == 1
    for password, winner in zip(candidates, won, strict=True):
        assert bool(stores[0].authenticate(registered.email, password)) == winner
    assert stores[0].session_account(keep, "keep").id == registered.id
    assert stores[0].session_account(other, "other") is None


def test_failed_session_revocation_rolls_back_the_password_change(tmp_path):
    store = AuthStore(tmp_path, "TESTCODE")
    registered = account(store)
    token = store.create_session(registered, "device", "127.0.0.1")
    with store._connect() as conn:
        conn.execute("CREATE TRIGGER deny_session_delete BEFORE DELETE ON sessions "
                     "BEGIN SELECT RAISE(ABORT,'fixture failure'); END")
    with pytest.raises(auth.sqlite3.IntegrityError):
        store.change_password(registered, OLD, NEW)
    assert store.authenticate(registered.email, OLD)
    assert store.authenticate(registered.email, NEW) is None
    assert store.session_account(token, "device")


def test_legacy_upgrade_cannot_overwrite_a_concurrent_new_password(tmp_path, monkeypatch):
    store = AuthStore(tmp_path, "TESTCODE")
    registered = account(store)
    salt = b"s" * 16
    with store._connect() as conn:
        conn.execute("UPDATE users SET password_hash=?,password_salt=? WHERE id=?",
                     (auth._password_hash(OLD, salt), salt, registered.id))
    another_process = AuthStore(tmp_path, "TESTCODE")
    entered, release = threading.Event(), threading.Event()
    main_thread = threading.get_ident()
    original = auth._argon_hash

    def hash_password(password, *args):
        if password == OLD and threading.get_ident() != main_thread:
            entered.set()
            assert release.wait(10)
        return original(password, *args)

    monkeypatch.setattr(auth, "_argon_hash", hash_password)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(store.authenticate, registered.email, OLD)
        try:
            assert entered.wait(5)
            another_process.change_password(registered, OLD, NEW)
        finally:
            release.set()
        assert pending.result(timeout=10) is None
    assert store.authenticate(registered.email, NEW)
    assert store.authenticate(registered.email, OLD) is None


def test_simultaneous_legacy_logins_both_remain_valid(tmp_path, monkeypatch):
    stores = [AuthStore(tmp_path, "TESTCODE"), AuthStore(tmp_path, "TESTCODE")]
    registered = account(stores[0])
    salt = b"s" * 16
    with stores[0]._connect() as conn:
        conn.execute("UPDATE users SET password_hash=?,password_salt=? WHERE id=?",
                     (auth._password_hash(OLD, salt), salt, registered.id))
    barrier = threading.Barrier(2)
    original = auth._argon_hash

    def hash_password(password, *args):
        if password == OLD and len(args) == 2:
            barrier.wait(timeout=10)
        return original(password, *args)

    monkeypatch.setattr(auth, "_argon_hash", hash_password)
    with ThreadPoolExecutor(max_workers=2) as pool:
        verified = list(pool.map(lambda store: store.authenticate(registered.email, OLD), stores))
    assert all(a and a.id == registered.id for a in verified)
    for store, a in zip(stores, verified, strict=True):
        assert store.create_session(a, "legacy", "127.0.0.1")


def test_credential_proof_is_account_bound_and_not_in_representations(tmp_path):
    store = AuthStore(tmp_path, "TESTCODE")
    first = account(store)
    second = store.register("second@example.org", OLD, "normal", username="Second",
                            terms_accepted=True, terms_version="1")
    assert first._credential and "_credential" not in repr(first)
    with store._connect() as conn:
        source = conn.execute("SELECT password_hash,password_salt FROM users WHERE id=?",
                              (first.id,)).fetchone()
        conn.execute("UPDATE users SET password_hash=?,password_salt=? WHERE id=?",
                     (*source, second.id))
    with pytest.raises(ValueError):
        store.create_session(replace(first, id=second.id), "forged", "127.0.0.1")


def test_http_login_racing_password_change_returns_401_without_new_session(parallel_site,
                                                                         monkeypatch):
    fixture_client, _, _, _, registered, url = parallel_site
    original = web.AUTH.authenticate
    entered, release = threading.Event(), threading.Event()
    scheduled = []

    def authenticate(email, password):
        result = original(email, password)
        if password == "parallel-test-passwort":
            entered.set()
            assert release.wait(10)
        return result

    monkeypatch.setattr(web.AUTH, "authenticate", authenticate)
    monkeypatch.setattr(web, "start_user_scheduler", lambda a: scheduled.append(a.id))
    with httpx.Client(base_url=url, headers=dict(fixture_client.headers), trust_env=False,
                      timeout=15) as client, ThreadPoolExecutor(max_workers=1) as pool:
        assert client.post("/api/consent", json={"accepted": True}).status_code == 200
        pending = pool.submit(client.post, "/api/auth/login", json={
            "email": registered.email, "password": "parallel-test-passwort"})
        try:
            assert entered.wait(5)
            independent = AuthStore(web.AUTH.data_dir, "TESTCODE")
            independent.change_password(registered, "parallel-test-passwort", NEW)
        finally:
            release.set()
        response = pending.result(timeout=10)
        assert response.status_code == 401
        assert web.AUTH.session_count(registered.id) == 0
        assert not scheduled and web.AUTH_COOKIE not in response.cookies
        valid = client.post("/api/auth/login", json={"email": registered.email, "password": NEW})
        assert valid.status_code == 200 and scheduled == [registered.id]
        assert "_credential" not in valid.text


@pytest.mark.parametrize("field", ["email", "username"])
def test_unpaired_surrogates_are_rejected_in_account_fields(tmp_path, field):
    store = AuthStore(tmp_path, "TESTCODE")
    values = {"email": "valid@example.org", "username": "Valid"}
    values[field] = "bad\ud800@example.org" if field == "email" else "Name\ud800"
    with pytest.raises(ValueError):
        store.register(password=OLD, plan="normal", terms_accepted=True, terms_version="1",
                       **values)
    assert store.accounts() == []
    assert store.authenticate("bad\ud800@example.org", OLD) is None


@pytest.mark.parametrize("winerror", [1, 50, 1314])
def test_windows_hardlink_errors_use_atomic_fallback(tmp_path, monkeypatch, winerror):
    def unsupported(*args):
        error = OSError(errno.EINVAL, "fixture Windows failure")
        error.winerror = winerror
        raise error
    monkeypatch.setattr(memory.os, "link", unsupported)
    path = tmp_path / "secret.key"
    secret = memory.load_secret_file(path, lambda: secrets.token_bytes(32), 32)
    assert path.read_bytes() == secret and len(secret) == 32
    assert not list(tmp_path.glob(".aquaticy-key-*"))


def test_unrelated_filesystem_errors_fail_without_publishing(tmp_path, monkeypatch):
    def failed(*args):
        raise OSError(errno.EIO, "fixture disk failure")
    monkeypatch.setattr(memory.os, "link", failed)
    with pytest.raises(OSError):
        memory.load_secret_file(tmp_path / "secret.key", lambda: secrets.token_bytes(32), 32)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("mode", ["headers", "defaults", "basic_auth"])
@pytest.mark.parametrize("destination", ["https://second.example/", "http://first.example/",
                                          "https://first.example:8443/"])
def test_redirects_strip_credentials_on_origin_change(monkeypatch, mode, destination):
    monkeypatch.setattr(netguard, "resolve", lambda host, port: ["8.8.8.8"])
    seen = []
    private = {"Authorization": "Bearer fixture-only", "Cookie": "raw=fixture-only",
               "X-Api-Key": "fixture-only", "X-Auth-Token": "fixture-only"}

    def serve(request):
        seen.append(request)
        return (httpx.Response(302, headers={"Location": destination}) if len(seen) == 1
                else httpx.Response(200, text="ok"))

    options = {"transport": httpx.MockTransport(serve), "headers": {"User-Agent": "Terra"}}
    if mode == "defaults":
        options["headers"].update(private)
    elif mode == "basic_auth":
        options["auth"] = ("fixture-user", "fixture-password")
    with httpx.Client(**options) as client:
        response = netguard.get(client, "https://first.example/", max_bytes=100,
                                headers=private if mode == "headers" else None)
    assert response.text == "ok" and "authorization" in seen[0].headers
    assert all(name not in seen[1].headers for name in private)
    assert seen[1].headers["user-agent"] == "Terra"


@pytest.mark.parametrize("start,destination", [("https://first.example/", "/next"),
                                               ("http://first.example/", "https://first.example/")])
def test_same_origin_and_default_https_upgrade_keep_authentication(monkeypatch, start, destination):
    monkeypatch.setattr(netguard, "resolve", lambda host, port: ["8.8.8.8"])
    seen = []

    def serve(request):
        seen.append(request)
        return (httpx.Response(302, headers={"Location": destination}) if len(seen) == 1
                else httpx.Response(200, text="ok"))

    with httpx.Client(transport=httpx.MockTransport(serve), auth=("user", "fixture")) as client:
        assert netguard.get(client, start, max_bytes=100).text == "ok"
    assert seen[0].headers["authorization"] == seen[1].headers["authorization"]


def test_redirect_preserves_target_scoped_cookies_without_raw_or_unscoped_cookie(monkeypatch):
    monkeypatch.setattr(netguard, "resolve", lambda host, port: ["8.8.8.8"])
    seen = []

    def serve(request):
        seen.append(request)
        return (httpx.Response(302, headers={"Location": "https://second.example/"})
                if len(seen) == 1 else httpx.Response(200, text="ok"))

    with httpx.Client(transport=httpx.MockTransport(serve), cookies={"unscoped": "fixture"},
                      headers={"Cookie": "raw=fixture"}) as client:
        client.cookies.set("target", "allowed", domain="second.example", path="/")
        netguard.get(client, "https://first.example/", max_bytes=100)
    assert seen[1].headers["cookie"] == "target=allowed"


def test_https_downgrade_never_sends_even_nonsecure_domain_cookie(monkeypatch):
    monkeypatch.setattr(netguard, "resolve", lambda host, port: ["8.8.8.8"])
    seen = []

    def serve(request):
        seen.append(request)
        return (httpx.Response(302, headers={"Location": "http://first.example/"})
                if len(seen) == 1 else httpx.Response(200, text="ok"))

    with httpx.Client(transport=httpx.MockTransport(serve)) as client:
        client.cookies.set("session", "fixture", domain="first.example", path="/")
        netguard.get(client, "https://first.example/", max_bytes=100)
    assert "session=fixture" in seen[0].headers["cookie"]
    assert "cookie" not in seen[1].headers


def test_redirect_to_private_address_still_stops_before_next_transport(monkeypatch):
    monkeypatch.setattr(netguard, "resolve", lambda host, port:
                        ["8.8.8.8"] if host == "first.example" else ["127.0.0.1"])
    seen = []

    def serve(request):
        seen.append(request)
        return httpx.Response(302, headers={"Location": "https://second.example/"})

    with (httpx.Client(transport=httpx.MockTransport(serve)) as client,
          pytest.raises(netguard.BlockedTarget)):
        netguard.get(client, "https://first.example/", max_bytes=100)
    assert len(seen) == 1


@pytest.mark.parametrize("kind", ["[", "{"])
def test_tool_arguments_reject_deep_values_and_keep_prior_complete_object(kind):
    deep = "[" * (MAX_DEPTH + 1) + "0" + "]" * (MAX_DEPTH + 1)
    invalid = '{"data":' + deep + "}" if kind == "{" else deep
    safe = '{"query":"first safe question"}'
    assert agent.split_json_objects(safe + invalid) == [safe.replace(":", ": ")]
    messages = [{"role": "assistant", "tool_calls": [{"function": {"arguments": invalid}}]}]
    agent.sanitize_history(messages)
    assert messages[0]["tool_calls"][0]["function"]["arguments"] == "{}"
    with pytest.raises(JsonDepthError):
        raw_decode(invalid)


def test_concatenated_model_arguments_keep_strings_arrays_and_offsets():
    first = {"text": 'escaped \\" [ { } ]', "data": [1, {"ok": True}]}
    second = {"query": "other safe question"}
    raw = json.dumps(first) + json.dumps(second)
    value, end = raw_decode(raw)
    assert value == first and json.loads(raw[end:]) == second
    assert [json.loads(s) for s in agent.split_json_objects(raw)] == [first, second]


def test_deep_planner_reply_returns_existing_research_fallback():
    raw = "[" * (MAX_DEPTH + 1) + '"query"' + "]" * (MAX_DEPTH + 1)
    assert subagents._parse_task_list(raw) == []
    assert subagents._parse_plan('{"tasks":' + raw + "}", "Fallback question", 3)[1] == [
        "Fallback question"]
