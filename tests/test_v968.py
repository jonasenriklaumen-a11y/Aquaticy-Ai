"""Key preservation, malformed input and private diagnostics for 9.6.8 Luna."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from aquaticy import (
    aiguard,
    auth,
    cluster,
    desktop,
    guardrails,
    keyvault,
    linked,
    memory,
    privacy,
    web,
)
from aquaticy.auth import AuthStore
from aquaticy.calc import CalcError, calculate
from aquaticy.extract import extract_product
from aquaticy.jsonutil import MAX_DEPTH, JsonDepthError, loads
from aquaticy.learning import Learning
from aquaticy.legal import LEGAL_VERSION
from tests.test_terra import FACT, QUESTION, SOURCE, remember
from tests.test_v965 import parallel_site as parallel_site


@pytest.mark.parametrize("filename,loader", [
    ("data.key", lambda p: privacy.master_key(p.parent)),
    ("auth.key", lambda p: AuthStore(p.parent, "TESTCODE")),
    ("vault.key", keyvault.load_secret),
    ("memory.key", memory._key_from_file),
    ("memory.salt", lambda p: memory._salt_for(p.parent)),
])
@pytest.mark.parametrize("content", [b"", b"broken"])
def test_corrupt_keys_fail_without_destroying_the_original(tmp_path, filename, loader, content):
    path = tmp_path / filename
    path.write_bytes(content)
    with pytest.raises(memory.CipherError, match="beschädigt"):
        loader(path)
    assert path.read_bytes() == content
    assert not list(tmp_path.glob(".aquaticy-key-*"))


def test_failed_master_load_is_not_cached_and_backup_restores_access(tmp_path):
    path = tmp_path / "data.key"
    path.write_bytes(b"")
    with pytest.raises(memory.CipherError):
        privacy.master_key(tmp_path)
    restored = secrets.token_bytes(32)
    path.write_bytes(restored)
    assert privacy.master_key(tmp_path) == restored


@pytest.mark.parametrize("hardlinks", [True, False])
def test_simultaneous_key_creators_publish_one_complete_private_key(tmp_path, monkeypatch,
                                                                  hardlinks):
    if not hardlinks:
        def unsupported(*args):
            raise OSError(errno.ENOTSUP, "hard links unavailable")
        monkeypatch.setattr(memory.os, "link", unsupported)
    path = tmp_path / "secret.key"
    barrier = threading.Barrier(8)

    def create():
        def candidate():
            barrier.wait(timeout=10)
            return secrets.token_bytes(32)
        return memory.load_secret_file(path, candidate, 32)

    with ThreadPoolExecutor(max_workers=8) as pool:
        keys = list(pool.map(lambda _: create(), range(8)))
    assert len(set(keys)) == 1
    assert keys[0] == path.read_bytes() and len(keys[0]) == 32
    assert not list(tmp_path.glob(".aquaticy-key-*"))
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("hardlinks", [True, False])
def test_independent_processes_create_and_reopen_the_same_key(tmp_path, hardlinks):
    path = tmp_path / "secret.key"
    script = (
        "import errno,hashlib,os,secrets,sys; from pathlib import Path; "
        "from aquaticy.memory import load_secret_file; "
        "original_link=os.link; "
        "os.link=lambda *a: original_link(*a) if sys.argv[2]=='yes' else "
        "(_ for _ in ()).throw(OSError(errno.ENOTSUP,'unavailable')); "
        "key=load_secret_file(Path(sys.argv[1]),lambda:secrets.token_bytes(32),32); "
        "print(hashlib.sha256(key).hexdigest())"
    )

    def run(_):
        return subprocess.run([sys.executable, "-c", script, str(path),
                               "yes" if hardlinks else "no"], check=True,
                              capture_output=True, text=True, timeout=20).stdout.strip()

    with ThreadPoolExecutor(max_workers=6) as pool:
        fingerprints = list(pool.map(run, range(6)))
    assert set(fingerprints) == {hashlib.sha256(path.read_bytes()).hexdigest()}
    assert not list(tmp_path.glob(".aquaticy-key-*"))


def test_failed_secret_creation_cleans_up_without_publishing(tmp_path):
    path = tmp_path / "secret.key"
    with pytest.raises(memory.CipherError):
        memory.load_secret_file(path, lambda: b"short", 32)
    assert not path.exists()
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig", "utf-16", "utf-32"])
def test_depth_limit_preserves_encodings_quotes_escapes_and_string_brackets(encoding):
    value = {"text": 'Wärme \\ " ' + "[{}]" * 100, "items": [True, None, 1]}
    assert loads(json.dumps(value, ensure_ascii=False).encode(encoding)) == value
    boundary = "[" * MAX_DEPTH + "0" + "]" * MAX_DEPTH
    assert loads(boundary.encode(encoding)) == json.loads(boundary)
    with pytest.raises(JsonDepthError):
        loads(("[" + boundary + "]").encode(encoding))


def test_existing_long_secret_is_preserved_without_rotation(tmp_path):
    path = tmp_path / "legacy.key"
    original = secrets.token_bytes(64)
    path.write_bytes(original)
    assert memory.load_secret_file(path, lambda: pytest.fail("must not rotate"), 32) == original
    assert path.read_bytes() == original


def test_encrypted_notes_and_passwords_survive_reopening(tmp_path):
    cipher = memory.Cipher(tmp_path / "memory.key")
    token = cipher.encrypt("Vertrauliche Erinnerung mit Umlauten: Größe und Wärme.")
    assert memory.Cipher(tmp_path / "memory.key").decrypt(token) == cipher.decrypt(token)
    store = AuthStore(tmp_path, "TESTCODE")
    account = store.register("unicode@example.org", "pässwort-sicher-123", "normal",
                             terms_accepted=True, terms_version="1")
    reopened = AuthStore(tmp_path, "TESTCODE")
    assert reopened.authenticate(account.email, "pässwort-sicher-123").id == account.id


def test_unicode_password_change_still_revokes_other_sessions(tmp_path):
    store = AuthStore(tmp_path, "TESTCODE")
    old, new = "pässwort-sicher-123", "äußerst-sicher-neu-456"
    account = store.register("unicode@example.org", old, "normal",
                             terms_accepted=True, terms_version="1")
    keep = store.create_session(account, "one", "127.0.0.1")
    other = store.create_session(account, "two", "127.0.0.1")
    with pytest.raises(ValueError, match="unterscheiden"):
        store.change_password(account, old, old, keep)
    store.change_password(account, old, new, keep)
    assert store.authenticate(account.email, old) is None
    assert store.authenticate(account.email, new).id == account.id
    assert store.session_account(keep, "one").id == account.id
    assert store.session_account(other, "two") is None


def test_invalid_unicode_password_is_rejected_and_login_keeps_dummy_hash(tmp_path, monkeypatch):
    invalid = "sicheres-passwort-\ud800"
    with pytest.raises(ValueError, match="ungültige Zeichen"):
        auth.validate_password(invalid)
    store = AuthStore(tmp_path, "TESTCODE")
    hashed = []
    monkeypatch.setattr(auth, "_argon_hash", lambda password, *args: hashed.append(password))
    assert store.authenticate("unknown@example.org", invalid) is None
    assert hashed == [""]


@pytest.mark.parametrize("expression", ["0**-1", "(-0.0)**-2", "0**(-1/2)"])
def test_zero_to_negative_power_is_a_controlled_calculation_error(expression):
    with pytest.raises(CalcError, match="Division durch null"):
        calculate(expression)
    assert calculate("2**-3") == 0.125


def test_malformed_origin_is_forbidden_without_changing_account(parallel_site):
    client = parallel_site[0]
    response = client.post("/api/password", json={"old": "parallel-test-passwort",
                                                  "new": "neues-sicheres-passwort"},
                           headers={"Origin": "http://["})
    assert response.status_code == 403
    assert web.AUTH.authenticate(parallel_site[4].email, "parallel-test-passwort")


def test_malformed_absolute_http_target_gets_a_controlled_bad_request(parallel_site):
    target = urlsplit(parallel_site[5])
    with socket.create_connection((target.hostname, target.port), timeout=5) as connection:
        connection.sendall(b"GET http://[/api/config HTTP/1.1\r\nHost: localhost\r\n\r\n")
        response = connection.recv(8192)
    assert response.startswith(b"HTTP/1.0 400 ")
    assert b"Content-Security-Policy:" in response


@pytest.mark.parametrize("route", ["/api/consent", "/cluster/hello", "/cluster/hello-status",
                                   "/cluster/hello-join"])
def test_excessive_json_nesting_is_rejected_before_handlers(parallel_site, monkeypatch, route):
    if route.startswith("/cluster/"):
        monkeypatch.setattr(web, "CLUSTER", SimpleNamespace(enabled=True))
    monkeypatch.setattr(web, "CLUSTER_HELLO_LIMIT", web.RateLimiter(30, 60))
    depth = MAX_DEPTH + 1
    body = '{"data":' + "[" * depth + "0" + "]" * depth + "}"
    response = parallel_site[0].post(route, content=body,
                                     headers={"Content-Type": "application/json"})
    assert response.status_code == 400
    assert "verschachtelt" in response.json()["error"]


def test_error_diagnostics_do_not_log_url_tokens_or_exception_secrets(parallel_site,
                                                                    monkeypatch, capsys):
    def broken(self):
        raise RuntimeError("private-exception-canary API-key-canary")
    monkeypatch.setattr(web.Handler, "_get", broken)
    response = parallel_site[0].get("/api/config?token=private-url-canary")
    assert response.status_code == 500
    output = capsys.readouterr()
    assert "RuntimeError" in output.out
    for secret in ("private-exception-canary", "API-key-canary", "private-url-canary"):
        assert secret not in output.out + output.err + response.text


def test_deep_discovery_packet_does_not_kill_discovery_and_next_beacon_works(tmp_path):
    node = cluster.Cluster(tmp_path)
    node.note_beacon(b"[" * 1000 + b"0" + b"]" * 1000, "127.0.0.1")
    assert node.found() == []
    other = cluster.Cluster(tmp_path / "other")
    node.note_beacon(json.dumps(other.beacon()).encode(), "127.0.0.1")
    assert [entry["node"] for entry in node.found()] == [other.node_id]


def test_deep_rpc_envelope_is_rejected_before_key_lookup(tmp_path):
    node = cluster.Cluster(tmp_path)
    depth = MAX_DEPTH + 1
    with pytest.raises(cluster.ClusterError, match="Ungueltige Nachricht"):
        node._unwrap(b"[" * depth + b"0" + b"]" * depth,
                     lambda _: pytest.fail("must not look up unauthenticated sender"))


def test_malformed_authenticated_rpc_json_is_a_cluster_error(tmp_path):
    node = cluster.Cluster(tmp_path)
    key = secrets.token_bytes(32)
    depth = MAX_DEPTH + 1
    for payload in (b"invalid", b"[" * depth + b"0" + b"]" * depth):
        envelope = json.dumps({"from": "other", "box": cluster._b64(
            cluster.seal(key, payload, "rpc"))}).encode()
        with pytest.raises(cluster.ClusterError):
            node._unwrap(envelope, lambda _: [key])


@pytest.mark.parametrize("nested", ["[" * 1500 + "{}" + "]" * 1500,
                                    '{"@graph":' * 1500 + "{}" + "}" * 1500])
def test_bad_nested_source_json_does_not_discard_valid_product_data(nested):
    html = ('<script type="application/ld+json">' + nested + '</script>'
            '<script type="application/ld+json">'
            '{"@type":"Product","name":"Gültiges Produkt",'
            '"offers":{"price":"10","priceCurrency":"EUR"}}</script>')
    product = extract_product(html, "https://example.org/product")
    assert product and product.name == "Gültiges Produkt" and product.price == "10"


def test_deep_safety_responses_remain_unclear_and_do_not_grant_approval():
    nested = "[" * 1500 + "0" + "]" * 1500
    assert guardrails.parse_verdict('{"zulaessig":true,"grund":' + nested + "}") is None
    assert aiguard.parse_judgement('{"missbrauch":false,"art":' + nested + "}") is None
    assert desktop.parse_object('{"kind":"dokument","data":' + nested + "}") is None
    assert linked._judge('{"ok":true,"feedback":' + nested + "}")[0] is False


def test_named_people_with_same_surname_do_not_share_cached_facts(tmp_path):
    store = Learning(tmp_path)
    store.set_consent(True, LEGAL_VERSION)
    assert remember(store) == 1
    assert store.research.recall("Welche Arbeiten von Mileva Einstein sind bekannt?") == []
    assert store.research.recall(QUESTION) == [{"text": "- " + FACT, "source": SOURCE}]
    assert store.research.recall("Was erforschte Einstein?")
    assert remember(store, question="Welche Arbeiten von Mileva Einstein sind bekannt?") == 0
