"""Vertiefte Pruefung: parallele Freigaben, Wiederholungen und Antwortabbrueche."""

from __future__ import annotations

import io
import json
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer

import httpx
import pytest

from aquaticy import cluster, web
from tests.test_cluster import _Handler, _paar


def accepted_invite(server):
    invitation = cluster.Invite(
        id="a" * 32, peer={"node": "c" * 32, "address": "127.0.0.1", "port": 1003},
        status="accepted", key=b"i" * 32, code="123456",
    )
    server.invites_out[invitation.id] = invitation
    return invitation


@pytest.mark.parametrize("state", ["disabled", "member"])
def test_stale_invitation_cannot_disclose_cluster_key(tmp_path, monkeypatch, state):
    master, member = _paar(tmp_path, 1001)
    server = master if state == "disabled" else member
    if state == "disabled":
        server.state["enabled"] = False
    invitation = accepted_invite(server)
    disclosed = []

    def transport(target, path, body, timeout):
        disclosed.append(path)
        return json.dumps({"box": cluster._b64(cluster.seal(
            invitation.key, b'{"ok": true}', "joined"))}).encode()

    monkeypatch.setattr(server, "_transport", transport)
    monkeypatch.setattr(server.db, "install", lambda: None)
    monkeypatch.setattr(server, "start", lambda: None)
    monkeypatch.setattr(server, "broadcast", lambda: None)
    with pytest.raises(cluster.ClusterError):
        server.confirm(invitation.id, invitation.code)
    assert disclosed == [], "ein alter Dialog darf keine Verbunddaten mehr freigeben"


def test_parallel_confirmation_joins_only_once(tmp_path, monkeypatch):
    master, _ = _paar(tmp_path, 1001)
    invitation = accepted_invite(master)
    first_sent, second_sent, release = threading.Event(), threading.Event(), threading.Event()
    sent = []

    def transport(target, path, body, timeout):
        sent.append(path)
        (first_sent if len(sent) == 1 else second_sent).set()
        assert release.wait(5)
        return json.dumps({"box": cluster._b64(cluster.seal(
            invitation.key, b'{"ok": true}', "joined"))}).encode()

    monkeypatch.setattr(master, "_transport", transport)
    monkeypatch.setattr(master.db, "install", lambda: None)
    monkeypatch.setattr(master, "start", lambda: None)
    monkeypatch.setattr(master, "broadcast", lambda: None)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(master.confirm, invitation.id, invitation.code)
        try:
            assert first_sent.wait(5)
            second = pool.submit(master.confirm, invitation.id, invitation.code)
            second_sent.wait(0.2)
        finally:
            release.set()
        assert first.result(timeout=5).status == "joined"
        with pytest.raises(cluster.ClusterError):
            second.result(timeout=5)
    assert sent == ["/cluster/hello-join"]
    assert sum(node["node"] == invitation.peer["node"] for node in master.members()) == 1


@pytest.fixture
def http_server(tmp_path, monkeypatch):
    server_cluster = cluster.Cluster(tmp_path)
    server_cluster.state["enabled"] = True
    monkeypatch.setattr(web, "CLUSTER", server_cluster)
    monkeypatch.setattr(web, "TOKEN", "")
    monkeypatch.setattr(web, "AUTH", None)
    monkeypatch.setattr(web, "AIGUARD", None)
    server = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("route", ["/api/consent", "/cluster/hello-status"])
@pytest.mark.parametrize("extra", [b"Content-Length: 99\r\n", b"Transfer-Encoding: chunked\r\n"])
def test_ambiguous_http_body_is_rejected(http_server, route, extra):
    body = b'{"accepted":true}'
    request = (f"POST {route} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
               f"Content-Length: {len(body)}\r\n".encode() + extra + b"\r\n" + body)
    with socket.create_connection(("127.0.0.1", http_server), timeout=2) as client:
        client.sendall(request)
        assert b" 400 " in client.recv(4096).split(b"\r\n")[0]


@pytest.mark.parametrize("part", ["headers", "body"])
def test_incomplete_http_request_does_not_hold_thread_forever(http_server, monkeypatch, part):
    monkeypatch.setattr(web, "REQUEST_READ_TIMEOUT", 0.1, raising=False)
    request = (b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n" if part == "headers" else
               b"POST /api/consent HTTP/1.1\r\nHost: 127.0.0.1\r\n"
               b"Content-Length: 100\r\n\r\n{")
    with socket.create_connection(("127.0.0.1", http_server), timeout=1) as client:
        client.sendall(request)
        response = client.recv(4096)
        assert response == b"" if part == "headers" else b" 408 " in response


@pytest.mark.parametrize("method", ["POST", "DELETE"])
def test_uncertain_forward_is_not_executed_twice(tmp_path, monkeypatch, method):
    home, entrance = _paar(tmp_path, 1001)
    handler = _Handler("/api/jobs")
    handler.command = method
    executed = []
    monkeypatch.setattr(entrance, "home_for", lambda user: home.node_id)

    def response_lost(*args):
        executed.append(method)
        raise cluster.ClusterError("Antwort nach Ausfuehrung verloren")

    monkeypatch.setattr(entrance, "_proxy_once", response_lost)
    with pytest.raises(cluster.ClusterError):
        entrance.forward(handler, "user1", b"{}", False, "127.0.0.1")
    assert executed == [method]


def test_explicit_moved_reply_can_redirect_without_duplicate_execution(tmp_path, monkeypatch):
    home, entrance = _paar(tmp_path, 1001)
    destinations = iter([home.node_id, entrance.node_id])
    attempts = []
    monkeypatch.setattr(entrance, "home_for", lambda user: next(destinations))

    def moved(*args):
        attempts.append(True)
        return "moved"  # Heimserver hat vor der Ausfuehrung abgelehnt.

    monkeypatch.setattr(entrance, "_proxy_once", moved)
    assert not entrance.forward(_Handler("/api/jobs"), "user1", b"{}", False, "127.0.0.1")
    assert attempts == [True]


@pytest.mark.parametrize("route", ["/api/consent", "/cluster/hello-status"])
def test_body_truncated_at_eof_is_rejected(http_server, route):
    body = b'{"accepted":true}'
    request = (f"POST {route} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
               f"Content-Length: {len(body) + 10}\r\n\r\n".encode() + body)
    with socket.create_connection(("127.0.0.1", http_server), timeout=2) as client:
        client.sendall(request)
        client.shutdown(socket.SHUT_WR)
        assert b" 400 " in client.recv(4096).split(b"\r\n")[0]


@pytest.mark.parametrize("stream", ["rotated_key", "truncated", "empty"])
def test_proxy_requires_complete_reply_with_original_key(tmp_path, monkeypatch, stream):
    home, entrance = _paar(tmp_path, 1001)
    original_key = entrance.key
    handler = _Handler("/api/prefs")

    def respond(request):
        envelope = json.loads(request.content)
        inner = json.loads(cluster.unseal(original_key, cluster._unb64(envelope["box"]), "rpc"))
        salt = b"s" * 16
        output = io.BytesIO()
        writer = cluster.FrameWriter(output, original_key, salt, f"stream:{inner['n']}")
        if stream != "empty":
            writer.write(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}")
        if stream != "truncated":
            writer.end()
        if stream == "rotated_key":
            entrance.info["secret"] = cluster._b64(b"n" * 32)
        return httpx.Response(200, content=output.getvalue(),
                              headers={"X-Aquaticy-Salt": cluster._b64(salt)})

    real_client = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: real_client(
        transport=httpx.MockTransport(respond), **kwargs))
    if stream == "rotated_key":
        assert entrance._proxy_once(handler, entrance.member(home.node_id), "user1", b"",
                                    False, "127.0.0.1") == "ok"
        assert handler.wfile.getvalue().endswith(b"{}")
    else:
        with pytest.raises(cluster.ClusterError):
            entrance._proxy_once(handler, entrance.member(home.node_id), "user1", b"",
                                 False, "127.0.0.1")
