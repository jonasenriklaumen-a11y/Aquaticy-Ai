"""Regressionen der Sicherheits-, Fehler- und Nutzungspruefung fuer 9.6.4."""

from __future__ import annotations

import json
import secrets
import threading
import time
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from aquaticy import cluster, web
from tests.test_cluster import Netz, _konto, _paar, _store


@pytest.mark.parametrize("method,path", [("GET", "/api/account"), ("POST", "/api/prefs")])
def test_cluster_checks_server_token_before_forwarding(tmp_path, monkeypatch, method, path):
    store = _store(tmp_path / "accounts")
    account = _konto(store, "security@example.org")
    token = store.create_session(account, "Security-Test\x1f", "127.0.0.1")
    home, entrance = _paar(tmp_path, 1)
    entrance.homes[account.id] = home.node_id
    forwarded = []

    def forward(handler, *args):
        forwarded.append(handler.path)
        handler._json({"forwarded": True})
        return True

    monkeypatch.setattr(entrance, "forward", forward)
    monkeypatch.setattr(web, "AUTH", store)
    monkeypatch.setattr(web, "TOKEN", "extra-server-password")
    monkeypatch.setattr(web, "CLUSTER", entrance)
    monkeypatch.setattr(web, "AIGUARD", None)
    server = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        headers = {"User-Agent": "Security-Test", "Cookie": f"{web.AUTH_COOKIE}={token}"}
        for password, expected in ((None, 401), ("wrong", 401), ("extra-server-password", 200)):
            if password is not None:
                headers["X-Aquaticy-Token"] = password
            connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            connection.request(method, path, body=b"{}" if method == "POST" else None,
                               headers=headers)
            response = connection.getresponse()
            response.read()
            connection.close()
            assert response.status == expected
        assert forwarded == [path]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("receiver", ["master", "member"])
def test_old_cluster_key_cannot_impersonate_surviving_node(tmp_path, receiver):
    master, member = _paar(tmp_path, 1)
    old_key = master.key
    new_key = b"n" * 32
    link = b"l" * 32
    if receiver == "master":
        # Entfernen des einzigen Mitglieds: ein Angreifer kennt den alten
        # Gruppenschluessel und gibt sich anschliessend als Master aus.
        master.remove(member.node_id, notify=False)
        target = master
        new_key = master.key
    else:
        member.state["link"] = cluster._b64(link)
        member._take_rekey({"box": cluster._b64(cluster.seal(link, new_key, "rekey"))})
        target = member
    inner = json.dumps({"op": "ping", "ts": time.time(),
                        "n": secrets.token_hex(12), "a": {}}).encode()
    forged = json.dumps({"from": master.node_id,
                         "box": cluster._b64(cluster.seal(old_key, inner, "rpc"))}).encode()
    with pytest.raises(cluster.ClusterError):
        target.handle_rpc(forged, "127.0.0.1")
    valid = json.dumps({"from": master.node_id,
                       "box": cluster._b64(cluster.seal(new_key, inner, "rpc"))}).encode()
    assert target.handle_rpc(valid, "127.0.0.1")


def test_key_rotation_keeps_remaining_members_connected(tmp_path):
    master, removed = _paar(tmp_path, 1001)
    remaining = cluster.Cluster(tmp_path / "remaining", port=1003)
    network = Netz()
    members = [*master.members(), {"node": remaining.node_id, "name": "remaining",
                                  "address": "127.0.0.1", "port": remaining.port}]
    master.info["members"] = members
    old_key = master.key
    link = b"l" * 32
    for server in (master, removed, remaining):
        server.state.update(enabled=True, cluster=json.loads(json.dumps(master.info)))
        network.knoten[server.port] = server
        server._transport = network
    master.state["links"] = {remaining.node_id: cluster._b64(link)}
    remaining.state["link"] = cluster._b64(link)
    master.remove(removed.node_id, notify=False)
    assert master.key == remaining.key != old_key
    assert "load" in master.call(remaining.node_id, "ping")
    assert "load" in remaining.call(master.node_id, "ping")


def connected_pair(tmp_path):
    master, member = _paar(tmp_path, 1001)
    network = Netz()
    for server in (master, member):
        network.knoten[server.port] = server
        server._transport = network
        server.last_ok = {node.node_id: time.time() for node in (master, member)}
    return master, member


def test_failed_profile_move_resumes_previous_home(tmp_path, monkeypatch):
    master, member = connected_pair(tmp_path)
    user = "user1"
    resumed = []
    member.hooks.adopt = resumed.append
    master._set_home(user, member.node_id)
    resumed.clear()

    def broken_copy(*args, **kwargs):
        raise OSError("Platte voll")

    monkeypatch.setattr(master, "sync_user", broken_copy)
    assert master._move(user, member.node_id, master.node_id) == member.node_id
    assert member.is_home(user), "fehlgeschlagene Kopie darf den alten Heimserver nicht sperren"
    assert resumed == [user], "die vorher gestoppten Auftraege muessen wieder anlaufen"
    assert master.homes[user] == member.node_id


def test_profile_can_return_to_a_previously_released_server(tmp_path):
    master, member = connected_pair(tmp_path)
    user = "user1"
    folder = master.data_dir / "users" / user
    folder.mkdir(parents=True)
    (folder / "note.txt").write_text("aktuelle Daten")
    master._set_home(user, master.node_id)
    for source, target in ((master, member), (member, master), (master, member)):
        assert master._move(user, source.node_id, target.node_id) == target.node_id
        assert target.is_home(user)
        assert not source.is_home(user)
        assert (target.data_dir / "users" / user / "note.txt").read_text() == "aktuelle Daten"


@pytest.mark.parametrize("port", [-1, 0, 65536, True, 12.5, [], {}, "12.5", None])
def test_invalid_connect_port_is_rejected_without_network(tmp_path, monkeypatch, port):
    server = cluster.Cluster(tmp_path)
    server.state["enabled"] = True
    calls = []
    monkeypatch.setattr(server, "invite", lambda *args: calls.append(args))
    monkeypatch.setattr(web, "CLUSTER", server)
    result, status = web.cluster_action(SimpleNamespace(ultra=True), {
        "action": "invite", "address": "127.0.0.1", "port": port})
    assert status == 400 and "Port" in result["error"]
    assert not calls


def test_forced_profile_copy_does_not_trust_old_sync_cache(tmp_path):
    master, member = connected_pair(tmp_path)
    source = master.data_dir / "users" / "user1"
    source.mkdir(parents=True)
    (source / "note.txt").write_text("authoritative")
    member.sync_user("user1", master.node_id, force=True)
    destination = member.data_dir / "users" / "user1" / "note.txt"
    destination.write_text("locally changed since last replication")
    member.sync_user("user1", master.node_id, force=True)
    assert destination.read_text() == "authoritative"


def test_changing_profile_cannot_be_committed_as_complete(tmp_path, monkeypatch):
    master, member = connected_pair(tmp_path)
    source = master.data_dir / "users" / "user1"
    source.mkdir(parents=True)
    (source / "note.txt").write_text("authoritative")
    master._set_home("user1", master.node_id)
    monkeypatch.setattr(member, "_fetch", lambda *args, **kwargs: None)
    assert master._move("user1", master.node_id, member.node_id) == master.node_id
    assert master.is_home("user1")
    assert not member.is_home("user1")
