"""Zwei echte CLI-Prozesse, getrennte Daten, TCP/HTTP wie in einem LAN.

Keine Modellaufrufe. Zustimmung erfolgt ueber dieselbe lokale Antwortdatei
wie bei `aquaticy cluster`; Anmeldung und Bedienung ueber die Web-API.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from aquaticy.auth import AuthStore, pro_code_for, ultra_code_for
from aquaticy.cluster import _b64, _unb64, seal

PASSWORD = "connect-test-passwort-963"


def wait_for(check, seconds=40):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        try:
            result = check()
            if result:
                return result
        except (httpx.TransportError, OSError, ValueError):
            pass
        time.sleep(0.2)
    raise AssertionError("Connect-Test: Bedingung nicht rechtzeitig erfuellt")


class Server:
    def __init__(self, root: Path):
        self.root = root
        self.store = AuthStore(root, pro_code_for(root), ultra_code_for(root))
        self.admin = self.store.register(
            "admin@example.org", PASSWORD, "ultra", ultra_code_for(root),
            username="Admin", terms_accepted=True, terms_version="1",
        )
        self.user = self.store.register(
            "user@example.org", PASSWORD, "normal", username="User",
            terms_accepted=True, terms_version="1",
        )
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.log = (root.parent / f"{root.name}-server.log").open("w")
        self.process = None
        try:
            self.start()
        except Exception:
            self.stop()
            self.log.close()
            raise

    def start(self):
        self.process = subprocess.Popen(
            [sys.executable, "-c", "from aquaticy.cli import main; main()",
             "web", "--lan", "--no-open",
             "--port", str(self.port)],
            env={**os.environ, "AQUATICY_DATA_DIR": str(self.root),
                 "AQUATICY_MODEL": "ollama/unused-connect-test", "PYTHONUNBUFFERED": "1",
                 "LITELLM_LOCAL_MODEL_COST_MAP": "True"},
            stdin=subprocess.DEVNULL, stdout=self.log, stderr=subprocess.STDOUT,
        )
        with self.client() as client:
            wait_for(lambda: client.get("/api/auth/status").status_code == 200)

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)

    def client(self):
        return httpx.Client(base_url=self.url, trust_env=False, timeout=15,
                            headers={"User-Agent": "Aquaticy-Connect-Test",
                                     "Accept-Language": "de-DE"})

    def login(self, client, email="admin@example.org"):
        assert client.post("/api/consent", json={"accepted": True}).status_code == 200
        response = client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
        assert response.status_code == 200, response.text

    def answer(self, invite_id, answer):
        folder = self.root / "cluster" / "answers"
        folder.mkdir(exist_ok=True)
        (folder / f"{invite_id}.json").write_text(
            json.dumps({"id": invite_id, "answer": answer}), encoding="utf-8",
        )

    def state(self):
        return json.loads((self.root / "cluster" / "state.json").read_text())


def action(client, **payload):
    response = client.post("/api/cluster", json=payload)
    assert response.status_code == 200, response.text
    return response.json()


def test_two_servers_connect_security_and_outage(tmp_path):
    servers = []
    try:
        a = Server(tmp_path / "a")
        servers.append(a)
        b = Server(tmp_path / "b")
        servers.append(b)
        with a.client() as ca, b.client() as cb, b.client() as ordinary:
            assert ca.get("/api/cluster").status_code == 401
            a.login(ca)
            b.login(cb)
            b.login(ordinary, "user@example.org")
            assert ordinary.get("/api/cluster").status_code == 403
            response = ordinary.post("/api/cluster", json={"action": "enable", "on": True})
            assert response.status_code == 403
            for client in (ca, cb):
                action(client, action="enable", on=True)
            denied = action(ca, action="invite", address="127.0.0.1", port=b.port)["invites"][-1]
            b.answer(denied["id"], "no")
            wait_for(lambda: ca.get("/api/cluster").json()["invites"][0]["status"] == "denied")
            response = ca.post("/api/cluster", json={
                "action": "confirm", "id": denied["id"], "code": "000000"})
            assert response.status_code == 400
            invite = action(ca, action="invite", address="127.0.0.1", port=b.port)["invites"][-1]
            b.answer(invite["id"], "yes")
            wait_for(lambda: ca.get("/api/cluster").json()["invites"][-1]["status"] == "accepted")
            pending = json.loads((b.root / "cluster" / "pending.json").read_text())
            code = next(p["code"] for p in pending if p["id"] == invite["id"])
            wrong = "000000" if code.replace(" ", "") != "000000" else "111111"
            response = ca.post("/api/cluster", json={
                "action": "confirm", "id": invite["id"], "code": wrong})
            assert response.status_code == 400
            action(ca, action="confirm", id=invite["id"], code=code)
            wait_for(lambda: b.state()["cluster"] and not b.state()["cluster"].get("joining"))
            # Der beigetretene CLI-Prozess startet sich selbst neu.
            wait_for(lambda: cb.get("/api/auth/status").status_code == 200
                     and cb.get("/api/cluster").status_code == 401)
            b.login(cb)
            assert cb.get("/api/cluster").json()["joined"]
            assert len(ca.get("/api/cluster").json()["members"]) == 2
            assert list((b.root / "cluster").glob("backup-*/accounts.sqlite3"))
            assert b.store.account(a.admin.id) is not None
            assert b.store.account(b.admin.id) is None

            # Das zweite angemeldete Konto muss nach dem Beitritt neu angemeldet werden.
            assert ordinary.get("/api/prefs").status_code == 401
            b.login(ordinary, "user@example.org")
            assert cb.post("/api/prefs", json={"theme": "dark"}).status_code == 200
            assert ca.get("/api/prefs").json()["theme"] == "dark"
            assert ordinary.get("/api/prefs").json()["theme"] == "system"
            assert cb.post("/api/prefs", json={"theme": "light"},
                           headers={"Origin": "https://evil.example"}).status_code == 403
            assert ca.get("/api/prefs").json()["theme"] == "dark"

            # Unverschluesselte oder fremde RPC/Proxy-Nachrichten duerfen nichts bewirken.
            for path in ("/cluster/rpc", "/cluster/proxy"):
                assert cb.post(path, json={"from": "0" * 32, "box": "AAAA"}).status_code == 403
            node_a = json.loads((a.root / "cluster" / "node.json").read_text())["id"]
            key = _unb64(a.state()["cluster"]["secret"])
            inner = json.dumps({"op": "ping", "ts": time.time(),
                                "n": secrets.token_hex(12), "a": {}}).encode()
            envelope = {"from": node_a, "box": _b64(seal(key, inner, "rpc"))}
            assert cb.post("/cluster/rpc", json=envelope).status_code == 200
            assert cb.post("/cluster/rpc", json=envelope).status_code == 403
            damaged = bytearray(_unb64(envelope["box"]))
            damaged[-1] ^= 1
            assert cb.post("/cluster/rpc", json={
                "from": node_a, "box": _b64(bytes(damaged))}).status_code == 403
            response = cb.post("/api/prefs", content='[1]',
                               headers={"Content-Type": "application/json"})
            assert response.status_code == 200
            assert response.json()["theme"] == "dark"

            # Eine angemeldete Sitzung ist auf beiden Servern gueltig und wird widerrufen.
            with b.client() as shared:
                shared.cookies.update(ca.cookies)
                wait_for(lambda: shared.get("/api/prefs").status_code == 200)
                assert ca.post("/api/auth/logout", json={}).status_code == 200
                wait_for(lambda: shared.get("/api/prefs").status_code == 401)

            # Tatsaechlichen Heimserver beenden: kein Zugriff auf eine veraltete Kopie.
            homes = a.state()["homes"]
            home = homes[a.admin.id]
            owner, entrance = (a, b) if home == node_a else (b, a)
            with entrance.client() as client:
                entrance.login(client)
                owner.stop()
                response = client.post("/api/prefs", json={"theme": "light"})
                assert response.status_code == 503, response.text
                owner.start()
                wait_for(lambda: client.get("/api/prefs").status_code == 200)
                assert client.get("/api/prefs").json()["theme"] == "dark"

            # Entfernen sperrt das Mitglied und wechselt den Verbundschluessel.
            a.login(ca)
            node_b = json.loads((b.root / "cluster" / "node.json").read_text())["id"]
            action(ca, action="remove", node=node_b)
            wait_for(lambda: b.state()["cluster"] is None)
            assert _unb64(a.state()["cluster"]["secret"]) != key
            assert ca.post("/cluster/rpc", json={
                "from": node_b, "box": _b64(seal(key, inner, "rpc"))}).status_code == 403
    finally:
        for server in reversed(servers):
            server.stop()
            server.log.close()


@pytest.mark.parametrize("scenario", [
    "polling", "temporary_failure", "invalid_port", "stale_status",
])
def test_connect_in_browser_preserves_code_during_polling(tmp_path, scenario):
    playwright = pytest.importorskip("playwright.sync_api")
    chromium = shutil.which("chromium")
    if not chromium:
        pytest.skip("System-Chromium fuer den Connect-Browsertest fehlt")
    servers = []
    try:
        a = Server(tmp_path / "a")
        servers.append(a)
        b = Server(tmp_path / "b")
        servers.append(b)
        with a.client() as ca, b.client() as cb, playwright.sync_playwright() as pw:
            a.login(ca)
            b.login(cb)
            action(cb, action="enable", on=True)
            browser = pw.chromium.launch(executable_path=chromium)
            context = browser.new_context(user_agent="Aquaticy-Connect-Test",
                                          extra_http_headers={"Accept-Language": "de-DE"})
            context.add_cookies([
                {"name": key, "value": value, "url": a.url} for key, value in ca.cookies.items()
            ])
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(a.url, wait_until="networkidle")
            page.locator("#auth-gate").wait_for(state="hidden")
            page.click("#btn-settings")
            page.locator("#dev-settings").scroll_into_view_if_needed()
            page.locator("#cluster-on").check()
            page.locator("#cluster-panel").wait_for(state="visible")
            if scenario == "stale_status":
                old_state = ca.get("/api/cluster").json()
                held = []

                def delay_first_status(route):
                    if route.request.method == "GET" and not held:
                        held.append(route)
                    else:
                        route.continue_()

                page.route("**/api/cluster", delay_first_status)
                for _ in range(60):
                    page.wait_for_timeout(100)
                    if held:
                        break
                assert held, "eine laufende Statusabfrage muss zurueckgehalten werden"
                page.locator("#cluster-on").uncheck()
                playwright.expect(page.locator("#cluster-panel")).to_be_hidden()
                held[0].fulfill(status=200, content_type="application/json",
                                body=json.dumps(old_state))
                page.wait_for_timeout(500)
                assert not page.locator("#cluster-on").is_checked()
                assert not page.locator("#cluster-panel").is_visible()
                assert not ca.get("/api/cluster").json()["enabled"]
                assert not errors
                browser.close()
                return
            page.fill("#cluster-ip", "127.0.0.1")
            if scenario == "invalid_port":
                page.fill("#cluster-port", f"{b.port}oops")
                page.click("#cluster-add")
                playwright.expect(page.locator("#cluster-status")).to_contain_text(
                    "Ungültiger Port", timeout=4000)
                pending_file = b.root / "cluster" / "pending.json"
                assert not pending_file.exists() or not json.loads(pending_file.read_text())
                browser.close()
                return
            page.fill("#cluster-port", str(b.port))
            page.click("#cluster-add")
            pending_file = b.root / "cluster" / "pending.json"
            pending = wait_for(lambda: json.loads(pending_file.read_text()))
            invite_id = pending[0]["id"]
            b.answer(invite_id, "yes")
            field = page.get_by_role("textbox", name="Code vom anderen Server")
            field.wait_for(timeout=15000)
            pending = json.loads(pending_file.read_text())
            code = next(p["code"] for p in pending if p["id"] == invite_id)
            field.fill(code)
            if scenario == "temporary_failure":
                page.route("**/api/cluster", lambda route: route.fulfill(
                    status=503, content_type="application/json",
                    body=json.dumps({"error": "Vorübergehend nicht erreichbar"}))
                    if route.request.method == "GET" else route.continue_())
            # Die Statusabfrage laeuft alle drei Sekunden, auch beim Tippen.
            page.wait_for_timeout(4200)
            assert field.is_visible()
            assert field.input_value() == code
            assert field.evaluate("element => element === document.activeElement")
            if scenario == "temporary_failure":
                assert page.locator("#cluster-on").is_checked()
                playwright.expect(page.locator("#cluster-status")).to_contain_text(
                    "Vorübergehend", timeout=10000)
                assert field.input_value() == code
                assert field.evaluate("element => element === document.activeElement")
                assert not page.locator("#errorbox").is_visible()
                page.unroute("**/api/cluster")
                playwright.expect(page.locator("#cluster-status")).not_to_contain_text(
                    "Vorübergehend", timeout=10000)
                assert field.input_value() == code
            page.get_by_role("button", name="Bestätigen", exact=True).click()
            wait_for(lambda: "Master" in page.locator("#cluster-status").inner_text())
            wait_for(lambda: b.state()["cluster"] and not b.state()["cluster"].get("joining"))
            assert not errors
            browser.close()
    finally:
        for server in reversed(servers):
            server.stop()
            server.log.close()
