"""OAuth isolation, callback diagnostics and delayed cluster runtime changes."""

from __future__ import annotations

import shutil
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer

import pytest
from typer.testing import CliRunner

from aquaticy import cli, cluster, web
from tests.test_v965 import parallel_site as parallel_site


@pytest.mark.parametrize("label", ["token", "refresh_token", "refresh-token", "id_token",
                                   "code", "X-Aquaticy-Token", "access_token"])
def test_error_filter_masks_oauth_and_access_credentials(label):
    for message in (f"{label}=unknown-secret-fixture", f'"{label}": "unknown-secret-fixture"'):
        result = web.scrub_error(message, [])
        assert "unknown-secret-fixture" not in result
        assert "••••" in result
    assert web.scrub_error("Das Passwort braucht mindestens 12 Zeichen.", []) == (
        "Das Passwort braucht mindestens 12 Zeichen.")


@pytest.mark.parametrize("plan", ["normal", "pro", "ultra"])
def test_own_google_application_never_inherits_operator_secret(settings, tmp_path, monkeypatch,
                                                              plan):
    operator = replace(settings, google_client_id="operator.apps.googleusercontent.com",
                       google_client_secret="operator-secret-fixture")
    monkeypatch.setattr(web, "get_settings", lambda: operator)
    profile = tmp_path / "profile"
    profile.mkdir()
    (profile / ".env").write_text("GOOGLE_CLIENT_ID=own.apps.googleusercontent.com\n")
    loaded = web._profile_settings(profile, plan)
    assert loaded.google_client_id == "own.apps.googleusercontent.com"
    assert loaded.google_client_secret == ""
    assert not web.google_state(loaded)["has_secret"]


def test_shared_google_application_remains_available(settings, tmp_path, monkeypatch):
    operator = replace(settings, google_client_id="operator.apps.googleusercontent.com",
                       google_client_secret="operator-secret-fixture")
    monkeypatch.setattr(web, "get_settings", lambda: operator)
    loaded = web._profile_settings(tmp_path / "profile", "ultra")
    assert loaded.google_client_id == operator.google_client_id
    assert loaded.google_client_secret == operator.google_client_secret


def test_own_google_secret_is_migrated_and_kept(settings, tmp_path, monkeypatch):
    operator = replace(settings, google_client_id="operator.apps.googleusercontent.com",
                       google_client_secret="operator-secret-fixture")
    monkeypatch.setattr(web, "get_settings", lambda: operator)
    profile = tmp_path / "profile"
    profile.mkdir()
    env = profile / ".env"
    env.write_text("GOOGLE_CLIENT_ID=own.apps.googleusercontent.com\n"
                   "GOOGLE_CLIENT_SECRET=own-secret-fixture\n")
    assert web._profile_settings(profile, "ultra").google_client_secret == "own-secret-fixture"
    assert "own-secret-fixture" not in env.read_text()
    assert web._profile_settings(profile, "ultra").google_client_secret == "own-secret-fixture"
    assert web.account_vault(profile).secret("GOOGLE_CLIENT_SECRET") == "own-secret-fixture"


@pytest.mark.parametrize("message,expected", [
    ("TimeoutError: access_token=callback-secret-fixture", web.GENERIC_ERROR),
    ("Anmeldung abgelehnt: token=callback-secret-fixture", "Anmeldung abgelehnt:"),
    ("Client-ID und Secret fehlen -- erst speichern.", "Client-ID und Secret fehlen"),
])
def test_google_error_page_filters_diagnostics_and_secrets(monkeypatch, message, expected):
    # Exercise the real HTTP callback response, including its security headers.
    monkeypatch.setattr(web, "AUTH", None)
    monkeypatch.setattr(web, "TOKEN", "")
    monkeypatch.setattr(web, "CLUSTER", None)
    monkeypatch.setattr(web.Handler, "_get", lambda handler: handler._google_page(False, message))
    server = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    conn = HTTPConnection("127.0.0.1", server.server_port, timeout=10)
    try:
        conn.request("GET", "/google")
        response = conn.getresponse()
        body = response.read().decode()
        assert response.status == 200 and expected in body
        assert "callback-secret-fixture" not in body and "TimeoutError" not in body
        assert response.getheader("Cache-Control") == "no-store"
        assert response.getheader("X-Content-Type-Options") == "nosniff"
        assert response.getheader("Content-Security-Policy")
    finally:
        conn.close()
        server.shutdown()
        server.server_close()
        worker.join(5)


def local_cluster(tmp_path, hooks):
    instance = cluster.Cluster(tmp_path, hooks=hooks)
    instance.state["cluster"] = {"id": "test-cluster", "version": 1, "secret": "fixture",
                                  "members": [{"node": instance.node_id}]}
    return instance


def test_stale_release_does_not_stop_a_local_account(tmp_path):
    calls = []
    instance = local_cluster(tmp_path,
                             cluster.Hooks(release=lambda user: calls.append(user) or True))
    instance.homes["account"] = instance.node_id
    instance._release_quietly("account")
    assert calls == []


def test_delayed_release_checks_assignment_again_before_retry(tmp_path):
    calls = []
    instance = local_cluster(tmp_path,
                             cluster.Hooks(release=lambda user: calls.append(user) or False))
    instance.homes["account"] = "other-node"

    class ReturnDuringWait:
        def is_set(self):
            return False

        def wait(self, timeout):
            instance.homes["account"] = instance.node_id
            return False

    instance._stop = ReturnDuringWait()
    instance._release_quietly("account")
    assert calls == ["account"]


def test_returning_membership_adopts_after_pending_release(tmp_path):
    entered, finish, adopted = threading.Event(), threading.Event(), threading.Event()
    order = []

    def release(user):
        order.append("release started")
        entered.set()
        assert finish.wait(10)
        order.append("release finished")
        return True

    def adopt(user):
        order.append("adopted")
        adopted.set()

    instance = local_cluster(tmp_path, cluster.Hooks(release=release, adopt=adopt))
    instance.homes["account"] = "other-node"
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(instance._release_quietly, "account")
        try:
            assert entered.wait(5)
            instance._take_members(dict(instance.info), {"account": instance.node_id})
        finally:
            finish.set()
        future.result(timeout=5)
        assert adopted.wait(5)
    assert order == ["release started", "release finished", "adopted"]


@pytest.mark.parametrize("stopped", [False, True])
def test_stale_adoption_does_not_restart_foreign_or_stopped_runtime(tmp_path, stopped):
    calls = []
    instance = local_cluster(tmp_path, cluster.Hooks(adopt=calls.append))
    instance.homes["account"] = instance.node_id if stopped else "other-node"
    if stopped:
        instance._stop.set()
    instance._adopt_quietly("account")
    assert calls == []


def test_ephemeral_server_prints_its_actual_address(settings, monkeypatch, capsys):
    for name in ("AUTH", "TOKEN", "AIGUARD", "SCHEDULER", "SERVER", "CLUSTER"):
        monkeypatch.setattr(web, name, getattr(web, name))
    monkeypatch.setattr(web, "USER_SCHEDULERS", {})
    monkeypatch.setattr(web, "get_settings", lambda: settings)
    monkeypatch.setattr(web, "_warm_up", lambda: None)
    monkeypatch.setattr("aquaticy.sandbox.sweep", lambda: None)

    class Scheduler:
        def __init__(self, *args):
            pass

        def start(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr("aquaticy.jobs.Scheduler", Scheduler)
    original = web.bind_server
    ports = []

    def bind(host, port):
        server = original(host, port)
        ports.append(server.server_port)
        server.serve_forever = lambda: None
        return server

    monkeypatch.setattr(web, "bind_server", bind)
    web.serve("127.0.0.1", 0, open_browser=False)
    output = capsys.readouterr().out
    assert ports[0] > 0 and f"http://127.0.0.1:{ports[0]}/" in output
    assert "http://127.0.0.1:0/" not in output


def test_cli_does_not_advertise_port_zero(monkeypatch):
    monkeypatch.setattr(web, "serve", lambda **kwargs: None)
    result = CliRunner().invoke(cli.app, ["web", "--port", "0", "--no-open"])
    assert result.exit_code == 0 and "Automatischer Port" in result.output
    assert "http://127.0.0.1:0/" not in result.output


@pytest.mark.parametrize("width,fontsize", [(320, "normal"), (390, "large"), (1280, "normal")])
def test_mobile_and_desktop_chat_and_settings_remain_usable(parallel_site, width, fontsize):
    playwright = pytest.importorskip("playwright.sync_api")
    executable = shutil.which("chromium")
    if not executable:
        pytest.skip("System-Chromium fehlt")
    client, _, _, _, _, url = parallel_site
    with playwright.sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=executable)
        try:
            context = browser.new_context(viewport={"width": width, "height": 800},
                                          user_agent="Parallel-Test",
                                          extra_http_headers={"Accept-Language": "de-DE"})
            context.add_cookies([{"name": name, "value": value, "url": url}
                                for name, value in client.cookies.items()])
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(url, wait_until="networkidle")
            page.locator("#auth-gate").wait_for(state="hidden")
            page.evaluate("size => document.documentElement.dataset.fontsize = size", fontsize)
            if width < 600:
                page.click("#btn-new-top")
            else:
                page.click("#btn-new")
            page.fill("#input", "Hallo Luna")
            page.click("#send")
            playwright.expect(page.locator("#thread")).to_contain_text("Antwort auf Hallo Luna")
            playwright.expect(page.locator("#send")).to_be_enabled()
            if page.evaluate("document.body.classList.contains('collapsed')"):
                page.click("#btn-side")
            page.click("#btn-settings")
            page.wait_for_function("""() => {
                const sheet = document.querySelector('#overlay .sheet');
                if (!sheet || !sheet.closest('.open')) return false;
                const rect = sheet.getBoundingClientRect();
                return rect.left >= -2 && rect.right <= innerWidth + 2;
            }""")
            playwright.expect(page.locator("#learning-enabled")).to_be_visible()
            assert not errors
        finally:
            browser.close()


def test_background_errors_keep_focus_and_foreground_errors_keep_dialog(parallel_site):
    playwright = pytest.importorskip("playwright.sync_api")
    executable = shutil.which("chromium")
    if not executable:
        pytest.skip("System-Chromium fehlt")
    client, _, _, _, _, url = parallel_site
    with playwright.sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=executable)
        try:
            context = browser.new_context(user_agent="Parallel-Test",
                                          extra_http_headers={"Accept-Language": "de-DE"})
            context.add_cookies([{"name": name, "value": value, "url": url}
                                for name, value in client.cookies.items()])
            page = context.new_page()
            errors, requests = [], []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(url, wait_until="networkidle")
            page.locator("#auth-gate").wait_for(state="hidden")

            def unavailable(route):
                requests.append(route.request.method)
                route.fulfill(status=503, content_type="application/json",
                              body='{"error":"Vorübergehend nicht erreichbar"}')

            page.route("**/test-unavailable", unavailable)
            page.fill("#input", "Entwurf bleibt erhalten")
            page.focus("#input")
            status = page.evaluate("""async () =>
                (await api('/test-unavailable', {quietErrors:true})).status""")
            assert status == 503 and requests == ["GET", "GET", "GET"]
            assert not page.locator("#errorbox").is_visible()
            assert page.locator("#input").evaluate("e => e === document.activeElement")
            assert page.locator("#input").input_value() == "Entwurf bleibt erhalten"
            requests.clear()
            status = page.evaluate("""async () =>
                (await api('/test-unavailable', {method:'POST'})).status""")
            assert status == 503 and requests == ["POST"]
            playwright.expect(page.locator("#errorbox")).to_be_visible()
            page.click("#error-ok")
            assert not errors
        finally:
            browser.close()
