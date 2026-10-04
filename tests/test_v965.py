"""Normalmodus-Tempo und voneinander unabhaengige Chats ueber HTTP/Chromium."""

from __future__ import annotations

import secrets
import shutil
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer
from types import SimpleNamespace

import httpx
import pytest

from aquaticy import agent as agents
from aquaticy import web
from aquaticy.auth import AuthStore, pro_code_for, ultra_code_for
from aquaticy.cache import Cache
from aquaticy.config import Settings
from tests.test_web import FakeAgent


@pytest.fixture
def parallel_site(tmp_path, monkeypatch):
    settings = Settings(data_dir=tmp_path, model="mistral/mistral-large-latest",
                        subagents_auto=False)
    gates = {name: threading.Event() for name in ("Recherche A", "Recherche B")}
    started = {name: threading.Event() for name in gates}
    made = []

    class TestAgent(FakeAgent):
        def __init__(self, settings, cache=None):
            super().__init__()
            self.cache = cache
            self.session_id = secrets.token_hex(12)
            self.messages = []
            self.cancelled = False
            made.append(self)

        def clear(self):
            self.session_id = secrets.token_hex(12)
            self.messages = []

        def resume(self, session_id, turns):
            self.session_id = session_id
            self.messages = [{"role": "user", "content": turn[0]} for turn in turns]

        def ask(self, question, **kwargs):
            self.asked.append(question)
            self.messages.append({"role": "user", "content": question})
            if question in gates:
                self.on_event("answer_chunk", {"text": f"Zwischenstand {question}"})
                started[question].set()
                assert gates[question].wait(30)
            answer = f"Antwort auf {question}"
            self.on_event("answer_chunk", {"text": answer})
            self.cache.add_history(self.session_id, question, answer)
            self.on_event("done", {})

        def cancel(self):
            self.cancelled = True
            for question in self.asked:
                if question in gates:
                    gates[question].set()

    monkeypatch.setattr(agents, "Agent", TestAgent)
    monkeypatch.setattr(web, "get_settings", lambda: settings)
    monkeypatch.setattr(web, "SESSIONS", web.SessionRegistry())
    monkeypatch.setattr(web, "DEFAULT_SESSION", web.ChatSession())
    monkeypatch.setattr(web, "RUNS", web.RunBook())
    monkeypatch.setattr(web, "CLUSTER", None)
    monkeypatch.setattr(web, "AIGUARD", None)
    monkeypatch.setattr(web, "TOKEN", "")
    monkeypatch.setattr(web, "SESSION", web.SessionProxy())
    monkeypatch.setattr(web, "start_user_scheduler", lambda account: None)
    store = AuthStore(tmp_path, pro_code_for(tmp_path), ultra_code_for(tmp_path))
    monkeypatch.setattr(web, "AUTH", store)
    account = store.register("parallel@example.org", "parallel-test-passwort", "normal",
                             username="Parallel", terms_accepted=True, terms_version="1")
    server = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}"
    client = httpx.Client(base_url=url, trust_env=False, timeout=5,
                         headers={"User-Agent": "Parallel-Test", "Accept-Language": "de-DE"})
    try:
        client.post("/api/consent", json={"accepted": True})
        response = client.post("/api/auth/login", json={"email": account.email,
                                                      "password": "parallel-test-passwort"})
        assert response.status_code == 200
        yield client, gates, started, made, account, url
    finally:
        for gate in gates.values():
            gate.set()
        client.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_two_researches_run_independently_and_stop_only_selected_chat(parallel_site):
    client, gates, started, made, account, _ = parallel_site
    chat_a = client.get("/api/chats").json()["current"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(client.post, "/api/chat", json={"message": "Recherche A"},
                        headers={"X-Aquaticy-Chat": chat_a})
        try:
            assert started["Recherche A"].wait(5)
            chat_b = client.post("/api/clear").json()["current"]
            assert chat_b != chat_a
            b = pool.submit(client.post, "/api/chat", json={"message": "Recherche B"},
                            headers={"X-Aquaticy-Chat": chat_b})
            assert started["Recherche B"].wait(5), "B darf nicht auf A warten"
            listed = client.get("/api/chats").json()["chats"]
            assert {c["session_id"] for c in listed if c.get("running")} == {chat_a, chat_b}
            assert web._cluster_load()["runs"] == 2
            assert not web._cluster_release(account.id)
            for chat in (chat_a, chat_b):
                state = client.get("/api/runstate", headers={"X-Aquaticy-Chat": chat}).json()
                assert state["running"]
            denied = client.post("/api/chat-edit", json={"action": "delete", "session_id": chat_a})
            assert denied.json()["code"] == "busy"
            opened = client.post("/api/open", json={"session_id": chat_a}).json()
            assert opened["ok"] and opened["session_id"] == chat_a
            client.post("/api/stop", headers={"X-Aquaticy-Chat": chat_b})
            assert a.done() is False and gates["Recherche A"].is_set() is False
            assert b.result(timeout=5).status_code == 200
            assert next(s for s in made if s.session_id == chat_b).cancelled
            assert not next(s for s in made if s.session_id == chat_a).cancelled
        finally:
            gates["Recherche A"].set()
            gates["Recherche B"].set()
        assert a.result(timeout=5).status_code == 200
    settings = web.SESSIONS.get(account).settings()
    cache = Cache(settings.db_path, settings.cache_ttl_hours)
    assert [e.question for e in cache.chat_history(chat_a)] == ["Recherche A"]
    assert [e.question for e in cache.chat_history(chat_b)] == ["Recherche B"]
    deleted = client.post("/api/chat-edit", json={"action": "delete", "session_id": chat_b})
    assert deleted.json()["ok"]
    assert client.get("/api/runstate", headers={"X-Aquaticy-Chat": chat_b}).status_code == 400
    assert not cache.chat_history(chat_b)


def test_chat_header_cannot_select_another_accounts_history(parallel_site):
    client, _, _, _, _, _ = parallel_site
    response = client.get("/api/runstate", headers={"X-Aquaticy-Chat": "foreign-chat-id"})
    assert response.status_code == 400
    assert "running" not in response.json()


def test_forgetting_account_stops_all_background_chats(parallel_site):
    client, gates, started, made, account, _ = parallel_site
    chat_a = client.get("/api/chats").json()["current"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(client.post, "/api/chat", json={"message": "Recherche A"},
                        headers={"X-Aquaticy-Chat": chat_a})
        try:
            assert started["Recherche A"].wait(5)
            chat_b = client.post("/api/clear").json()["current"]
            b = pool.submit(client.post, "/api/chat", json={"message": "Recherche B"},
                            headers={"X-Aquaticy-Chat": chat_b})
            assert started["Recherche B"].wait(5)
            web.forget_account_runtime(account)
            assert a.result(timeout=5).status_code == b.result(timeout=5).status_code == 200
            assert all(s.cancelled and s.closed for s in made if s.asked)
            assert account.id not in web.SESSIONS._sessions
        finally:
            for gate in gates.values():
                gate.set()


@pytest.mark.parametrize("finish_background", [False, True])
def test_browser_can_write_in_b_and_return_to_running_a(parallel_site, finish_background):
    playwright = pytest.importorskip("playwright.sync_api")
    chromium = shutil.which("chromium")
    if not chromium:
        pytest.skip("System-Chromium fehlt")
    client, gates, started, _, _, url = parallel_site
    with playwright.sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=chromium)
        context = browser.new_context(user_agent="Parallel-Test",
                                      extra_http_headers={"Accept-Language": "de-DE"})
        context.add_cookies([{"name": k, "value": v, "url": url}
                            for k, v in client.cookies.items()])
        page = context.new_page()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        try:
            page.goto(url, wait_until="networkidle")
            page.locator("#auth-gate").wait_for(state="hidden")
            page.fill("#input", "Recherche A")
            page.click("#send")
            playwright.expect(page.locator("#thread")).to_contain_text("Zwischenstand Recherche A")
            page.click("#btn-new")
            playwright.expect(page.locator("#send")).to_be_enabled()
            assert not gates["Recherche A"].is_set()
            question_b = "Recherche B" if finish_background else "Hallo B"
            page.fill("#input", question_b)
            page.click("#send")
            if finish_background:
                playwright.expect(page.locator("#thread")).to_contain_text(
                    "Zwischenstand Recherche B")
                gates["Recherche A"].set()
                page.wait_for_timeout(300)
                playwright.expect(page.locator("#send")).to_be_disabled()
                assert "Recherche A" not in page.locator("#thread").inner_text()
                gates["Recherche B"].set()
            playwright.expect(page.locator("#thread")).to_contain_text(f"Antwort auf {question_b}")
            assert "Recherche A" not in page.locator("#thread").inner_text()
            page.fill("#input", "Entwurf B")
            page.get_by_role("button", name="Chat öffnen: Recherche A", exact=True).click()
            playwright.expect(page.locator("#thread")).to_contain_text("Zwischenstand Recherche A")
            gates["Recherche A"].set()
            playwright.expect(page.locator("#thread")).to_contain_text("Antwort auf Recherche A")
            page.get_by_role("button", name=f"Chat öffnen: {question_b}", exact=True).click()
            playwright.expect(page.locator("#input")).to_have_value("Entwurf B")
            playwright.expect(page.locator("#thread")).to_contain_text(f"Antwort auf {question_b}")
            assert started["Recherche A"].is_set()
            assert not errors
        finally:
            gates["Recherche A"].set()
            browser.close()


@pytest.mark.parametrize("mode", ["normal", "pro", "code"])
def test_read_groups_keep_writes_ordered_and_pro_unchanged(mode):
    calls = [{"function": {"name": n}, "id": str(i)} for i, n in enumerate(
        ["fetch_page", "fetch_page", "remember", "fetch_page", "fetch_page"])]
    finished = []
    lock = threading.Lock()
    active = peak = 0

    def runner(call):
        nonlocal active, peak
        if call["function"]["name"] == "remember":
            assert set(finished) == {"0", "1"}
        else:
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.03)
            with lock:
                active -= 1
        with lock:
            finished.append(call["id"])
        return {"id": call["id"]}

    began = time.monotonic()
    agent = agents.Agent.__new__(agents.Agent)
    agent.mode = mode
    agent.messages = []
    agent.toolbox = SimpleNamespace(stats=SimpleNamespace(searches=[]))
    agent._tool_result = runner
    agent._run_round(calls)
    result = agent.messages
    elapsed = time.monotonic() - began
    assert result == [{"id": str(i)} for i in range(5)]
    assert peak == (2 if mode == "normal" else 1)
    if mode != "normal":
        assert finished == [str(i) for i in range(5)]
    print(f"{mode}: {elapsed:.3f}s")
