"""10.0.3 Luna: user, bug hunter, security and privacy regressions."""

from __future__ import annotations

import gzip
import json
import shutil
import time
import tracemalloc
import zlib
from contextlib import contextmanager
from copy import deepcopy

import httpx
import pytest

from aquaticy import agent as agent_module
from aquaticy import metering, web
from aquaticy import upgrading as up
from aquaticy.auth import ultra_code_for
from aquaticy.config import Settings
from aquaticy.injection import RULES
from aquaticy.legal import LEGAL_VERSION
from tests.test_agent import _message
from tests.test_upgrading import BASE, FAKTEN, Ollama
from tests.test_v965 import parallel_site as parallel_site
from tests.test_v967 import FACT, contribute
from tests.test_v967 import learners as learners


@pytest.fixture
def upgrade_page(parallel_site):
    playwright = pytest.importorskip("playwright.sync_api")
    chromium = shutil.which("chromium")
    if not chromium:
        pytest.skip("System-Chromium fehlt")
    client, _, _, _, _, url = parallel_site
    account = web.AUTH.register("upgrading@example.org", "luna-upgrade-test-passwort", "ultra",
                                pro_code=ultra_code_for(web.AUTH.data_dir),
                                terms_accepted=True, terms_version="1")
    assert client.post("/api/auth/login", json={
        "email": account.email, "password": "luna-upgrade-test-passwort",
    }).status_code == 200
    with playwright.sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=chromium)
        try:
            context = browser.new_context(viewport={"width": 390, "height": 800},
                                          user_agent="Parallel-Test",
                                          extra_http_headers={"Accept-Language": "de-DE"})
            context.add_cookies([{"name": k, "value": v, "url": url}
                                for k, v in client.cookies.items()])
            page = context.new_page()
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(url, wait_until="networkidle")
            page.locator("#auth-gate").wait_for(state="hidden")
            if page.evaluate("document.body.classList.contains('collapsed')"):
                page.click("#btn-side")
            yield page, playwright.expect
            assert not errors
        finally:
            browser.close()


def test_upgrade_ui_follows_async_start_and_stops_after_closing(upgrade_page):
    page, expect = upgrade_page
    state = {"enabled": False, "running": False, "tracks": [], "minor": 5}
    reads = []

    def upgrades(route):
        if route.request.method == "POST":
            state["enabled"] = route.request.post_data_json["on"]
            result = {"ok": True, "ultra": state}
        else:
            reads.append(True)
            result = {"available": True, "ultra": state}
        route.fulfill(content_type="application/json", body=json.dumps(result))

    page.route("**/api/upgrades", upgrades)
    page.click("#btn-settings")
    page.locator("#dev-settings").scroll_into_view_if_needed()
    expect(page.locator("#upgrade-on")).to_be_enabled()
    page.clock.install()
    page.locator("#upgrade-on").check()
    expect(page.locator("#upgrade-panel")).to_be_visible()
    # The worker starts after the POST response, not inside that response.
    state["running"] = True
    page.clock.run_for(11_000)
    expect(page.locator("#upgrade-status")).to_contain_text("Trainiert gerade")
    state.update(running=False, tracks=[{
        "base": "gemma3:4b", "current_label": "gemma3:4b", "versions": [],
        "candidate": {"label": "gemma3:4b 1.1", "gain_text": "+10 %", "can_upgrade": True},
    }])
    page.clock.run_for(5_000)
    expect(page.locator(".upgrade-go")).to_be_enabled()
    page.locator(".upgrade-go").focus()
    page.clock.run_for(11_000)
    assert page.locator(".upgrade-go").evaluate("e => e === document.activeElement")
    page.evaluate("closeSettings()")
    page.clock.run_for(500)
    count = len(reads)
    page.clock.run_for(30_000)
    assert len(reads) == count


def test_late_upgrade_read_cannot_undo_newer_action(upgrade_page):
    page, expect = upgrade_page
    page.click("#btn-settings")
    expect(page.locator("#overlay")).to_be_visible()
    page.evaluate("""() => {
        window.realUpgradeApi = api;
        window.finishOldRead = null;
        api = (path, options) => path !== '/api/upgrades' ? realUpgradeApi(path, options)
          : options?.method === 'POST'
            ? Promise.resolve({ok:true,
                json:async () => ({ok:true, ultra:{enabled:false, tracks:[]}})})
            : new Promise(resolve => { finishOldRead = resolve; });
        upgradeZeigen({enabled:true, tracks:[]});
        upgradeLaden();
    }""")
    page.evaluate("""upgradeAktion({action:'enable', on:false},
                                   document.querySelector('#upgrade-on'))""")
    expect(page.locator("#upgrade-on")).not_to_be_checked()
    page.evaluate("finishOldRead({ok:true, json:async () => ({ultra:{enabled:true, tracks:[]}})})")
    expect(page.locator("#upgrade-on")).not_to_be_checked()


def test_no_gain_benchmark_is_reused_but_new_facts_and_force_are_tested(tmp_path):
    up.set_enabled(tmp_path, True, [BASE])
    backend = Ollama(base_kennt=20)
    asked = []
    original = backend.ask

    def ask(model, prompt):
        asked.append(model)
        return original(model, prompt)

    backend.ask = ask
    assert up.train_all(tmp_path, FAKTEN[:10], backend) == 0
    assert len(asked) == 20
    assert up.train_all(tmp_path, FAKTEN[:10], backend) == 0
    assert len(asked) == 20
    assert up.train_all(tmp_path, FAKTEN[:11], backend) == 0
    assert len(asked) == 42
    assert up.train_all(tmp_path, FAKTEN[:11], backend, force=True) == 0
    assert len(asked) == 64
    assert list(backend.modelle) == [BASE]


@pytest.mark.parametrize("failure", ["exception", "disable", "cancel"])
def test_incomplete_benchmark_is_never_cached(tmp_path, failure):
    up.set_enabled(tmp_path, True, [BASE])
    backend = Ollama(base_kennt=20)
    original = backend.ask
    cancelled = False

    def ask(model, prompt):
        nonlocal cancelled
        if ":training-" in model:
            if failure == "exception":
                raise RuntimeError("interrupted")
            if failure == "disable":
                up.set_enabled(tmp_path, False, [])
            cancelled = True
        return original(model, prompt)

    backend.ask = ask
    assert up.train_all(tmp_path, FAKTEN, backend, cancelled=lambda: cancelled) == 0
    assert not up.load(tmp_path)["tracks"][BASE]["trained_hash"]
    backend.ask = original
    up.set_enabled(tmp_path, True, [])
    assert up.train_all(tmp_path, FAKTEN, backend) == 0
    assert up.load(tmp_path)["tracks"][BASE]["trained_hash"]


def test_rollback_rechecks_knowledge_against_the_selected_baseline(tmp_path):
    up.set_enabled(tmp_path, True, [BASE])
    backend = Ollama(base_kennt=18)
    assert up.train_all(tmp_path, FAKTEN, backend) == 1
    up.upgrade(tmp_path, BASE)
    up.rollback(tmp_path, BASE, "1")
    assert up.train_all(tmp_path, FAKTEN, backend) == 1
    assert up.load(tmp_path)["tracks"][BASE]["candidate"]["based_on"] == "1"


@contextmanager
def compressed_response(payload, encoding):
    response = httpx.Response(200, headers={"Content-Encoding": encoding},
                              stream=httpx.ByteStream(payload),
                              request=httpx.Request("POST", "http://localhost:11434/api/chat"))
    try:
        yield response
    finally:
        response.close()


def test_ollama_compression_bomb_is_bounded_before_decompression(monkeypatch):
    payload = gzip.compress(b"x" * (16 * 1024 * 1024))
    monkeypatch.setattr(httpx, "stream", lambda *a, **kw: compressed_response(payload, "gzip"))
    tracemalloc.start()
    try:
        with pytest.raises(RuntimeError):
            up.OllamaBackend().ask(BASE, "word")
        _, peak = tracemalloc.get_traced_memory()
        assert peak < 8 * 1024 * 1024
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("encoding", ["identity", "gzip", "deflate"])
def test_ollama_accepts_bounded_compressed_json(monkeypatch, encoding):
    payload = b'{"message":{"content":"Antwort"}}'
    if encoding == "gzip":
        payload = gzip.compress(payload)
    elif encoding == "deflate":
        payload = zlib.compress(payload)

    monkeypatch.setattr(httpx, "stream", lambda *a, **kw: compressed_response(payload, encoding))
    assert up.OllamaBackend().ask(BASE, "word") == "Antwort"


@pytest.mark.parametrize("encoding,payload", [("gzip", b"invalid"), ("br", b"invalid")])
def test_ollama_rejects_invalid_or_unnegotiated_compression(monkeypatch, encoding, payload):
    monkeypatch.setattr(httpx, "stream", lambda *a, **kw: compressed_response(payload, encoding))
    with pytest.raises(RuntimeError):
        up.OllamaBackend().ask(BASE, "word")


@pytest.mark.parametrize("action", ["wipe_data", "remove_account"])
def test_account_erasure_also_removes_upgrade_preferences_and_seen_notices(learners, action):
    auth, accounts, _ = learners
    directory = auth.data_dir
    up.set_enabled(directory, True, [BASE])
    assert up.train_all(directory, FAKTEN, Ollama(base_kennt=18)) == 1
    release = up.upgrade(directory, BASE)
    for account in accounts:
        up.choose(directory, f"ollama_chat/{BASE}", False, account.id)
        up.mark_seen(directory, account.id, release["id"])
    before = up.load(directory)
    assert len(before["pins"]) == len(before["seen"]) == 2
    getattr(auth, action)(accounts[0])
    after = up.load(directory)
    owner, other = (up._owner(account.id) for account in accounts)
    assert owner not in after["pins"] and owner not in after["seen"]
    assert after["pins"] == {other: before["pins"][other]}
    assert after["seen"] == {other: before["seen"][other]}
    assert after["tracks"] == before["tracks"]


def test_forged_seen_notice_cannot_create_account_metadata(tmp_path):
    up.set_enabled(tmp_path, True, [BASE])
    before = (tmp_path / up.STATE_NAME).read_bytes()
    with pytest.raises(up.UpgradeError):
        up.mark_seen(tmp_path, "account", "a" * 16)
    assert (tmp_path / up.STATE_NAME).read_bytes() == before


def test_erasure_does_not_create_an_unused_upgrading_state(learners):
    auth, accounts, _ = learners
    auth.wipe_data(accounts[0])
    auth.remove_account(accounts[1])
    assert not (auth.data_dir / up.STATE_NAME).exists()


@pytest.mark.parametrize("action", ["wipe_data", "remove_account"])
def test_failed_metadata_erasure_stops_before_destructive_database_changes(learners,
                                                                         monkeypatch, action):
    auth, accounts, _ = learners
    up.set_enabled(auth.data_dir, True, [BASE])
    with up._edit(auth.data_dir) as state:
        state["pins"][up._owner(accounts[0].id)] = f"ollama_chat/{BASE}"
    profile = auth.profile_dir(accounts[0].id)
    (profile / "keep.txt").write_text("still here")

    def unavailable(*args):
        raise OSError("cannot replace upgrading state")

    monkeypatch.setattr(up, "save", unavailable)
    with pytest.raises(OSError):
        getattr(auth, action)(accounts[0])
    assert auth.account(accounts[0].id) is not None
    assert (profile / "keep.txt").read_text() == "still here"


@pytest.fixture
def live_model(learners, monkeypatch):
    auth, accounts, stores = learners
    for store in stores:
        store.set_consent(True, LEGAL_VERSION)
        assert contribute(store) == 1
    up.set_enabled(auth.data_dir, True, [BASE])
    backend = Ollama()
    backend.ask = lambda model, prompt: (
        up.questions([FACT])[0][1] if model.startswith(up.PREFIX) else "unbekannt")
    assert up.train_all(auth.data_dir, stores[0].confirmed_facts(metadata=True), backend,
                        manifest=stores[0].upgrade_manifest) == 1
    with up._edit(auth.data_dir) as state:
        state["managed_knowledge"] = True
    up.upgrade(auth.data_dir, BASE)
    monkeypatch.setattr(web, "UPGRADE_DIR", auth.data_dir)
    operator = Settings(data_dir=auth.data_dir, model=f"ollama_chat/{BASE}",
                        subagents_auto=False)
    monkeypatch.setattr(web, "get_settings", lambda: operator)
    session = web.ChatSession(profile=auth.profile_dir(accounts[0].id), account=accounts[0])
    settings = session.settings()
    return auth, accounts, stores, settings


@pytest.mark.parametrize("path", ["agent", "final", "helper"])
def test_real_model_requests_keep_rules_and_live_knowledge_without_history_mutation(live_model,
                                                                                monkeypatch, path):
    import litellm

    _, _, _, settings = live_model
    sent = []

    def completion(**kwargs):
        sent.append(deepcopy(kwargs))
        return _message("Antwort")

    @contextmanager
    def immediate(*args):
        yield

    monkeypatch.setattr(litellm, "completion", completion)
    monkeypatch.setattr(agent_module, "paced", immediate)
    agent = agent_module.Agent(settings)
    agent.messages[0]["content"] += "\nKEEP-SAFETY-MARKER"
    agent.messages.append({"role": "user", "content": "Wie funktioniert Photosynthese?"})
    before = deepcopy(agent.messages)
    if path == "agent":
        agent._completion(agent.messages, stream=False)
    elif path == "final":
        agent._final_answer(stream=False)
    else:
        metering.completion(settings, model=settings.model, messages=agent.messages)
    assert len(sent) == 1
    system = sent[0]["messages"][0]["content"]
    assert system.startswith(before[0]["content"])
    assert FACT in system and RULES in system
    assert agent.messages[:len(before)] == before
    assert FACT not in json.dumps(agent.messages)
    # Repeated preparation starts with the original rules each time.
    next_messages = metering.prepare_messages(settings, settings.model, agent.messages)
    assert next_messages[0]["content"] == system


@pytest.mark.parametrize("change", ["withdraw", "expire", "wipe", "delete"])
def test_live_model_context_cannot_survive_source_withdrawal(live_model, change):
    auth, accounts, stores, settings = live_model
    derived = settings.model
    assert FACT in settings.model_context(derived)
    if change == "withdraw":
        stores[1].set_consent(False, LEGAL_VERSION)
    elif change == "expire":
        with stores[0].connect() as conn:
            conn.execute("UPDATE learning_facts SET expires=0")
    elif change == "wipe":
        auth.wipe_data(accounts[1])
    else:
        auth.remove_account(accounts[1])
    with pytest.raises(up.UpgradeError):
        metering.prepare_messages(settings, derived, [{"role": "system", "content": "Rules"}])


def test_context_is_limited_to_version_dependencies_and_decrypted_data_is_validated(live_model):
    auth, _, stores, settings = live_model
    facts = stores[0].confirmed_facts(metadata=True)
    assert len(facts) == 1
    assert stores[0].confirmed_facts(fact_ids=()) == []
    assert stores[0].confirmed_facts(fact_ids=("' OR 1=1 --",)) == []
    assert stores[0].confirmed_facts(fact_ids=(facts[0]["id"],)) == [
        {"text": facts[0]["text"], "source": facts[0]["source"]}]
    assert up.model_context(auth.data_dir, "mistral/foreign", True) == ""
    assert up.model_context(auth.data_dir, f"ollama_chat/{BASE}", True) == ""
    with stores[0].connect() as conn:
        conn.execute("UPDATE learning_facts SET text='tampered' WHERE id=?", (facts[0]["id"],))
    with pytest.raises(up.UpgradeError, match="gültiges"):
        settings.model_context(settings.model)


def test_multimodal_system_content_keeps_existing_blocks(live_model):
    _, _, _, settings = live_model
    messages = [{"role": "system", "content": [{"type": "text", "text": "KEEP-RULES"}]},
                {"role": "user", "content": "Photosynthese"}]
    before = deepcopy(messages)
    prepared = metering.prepare_messages(settings, settings.model, messages)
    assert messages == before
    assert prepared[0]["content"][0] == before[0]["content"][0]
    assert FACT in prepared[0]["content"][1]["text"]


def test_model_context_keeps_the_original_build_expiry_even_without_worker(live_model):
    auth, _, _, settings = live_model
    with up._edit(auth.data_dir) as state:
        state["managed_knowledge"] = False
        entry = state["tracks"][BASE]["versions"][-1]
        entry["dependencies"] = {key: time.time() - 1 for key in entry["dependencies"]}
    with pytest.raises(up.UpgradeError, match="gültiges"):
        settings.model_context(settings.model)
