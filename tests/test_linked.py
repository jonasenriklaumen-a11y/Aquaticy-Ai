"""Verknuepfte KI-Konten und AI Council (9.6.1)."""

from __future__ import annotations

import types
from pathlib import Path
from typing import Any

import httpx
import pytest

from aquaticy import linked


def _client(routen: dict[str, Any]) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        for teil, antwort in routen.items():
            if teil in str(request.url):
                return antwort(request) if callable(antwort) else antwort
        return httpx.Response(404)
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_anthropic_reads_models_tier_and_tokens() -> None:
    gesehen: list[httpx.Request] = []

    def nachricht(request: httpx.Request) -> httpx.Response:
        gesehen.append(request)
        return httpx.Response(200, json={}, headers={
            "anthropic-ratelimit-requests-limit": "1000",
            "anthropic-ratelimit-tokens-limit": "450000",
            "anthropic-ratelimit-tokens-remaining": "449990"})

    client = _client({
        "/v1/models": httpx.Response(200, json={"data": [
            {"id": "claude-sonnet-4-5", "display_name": "Claude Sonnet 4.5"},
            {"id": "claude-haiku-4-5", "display_name": "Claude Haiku 4.5"}]}),
        "/v1/messages": nachricht})
    info = linked.inspect("anthropic", "sk-ant-test-123456", client)
    assert [m["id"] for m in info["models"]] == ["anthropic/claude-sonnet-4-5",
                                                 "anthropic/claude-haiku-4-5"]
    assert info["tier"] == "Tier 2"
    assert info["tokens"]["remaining"] == 449990
    # Die Probe nimmt das kleinste Modell und genau einen Token.
    assert b'"max_tokens":1' in gesehen[0].content.replace(b" ", b"")
    assert b"haiku" in gesehen[0].content


def test_openai_filters_chat_models_and_reads_limits() -> None:
    client = _client({
        "/v1/models": httpx.Response(200, json={"data": [
            {"id": "gpt-4o"}, {"id": "gpt-4o-mini"}, {"id": "whisper-1"},
            {"id": "gpt-4o-realtime-preview"}, {"id": "text-embedding-3-large"}]}),
        "/v1/chat/completions": httpx.Response(200, json={}, headers={
            "x-ratelimit-limit-tokens": "2000000", "x-ratelimit-remaining-tokens": "1999000"})})
    info = linked.inspect("openai", "sk-test-1234567890", client)
    assert {m["id"] for m in info["models"]} == {"openai/gpt-4o", "openai/gpt-4o-mini"}
    assert info["tier"] == "Tier 2"
    assert info["tokens"]["limit"] == 2_000_000


def test_gemini_key_goes_in_header_not_url() -> None:
    gesehen: list[httpx.Request] = []

    def modelle(request: httpx.Request) -> httpx.Response:
        gesehen.append(request)
        return httpx.Response(200, json={"models": [
            {"name": "models/gemini-2.5-pro", "displayName": "Gemini 2.5 Pro",
             "supportedGenerationMethods": ["generateContent"]},
            {"name": "models/text-embedding-004", "supportedGenerationMethods": ["embedContent"]}]})

    info = linked.inspect("gemini", "AIzaTestKey123456", _client({"/models": modelle}))
    assert [m["id"] for m in info["models"]] == ["gemini/gemini-2.5-pro"]
    assert "AIzaTestKey" not in str(gesehen[0].url)
    assert gesehen[0].headers["x-goog-api-key"] == "AIzaTestKey123456"
    assert info["tokens"] is None and "AI Studio" in info["note"]


def test_rejected_key_is_reported() -> None:
    client = _client({"/v1/models": httpx.Response(401)})
    with pytest.raises(linked.LinkError, match="lehnt den Schlüssel ab"):
        linked.inspect("openai", "sk-falsch-123456", client)


def _settings(tmp_path: Path, keys: dict[str, str]) -> Any:
    return types.SimpleNamespace(
        data_dir=tmp_path, api_keys=dict(keys), own_key_names=frozenset(keys),
        account_email="a@example.org", model="mistral/mistral-large-latest",
        llm_kwargs_for=lambda model: {})


def test_picker_and_roles_only_for_own_linked_keys(tmp_path: Path) -> None:
    linked.save(tmp_path, "anthropic", {"models": [{"id": "anthropic/claude-opus-4-1",
                                                    "label": "Opus"}]})
    linked.save(tmp_path, "gemini", {"models": [{"id": "gemini/gemini-2.5-flash"},
                                                {"id": "gemini/gemini-2.5-pro"}]})
    linked.save(tmp_path, "openai", {"models": [{"id": "openai/gpt-4o"}]})
    # OpenAI ist ausgelesen, aber der Schluessel gehoert nicht dem Konto.
    s = _settings(tmp_path, {"ANTHROPIC_API_KEY": "k1", "GEMINI_API_KEY": "k2"})
    assert {m["id"] for m in linked.picker_models(s)} == {
        "anthropic/claude-opus-4-1", "gemini/gemini-2.5-flash", "gemini/gemini-2.5-pro"}
    arbeiter, pruefer = linked.council_roles(s)
    assert arbeiter == [("anthropic", "anthropic/claude-opus-4-1")]
    assert pruefer == ("gemini", "gemini/gemini-2.5-pro"), "Gemini prueft, das staerkste"


def test_council_iterates_until_the_judge_agrees(tmp_path: Path,
                                                 monkeypatch: pytest.MonkeyPatch) -> None:
    linked.save(tmp_path, "anthropic", {"models": [{"id": "anthropic/claude-sonnet-4-5"}]})
    linked.save(tmp_path, "openai", {"models": [{"id": "openai/gpt-4o"}]})
    linked.save(tmp_path, "gemini", {"models": [{"id": "gemini/gemini-2.5-pro"}]})
    s = _settings(tmp_path, {"ANTHROPIC_API_KEY": "a", "OPENAI_API_KEY": "b",
                             "GEMINI_API_KEY": "c"})
    urteile = iter(['{"ok": false, "feedback": "Zahl prüfen"}', '{"ok": true}'])
    aufrufe: list[tuple[str, str]] = []

    def ask(settings: Any, model: str, system: str, user: str, *, json_mode: bool = False):
        aufrufe.append((model, system[:20]))
        if system == linked.JUDGE_PROMPT:
            return next(urteile)
        if system == linked.FINAL_PROMPT:
            return "Endgültige Antwort"
        return f"Lösung von {model}"

    monkeypatch.setattr(linked, "_ask", ask)
    ereignisse: list[dict[str, Any]] = []
    antwort = linked.run_council(s, "Was ist 2+2?", emit=lambda art, **d: ereignisse.append(d))
    assert antwort == "Endgültige Antwort"
    urteile_gesehen = [e for e in ereignisse if e.get("phase") == "verdict"]
    assert [e["ok"] for e in urteile_gesehen] == [False, True], "zweite Runde nach Einwand"
    bearbeiter = {m for m, sys in aufrufe if sys.startswith(linked.WORKER_PROMPT[:20])}
    assert bearbeiter == {"anthropic/claude-sonnet-4-5", "openai/gpt-4o"}
    assert ("gemini/gemini-2.5-pro", linked.CHECK_PROMPT[:20]) in aufrufe
    assert aufrufe[-1][0] == s.model, "der Richter ist das Hauptmodell"


def test_web_link_stores_key_only_when_accepted(tmp_path: Path,
                                                monkeypatch: pytest.MonkeyPatch) -> None:
    from aquaticy import web

    gespeichert: dict[str, str] = {}

    class Tresor:
        def set(self, name: str, wert: str) -> None:
            gespeichert[name] = wert

        def remove(self, name: str) -> bool:
            return gespeichert.pop(name, None) is not None

    sitzung = types.SimpleNamespace(
        account=types.SimpleNamespace(id="u1"), profile=tmp_path,
        settings=lambda: _settings(tmp_path, gespeichert), reload=lambda: None)
    monkeypatch.setattr(web, "SESSION", sitzung)
    monkeypatch.setattr(web, "account_vault", lambda profile, account: Tresor())
    monkeypatch.setattr(web, "forget_strong_models", lambda *a: None)

    def abgelehnt(provider: str, key: str) -> dict[str, Any]:
        raise linked.LinkError("Claude lehnt den Schlüssel ab — bitte prüfen.")

    monkeypatch.setattr(linked, "inspect", abgelehnt)
    antwort, status = web.linked_action({"action": "link", "provider": "anthropic",
                                         "key": "sk-ant-falsch-123"})
    assert status == 400 and not gespeichert
    monkeypatch.setattr(linked, "inspect", lambda provider, key: {
        "models": [{"id": "anthropic/claude-sonnet-4-5", "label": "Sonnet"}],
        "tier": "Tier 1", "tokens": {"limit": 10, "remaining": 9, "per": "Minute"}})
    antwort, status = web.linked_action({"action": "link", "provider": "anthropic",
                                         "key": "sk-ant-richtig-123"})
    assert status == 200 and gespeichert == {"ANTHROPIC_API_KEY": "sk-ant-richtig-123"}
    karte = next(k for k in antwort["accounts"] if k["provider"] == "anthropic")
    assert karte["linked"] and karte["tier"] == "Tier 1" and karte["models"] == ["Sonnet"]
    assert "richtig-123" not in str(antwort), "der Schluessel geht nie zurueck an den Browser"


def test_linked_model_goes_direct_but_lm_studio_stays(tmp_path: Path) -> None:
    from aquaticy.config import Settings

    linked.save(tmp_path, "openai", {"models": [{"id": "openai/gpt-4o"}]})
    s = Settings(model="openai/lokal", api_base="http://lmstudio.local:1234/v1",
                 api_base_for="openai/lokal", data_dir=tmp_path,
                 api_keys={"OPENAI_API_KEY": "sk-eigen-1234567890"},
                 own_key_names=frozenset({"OPENAI_API_KEY"}), account_email="a@example.org")
    # Das verknuepfte Modell: eigener Schluessel, direkt zu OpenAI.
    assert s.llm_kwargs_for("openai/gpt-4o") == {"api_key": "sk-eigen-1234567890"}
    # Das lokale Modell des Betreibers bleibt, wie es war.
    assert s.llm_kwargs_for("openai/lokal")["api_base"] == "http://lmstudio.local:1234/v1"
    # Ohne eigenen Schluessel ist nichts verknuepft.
    s2 = Settings(data_dir=tmp_path, account_email="a@example.org")
    assert not s2.is_linked("openai/gpt-4o")


def test_key_tells_its_provider() -> None:
    assert linked.detect_provider("sk-ant-api03-abc") == "anthropic"
    assert linked.detect_provider("sk-proj-abc123") == "openai"
    assert linked.detect_provider(" AIzaSyAbc ") == "gemini"
    assert linked.detect_provider("nvapi-123") == ""


def test_sign_in_offers_only_what_the_provider_has() -> None:
    assert "apple" in linked.SIGN_IN["openai"]
    assert "apple" not in linked.SIGN_IN["anthropic"]
    assert linked.SIGN_IN["gemini"] == ("google",)


def test_web_quick_link_detects_the_provider(tmp_path: Path,
                                             monkeypatch: pytest.MonkeyPatch) -> None:
    from aquaticy import web

    gespeichert: dict[str, str] = {}

    class Tresor:
        def set(self, name: str, wert: str) -> None:
            gespeichert[name] = wert

    sitzung = types.SimpleNamespace(
        account=types.SimpleNamespace(id="u2"), profile=tmp_path,
        settings=lambda: _settings(tmp_path, gespeichert), reload=lambda: None)
    monkeypatch.setattr(web, "SESSION", sitzung)
    monkeypatch.setattr(web, "account_vault", lambda profile, account: Tresor())
    monkeypatch.setattr(web, "forget_strong_models", lambda *a: None)
    monkeypatch.setattr(linked, "inspect", lambda provider, key: {"models": [], "tier": ""})
    antwort, status = web.linked_action({"action": "link", "key": "AIzaSyTest1234567"})
    assert status == 200 and antwort["provider"] == "gemini"
    assert gespeichert == {"GEMINI_API_KEY": "AIzaSyTest1234567"}
    karte = next(k for k in antwort["accounts"] if k["provider"] == "openai")
    assert [w["id"] for w in karte["sign_in"]] == ["google", "apple", "email"]
    antwort, status = web.linked_action({"action": "link", "key": "irgendwas-12345"})
    assert status == 400 and "erkenne" in antwort["error"]
