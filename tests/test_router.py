"""Automatische Modellwahl und Bilder erstellen (9.5.10).

Die Wahl kommt ohne Modellaufruf aus -- also laesst sie sich ohne Attrappe
fuer ein Modell pruefen. Die Bildanbieter antworten aus einem MockTransport:
echte Schluessel gibt es in den Tests nicht.
"""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from aquaticy import images, router
from aquaticy.config import Settings

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


@pytest.fixture(autouse=True)
def _frisch() -> None:
    router.forget()


@pytest.mark.parametrize(
    ("frage", "erwartet"),
    [
        ("Erstelle mir ein Bild von einem Hund am Strand", "bild"),
        ("Kannst du mir ein Logo für meine Bäckerei entwerfen?", "bild"),
        ("male ein Bild von einem Sonnenuntergang", "bild"),
        ("Generate an image of a red bicycle", "bild"),
        ("Ein Poster für das Sommerfest gestalten", "bild"),
        ("Zeig mir ein Bild vom Eiffelturm", "recherche"),
        ("Such mir ein Foto vom Brandenburger Tor", "recherche"),
        ("mach mal eine Liste mit Ideen", "recherche"),
        ("Wie hoch ist die Zugspitze?", "recherche"),
        ("Schreib mir eine Python-Funktion, die Primzahlen findet", "code"),
        ("Traceback (most recent call last):\n  File \"x.py\"", "code"),
        ("```js\nconst a = 1\n```\nwas macht das?", "code"),
        ("Warum ist mein SQL so langsam? Kannst du es optimieren?", "code"),
        ("Hallo!", "schnell"),
        ("danke dir", "schnell"),
        ("Vielen Dank, das hilft!", "schnell"),
        ("Danke", "schnell"),
        ("Schreib einen Brief an meinen Vermieter wegen der Heizung", "schreiben"),
        ("Übersetze das bitte ins Englische: Guten Morgen", "schreiben"),
        ("", "recherche"),
    ],
)
def test_messages_land_in_the_right_drawer(frage: str, erwartet: str) -> None:
    assert router.kategorie(frage) == erwartet


def test_code_mode_is_always_code() -> None:
    assert router.kategorie("Hallo", mode="code") == "code"


def test_classifying_is_fast() -> None:
    lang = "Bitte erkläre mir ausführlich " * 400
    start = time.perf_counter()
    for _ in range(200):
        router.kategorie(lang)
    assert (time.perf_counter() - start) / 200 < 0.01, "unter zehn Millisekunden je Nachricht"


def _settings(tmp_path: Path, **mehr: Any) -> Settings:
    mehr.setdefault("model", "mistral/mistral-large-latest")
    return Settings(data_dir=tmp_path / "d", **mehr)


def test_the_choice_per_drawer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from aquaticy import system

    monkeypatch.setattr(system, "strongest_model", lambda s, purpose="work": {
        "code": "mistral/codestral-latest", "work": "mistral/mistral-large-latest"}[purpose])
    settings = _settings(tmp_path)
    settings.api_keys["MISTRAL_API_KEY"] = "k"
    assert router.choose(settings, "Schreib ein Bash-Skript, das Logs packt").model == (
        "mistral/codestral-latest")
    assert router.choose(settings, "Hallo").model == "mistral/mistral-small-latest"
    wahl = router.choose(settings, "Erstelle ein Bild von einem Leuchtturm")
    assert wahl.kategorie == "bild" and wahl.model == "mistral/mistral-large-latest"
    assert wahl.bild_modell == images.BACKENDS["mistral"].model
    assert router.choose(settings, "Wie wird das Wetter?").model == "mistral/mistral-large-latest"


def test_no_image_backend_is_said_honestly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aquaticy import system

    monkeypatch.delenv("MISTRAL_API_KEY", raising=False)
    monkeypatch.delenv("NVIDIA_NIM_API_KEY", raising=False)
    monkeypatch.setattr(system, "strongest_model", lambda s, purpose="work": "")
    wahl = router.choose(_settings(tmp_path), "Male ein Bild von einer Katze")
    assert wahl.bild_modell == "" and "kein Bildmodell" in wahl.grund
    assert wahl.model == "mistral/mistral-large-latest", "ohne Liste bleibt das eingestellte"


def test_the_list_of_models_is_remembered(tmp_path: Path,
                                          monkeypatch: pytest.MonkeyPatch) -> None:
    from aquaticy import system

    aufrufe: list[str] = []
    monkeypatch.setattr(system, "strongest_model",
                        lambda s, purpose="work": aufrufe.append(purpose) or "m/x")
    settings = _settings(tmp_path)
    for _ in range(5):
        router.choose(settings, "Wie hoch ist der Mount Everest?")
    assert aufrufe == ["work"], "einmal nachgesehen, dann gemerkt"


# -- Bildanbieter --------------------------------------------------------------------
def test_backends_follow_the_keys_and_the_own_provider(tmp_path: Path,
                                                       monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MISTRAL_API_KEY", raising=False)
    monkeypatch.delenv("NVIDIA_NIM_API_KEY", raising=False)
    settings = _settings(tmp_path)
    assert images.available(settings) == []
    settings.api_keys.update({"MISTRAL_API_KEY": "m", "NVIDIA_NIM_API_KEY": "n"})
    assert [b.provider for b in images.available(settings)] == ["mistral", "nvidia_nim"]
    settings.model = "nvidia_nim/meta/llama-3.3-70b-instruct"
    assert images.available(settings)[0].provider == "nvidia_nim", "erst der eigene Anbieter"


def test_nvidia_flux_request_and_answer(tmp_path: Path) -> None:
    gefragt: list[httpx.Request] = []

    def handler(anfrage: httpx.Request) -> httpx.Response:
        gefragt.append(anfrage)
        return httpx.Response(200, json={"artifacts": [
            {"base64": base64.b64encode(PNG).decode(), "finishReason": "SUCCESS"}]})

    settings = _settings(tmp_path, model="nvidia_nim/meta/llama-3.3-70b-instruct")
    settings.api_keys["NVIDIA_NIM_API_KEY"] = "nv-key"
    bild = images.generate(settings, "a lighthouse at dawn", "quer",
                           client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert bild["bytes"] == PNG and bild["mime"] == "image/png"
    anfrage = gefragt[0]
    assert str(anfrage.url) == images.NVIDIA_FLUX_URL
    assert anfrage.headers["authorization"] == "Bearer nv-key"
    body = json.loads(anfrage.content)
    assert (body["width"], body["height"]) == (1344, 768)
    assert body["prompt"] == "a lighthouse at dawn"


def test_nvidia_content_filter_is_an_error(tmp_path: Path) -> None:
    settings = _settings(tmp_path, model="nvidia_nim/x")
    settings.api_keys["NVIDIA_NIM_API_KEY"] = "k"
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={
        "artifacts": [{"base64": "", "finishReason": "CONTENT_FILTERED"}]})))
    with pytest.raises(images.ImageError, match="Inhaltsregeln"):
        images.generate(settings, "x", client=client)


def test_mistral_conversation_then_file(tmp_path: Path) -> None:
    gefragt: list[httpx.Request] = []

    def handler(anfrage: httpx.Request) -> httpx.Response:
        gefragt.append(anfrage)
        if anfrage.url.path == "/v1/conversations":
            return httpx.Response(200, json={"outputs": [
                {"type": "tool.execution", "name": "image_generation"},
                {"type": "message.output", "content": [
                    {"type": "text", "text": "Hier ist dein Bild"},
                    {"type": "tool_file", "tool": "image_generation", "file_id": "f-123",
                     "file_type": "png"}]}]})
        if anfrage.url.path == "/v1/files/f-123/content":
            return httpx.Response(200, content=PNG)
        return httpx.Response(404)

    settings = _settings(tmp_path)
    settings.api_keys["MISTRAL_API_KEY"] = "mi-key"
    bild = images.generate(settings, "ein Leuchtturm", "hoch",
                           client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert bild["bytes"] == PNG and bild["modell"] == "Mistral Bildgenerierung"
    body = json.loads(gefragt[0].content)
    assert body["tools"] == [{"type": "image_generation"}] and "Hochformat" in body["inputs"]
    assert all(a.headers["authorization"] == "Bearer mi-key" for a in gefragt)


@pytest.mark.parametrize(
    ("antwort", "fehler"),
    [
        (httpx.Response(401), "Schluessel"),
        (httpx.Response(429), "zu viele"),
        (httpx.Response(200, json={"outputs": []}), "kein Bild"),
        (httpx.Response(200, json={"outputs": [{"content": [
            {"type": "tool_file", "file_id": "../../etc"}]}]}), "kein Bild"),
        (httpx.Response(200, json={"outputs": [{"content": [
            {"type": "tool_file", "file_id": "a\r\nHost: x"}]}]}), "kein Bild"),
        (httpx.Response(200, text="kein json"), "unerwartet"),
    ],
)
def test_mistral_failures_are_readable(tmp_path: Path, antwort: httpx.Response,
                                       fehler: str) -> None:
    settings = _settings(tmp_path)
    settings.api_keys["MISTRAL_API_KEY"] = "k"
    client = httpx.Client(transport=httpx.MockTransport(lambda r: antwort))
    with pytest.raises(images.ImageError, match=fehler):
        images.generate(settings, "x", client=client)


def test_images_are_checked_to_be_images(tmp_path: Path) -> None:
    settings = _settings(tmp_path, model="nvidia_nim/x")
    settings.api_keys["NVIDIA_NIM_API_KEY"] = "k"
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={
        "artifacts": [{"base64": base64.b64encode(b"<html>").decode()}]})))
    with pytest.raises(images.ImageError, match="unerwartet"):
        images.generate(settings, "x", client=client)


def test_without_a_key_there_is_an_honest_no(tmp_path: Path,
                                             monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MISTRAL_API_KEY", raising=False)
    monkeypatch.delenv("NVIDIA_NIM_API_KEY", raising=False)
    with pytest.raises(images.ImageError, match="Schluessel fuer NVIDIA oder Mistral"):
        images.generate(_settings(tmp_path), "x")
    with pytest.raises(images.ImageError, match="Beschreibung"):
        images.generate(_settings(tmp_path), "   ")


# -- Im Agenten ----------------------------------------------------------------------
def _antwort(text: str = "", tool_calls: Any = None) -> SimpleNamespace:
    return SimpleNamespace(choices=[SimpleNamespace(
        message=SimpleNamespace(content=text, tool_calls=tool_calls))])


def test_the_master_changes_the_agents_do_not(settings: Settings,
                                              monkeypatch: pytest.MonkeyPatch) -> None:
    from aquaticy import system
    from aquaticy.agent import Agent

    monkeypatch.setattr(system, "strongest_model", lambda s, purpose="work": {
        "code": "mistral/codestral-latest", "work": "mistral/mistral-large-latest"}[purpose])
    settings.auto_model = True
    modelle: list[str] = []
    monkeypatch.setattr("litellm.completion",
                        lambda **kw: modelle.append(kw["model"]) or _antwort("fertig"))
    ereignisse: list[tuple[str, dict]] = []
    agent = Agent(settings, cache=None, on_event=lambda e, p: ereignisse.append((e, p)))
    fast_vorher = system.fast_model(settings)
    agent.ask("Schreib mir eine Python-Funktion für Fibonacci", stream=False)
    assert modelle == ["mistral/codestral-latest"]
    wahl = next(p for e, p in ereignisse if e == "model_auto")
    assert wahl["kategorie"] == "code" and wahl["grund"] == "Programmieren"
    assert settings.model == "mistral/mistral-large-latest", "die Einstellung bleibt"
    assert system.fast_model(settings) == fast_vorher, "die Agenten bleiben dieselben"
    assert agent.active_model == "mistral/mistral-large-latest", "nur fuer diesen Turn"
    agent.ask("Hallo", stream=False)
    assert modelle[-1] in ("mistral/mistral-small-latest",) or modelle == [
        "mistral/codestral-latest"], "Hallo bekommt das schnelle -- oder die Standardantwort"


def test_switched_off_changes_nothing(settings: Settings,
                                      monkeypatch: pytest.MonkeyPatch) -> None:
    from aquaticy.agent import Agent

    modelle: list[str] = []
    monkeypatch.setattr("litellm.completion",
                        lambda **kw: modelle.append(kw["model"]) or _antwort("fertig"))
    ereignisse: list[str] = []
    agent = Agent(settings, cache=None, on_event=lambda e, p: ereignisse.append(e))
    agent.ask("Schreib mir eine Python-Funktion für Fibonacci", stream=False)
    assert modelle == ["mistral/mistral-large-latest"] and "model_auto" not in ereignisse


def test_the_image_tool_saves_a_labelled_ai_image(settings: Settings,
                                                  monkeypatch: pytest.MonkeyPatch) -> None:
    from aquaticy import system
    from aquaticy.agent import Agent
    from aquaticy.media import snapshot_path

    monkeypatch.setattr(system, "strongest_model", lambda s, purpose="work": "")
    settings.auto_model = True
    settings.api_keys["MISTRAL_API_KEY"] = "k"
    gebeten: list[tuple[str, str, str]] = []
    monkeypatch.setattr(images, "generate", lambda s, prompt, fmt, model="": gebeten.append(
        (prompt, fmt, model)) or {"bytes": PNG, "mime": "image/png", "modell": "Test-Maler"})
    aufruf = SimpleNamespace(id="c1", type="function", function=SimpleNamespace(
        name="create_image", arguments=json.dumps({"prompt": "a lighthouse", "format": "quer"})))
    antworten = [_antwort(tool_calls=[aufruf]), _antwort("Hier ist dein KI-Bild.")]
    angebot: list[list[str]] = []

    def llm(**kw: Any) -> Any:
        angebot.append([t["function"]["name"] for t in kw.get("tools") or []])
        return antworten.pop(0)

    monkeypatch.setattr("litellm.completion", llm)
    agent = Agent(settings, cache=None)
    ergebnis = agent.ask("Erstelle mir ein Bild von einem Leuchtturm", stream=False)
    assert "create_image" in angebot[0]
    assert gebeten == [("a lighthouse", "quer", images.BACKENDS["mistral"].model)]
    bild = ergebnis.visuals[0]
    assert bild["kind"] == "erstellt" and "KI-Bild" in bild["title"]
    assert bild["caption"] == "a lighthouse"
    datei = snapshot_path(settings.data_dir, bild["media_id"])
    assert datei is not None and datei.read_bytes() == PNG
    assert "-fest" in bild["media_id"], "erstellte Bilder werden nicht weggeraeumt"


def test_no_image_tool_without_a_provider(settings: Settings,
                                          monkeypatch: pytest.MonkeyPatch) -> None:
    from aquaticy.agent import Agent

    monkeypatch.delenv("MISTRAL_API_KEY", raising=False)
    monkeypatch.delenv("NVIDIA_NIM_API_KEY", raising=False)
    agent = Agent(settings, cache=None)
    assert "create_image" not in [t["function"]["name"] for t in agent.tools]


def test_image_prompts_go_through_the_legal_check() -> None:
    from aquaticy.guardrails import SENSITIVE_TOOLS

    assert "create_image" in SENSITIVE_TOOLS


def test_the_switch_is_for_every_account(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from aquaticy import web

    profil = tmp_path / "normal"
    profil.mkdir()
    sitzung = web.ChatSession(account=SimpleNamespace(plan="normal", username="n"),
                              profile=profil)
    monkeypatch.setattr(web, "SESSION", sitzung)
    web.save_values({"AQUATICY_AUTO_MODEL": "true"})
    assert sitzung.settings().auto_model is True
    assert web.current_values()["AQUATICY_AUTO_MODEL"] == "true"
    html = web.UI_FILE.read_text(encoding="utf-8")
    teil = html[html.index('id="dev-settings"'):html.index("</fieldset>",
                                                           html.index('id="dev-settings"'))]
    assert 'name="AQUATICY_AUTO_MODEL"' in teil, "unter Dev settings"
