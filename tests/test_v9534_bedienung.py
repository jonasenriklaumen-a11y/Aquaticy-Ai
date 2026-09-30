"""9.5.34 (intern): VM-Netz je Tarif, Modellmenue unten, Bilderstellung, Antwortpruefung."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from aquaticy import agent as agent_module  # noqa: F401
from aquaticy import web
from aquaticy.agent import Agent
from aquaticy.aiguard import ANSWER_REFUSAL, answer_problem
from aquaticy.config import Settings
from aquaticy.images import Backend


# -- Attrappen (wie in test_agent.py) ---------------------------------------------------
def _message(content: str = "", tool_calls: list[Any] | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content, tool_calls=tool_calls))]
    )


class ScriptedLLM:
    def __init__(self, *responses: Any) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def __call__(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if not self.responses:
            raise AssertionError("mehr LLM-Aufrufe als vorbereitete Antworten")
        return self.responses.pop(0)


def _agent(settings: Settings) -> tuple[Agent, list[tuple[str, dict[str, Any]]]]:
    ereignisse: list[tuple[str, dict[str, Any]]] = []
    agent = Agent(settings, cache=None, on_event=lambda n, p: ereignisse.append((n, p)))
    return agent, ereignisse


# -- VM-Netz: Normal/Pro nur Internet, Ultra Internet + lokales Netz ---------------------
def _laufzeit() -> Any:
    return SimpleNamespace(binary="docker", extra=[], label="test")


def _flags(**kwargs: Any) -> list[str]:
    from aquaticy.sandbox import Sandbox

    box = Sandbox(**kwargs)
    box.runtime = _laufzeit()
    box._name, box._volume = "kiste", "datentraeger"
    return box._run_flags()


def test_a_vm_without_network_has_none() -> None:
    flags = _flags()
    assert "--network" in flags and flags[flags.index("--network") + 1] == "none"
    assert "NET_ADMIN" not in flags


def test_internet_keeps_the_lock_and_needs_net_admin_for_it() -> None:
    flags = _flags(internet=True)
    assert "--network" not in flags and "NET_ADMIN" in flags


def test_lan_drops_the_lock_and_needs_no_net_admin() -> None:
    from aquaticy.sandbox import Sandbox

    box = Sandbox(internet=True, lan=True)
    assert box.lan and box.netz_offen
    flags = _flags(internet=True, lan=True)
    assert "--network" not in flags and "NET_ADMIN" not in flags


def test_lan_without_any_network_means_nothing() -> None:
    from aquaticy.sandbox import Sandbox

    assert Sandbox(lan=True).lan is False


@pytest.mark.parametrize(("lan", "gesperrt"), [(False, True), (True, False)])
def test_the_lock_is_set_up_unless_lan_is_on(monkeypatch: pytest.MonkeyPatch, lan: bool,
                                             gesperrt: bool) -> None:
    from aquaticy import sandbox

    box = sandbox.Sandbox(internet=True, lan=lan)
    box.runtime = _laufzeit()
    aufrufe: list[str] = []
    monkeypatch.setattr(box, "_lock_network", lambda: aufrufe.append("sperre"))
    monkeypatch.setattr(box, "_create_volume", lambda: None)
    monkeypatch.setattr(box, "_start_container", lambda: None)
    monkeypatch.setattr(box, "_check_nested_network", lambda: None)
    monkeypatch.setattr(box, "_touch_locked", lambda: None)
    box.ensure()
    assert bool(aufrufe) is gesperrt


def test_shared_builds_the_lan_vm_with_internet(tmp_path: Path) -> None:
    from aquaticy import sandbox

    einstellungen = Settings(data_dir=tmp_path / "d", env_path=tmp_path / ".env")
    einstellungen.vm_lan = True
    try:
        box = sandbox.shared(einstellungen)
        assert box.lan and box.internet and not box.user_mode
    finally:
        sandbox.forget_shared(einstellungen)


@pytest.mark.parametrize("plan", ["normal", "pro"])
def test_normal_and_pro_always_have_internet_never_lan(tmp_path: Path, plan: str) -> None:
    profil = tmp_path / "konto"
    profil.mkdir()
    (profil / ".env").write_text("AQUATICY_VM_INTERNET=false\nAQUATICY_VM_LAN=true\n")
    einstellungen = web._profile_settings(profil, plan)
    assert einstellungen.vm_internet is True and einstellungen.vm_lan is False


def test_ultra_chooses_lan_itself(tmp_path: Path) -> None:
    profil = tmp_path / "konto"
    profil.mkdir()
    (profil / ".env").write_text("AQUATICY_VM_LAN=true\n")
    assert web._profile_settings(profil, "ultra").vm_lan is True
    (profil / ".env").write_text("AQUATICY_VM_LAN=false\n")
    assert web._profile_settings(profil, "ultra").vm_lan is False


def test_the_model_cannot_switch_the_lan_on() -> None:
    from aquaticy import preferences

    assert "AQUATICY_VM_LAN" in preferences.PROTECTED


def test_the_model_is_told_about_lan() -> None:
    from aquaticy.tools import VM_NET_LAN, vm_schemas_for

    einstellungen = Settings()
    einstellungen.vm_lan = True
    text = next(s for s in vm_schemas_for(einstellungen)
                if s["function"]["name"] == "vm_run")["function"]["description"]
    assert VM_NET_LAN in text


# -- Antworten von Aquaticy pruefen -------------------------------------------------------
def test_an_insulting_answer_is_withdrawn(monkeypatch: pytest.MonkeyPatch,
                                          settings: Settings) -> None:
    monkeypatch.setattr("litellm.completion", ScriptedLLM(
        _message(content="Du bist ein Idiot und ein Versager, halt die Klappe.")))
    agent, ereignisse = _agent(settings)
    result = agent.ask("Wie geht das?", stream=False)
    assert result.answer == ANSWER_REFUSAL
    assert "kann ich nicht helfen" in result.answer
    assert any(n == "answer_reset" and p.get("reason") == "antwort_geprueft"
               for n, p in ereignisse)
    # Auch aus dem Verlauf -- sonst steht es im Kontext der naechsten Frage.
    assert agent.messages[-1]["content"] == ANSWER_REFUSAL


def test_a_normal_answer_passes(monkeypatch: pytest.MonkeyPatch, settings: Settings) -> None:
    monkeypatch.setattr("litellm.completion", ScriptedLLM(
        _message(content="Die Hauptstadt von Frankreich ist Paris.")))
    agent, ereignisse = _agent(settings)
    result = agent.ask("Hauptstadt von Frankreich?", stream=False)
    assert "Paris" in result.answer
    assert not any(n == "answer_reset" for n, _ in ereignisse)


def test_the_answer_check_can_be_switched_off_by_the_operator(
        monkeypatch: pytest.MonkeyPatch, settings: Settings) -> None:
    settings.answer_check = False
    monkeypatch.setattr("litellm.completion", ScriptedLLM(
        _message(content="Du bist ein Idiot und ein Versager, halt die Klappe.")))
    agent, _ = _agent(settings)
    assert agent.ask("Hallo zusammen", stream=False).answer != ANSWER_REFUSAL


def test_quoting_an_insult_in_an_explanation_is_fine() -> None:
    assert answer_problem('Ist "du Idiot" eine Beleidigung? Ja, nach § 185 StGB.') == ""
    assert answer_problem(
        "Der Pirat rief: du Idiot, das Schiff sinkt! Dann segelte er weiter.") == ""


def test_the_model_judges_risky_topics_only() -> None:
    aufrufe: list[str] = []

    def urteil(prompt: str, settings: Any) -> str:
        aufrufe.append(prompt)
        return json.dumps({"missbrauch": True, "art": "Schadsoftware"})

    # Kein Stichwort -> kein Modellaufruf.
    assert answer_problem("Heute scheint die Sonne und es ist warm draußen.", object(),
                          ask=urteil) == ""
    assert not aufrufe
    # Stichwort -> das Modell urteilt.
    assert answer_problem("Hier ein Keylogger: ```python\nimport pynput\n``` viel Spaß damit",
                          object(), ask=urteil) == "Schadsoftware"
    assert aufrufe


def test_a_failing_model_never_withdraws_an_answer() -> None:
    def kaputt(prompt: str, settings: Any) -> str:
        raise RuntimeError("Netz weg")

    assert answer_problem("Ein Text über Sprengstoff in der Geschichte des Bergbaus.",
                          object(), ask=kaputt) == ""


def test_the_judge_prompt_for_answers_allows_education() -> None:
    from aquaticy.aiguard import answer_prompt

    text = answer_prompt("Antworttext")
    assert "Bildung" in text and "Im Zweifel: kein Problem" in text


# -- Bilderstellung -------------------------------------------------------------------------
def test_image_mode_without_a_model_says_what_to_do(monkeypatch: pytest.MonkeyPatch,
                                                    settings: Settings) -> None:
    monkeypatch.setattr("aquaticy.images.available", lambda s: [])
    llm = ScriptedLLM()
    monkeypatch.setattr("litellm.completion", llm)
    agent, _ = _agent(settings)
    result = agent.ask("Male einen Leuchtturm", stream=False, image_mode=True)
    assert "Schlüssel" in result.answer and "Bilderstellung" in result.answer
    assert not llm.calls, "ohne Bildmodell kein einziger Modellaufruf"


def test_image_mode_picks_an_image_model_and_offers_the_tool(
        monkeypatch: pytest.MonkeyPatch, settings: Settings) -> None:
    flux = Backend("nvidia_nim", "nvidia_nim/black-forest-labs/flux.1-schnell",
                   "FLUX.1 schnell (NVIDIA)", "NVIDIA_NIM_API_KEY")
    monkeypatch.setattr("aquaticy.images.available", lambda s: [flux])
    llm = ScriptedLLM(_message(content="Ein Leuchtturm."))
    monkeypatch.setattr("litellm.completion", llm)
    agent, ereignisse = _agent(settings)
    # Web aus -- das Bild kommt vom Bildmodell, nicht aus dem Netz.
    result = agent.ask("Male einen Leuchtturm", stream=False, image_mode=True,
                       online=False, mode="pro", structured=True, sandbox=True)
    namen = [t["function"]["name"] for t in llm.calls[0]["tools"]]
    assert "create_image" in namen
    assert agent.toolbox.image_model == flux.model
    assert agent.mode == "normal", "Bilderstellung landet im Standard-Modus"
    assert not agent.structured and not agent.sandbox
    assert any(n == "image_mode" and p["modell"] == flux.label for n, p in ereignisse)
    letzte_frage = next(m for m in reversed(llm.calls[0]["messages"]) if m["role"] == "user")
    assert "create_image" in letzte_frage["content"]
    assert result.answer == "Ein Leuchtturm."


def test_image_mode_is_only_for_one_turn(monkeypatch: pytest.MonkeyPatch,
                                         settings: Settings) -> None:
    flux = Backend("nvidia_nim", "nvidia_nim/x", "FLUX", "NVIDIA_NIM_API_KEY")
    monkeypatch.setattr("aquaticy.images.available", lambda s: [flux])
    llm = ScriptedLLM(_message(content="Bild."), _message(content="Ein normaler Text."))
    monkeypatch.setattr("litellm.completion", llm)
    agent, _ = _agent(settings)
    agent.ask("Male etwas", stream=False, image_mode=True)
    agent.ask("Erkläre mir bitte etwas", stream=False)
    zweite = next(m for m in reversed(llm.calls[1]["messages"]) if m["role"] == "user")
    assert "Bilderstellung ist gewählt" not in zweite["content"]


def test_the_server_passes_image_mode_on(monkeypatch: pytest.MonkeyPatch) -> None:
    quelle = Path(web.__file__).read_text(encoding="utf-8")
    assert 'payload.get("image_mode") is True' in quelle
    assert "image_mode=image_mode" in quelle and 'wunsch["mode"] = "normal"' in quelle


# -- Oberflaeche ----------------------------------------------------------------------------
def test_the_model_button_sits_next_to_the_send_button() -> None:
    html = web.UI_FILE.read_text(encoding="utf-8")
    kopf = html[html.index('<div class="topbar">'): html.index('<div class="picker"')]
    assert 'id="btn-model"' not in kopf, "oben ist die Modellauswahl weg"
    crow = html[html.index('<div class="crow">'): html.index('id="send"')]
    assert 'id="btn-model"' in crow, "unten steht sie links neben Senden"


def test_the_menu_has_image_mode_effort_and_more_settings() -> None:
    html = web.UI_FILE.read_text(encoding="utf-8")
    menue = html[html.index('id="picker-models"'): html.index('id="win-aufwand"')]
    assert 'id="btn-imagemode"' in menue and "Bilderstellung" in menue
    assert menue.index('id="btn-aufwand"') < menue.index('id="btn-weitere"')
    aufwand = html[html.index('id="win-aufwand"'): html.index('id="win-weitere"')]
    assert 'id="efforts"' in aufwand and 'id="agents"' in aufwand
    weitere = html[html.index('id="win-weitere"'): html.index('<main id="main">')]
    for schalter in ("werkstatt", "online", "structure", "recheck", "denken"):
        assert f'id="{schalter}"' in weitere, schalter


def test_the_browser_sends_image_mode() -> None:
    html = web.UI_FILE.read_text(encoding="utf-8")
    assert "image_mode: imageMode" in html
    assert 'if (imageMode) setImageMode(false);' in html


def test_the_lan_switch_exists_for_ultra() -> None:
    html = web.UI_FILE.read_text(encoding="utf-8")
    assert 'id="vmlan"' in html and 'name="AQUATICY_VM_LAN"' in html
