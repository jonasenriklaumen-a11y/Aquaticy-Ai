"""10.1.4: Grundschutz ohne Leitplanken und der Schalter gilt nur fuer das eigene Konto."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from aquaticy import web
from aquaticy.guardrails import Guard


def _urteil(zulaessig: bool, regel: str = "", art: str = "", schwere: int = 0):
    antwort = json.dumps({"zulaessig": zulaessig, "regel": regel, "grund": "Test",
                          "missbrauch": bool(art), "missbrauch_art": art,
                          "missbrauch_schwere": schwere})
    gefragt: list[str] = []

    def ask(prompt: str, model: str, settings) -> str:
        gefragt.append(prompt)
        return antwort

    ask.gefragt = gefragt  # type: ignore[attr-defined]
    return ask


def test_without_guardrails_the_request_is_not_checked(settings) -> None:
    ask = _urteil(False, "persoenlichkeit")
    guard = Guard(settings, ask=ask, baseline=True)
    assert guard.check_request("irgendeine Frage").allowed
    assert guard.check_call("find_profiles", {"name": "Anna"}).allowed
    assert ask.gefragt == [], "ausserhalb des Grundschutzes wird nichts gefragt"


def test_the_vm_watchdog_stays_on(settings) -> None:
    guard = Guard(settings, ask=_urteil(True, art="malware", schwere=3), baseline=True)
    urteil = guard.check_call("vm_run", {"command": "x"})
    assert urteil.abuse and urteil.abuse_kind == "malware"


def test_an_ordinary_no_does_not_stop_the_vm(settings) -> None:
    guard = Guard(settings, ask=_urteil(False, "vertrag"), baseline=True)
    assert guard.check_call("vm_write", {"path": "a.py"}) .allowed
    assert not guard.check_call("vm_run", {"command": "y"}).abuse


def test_images_that_hurt_real_people_stay_blocked(settings) -> None:
    guard = Guard(settings, ask=_urteil(False, "persoenlichkeit"), baseline=True)
    assert not guard.check_call("create_image", {"prompt": "x"}).allowed
    guard = Guard(settings, ask=_urteil(False, "vertrag"), baseline=True)
    assert guard.check_call("create_image", {"prompt": "y"}).allowed


def test_no_answer_from_the_checker_means_no(settings) -> None:
    guard = Guard(settings, ask=lambda *a: "kein json", baseline=True)
    assert not guard.check_call("vm_run", {"command": "z"}).allowed


def test_the_toolbox_stops_flagged_vm_code(settings, monkeypatch) -> None:
    from aquaticy.tools import Toolbox

    settings.legal_guard = False
    box = Toolbox(settings)
    assert box.guard is not None and box.guard.baseline
    box.guard._ask = _urteil(True, art="malware", schwere=3)
    ergebnis = box._call("vm_run", {"command": "x"})
    assert ergebnis.get("skipped_reason") == "aiguard_stop"
    box.close()


def test_the_switch_only_counts_for_the_account_that_set_it(settings, monkeypatch,
                                                            tmp_path: Path) -> None:
    betreiber = dataclasses.replace(settings, legal_guard=False)
    monkeypatch.setattr(web, "get_settings", lambda: betreiber)
    monkeypatch.setattr(web, "AUTH", None)
    andere = tmp_path / "anderes"
    andere.mkdir()
    assert web._profile_settings(andere, "ultra").legal_guard is True
    eigenes = tmp_path / "eigenes"
    eigenes.mkdir()
    (eigenes / ".env").write_text("AQUATICY_LEGAL_GUARD=aus\n")
    assert web._profile_settings(eigenes, "ultra").legal_guard is False
    assert web._profile_settings(eigenes, "pro").legal_guard is True


@pytest.mark.parametrize("tool", ["vm_run", "vm_write", "blender_run", "desktop_type",
                                  "create_image"])
def test_baseline_tools_are_all_checked(settings, tool: str) -> None:
    ask = _urteil(True)
    Guard(settings, ask=ask, baseline=True).check_call(tool, {"x": tool})
    assert ask.gefragt, tool
