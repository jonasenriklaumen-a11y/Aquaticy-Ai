"""10.0 Luna: Auto-Upgrading -- lokale Modelle lernen bestaetigtes Wissen dazu."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from aquaticy import upgrading as up
from aquaticy import web
from aquaticy.legal import LEGAL_VERSION
from tests.test_v967 import FACT, contribute, learners  # noqa: F401

BASE = "gemma3:4b"
def _wort(i: int) -> str:
    return "Fachbegriff" + chr(97 + i) * 3


FAKTEN = [
    {"text": f"Satz Nummer {i} erklaert das Wort {_wort(i)} ausfuehrlich genug.",
     "source": "https://de.wikipedia.org/wiki/Wasser"}
    for i in range(20)
]


class Ollama:
    """Ein gestelltes Ollama: ein Modell kennt, was in seinem System-Text steht."""

    def __init__(self, base_kennt: int = 0) -> None:
        self.modelle: dict[str, str] = {BASE: ""}
        #: So viele Antworten kennt das Ausgangsmodell schon von sich aus.
        self.base_kennt = base_kennt
        self.geloescht: list[str] = []

    def create(self, name: str, base: str, system: str) -> None:
        self.modelle[name] = self.modelle.get(base, "") + system

    def copy(self, source: str, target: str) -> None:
        self.modelle[target] = self.modelle[source]

    def delete(self, name: str) -> None:
        self.geloescht.append(name)
        self.modelle.pop(name, None)

    def ask(self, model: str, prompt: str) -> str:
        luecke = prompt.split("\n\n", 1)[1]
        nummer = int(re.search(r"Nummer (\d+)", luecke).group(1))
        wissen = self.modelle[model]
        if f" {_wort(nummer)} " in wissen or nummer < self.base_kennt:
            return _wort(nummer)
        return "keine Ahnung"


@pytest.fixture
def ordner(tmp_path: Path) -> Path:
    up.set_enabled(tmp_path, True, [BASE, "aquaticy-alt:1.1"])
    return tmp_path


def test_names_follow_the_scheme_without_v() -> None:
    assert up.label(BASE, [1, 0]) == "gemma3:4b"
    assert up.label(BASE, [1, 1]) == "gemma3:4b 1.1"
    assert up.label(BASE, [2, 0]) == "gemma3:4b 2"
    assert up.label(BASE, [2, 1]) == "gemma3:4b 2.1"
    assert up.model_name(BASE, [1, 0]) == BASE
    assert up.model_name(BASE, [2, 1]) == "aquaticy-gemma3-4b:2.1"


def test_even_tiny_gains_are_shown_exactly() -> None:
    assert up.gain_text(0.00000002) == "+0,00000002 %"
    assert up.gain_text(12.345) == "+12,35 %"
    assert up.gain_text(0) == "±0 %"
    assert up.gain_percent(0.5, 0.525) == pytest.approx(5.0)


def test_only_local_models_get_a_track_and_own_builds_are_skipped(ordner: Path) -> None:
    assert list(up.load(ordner)["tracks"]) == [BASE]


def test_a_gain_from_5_percent_makes_a_minor_version(ordner: Path) -> None:
    ollama = Ollama(base_kennt=18)          # vorher 18/20, danach 20/20: +11 %
    assert up.train_all(ordner, FAKTEN, ollama) == 1
    stand = up.view(ordner)["tracks"][0]
    assert stand["candidate"]["label"] == "gemma3:4b 1.1"
    assert stand["candidate"]["can_upgrade"] and not stand["candidate"]["major"]
    assert "aquaticy-gemma3-4b:1.1" in ollama.modelle
    assert not any(n.endswith(":training") for n in ollama.modelle), "Zwischenstand weg"


def test_a_gain_from_30_percent_jumps_a_whole_version(ordner: Path) -> None:
    ollama = Ollama(base_kennt=10)          # 10/20 -> 20/20: +100 %
    up.train_all(ordner, FAKTEN, ollama)
    kandidat = up.view(ordner)["tracks"][0]["candidate"]
    assert kandidat["label"] == "gemma3:4b 2" and kandidat["major"]
    up.upgrade(ordner, BASE)
    # Danach: unter 30 % -> 2.1
    track = up.load(ordner)["tracks"][BASE]
    assert up.next_version(track, 6.0) == [2, 1]
    assert up.next_version(track, 31.0) == [3, 0]


def test_below_5_percent_upgrading_stays_grey_but_ultra_can_use_it(ordner: Path) -> None:
    ollama = Ollama(base_kennt=19)          # 19/20 und ein halber Treffer: knapp unter 5 %
    up.train_all(ordner, FAKTEN, ollama)
    kandidat = up.view(ordner)["tracks"][0]["candidate"]
    assert 0 < kandidat["gain"] < up.MINOR_GAIN and not kandidat["can_upgrade"]
    with pytest.raises(up.UpgradeError, match="ab 5"):
        up.upgrade(ordner, BASE)
    # Ultra sieht und nutzt den Kandidaten sofort, alle anderen nicht.
    ultra = [w.kind for w in up.choices(ordner, True)[BASE]]
    normal = [w.kind for w in up.choices(ordner, False)[BASE]]
    assert "candidate" in ultra and "candidate" not in normal
    modell = f"ollama_chat/{up.load(ordner)['tracks'][BASE]['candidate']['model']}"
    assert up.allowed(ordner, modell, True) and not up.allowed(ordner, modell, False)


def test_no_gain_no_candidate(ordner: Path) -> None:
    ollama = Ollama(base_kennt=20)
    assert up.train_all(ordner, FAKTEN, ollama) == 0
    assert up.view(ordner)["tracks"][0]["candidate"] is None


def test_upgrade_launch_notice_and_the_four_day_rule(ordner: Path) -> None:
    up.train_all(ordner, FAKTEN, Ollama(base_kennt=18))
    jetzt = 1_000_000.0
    start = up.upgrade(ordner, BASE, now=jetzt)
    neu = "ollama_chat/aquaticy-gemma3-4b:1.1"
    # Das Modell geht hoch -- fuer jedes Konto, das auf dem Strang steht.
    assert up.resolve(ordner, f"ollama_chat/{BASE}", False, "konto-a", now=jetzt) == neu
    # Startmeldung: einmal je Konto.
    meldung = up.launch_notice(ordner, "konto-a", now=jetzt + 10)
    assert meldung and meldung["model"] == neu and "stärker" in meldung["text"]
    up.mark_seen(ordner, "konto-a", start["id"])
    assert up.launch_notice(ordner, "konto-a", now=jetzt + 20) is None
    assert up.launch_notice(ordner, "konto-b", now=jetzt + 20)
    # Beide Fassungen sind vier Tage fuer alle waehlbar ...
    normal = {w.model for w in up.choices(ordner, False, now=jetzt + 3 * 86400)[BASE]}
    assert normal == {BASE, "aquaticy-gemma3-4b:1.1"}
    # ... und wer die alte bewusst waehlt, bleibt dabei.
    up.choose(ordner, f"ollama_chat/{BASE}", False, "konto-b")
    assert up.resolve(ordner, f"ollama_chat/{BASE}", False, "konto-b",
                      now=jetzt + 3 * 86400) == f"ollama_chat/{BASE}"
    # Nach vier Tagen sieht nur noch Ultra die alte.
    spaeter = jetzt + 5 * 86400
    assert {w.model for w in up.choices(ordner, False, now=spaeter)[BASE]} == {
        "aquaticy-gemma3-4b:1.1"}
    assert BASE in {w.model for w in up.choices(ordner, True, now=spaeter)[BASE]}
    assert up.resolve(ordner, f"ollama_chat/{BASE}", False, "konto-b", now=spaeter) == neu
    assert not up.allowed(ordner, f"ollama_chat/{BASE}", False, now=spaeter)
    assert up.allowed(ordner, f"ollama_chat/{BASE}", True, now=spaeter)


def test_everyone_goes_up_with_the_next_release_ultra_too(ordner: Path) -> None:
    ollama = Ollama(base_kennt=18)
    up.train_all(ordner, FAKTEN, ollama)
    kandidat = "ollama_chat/" + up.load(ordner)["tracks"][BASE]["candidate"]["model"]
    # Ultra probiert den Kandidaten aus -- und bleibt dabei, solange er Kandidat ist.
    up.choose(ordner, kandidat, True, "ultra")
    assert up.resolve(ordner, kandidat, True, "ultra") == kandidat
    up.upgrade(ordner, BASE)
    assert up.resolve(ordner, kandidat, True, "ultra") == kandidat   # jetzt die neueste
    # Naechste Freigabe: auch Ultra geht mit hoch.
    ollama.modelle["aquaticy-gemma3-4b:1.1"] = ""
    ollama.base_kennt = 0
    up.train_all(ordner, FAKTEN[:10], ollama, force=True)
    neu = up.load(ordner)["tracks"][BASE]["candidate"]
    up.upgrade(ordner, BASE)
    assert up.resolve(ordner, kandidat, True, "ultra") == "ollama_chat/" + neu["model"]


def test_rollback_and_skip(ordner: Path) -> None:
    ollama = Ollama(base_kennt=18)
    up.train_all(ordner, FAKTEN, ollama)
    up.upgrade(ordner, BASE)
    stand = up.generation(ordner)
    up.rollback(ordner, BASE, "1")
    assert up.load(ordner)["tracks"][BASE]["current"] == "1"
    assert up.generation(ordner) == stand + 1
    assert up.resolve(ordner, "ollama_chat/aquaticy-gemma3-4b:1.1", False) == f"ollama_chat/{BASE}"
    # Neuer Kandidat -- die naechste freie Nummer, keine doppelte 1.1.
    up.train_all(ordner, FAKTEN, ollama, force=True)
    kandidat = up.load(ordner)["tracks"][BASE]["candidate"]
    assert kandidat["version"] == [1, 2]
    up.skip(ordner, BASE, ollama)
    assert up.load(ordner)["tracks"][BASE]["candidate"] is None
    assert kandidat["model"] in ollama.geloescht
    with pytest.raises(up.UpgradeError):
        up.skip(ordner, BASE, ollama)


def test_training_only_runs_with_new_knowledge(ordner: Path) -> None:
    ollama = Ollama(base_kennt=18)
    up.train_all(ordner, FAKTEN, ollama)
    up.skip(ordner, BASE)
    assert up.train_all(ordner, FAKTEN, ollama) == 0, "dasselbe Wissen noch einmal"
    assert up.train_all(ordner, [], ollama) == 0
    assert "bestätigtes Wissen" in up.view(ordner)["message"]


def test_switched_off_means_no_training(tmp_path: Path) -> None:
    up.set_enabled(tmp_path, False, [BASE])
    assert up.train_all(tmp_path, FAKTEN, Ollama()) == 0


def test_the_picker_shows_versions_instead_of_raw_names(ordner: Path) -> None:
    up.train_all(ordner, FAKTEN, Ollama(base_kennt=18))
    up.upgrade(ordner, BASE)
    roh = [{"id": f"ollama_chat/{BASE}", "label": BASE},
           {"id": "ollama_chat/aquaticy-gemma3-4b:1.1", "label": "x"},
           {"id": "mistral/mistral-large-latest", "label": "mistral"}]
    liste = up.picker_entries(ordner, roh, False)
    assert [m["label"] for m in liste] == ["gemma3:4b 1.1", "gemma3:4b", "mistral"]
    assert liste[0]["upgrade"] == "current" and "stärker" in liste[0]["note"]
    assert up.display_label(ordner, "ollama_chat/aquaticy-gemma3-4b:1.1") == "gemma3:4b 1.1"


def test_confirmed_facts_need_two_accounts_and_carry_no_account(learners) -> None:  # noqa: F811
    _, _, (first, second) = learners
    first.set_consent(True, LEGAL_VERSION)
    second.set_consent(True, LEGAL_VERSION)
    contribute(first)
    assert first.confirmed_facts() == [], "ein Konto allein bestaetigt nichts"
    contribute(second)
    fakten = second.confirmed_facts()
    assert fakten == [{"text": FACT, "source": "https://de.wikipedia.org/wiki/Photosynthese"}]


# -- Web: wer darf was -------------------------------------------------------------------
class Sitzung:
    def __init__(self, ultra: bool, kennung: str = "k1") -> None:
        self.ultra = ultra
        self.account = type("Konto", (), {"id": kennung})()


@pytest.fixture
def server_ordner(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.setattr(web, "UPGRADE_DIR", tmp_path)
    monkeypatch.setattr(web, "UPGRADER", None)
    monkeypatch.setattr("aquaticy.local_model.installed_models", lambda url="": [BASE])
    return tmp_path


def test_only_ultra_steers_auto_upgrading(server_ordner: Path) -> None:
    antwort, status = web.upgrades_action(Sitzung(False), {"action": "enable", "on": True})
    assert status == 403 and antwort.get("locked")
    for aktion in ("train", "upgrade", "skip", "rollback"):
        assert web.upgrades_action(Sitzung(False), {"action": aktion, "base": BASE})[1] == 403
    antwort, status = web.upgrades_action(Sitzung(True), {"action": "enable", "on": True})
    assert status == 200 and antwort["ultra"]["enabled"]
    assert antwort["ultra"]["tracks"][0]["base"] == BASE
    # Upgraden ohne Kandidaten: ein Hinweis, kein Absturz.
    antwort, status = web.upgrades_action(Sitzung(True), {"action": "upgrade", "base": BASE})
    assert status == 400 and "keine neue Version" in antwort["error"]
    assert "ultra" not in web.upgrades_view(Sitzung(False))
    assert "ultra" in web.upgrades_view(Sitzung(True))


def test_every_account_sees_the_launch_once(server_ordner: Path) -> None:
    up.set_enabled(server_ordner, True, [BASE])
    up.train_all(server_ordner, FAKTEN, Ollama(base_kennt=18))
    up.upgrade(server_ordner, BASE)
    meldung = web.upgrades_view(Sitzung(False, "normal1"))["notice"]
    assert meldung and meldung["label"] == "gemma3:4b 1.1"
    _, status = web.upgrades_action(Sitzung(False, "normal1"),
                                          {"action": "seen", "id": meldung["id"]})
    assert status == 200
    assert web.upgrades_view(Sitzung(False, "normal1"))["notice"] is None
    assert web.upgrades_action(Sitzung(False), {"action": "seen", "id": "../x"})[1] == 400


def test_the_ui_has_the_launch_window_and_the_green_button() -> None:
    html = web.UI_FILE.read_text(encoding="utf-8")
    assert 'id="launchbox"' in html and 'id="launch-back"' in html and 'id="launch-try"' in html
    assert ">‹ Zurück</button>" in html and ">Ausprobieren</button>" in html
    assert 'los.className = "btn upgrade-go" + (k && k.can_upgrade ? " bereit" : "");' in html
    assert "los.disabled = !(k && k.can_upgrade);" in html
    assert ".btn.upgrade-go.bereit{background:var(--go)" in html and "--go:#2f8f4e" in html
    assert "pruefeUpgrade();" in html


def test_without_the_web_server_nothing_changes(monkeypatch) -> None:
    monkeypatch.setattr(web, "UPGRADE_DIR", None)
    assert web.upgrades_view(Sitzung(True)) == {"available": False, "notice": None}
