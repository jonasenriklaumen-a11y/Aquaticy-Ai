"""Das Kontingent normaler Konten (seit 9.5.14): 5-Stunden-Sitzung und Woche.

* Sitzung: 200.000 Token, beginnt mit der ersten Nachricht, endet 5 Std. spaeter.
* Woche: 1.500.000 Token, beginnt zur Uhrzeit der Kontoerstellung.
* Gespeichert am Konto in der Kontendatenbank, gerechnet auf dem Server, an
  den Browser gehen Prozent und Uhrzeiten -- keine Tokenzahlen.
"""

from __future__ import annotations

import os
import time
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from aquaticy import metering, quota
from aquaticy.quota import SESSION_SECONDS, SESSION_TOKENS, WEEK_TOKENS, Quota, QuotaExceeded


@pytest.fixture(autouse=True)
def _berlin(monkeypatch: pytest.MonkeyPatch):
    """Ortszeit Berlin -- mit Sommer- und Winterzeit."""
    monkeypatch.setenv("TZ", "Europe/Berlin")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


def _ts(*teile: int) -> float:
    return datetime(*teile).timestamp()


#: Ein Dienstag, 14:32 -- als Zeitangabe, gerechnet wird erst im Test (in Berliner Zeit).
ERSTELLT = (2026, 9, 22, 14, 32)


@pytest.fixture
def konto(tmp_path: Path) -> Quota:
    return Quota(tmp_path / "accounts.sqlite3", "konto-1", _ts(*ERSTELLT))


def test_the_limits_are_the_agreed_ones() -> None:
    assert SESSION_TOKENS == 200_000
    assert SESSION_SECONDS == 5 * 3600
    assert WEEK_TOKENS == 1_500_000


# -- Die Woche beginnt zur Uhrzeit der Kontoerstellung ------------------------------
@pytest.mark.parametrize("jetzt,anfang,ende", [
    ((2026, 9, 22, 15, 0), (2026, 9, 22, 14, 32), (2026, 9, 29, 14, 32)),
    ((2026, 9, 29, 14, 31), (2026, 9, 22, 14, 32), (2026, 9, 29, 14, 32)),
    ((2026, 9, 29, 14, 32), (2026, 9, 29, 14, 32), (2026, 10, 6, 14, 32)),
    ((2026, 10, 3, 8, 0), (2026, 9, 29, 14, 32), (2026, 10, 6, 14, 32)),
    # Ueber die Zeitumstellung (25.10.2026): trotzdem Dienstag 14:32 Ortszeit.
    ((2026, 10, 28, 9, 0), (2026, 10, 27, 14, 32), (2026, 11, 3, 14, 32)),
])
def test_the_week_starts_at_the_time_the_account_was_made(
    jetzt: tuple[int, ...], anfang: tuple[int, ...], ende: tuple[int, ...]
) -> None:
    assert quota.week_window(_ts(*ERSTELLT), _ts(*jetzt)) == (_ts(*anfang), _ts(*ende))


def test_the_first_week_does_not_start_before_the_account() -> None:
    anfang, ende = quota.week_window(_ts(*ERSTELLT), _ts(*ERSTELLT) + 60)
    assert anfang == _ts(*ERSTELLT) and ende == _ts(2026, 9, 29, 14, 32)


def _woche_voll(konto: Quota, bis: float) -> None:
    """Eine volle Woche -- verteilt auf Sitzungen, denn seit 9.5.16 bucht keine
    einzelne Buchung ueber das Limit der Sitzung hinaus."""
    rest, zeitpunkt = WEEK_TOKENS, bis - 9 * (SESSION_SECONDS + 60)
    while rest > 0:
        teil = min(rest, SESSION_TOKENS)
        konto.record(teil, "m", now=zeitpunkt)
        rest -= teil
        zeitpunkt += SESSION_SECONDS + 60


def test_last_weeks_usage_does_not_count(konto: Quota) -> None:
    _woche_voll(konto, _ts(2026, 9, 28, 20, 0))
    with pytest.raises(QuotaExceeded) as fehler:
        konto.check(now=_ts(2026, 9, 29, 14, 0))
    assert fehler.value.which == "week"
    assert "in 32 Min. (um 14:32)" in str(fehler.value)
    stand = konto.status(now=_ts(2026, 9, 25, 9, 0))
    assert stand["week"]["resets_text"] == "Dienstag, 29.09. um 14:32"
    konto.check(now=_ts(2026, 9, 29, 14, 33))  # neue Woche, neues Budget


# -- Die Sitzung: 5 Stunden ab der ersten Nachricht ---------------------------------
def test_no_session_before_the_first_message(konto: Quota) -> None:
    stand = konto.status(now=_ts(2026, 9, 24, 10, 0))
    assert stand["session"]["active"] is False
    assert stand["session"]["percent"] == 0
    assert "nächsten Nachricht" in stand["session"]["resets_text"]


def test_the_session_starts_with_the_first_message_and_ends_five_hours_later(
    konto: Quota,
) -> None:
    start = _ts(2026, 9, 24, 10, 0)
    assert konto.begin(now=start) == start
    assert konto.begin(now=start + 3600) == start, "eine laufende Sitzung bleibt"
    konto.record(50_000, "m", now=start + 60)
    stand = konto.status(now=start + 120)
    assert stand["session"]["percent"] == 25
    assert stand["session"]["resets_at"] == start + SESSION_SECONDS
    assert stand["session"]["resets_text"] == "in 4 Std. 58 Min. (um 15:00)"
    danach = konto.status(now=start + SESSION_SECONDS)
    assert danach["session"]["active"] is False and danach["session"]["percent"] == 0
    assert danach["week"]["percent"] == 4, "die Woche behaelt alles (50.000 von 1,5 Mio.)"


def test_a_full_session_stops_and_says_when_it_resets(konto: Quota) -> None:
    start = _ts(2026, 9, 24, 10, 0)
    konto.begin(now=start)
    konto.record(SESSION_TOKENS, "m", now=start + 10)
    with pytest.raises(QuotaExceeded) as fehler:
        konto.check(now=start + 20)
    assert fehler.value.which == "session"
    assert "um 15:00" in str(fehler.value)
    assert "_used" not in fehler.value.status, "keine Tokenzahlen nach draussen"
    konto.check(now=start + SESSION_SECONDS + 1)  # neue Sitzung


def test_tokens_after_the_session_start_a_new_one(konto: Quota) -> None:
    start = _ts(2026, 9, 24, 10, 0)
    konto.begin(now=start)
    konto.record(190_000, "m", now=start + 10)
    konto.record(10_000, "m", now=start + SESSION_SECONDS + 5)  # Lauf ueber das Ende hinaus
    stand = konto.status(now=start + SESSION_SECONDS + 10)
    assert stand["session"]["active"] and stand["session"]["started_at"] == (
        start + SESSION_SECONDS + 5)
    assert stand["session"]["percent"] == 5


def test_a_session_past_midnight_says_in_how_long(konto: Quota) -> None:
    start = _ts(2026, 9, 24, 22, 0)
    konto.begin(now=start)
    assert konto.status(now=start + 1800)["session"]["resets_text"] == (
        "in 4 Std. 30 Min. (um 03:00)")


def test_need_is_checked_against_what_is_left(konto: Quota) -> None:
    start = _ts(2026, 9, 24, 10, 0)
    konto.record(SESSION_TOKENS - 1_000, "m", now=start)
    konto.check(need=500, now=start + 1)
    with pytest.raises(QuotaExceeded):
        konto.check(need=5_000, now=start + 1)


def test_percent_is_rounded_up_and_capped(konto: Quota) -> None:
    start = _ts(2026, 9, 24, 10, 0)
    konto.record(1, "m", now=start)
    assert konto.status(now=start + 1)["session"]["percent"] == 1, "etwas ist nie 0 %"
    konto.record(SESSION_TOKENS * 3, "m", now=start + 2)
    assert konto.status(now=start + 3)["session"]["percent"] == 100


# -- Am Konto, nicht im Profil --------------------------------------------------------
def test_usage_belongs_to_the_account(tmp_path: Path) -> None:
    datenbank = tmp_path / "accounts.sqlite3"
    eins = Quota(datenbank, "eins", _ts(*ERSTELLT))
    zwei = Quota(datenbank, "zwei", _ts(*ERSTELLT))
    jetzt = _ts(2026, 9, 24, 10, 0)
    eins.record(100_000, "m", now=jetzt)
    assert eins.status(now=jetzt)["session"]["percent"] == 50
    assert zwei.status(now=jetzt)["session"]["percent"] == 0
    # Ein neues Objekt fuer dasselbe Konto sieht denselben Stand.
    assert Quota(datenbank, "eins", _ts(*ERSTELLT)).status(now=jetzt)["session"]["percent"] == 50


def test_old_entries_are_cleaned_up(konto: Quota) -> None:
    konto.record(10, "m", now=_ts(2026, 9, 1, 10, 0))
    konto.record(10, "m", now=_ts(2026, 9, 24, 10, 0))
    with konto._connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM token_usage").fetchone()[0] == 1


def test_the_account_store_hands_out_the_quota(tmp_path: Path) -> None:
    from aquaticy.auth import AuthStore

    store = AuthStore(tmp_path / "konten", "ABCDEF234")
    konto = store.register("a@example.org", "ein langes Passwort", "normal",
                           username="Anna", terms_accepted=True, terms_version="1")
    kontingent = store.quota(konto)
    assert kontingent.db_path == store.db_path, "in der Kontendatenbank"
    assert kontingent.account_id == konto.id and kontingent.created_at == konto.created_at
    assert store.account(konto.id) == konto
    assert store.account("gibtsnicht") is None


# -- metering: jeder Aufruf zaehlt ins Kontingent -------------------------------------
def test_metering_records_into_statistics_and_quota(tmp_path: Path,
                                                    monkeypatch: pytest.MonkeyPatch) -> None:
    from aquaticy.usage import UsageLog

    kontingent = Quota(tmp_path / "accounts.sqlite3", "k", time.time() - 3600)
    settings = SimpleNamespace(db_path=tmp_path / "profil.sqlite3", quota=kontingent)
    antwort = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="x"))],
                              usage=SimpleNamespace(prompt_tokens=40_000, completion_tokens=0))
    monkeypatch.setattr("litellm.completion", lambda **kw: antwort)
    metering.completion(settings, model="m", messages=[])
    assert UsageLog(settings.db_path).total_tokens() == 40_000
    assert kontingent.status()["session"]["percent"] == 20
    metering.charge_image(settings, "bild")
    assert kontingent.status()["session"]["percent"] == 23  # 45.000 von 200.000


def test_without_a_quota_nothing_is_limited(tmp_path: Path) -> None:
    settings = SimpleNamespace(db_path=tmp_path / "p.sqlite3", quota=None)
    metering.check(settings, need=10**9)
    assert metering.remaining(settings) is None


def test_the_image_share_is_said_in_percent() -> None:
    assert metering.share_of_session(metering.IMAGE_TOKENS) == "2,5 %"


def test_timezone_is_restored() -> None:
    assert os.environ.get("TZ") == "Europe/Berlin"
