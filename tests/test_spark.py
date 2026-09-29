"""Regressionen fuer Kontooperationen und parallele Tokenbuchungen."""

import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aquaticy import cli, config
from aquaticy.aiguard import AiGuard
from aquaticy.auth import AuthStore
from aquaticy.quota import Quota
from aquaticy.web import HELP_MARKDOWN, ChatSession

TERMS = {"terms_accepted": True, "terms_version": "test"}
PASSWORD = "ein sehr langes Testpasswort"


@pytest.mark.parametrize("conflict", ["device", "username"])
def test_registration_is_atomic_across_store_instances(
    tmp_path: Path, conflict: str
) -> None:
    first = AuthStore(tmp_path, "PRO123456")
    second = AuthStore(tmp_path, "PRO123456")
    barrier = threading.Barrier(2)

    def create(store: AuthStore, number: int) -> str:
        # Seit 9.5.31 sperrt nicht mehr dieselbe IP-Adresse, sondern etwa
        # dasselbe Geraet (Anhaltspunkte, aquaticy/devices.py).
        from aquaticy.devices import clean_device

        geraet = clean_device({}, cookie="D" * 32) if conflict == "device" else None
        barrier.wait()
        try:
            store.register(f"{number}@example.org", PASSWORD, "normal",
                           username="Derselbe" if conflict == "username" else f"Nutzer{number}",
                           ip=f"203.0.113.{number}", device=geraet, **TERMS)
        except ValueError:
            return "blocked"
        return "created"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda args: create(*args), [(first, 1), (second, 2)]))
    assert sorted(results) == ["blocked", "created"]
    assert len(first.accounts()) == 1


def test_unicode_and_at_sign_usernames_can_be_looked_up(tmp_path: Path) -> None:
    store = AuthStore(tmp_path, "PRO123456")
    first = store.register("a@example.org", PASSWORD, "normal", username="Änne", **TERMS)
    assert store.account_by_name("änne") == first
    with pytest.raises(ValueError):
        store.register("b@example.org", PASSWORD, "normal", username="änne", **TERMS)
    second = store.register("c@example.org", PASSWORD, "normal", username="foo@bar", **TERMS)
    assert store.account_by_name("foo@bar") == second


def test_remove_erases_account_related_data(tmp_path: Path) -> None:
    store = AuthStore(tmp_path, "PRO123456")
    account = store.register("delete@example.org", PASSWORD, "normal",
                             username="DeleteMe", **TERMS)
    token = store.create_session(account, "browser", "127.0.0.1")
    quota = store.quota(account)
    quota.record(32)
    guard = AiGuard(store.db_path)
    guard.ban_user(account.id)
    guard.note(account.id, "test", enforce=False)
    profile = store.profile_dir(account.id)
    (profile / "chat.txt").write_text("private Daten", encoding="utf-8")

    store.remove_account(account)

    assert store.account(account.id) is None
    assert store.session_account(token, "browser", "127.0.0.1") is None
    assert not profile.exists()
    with sqlite3.connect(store.db_path) as conn:
        for table, column in (("sessions", "user_id"), ("token_usage", "account_id"),
                              ("token_sessions", "account_id"),
                              ("aiguard_flags", "user_id")):
            assert conn.execute(f"SELECT count(*) FROM {table} WHERE {column}=?",
                                (account.id,)).fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM aiguard_bans WHERE subject=?",
                            (f"user:{account.id}",)).fetchone()[0] == 0


def test_remove_terminal_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AQUATICY_DATA_DIR", str(tmp_path))
    config.reset_settings_cache()
    try:
        store = AuthStore(tmp_path, "PRO123456")
        account = store.register("command@example.org", PASSWORD, "normal",
                                 username="DeleteMe", **TERMS)
        # Ohne Bestaetigung (9.5.22) bleibt das Konto stehen.
        result = CliRunner().invoke(cli.app, ["remove", "DeleteMe"], input="n\n")
        assert result.exit_code == 1 and "command@example.org" in result.output
        assert store.account(account.id) is not None
        result = CliRunner().invoke(cli.app, ["remove", "DeleteMe"], input="y\n")
        assert result.exit_code == 0, result.output
        assert store.account(account.id) is None
        assert CliRunner().invoke(cli.app, ["remove", "DeleteMe", "--yes"]).exit_code == 1
    finally:
        config.reset_settings_cache()


def test_concurrent_record_cannot_overbook(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import aquaticy.quota as quota_module

    monkeypatch.setattr(quota_module, "SESSION_TOKENS", 40)
    monkeypatch.setattr(quota_module, "WEEK_TOKENS", 100)
    db = tmp_path / "tokens.sqlite3"
    first = Quota(db, "user", time.time() - 1)
    (tmp_path / "other").mkdir()
    second = Quota(tmp_path / "other" / ".." / "tokens.sqlite3", "user", first.created_at)
    barrier = threading.Barrier(2)

    def charge(quota: Quota) -> None:
        barrier.wait()
        quota.record(30)

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(charge, (first, second)))
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT SUM(tokens) FROM token_usage").fetchone()[0] == 40


def test_concurrent_settlement_cannot_overbook(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import aquaticy.quota as quota_module

    monkeypatch.setattr(quota_module, "SESSION_TOKENS", 40)
    monkeypatch.setattr(quota_module, "WEEK_TOKENS", 100)
    db = tmp_path / "tokens.sqlite3"
    first = Quota(db, "user", time.time() - 1)
    (tmp_path / "other").mkdir()
    second = Quota(tmp_path / "other" / ".." / "tokens.sqlite3", "user", first.created_at)
    reservations = (first.reserve(10), second.reserve(10))
    barrier = threading.Barrier(2)

    def settle(args: tuple[Quota, int]) -> None:
        barrier.wait()
        args[0].settle(args[1], 30)

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(settle, zip((first, second), reservations, strict=True)))
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT SUM(tokens) FROM token_usage").fetchone()[0] == 40


def test_old_reservation_does_not_increase_new_session_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import aquaticy.quota as quota_module

    monkeypatch.setattr(quota_module, "SESSION_TOKENS", 40)
    monkeypatch.setattr(quota_module, "WEEK_TOKENS", 100)
    old = 1_000_000.0
    new = old + quota_module.SESSION_SECONDS + 1
    quota = Quota(tmp_path / "tokens.sqlite3", "user", old - 1)
    reservation = quota.reserve(10, now=old)
    quota.record(30, now=new)
    with quota._connect() as conn:
        assert quota._frei(conn, new, ohne=reservation) == 10


def test_tool_cost_settles_the_existing_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aquaticy.config import Settings
    from aquaticy.tools import Toolbox

    quota = Quota(tmp_path / "tokens.sqlite3", "user", time.time() - 1)
    settings = Settings(data_dir=tmp_path, quota=quota)
    box = Toolbox(settings, cache=None)
    monkeypatch.setattr(box, "_call", lambda *_: {
        "results": [], "queries": ["one", "two"]})

    def no_second_booking(*args: object, **kwargs: object) -> None:
        raise AssertionError("Die Reservierung darf nicht vor der Buchung frei werden")

    monkeypatch.setattr(quota, "record", no_second_booking)
    assert box.call("web_search", {"query": "x"})["queries"] == ["one", "two"]
    with sqlite3.connect(quota.db_path) as conn:
        assert conn.execute("SELECT SUM(tokens) FROM token_usage").fetchone()[0] == 100


def test_help_lists_browser_commands_and_terminal_commands() -> None:
    text = ChatSession().command("/help")["text"]
    assert text == HELP_MARKDOWN
    for command in ("location", "model", "max", "image", "export", "history", "notes",
                    "clear", "memory", "uploads", "forget", "help", "quit", "exit", "q"):
        assert f"/{command}" in text
        assert f"/{command}" in cli.HELP_TEXT
    for command in cli.COMMANDS:
        assert f"aquaticy {command}" in cli.HELP_TEXT
