"""Jeder Modellaufruf zaehlt -- und das Kontingent gilt auch mitten im Lauf.

Bis 9.5.10 wurde nur das Hauptmodell mitgezaehlt. Agenten, Master, Planer,
Rechtspruefer, Bildmodell und die Bildbeschreibung liefen am Zaehler vorbei --
und das Kontingent eines normalen Kontos (150.000 Token) wurde nur VOR einer
Anfrage geprueft. Eine einzige Anfrage mit vielen Agenten konnte es so weit
ueberschreiten.

Jetzt gilt:

* Alle Aufrufe gehen ueber ``completion()`` hier. Sie werden im Zaehler des
  Kontos vermerkt (die Zahlen des Anbieters, sonst geschaetzt: drei Zeichen
  sind ein Token).
* Hat das Konto ein Kontingent (``settings.token_limit``, nur normale Konten),
  wird VOR jedem Aufruf geprueft. Ist es aufgebraucht, kommt
  ``QuotaExceeded`` -- der Lauf endet, statt weiter auf Kosten des Betreibers
  zu laufen.
* Ein erstelltes Bild zaehlt pauschal ``IMAGE_TOKENS`` -- ein Bildmodell
  rechnet nicht in Token ab, kostet aber trotzdem.
"""

from __future__ import annotations

import contextlib
from typing import Any

#: So viel zaehlt ein erstelltes Bild.
IMAGE_TOKENS = 5_000


class QuotaExceeded(RuntimeError):
    """Das Kontingent des Kontos ist aufgebraucht."""


def limit_of(settings: Any) -> int | None:
    limit = getattr(settings, "token_limit", None)
    return int(limit) if isinstance(limit, int) and limit > 0 else None


def used(settings: Any) -> int:
    from aquaticy.usage import UsageLog

    return UsageLog(settings.db_path).total_tokens()


def remaining(settings: Any) -> int | None:
    """Wie viel noch geht -- ``None`` heisst: kein Kontingent (Pro, lokal)."""
    limit = limit_of(settings)
    if limit is None:
        return None
    return max(0, limit - used(settings))


def message(settings: Any) -> str:
    limit = limit_of(settings) or 0
    return (
        f"Dein Kontingent von {limit:,} Token ist aufgebraucht. Mit einem Pro-Konto "
        "gibt es kein Tokenlimit."
    ).replace(",", ".")


def check(settings: Any, need: int = 0) -> None:
    """Wirft ``QuotaExceeded``, wenn das Konto nichts mehr uebrig hat."""
    rest = remaining(settings)
    if rest is not None and (rest <= 0 or rest < need):
        raise QuotaExceeded(message(settings))


def record(settings: Any, model: str, tokens_in: int, tokens_out: int) -> None:
    """Vermerkt einen Aufruf. Zaehlen darf nie eine Antwort kosten."""
    with contextlib.suppress(Exception):
        from aquaticy.usage import UsageLog

        UsageLog(settings.db_path).record(model, max(0, int(tokens_in)), max(0, int(tokens_out)))


def _counted(messages: Any, response: Any) -> tuple[int, int]:
    """Die Zahlen des Anbieters, sonst eine Schaetzung aus dem Text."""
    from aquaticy.usage import message_tokens, tokens

    usage = getattr(response, "usage", None)
    rein = getattr(usage, "prompt_tokens", None)
    raus = getattr(usage, "completion_tokens", None)
    if isinstance(rein, int) and isinstance(raus, int) and rein >= 0 and raus >= 0:
        return rein, raus
    try:
        rein = message_tokens(messages if isinstance(messages, list) else [])
    except Exception:
        rein = 0
    text = ""
    with contextlib.suppress(Exception):
        text = str(response.choices[0].message.content or "")
    return rein, tokens(text)


def completion(settings: Any, *, enforce: bool = True, **kwargs: Any) -> Any:
    """``litellm.completion`` -- gezaehlt und, wo verlangt, gegen das Kontingent geprueft.

    Args:
        enforce: Vorher pruefen. Der Rechtspruefer prueft nicht (er soll im
            Zweifel lieber ablehnen als ausfallen) -- gezaehlt wird er trotzdem.
    """
    import litellm

    if enforce:
        check(settings)
    response = litellm.completion(**kwargs)
    if not kwargs.get("stream"):
        rein, raus = _counted(kwargs.get("messages"), response)
        record(settings, str(kwargs.get("model") or ""), rein, raus)
    return response


def charge_image(settings: Any, model: str) -> None:
    record(settings, model, 0, IMAGE_TOKENS)
