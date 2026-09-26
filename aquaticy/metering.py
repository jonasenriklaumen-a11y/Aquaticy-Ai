"""Was zaehlt -- und das Kontingent gilt auch mitten im Lauf.

Bis 9.5.10 wurde nur das Hauptmodell mitgezaehlt. Agenten, Master, Planer,
Rechtspruefer, Bildmodell und die Bildbeschreibung liefen am Zaehler vorbei --
und das Kontingent eines normalen Kontos wurde nur VOR einer Anfrage
geprueft. Eine einzige Anfrage mit vielen Agenten konnte es so weit
ueberschreiten.

Jetzt gilt:

* **Modellaufrufe** gehen ueber ``completion()`` hier (das Hauptmodell streamt
  und meldet sich ueber ``record()``). Sie landen in der Statistik des Profils
  und -- bei normalen Konten -- im Kontingent (aquaticy/quota.py). Gezaehlt
  werden die Zahlen des Anbieters, sonst geschaetzt: drei Zeichen sind ein
  Token.
* **Eigene Schluessel zaehlen nicht (seit 9.5.14 Seashell).** Laeuft ein
  Modell mit dem API-Schluessel des Kontos (aquaticy/keyvault.py), bezahlt es
  das Konto beim Anbieter selbst -- das Kontingent bleibt davon unberuehrt,
  und vor so einem Aufruf wird auch nicht geprueft. Gestellte Modelle (mit
  dem Schluessel des Betreibers, oder lokal wie Ollama auf dem Server)
  zaehlen wie immer.
* **Serverarbeit zaehlt immer.** Was auf dem Server passiert -- Werkstatt,
  Seitenabrufe, Suchen, Handlungen im User mode --, kostet den Server, egal
  mit wessen Schluessel das Modell laeuft. Sie wird in Token umgerechnet
  (``WORK_COSTS``), damit sie in dasselbe Kontingent passt.
* Hat das Konto ein Kontingent (``settings.quota``, nur normale Konten), wird
  VOR jedem gestellten Aufruf und vor jeder Serverarbeit geprueft. Ist
  Sitzung oder Woche aufgebraucht, kommt ``QuotaExceeded``.
* Ein erstelltes Bild zaehlt pauschal ``IMAGE_TOKENS`` -- ein Bildmodell
  rechnet nicht in Token ab, kostet aber trotzdem. Mit eigenem Bildschluessel
  zaehlt nur das Ablegen auf dem Server.

Seit 9.5.15:

* **Reservieren statt pruefen-und-spaeter-buchen.** Vor jedem gestellten
  Aufruf wird in einer einzigen Datenbank-Transaktion geprueft UND gebucht
  (``reserve``); danach ersetzt ``Reservation.settle`` die Schaetzung durch
  die Zahlen des Anbieters. Parallele Agenten und Auftraege koennen so nicht
  mehr alle gleichzeitig "noch frei" sehen.
* **Fail-closed.** Laesst sich das Kontingent nicht schreiben, faellt der
  Aufruf aus, statt unbezahlt zu laufen. Fehler beim Verrechnen danach
  lassen die (hoehere) Reservierung stehen und werden protokolliert -- nie
  still verschluckt.
* **Echte Zahlen auch beim Streamen**: ``usage_of`` liest die Zahlen des
  Anbieters (samt Reasoning- und Cache-Token, die in prompt/completion
  enthalten sind), gestreamt ueber ``stream_options.include_usage``.
"""

from __future__ import annotations

import contextlib
import logging
import math
from typing import Any

from aquaticy.quota import SESSION_TOKENS, QuotaExceeded

__all__ = [
    "IMAGE_TOKENS",
    "WORK_COSTS",
    "QuotaExceeded",
    "charge_image",
    "charge_work",
    "check",
    "check_image",
    "check_work",
    "completion",
    "is_own",
    "quota_of",
    "record",
    "remaining",
    "reserve",
    "reserve_work",
    "share_of_session",
    "usage_of",
    "work_cost",
]

LOG = logging.getLogger("aquaticy.metering")

#: So viel reserviert ein Aufruf fuer die Antwort, wenn er selbst keine Grenze nennt.
DEFAULT_OUTPUT_RESERVE = 4_096

#: So viel zaehlt ein erstelltes Bild (mit dem Schluessel des Betreibers).
IMAGE_TOKENS = 5_000

#: Was Arbeit auf dem Server kostet -- in Token gerechnet, damit sie mit den
#: Modellaufrufen in dasselbe Kontingent passt. (Einheit, Token je Einheit)
WORK_COSTS: dict[str, tuple[str, int]] = {
    "werkstatt": ("je angefangene Sekunde Rechenzeit in der Werkstatt", 150),
    "werkstatt_start": ("je Start einer Werkstatt", 750),
    "datei": ("je Datei, die in die Werkstatt geht oder aus ihr kommt", 50),
    "seite": ("je abgerufene Webseite", 100),
    "suche": ("je Suchanfrage", 50),
    "desktop": ("je Handlung im User mode (sehen, klicken, tippen)", 100),
    "bild": ("je Bild, das auf dem Server abgelegt wird", 100),
}


def quota_of(settings: Any) -> Any:
    """Das Kontingent des Kontos -- ``None`` heisst: keins (Pro, lokal)."""
    quota = getattr(settings, "quota", None)
    return quota if hasattr(quota, "check") and hasattr(quota, "record") else None


def is_own(settings: Any, model: str) -> bool:
    """Laeuft *model* mit dem eigenen Schluessel des Kontos (``Settings.key_source``)?"""
    quelle = getattr(settings, "key_source", None)
    if not model or not callable(quelle):
        return False
    try:
        return quelle(str(model)) == "own"
    except Exception:
        return False


def remaining(settings: Any) -> int | None:
    """Was noch geht -- ``None`` heisst: kein Kontingent."""
    quota = quota_of(settings)
    return None if quota is None else quota.remaining()


def share_of_session(tokens: int) -> str:
    """Wie viel einer Sitzung *tokens* sind -- fuer Saetze an Menschen."""
    anteil = tokens * 100 / SESSION_TOKENS
    return f"{anteil:.1f}".rstrip("0").rstrip(".").replace(".", ",") + " %"


def check(settings: Any, need: int = 0, *, model: str = "") -> None:
    """Wirft ``QuotaExceeded``, wenn Sitzung oder Woche nichts mehr hergeben.

    Args:
        model: Der Aufruf, der gleich kommt. Laeuft er mit dem eigenen
            Schluessel des Kontos, kostet er das Kontingent nichts -- dann
            wird auch nicht geprueft.
    """
    quota = quota_of(settings)
    if quota is None or is_own(settings, model):
        return
    quota.check(need)


def record(
    settings: Any, model: str, tokens_in: int, tokens_out: int, *, own: bool | None = None
) -> None:
    """Vermerkt einen Modellaufruf. Zaehlen darf nie eine Antwort kosten.

    In der Statistik steht jeder Aufruf; ins Kontingent kommt nur, was nicht
    mit dem eigenen Schluessel des Kontos lief.
    """
    rein, raus = max(0, int(tokens_in or 0)), max(0, int(tokens_out or 0))
    _statistik(settings, model, rein, raus)
    eigen = is_own(settings, model) if own is None else bool(own)
    quota = quota_of(settings)
    if quota is not None and not eigen:
        try:
            quota.record(rein + raus, model)
        except Exception:
            # Nicht still: wer hier schweigt, laesst Nutzung unbezahlt durch.
            LOG.exception("Kontingent: Verbrauch liess sich nicht eintragen (%s)", model)


def _statistik(settings: Any, model: str, rein: int, raus: int) -> None:
    """Die Statistik des Profils -- ein Fehler dort kostet keine Antwort, wird aber gemeldet."""
    try:
        from aquaticy.usage import UsageLog

        UsageLog(settings.db_path).record(model, rein, raus)
    except Exception:
        LOG.warning("Statistik: Aufruf liess sich nicht eintragen (%s)", model, exc_info=True)


class Reservation:
    """Eine Buchung im Kontingent, bevor der Aufruf laeuft -- danach verrechnet."""

    def __init__(self, settings: Any, model: str, quota: Any, nummer: int) -> None:
        self.settings = settings
        self.model = model
        self._quota = quota
        self._nummer = nummer
        self._offen = True
        #: Die Aufrufargumente, fuer die reserviert wurde (Agent, seit 9.5.16).
        self.kwargs: dict[str, Any] | None = None

    def settle(self, tokens_in: int, tokens_out: int) -> None:
        """Ersetzt die Reservierung durch den echten Verbrauch."""
        if not self._offen:
            return
        self._offen = False
        rein, raus = max(0, int(tokens_in or 0)), max(0, int(tokens_out or 0))
        _statistik(self.settings, self.model, rein, raus)
        if self._quota is None:
            return
        try:
            self._quota.settle(self._nummer, rein + raus, self.model)
        except Exception:
            # Die Reservierung bleibt stehen -- lieber zu viel gezaehlt als zu wenig.
            LOG.exception("Kontingent: Verrechnen fehlgeschlagen (%s)", self.model)

    def cancel(self) -> None:
        """Gibt die Reservierung frei -- der Aufruf ist gar nicht zustande gekommen."""
        if not self._offen:
            return
        self._offen = False
        if self._quota is None:
            return
        try:
            self._quota.settle(self._nummer, 0, self.model)
        except Exception:
            LOG.exception("Kontingent: Freigeben fehlgeschlagen (%s)", self.model)


def reserve(settings: Any, model: str, estimate: int) -> Reservation:
    """Reserviert *estimate* Token fuer einen Aufruf mit *model* -- atomar.

    Mit eigenem Schluessel des Kontos (oder ohne Kontingent) wird nichts
    reserviert; gezaehlt wird dann nur die Statistik.

    Raises:
        QuotaExceeded: nichts mehr frei.
        Exception: das Kontingent laesst sich nicht schreiben -- dann laeuft
            auch der Aufruf nicht (fail-closed).
    """
    quota = quota_of(settings)
    if quota is None or is_own(settings, model):
        return Reservation(settings, model, None, 0)
    nummer = quota.reserve(max(1, int(estimate or 0)), model)
    return Reservation(settings, model, quota, nummer)


def estimate(messages: Any, max_tokens: Any = None, tools: Any = None) -> int:
    """Was ein Aufruf hoechstens kosten duerfte -- fuer die Reservierung."""
    from aquaticy.usage import message_tokens, tokens

    rein = 0
    with contextlib.suppress(Exception):
        rein = message_tokens(messages if isinstance(messages, list) else [])
    if tools:
        with contextlib.suppress(Exception):
            import json

            rein += tokens(json.dumps(tools))
    try:
        raus = int(max_tokens) if max_tokens else DEFAULT_OUTPUT_RESERVE
    except (TypeError, ValueError):
        raus = DEFAULT_OUTPUT_RESERVE
    return max(1, rein + max(0, raus))


#: Weniger Platz fuer die Antwort lohnt keinen Aufruf mehr.
MIN_OUTPUT_TOKENS = 256
#: Erst unterhalb davon wird die Antwortlaenge an den Rest angepasst -- darueber
#: bliebe eine Obergrenze wirkungslos und manche Anbieter lehnen riesige ab.
OUTPUT_CAP_FROM = 16_384


def output_cap(settings: Any, model: str, messages: Any, tools: Any = None,
               max_tokens: Any = None) -> int | None:
    """Wie lang die Antwort hoechstens sein darf, damit das Kontingent reicht.

    ``None`` = keine Obergrenze noetig (kein Kontingent, eigener Schluessel oder
    genug Rest). Seit 9.5.16: bis dahin lief ein Aufruf auch dann, wenn seine
    Antwort ueber den Rest hinausging -- und das Limit wurde ueberschritten.

    Raises:
        QuotaExceeded: Schon die Frage allein passt nicht mehr hinein.
    """
    quota = quota_of(settings)
    if quota is None or is_own(settings, model):
        return None
    rest = quota.remaining()
    rein = estimate(messages, 1, tools) - 1
    platz = rest - rein
    if platz < MIN_OUTPUT_TOKENS:
        quota.check(max(1, rein + MIN_OUTPUT_TOKENS))
        raise QuotaExceeded(
            "Der Rest deines Kontingents reicht für diese Anfrage nicht mehr. Eine kürzere "
            "Frage oder ein neuer Chat braucht weniger.", "session")
    gewuenscht = int(max_tokens) if isinstance(max_tokens, int) and max_tokens > 0 else 0
    if gewuenscht and gewuenscht <= platz:
        return None
    if not gewuenscht and platz >= OUTPUT_CAP_FROM:
        return None
    return min(platz, gewuenscht or platz)


def usage_of(usage: Any) -> tuple[int, int] | None:
    """Die Zahlen des Anbieters -- oder None, wenn er keine geschickt hat.

    ``prompt_tokens`` enthaelt die Cache-Token, ``completion_tokens`` die
    Reasoning-Token; nennt der Anbieter ein hoeheres ``total_tokens``, gilt das.
    """
    if usage is None:
        return None
    def wert(name: str) -> Any:
        return usage.get(name) if isinstance(usage, dict) else getattr(usage, name, None)

    rein, raus, summe = wert("prompt_tokens"), wert("completion_tokens"), wert("total_tokens")
    if not isinstance(rein, int) or not isinstance(raus, int) or rein < 0 or raus < 0:
        return None
    if isinstance(summe, int) and summe > rein + raus:
        raus = summe - rein
    return rein, raus


# -- Serverarbeit ---------------------------------------------------------------
def work_cost(kind: str, amount: float = 1.0) -> int:
    """Was *amount* Einheiten dieser Arbeit kosten -- angefangene Einheiten zaehlen voll."""
    _, je = WORK_COSTS.get(kind, ("", 0))
    return int(je * max(1, math.ceil(max(0.0, float(amount or 0.0)))))


def check_work(settings: Any, kind: str, amount: float = 1.0) -> None:
    """Wirft ``QuotaExceeded``, wenn fuer diese Arbeit nichts mehr uebrig ist."""
    quota = quota_of(settings)
    if quota is not None:
        quota.check(work_cost(kind, amount))


def charge_work(settings: Any, kind: str, amount: float = 1.0) -> None:
    """Bucht Arbeit auf dem Server -- egal, mit wessen Schluessel das Modell laeuft."""
    quota = quota_of(settings)
    kosten = work_cost(kind, amount)
    if quota is not None and kosten > 0:
        try:
            quota.record(kosten, f"server:{kind}")
        except Exception:
            LOG.exception("Kontingent: Serverarbeit liess sich nicht eintragen (%s)", kind)


def reserve_work(settings: Any, kind: str, amount: float = 1.0) -> Reservation:
    """Haelt die Mindestkosten einer Serverarbeit frei, solange sie laeuft (atomar).

    Danach wird die Reservierung freigegeben und die echte Arbeit gebucht
    (``charge_work``). So koennen parallele Werkzeuge nicht alle auf den
    letzten freien Rest zugleich losgehen.
    """
    quota = quota_of(settings)
    if quota is None:
        return Reservation(settings, f"server:{kind}", None, 0)
    nummer = quota.reserve(work_cost(kind, amount), f"server:{kind}")
    return Reservation(settings, f"server:{kind}", quota, nummer)


# -- Modellaufrufe ------------------------------------------------------------------
def _counted(messages: Any, response: Any) -> tuple[int, int]:
    """Die Zahlen des Anbieters, sonst eine Schaetzung aus dem Text."""
    from aquaticy.usage import message_tokens, tokens

    echt = usage_of(getattr(response, "usage", None))
    if echt is not None:
        return echt
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

    modell = str(kwargs.get("model") or "")
    if kwargs.get("stream"):
        # Gestreamte Aufrufe reservieren und verrechnen selbst (Agent._reserve,
        # _note_usage). Bis 9.5.16 stand hier ein Zweig dafuer, der das
        # Gegenteil seines Kommentars tat -- benutzt hat ihn niemand.
        raise ValueError("metering.completion streamt nicht -- dafuer Agent._reserve nehmen.")
    if enforce:
        check(settings, model=modell)
        deckel = output_cap(settings, modell, kwargs.get("messages"), kwargs.get("tools"),
                            kwargs.get("max_tokens"))
        if deckel is not None:
            kwargs["max_tokens"] = deckel
    # Reserviert wird immer -- auch beim Rechtspruefer, der vorher nicht
    # prueft: gebucht werden muss er trotzdem, und zwar bevor er laeuft.
    try:
        buchung = reserve(settings, modell, estimate(kwargs.get("messages"),
                                                     kwargs.get("max_tokens"),
                                                     kwargs.get("tools")))
    except QuotaExceeded:
        if enforce:
            raise
        buchung = Reservation(settings, modell, None, 0)
        LOG.info("Kontingent erschoepft -- der Rechtspruefer laeuft trotzdem (%s)", modell)
    try:
        response = litellm.completion(**kwargs)
    except BaseException:
        buchung.cancel()
        raise
    rein, raus = _counted(kwargs.get("messages"), response)
    buchung.settle(rein, raus)
    return response


def check_image(settings: Any, model: str) -> None:
    """Vor einem Bild: gestellt kostet es IMAGE_TOKENS, mit eigenem Schluessel nur das Ablegen."""
    if is_own(settings, model):
        check_work(settings, "bild")
    else:
        check(settings, need=IMAGE_TOKENS)


def charge_image(settings: Any, model: str) -> None:
    """Bucht ein erstelltes Bild -- je nachdem, wessen Schluessel es gemalt hat."""
    if is_own(settings, model):
        charge_work(settings, "bild")
        _statistik(settings, model, 0, IMAGE_TOKENS)
    else:
        record(settings, model, 0, IMAGE_TOKENS)
