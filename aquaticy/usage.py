"""Der Zaehler: wie viel Aquaticy verbraucht.

Ein Token sind hier **drei Zeichen**. Das ist eine Vereinbarung, keine
Messung: jeder Anbieter zerlegt Text anders, und die genauen Zahlen kaeme man
nur mit dem jeweiligen Zerleger heraus. Drei Zeichen liegen fuer deutschen
Fliesstext nah genug dran, um Groessenordnungen zu sehen -- und darum geht es:
ob eine Frage hundert oder hunderttausend Token gekostet hat.

Gezaehlt wird, was tatsaechlich ueber die Leitung geht:

* **hinein** alles, was in einem Aufruf beim Modell landet -- Systemtext,
  Gespraech, Werkzeug-Ausgaben. Das wiederholt sich mit jeder Runde, weil die
  Schnittstelle zustandslos ist; genau so rechnen die Anbieter auch ab.
* **heraus** die Antwort und die Argumente der Werkzeugaufrufe.

Abgelegt wird tageweise je Modell in derselben Datenbank wie der Cache --
das ist die Statistik. Das Kontingent normaler Konten (5-Stunden-Sitzung und
Woche) steht getrennt davon am Konto in der Kontendatenbank
(aquaticy/quota.py); Pro-Konten bleiben unbegrenzt.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import date, timedelta
from pathlib import Path
from typing import Any

#: Ein Token sind drei Zeichen -- so vereinbart.
CHARS_PER_TOKEN = 3


def tokens(text: str) -> int:
    """Zeichen in Token, immer aufgerundet."""
    if not text:
        return 0
    return -(-len(text) // CHARS_PER_TOKEN)


#: So viel zaehlt ein mitgeschicktes Bild. Die Anbieter rechnen ein Bild nach
#: seiner Groesse in Kacheln ab -- ueblich sind rund 1.000 bis 2.000 Token.
#: Bis 9.5.11 zaehlte hier die Laenge der Base64-Daten: ein Foto von 300 KB
#: waren damit 133.000 "Token", fast das ganze Kontingent eines normalen
#: Kontos fuer eine einzige Bildbeschreibung.
IMAGE_INPUT_TOKENS = 1_500


def message_tokens(messages: list[dict[str, Any]]) -> int:
    """Was ein ganzer Nachrichtenstapel kostet.

    Auch Bilder zaehlen mit -- pauschal (IMAGE_INPUT_TOKENS), so wie die
    Anbieter sie abrechnen, nicht nach der Laenge ihrer Daten.
    """
    gesamt = 0
    for message in messages:
        content = message.get("content")
        if isinstance(content, str):
            gesamt += tokens(content)
        elif isinstance(content, list):
            for teil in content:
                if isinstance(teil, dict):
                    gesamt += tokens(str(teil.get("text", "")))
                    if teil.get("image_url"):
                        gesamt += IMAGE_INPUT_TOKENS
        for call in message.get("tool_calls") or []:
            function = call.get("function", {}) if isinstance(call, dict) else {}
            gesamt += tokens(str(function.get("name", "")))
            gesamt += tokens(str(function.get("arguments", "")))
    return gesamt


class UsageLog:
    """Schreibt den Verbrauch mit und rechnet ihn zusammen."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self._lock = threading.Lock()
        self._setup()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _setup(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS usage (
                    day       TEXT NOT NULL,
                    model     TEXT NOT NULL,
                    tokens_in INTEGER NOT NULL DEFAULT 0,
                    tokens_out INTEGER NOT NULL DEFAULT 0,
                    calls     INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (day, model)
                )
                """
            )

    def record(self, model: str, tokens_in: int, tokens_out: int) -> None:
        """Traegt einen Aufruf ein. Fehler hier duerfen keine Antwort kosten."""
        if tokens_in <= 0 and tokens_out <= 0:
            return
        heute = date.today().isoformat()
        name = (model or "unbekannt").strip() or "unbekannt"
        try:
            with self._lock, self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO usage (day, model, tokens_in, tokens_out, calls)
                    VALUES (?, ?, ?, ?, 1)
                    ON CONFLICT(day, model) DO UPDATE SET
                        tokens_in = tokens_in + excluded.tokens_in,
                        tokens_out = tokens_out + excluded.tokens_out,
                        calls = calls + 1
                    """,
                    (heute, name, max(0, tokens_in), max(0, tokens_out)),
                )
        except sqlite3.Error:
            # Ein Zaehler, der die Antwort verhindert, waere die falsche
            # Reihenfolge der Wichtigkeit.
            pass

    def summary(self, days: int = 7) -> dict[str, Any]:
        """Heute, die letzten Tage, insgesamt -- und je Modell."""
        seit = (date.today() - timedelta(days=max(1, days) - 1)).isoformat()
        heute = date.today().isoformat()
        leer = {"tokens_in": 0, "tokens_out": 0, "calls": 0}
        try:
            with self._connect() as conn:
                gesamt = conn.execute(
                    "SELECT COALESCE(SUM(tokens_in),0) AS tokens_in, "
                    "COALESCE(SUM(tokens_out),0) AS tokens_out, "
                    "COALESCE(SUM(calls),0) AS calls FROM usage"
                ).fetchone()
                tag = conn.execute(
                    "SELECT COALESCE(SUM(tokens_in),0) AS tokens_in, "
                    "COALESCE(SUM(tokens_out),0) AS tokens_out, "
                    "COALESCE(SUM(calls),0) AS calls FROM usage WHERE day = ?",
                    (heute,),
                ).fetchone()
                fenster = conn.execute(
                    "SELECT COALESCE(SUM(tokens_in),0) AS tokens_in, "
                    "COALESCE(SUM(tokens_out),0) AS tokens_out, "
                    "COALESCE(SUM(calls),0) AS calls FROM usage WHERE day >= ?",
                    (seit,),
                ).fetchone()
                modelle = conn.execute(
                    "SELECT model, SUM(tokens_in) AS tokens_in, "
                    "SUM(tokens_out) AS tokens_out, SUM(calls) AS calls "
                    "FROM usage GROUP BY model ORDER BY (SUM(tokens_in)+SUM(tokens_out)) DESC "
                    "LIMIT 12"
                ).fetchall()
                verlauf = conn.execute(
                    "SELECT day, SUM(tokens_in) AS tokens_in, SUM(tokens_out) AS tokens_out "
                    "FROM usage WHERE day >= ? GROUP BY day ORDER BY day",
                    (seit,),
                ).fetchall()
        except sqlite3.Error:
            return {"today": leer, "window": leer, "total": leer, "models": [], "days": []}
        return {
            "chars_per_token": CHARS_PER_TOKEN,
            "today": dict(tag),
            "window": dict(fenster),
            "window_days": max(1, days),
            "total": dict(gesamt),
            "models": [dict(row) for row in modelle],
            "days": [dict(row) for row in verlauf],
        }

    def total_tokens(self) -> int:
        """Gesamtverbrauch fuer Quota und Kontenliste."""
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT COALESCE(SUM(tokens_in + tokens_out), 0) FROM usage"
                ).fetchone()
            return int(row[0] or 0)
        except sqlite3.Error:
            return 0


def kurz(zahl: Any) -> str:
    """Grosse Zahlen fuer Menschen: 1234567 -> "1,23 Mio".

    Bis 9.5.13 rechnete das der Browser; jetzt kommt der fertige Text vom
    Server.
    """
    try:
        n = float(zahl or 0)
    except (TypeError, ValueError):
        n = 0.0
    if n >= 1e9:
        return f"{n / 1e9:.2f}".replace(".", ",") + " Mrd"
    if n >= 1e6:
        return f"{n / 1e6:.2f}".replace(".", ",") + " Mio"
    if n >= 1e3:
        return f"{n / 1e3:.1f}".replace(".", ",") + " Tsd"
    return str(int(n))


def summary_view(summary: dict[str, Any]) -> dict[str, Any]:
    """Die Statistik als fertige Texte -- der Browser zeigt sie nur noch an."""
    kacheln = []
    for key, was in (("today", "Heute"),
                     ("window", f"Letzte {summary.get('window_days') or 7} Tage"),
                     ("total", "Insgesamt")):
        wert = summary.get(key) or {}
        rein, raus = int(wert.get("tokens_in") or 0), int(wert.get("tokens_out") or 0)
        kacheln.append({
            "wert": kurz(rein + raus),
            "was": f"{was} (Token)",
            "dazu": f"{kurz(rein)} hinein · {kurz(raus)} heraus · "
                    f"{int(wert.get('calls') or 0)} Aufrufe",
        })
    modelle = [
        f"{m.get('model')}: {kurz(int(m.get('tokens_in') or 0) + int(m.get('tokens_out') or 0))}"
        f" Token in {int(m.get('calls') or 0)} Aufrufen"
        for m in summary.get("models") or []
    ]
    return {
        "tiles": kacheln,
        "detail": ("Je Modell:\n" + "\n".join(modelle)) if modelle else "Noch nichts gezählt.",
    }
