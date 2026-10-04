"""Opt-in learning from public source excerpts, never from private chat text.

The shared store supplies untrusted research material, not new model weights.
Contributor HMACs are retained solely for withdrawal/deletion. All text and
source URLs are encrypted; the bounded search index contains keyed hashes.
"""

from __future__ import annotations

import re
import secrets
import sqlite3
import time
import unicodedata
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import unquote, urlsplit

from aquaticy.injection import clean_text, suspicious
from aquaticy.legal import LEGAL_VERSION
from aquaticy.memory import secure_file
from aquaticy.privacy import ServerSecrets, key_root

MAX_FACTS = 2000
MAX_CONTRIBUTIONS = 200
LIFETIME = 30 * 86400
# Deliberately narrow: no biographies, user pages, medicine, weapons or news.
# Expanding this policy requires reviewing both privacy and poisoning risks.
TOPICS = frozenset(
    {
        "Wasser",
        "Photosynthese",
        "Gravitation",
        "Lichtgeschwindigkeit",
        "Sonnensystem",
        "Aggregatzustand",
        "Elektrischer_Widerstand",
        "Ohmsches_Gesetz",
        "Pythagoras-Satz",
        "Satz_des_Pythagoras",
        "Primzahl",
        "Bruchrechnung",
        "Binärsystem",
        "Dezimalsystem",
        "Algorithmus",
        "Sortierverfahren",
        "Datenstruktur",
        "Programmiersprache",
        "Python_(Programmiersprache)",
        "JavaScript",
        "HTML",
        "CSS",
        "Unicode",
        "UTF-8",
        "Water",
        "Photosynthesis",
        "Gravity",
        "Speed_of_light",
        "Solar_System",
        "State_of_matter",
        "Electrical_resistance_and_conductance",
        "Ohm's_law",
        "Pythagorean_theorem",
        "Prime_number",
        "Fraction",
        "Binary_number",
        "Decimal",
        "Algorithm",
        "Sorting_algorithm",
        "Data_structure",
        "Programming_language",
        "Python_(programming_language)",
    }
)
_WORDS = re.compile(r"[^\W\d_]{3,}", re.UNICODE)
_STOP = frozenset(
    [
        "der",
        "die",
        "das",
        "ein",
        "eine",
        "einer",
        "einem",
        "einen",
        "und",
        "oder",
        "ist",
        "sind",
        "wird",
        "werden",
        "mit",
        "von",
        "für",
        "aus",
        "als",
        "auf",
        "bei",
        "den",
        "dem",
        "des",
        "was",
        "wie",
        "warum",
        "welche",
        "welcher",
        "the",
        "and",
        "for",
        "from",
        "are",
        "that",
        "this",
        "with",
        "into",
        "its",
        "how",
        "what",
        "which",
        "explain",
        "erkläre",
        "bitte",
        "auch",
        "über",
        "kann",
        "durch",
        "nicht",
        "more",
        "about",
        "there",
        "their",
    ]
)
_PERSONAL = re.compile(
    r"@|https?://|www\.|\b\d{5,}\b|\b(?:ich|mein\w*|unser\w*|dein\w*|du|"
    r"we|our|your|you|my|born|geboren|gestorben|patient\w*|diagnos\w*|"
    r"passwor\w*|secret\w*|token\w*|api.?key|email|e-mail|adresse|address|"
    r"telefon\w*|phone|konto\w*|account\w*|wohn\w*)\b",
    re.IGNORECASE,
)
_INSTRUCTIONS = re.compile(
    r"[<>`{}]|\b(?:ignore|execute|run|send|upload|download|install|delete|"
    r"sudo|curl|wget|eval|exec|ignoriere|führe|sende|schicke|lösche|lade|"
    r"assistant|assistent|nutzer|benutzer|user|prompt|anweisung\w*)\b",
    re.IGNORECASE,
)


def words(text: str) -> set[str]:
    return {
        w for w in _WORDS.findall(unicodedata.normalize("NFKC", text).casefold()) if w not in _STOP
    }


def public_source(url: str) -> str:
    """Only exact HTTPS article URLs; no credentials, queries or hidden paths."""
    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.netloc not in {"de.wikipedia.org", "en.wikipedia.org"}
            or parsed.query
            or parsed.fragment
        ):
            return ""
        path = unquote(parsed.path)
        if not path.startswith("/wiki/") or path[6:] not in TOPICS:
            return ""
        return url
    except ValueError:
        return ""


def safe_excerpt(text: str, private: set[str] | None = None) -> bool:
    if not 80 <= len(text) <= 600 or clean_text(text) != text:
        return False
    normalized = unicodedata.normalize("NFKC", text)
    if suspicious(text) or _PERSONAL.search(normalized) or _INSTRUCTIONS.search(normalized):
        return False
    # Conservatively reject likely full names, long identifiers and controls.
    if re.search(r"\b[A-ZÄÖÜ][a-zäöüß]+\s+[A-ZÄÖÜ][a-zäöüß]+\b", normalized):
        return False
    if re.search(r"\b[A-Za-z0-9_/-]{32,}\b", normalized):
        return False
    if any(unicodedata.category(c).startswith("C") for c in text):
        return False
    folded = normalized.casefold()
    return not any(
        unicodedata.normalize("NFKC", p).casefold() in folded for p in private or () if len(p) >= 3
    )


SCHEMA = """
CREATE TABLE IF NOT EXISTS learning_consent (
    owner TEXT PRIMARY KEY, version TEXT NOT NULL, enabled INTEGER NOT NULL,
    epoch TEXT NOT NULL, at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS learning_facts (
    id TEXT PRIMARY KEY, text TEXT NOT NULL, source TEXT NOT NULL,
    created REAL NOT NULL, expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS learning_contributions (
    owner TEXT NOT NULL, fact TEXT NOT NULL, PRIMARY KEY(owner, fact));
CREATE TABLE IF NOT EXISTS learning_terms (
    term TEXT NOT NULL, fact TEXT NOT NULL, PRIMARY KEY(term, fact));
CREATE INDEX IF NOT EXISTS learning_contributions_fact ON learning_contributions(fact);
CREATE INDEX IF NOT EXISTS learning_terms_fact ON learning_terms(fact);
CREATE INDEX IF NOT EXISTS learning_facts_expires ON learning_facts(expires);
"""


class Learning:
    def __init__(self, profile: Path | str) -> None:
        root, owner = key_root(profile)
        root.mkdir(parents=True, exist_ok=True)
        self.path = root / "accounts.sqlite3"
        self.secrets = ServerSecrets(root)
        self.owner = self.secrets.blind("learning-owner", owner)
        self.account_id = owner if owner != "lokal" else ""
        with self.connect() as conn:
            conn.executescript(SCHEMA)
        secure_file(self.path)

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=5)
        try:
            conn.execute("PRAGMA secure_delete=ON")
            with conn:
                yield conn
        finally:
            conn.close()

    def ticket(self, conn=None) -> str:
        if conn is None:
            with self.connect() as current:
                return self.ticket(current)
        row = conn.execute(
            "SELECT epoch FROM learning_consent WHERE owner=? AND enabled=1 AND version=?",
            (self.owner, LEGAL_VERSION),
        ).fetchone()
        return str(row[0]) if row else ""

    def status(self) -> dict:
        with self.connect() as conn:
            self._expire(conn)
            count = conn.execute(
                "SELECT COUNT(*) FROM learning_contributions c "
                "JOIN learning_facts f ON f.id=c.fact "
                "WHERE c.owner=? AND f.expires>?",
                (self.owner, time.time()),
            ).fetchone()[0]
            return {
                "enabled": bool(self.ticket(conn)),
                "version": LEGAL_VERSION,
                "contributions": count,
            }

    @staticmethod
    def _prune(conn, now: float) -> None:
        conn.execute("DELETE FROM learning_facts WHERE expires<=?", (now,))
        conn.execute(
            "DELETE FROM learning_contributions WHERE fact NOT IN (SELECT id FROM learning_facts)"
        )
        conn.execute("DELETE FROM learning_terms WHERE fact NOT IN (SELECT id FROM learning_facts)")

    def _expire(self, conn) -> None:
        now = time.time()
        # Normal reads need no writer reservation.
        if conn.execute("SELECT 1 FROM learning_facts WHERE expires<=? LIMIT 1",
                        (now,)).fetchone():
            conn.execute("BEGIN IMMEDIATE")
            self._prune(conn, now)

    def set_consent(self, enabled: bool, version: str) -> dict:
        if type(enabled) is not bool or (enabled and version != LEGAL_VERSION):
            raise ValueError("Bitte bestätige die aktuelle Erklärung zum gemeinsamen Lernen.")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if (
                enabled
                and self.account_id
                and not conn.execute(
                    "SELECT 1 FROM users WHERE id=?", (self.account_id,)
                ).fetchone()
            ):
                raise ValueError("Das Konto existiert nicht mehr.")
            conn.execute(
                "INSERT OR REPLACE INTO learning_consent VALUES (?, ?, ?, ?, ?)",
                (self.owner, LEGAL_VERSION, int(enabled), secrets.token_hex(16), time.time()),
            )
            if not enabled:
                self._erase(conn)
        return self.status()

    def _erase(self, conn) -> None:
        conn.execute("DELETE FROM learning_contributions WHERE owner=?", (self.owner,))
        conn.execute(
            "DELETE FROM learning_facts WHERE id NOT IN (SELECT fact FROM learning_contributions)"
        )
        self._prune(conn, time.time())

    def forget(self, conn=None) -> None:
        if conn is not None:
            conn.execute("DELETE FROM learning_consent WHERE owner=?", (self.owner,))
            self._erase(conn)
            return
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self.forget(conn)

    def learn(
        self,
        ticket: str,
        question: str,
        answer: str,
        pages: list[tuple[str, str]],
        private: set[str] | None = None,
    ) -> int:
        """Select relevant original public sentences after the answer's safety check.

        No question, answer, chat ID or model-generated paraphrase is persisted.
        Fresh consent is checked under the same write lock as publication.
        """
        if (not ticket or _PERSONAL.search(unicodedata.normalize("NFKC", question))
                or suspicious(answer)):
            return 0
        query, used = words(question[:8000]), words(answer[:30000])
        candidates: list[tuple[str, str]] = []
        for url, body in pages[:6]:
            if not public_source(url) or suspicious(body):
                continue
            for sentence in re.split(r"(?<=[.!?])\s+|\n+", body[:48000])[:300]:
                if clean_text(sentence) != sentence:
                    continue
                text = " ".join(sentence.split())
                terms = words(text)
                if safe_excerpt(text, private) and terms & query and len(terms & used) >= 3:
                    candidates.append((text, url))
                if len(candidates) >= 3:
                    break
            if len(candidates) >= 3:
                break
        if not candidates:
            return 0
        count = 0
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if not secrets.compare_digest(ticket, self.ticket(conn)):
                return 0
            if (
                self.account_id
                and not conn.execute(
                    "SELECT 1 FROM users WHERE id=?", (self.account_id,)
                ).fetchone()
            ):
                return 0
            now = time.time()
            self._prune(conn, now)
            own = conn.execute(
                "SELECT COUNT(*) FROM learning_contributions WHERE owner=?", (self.owner,)
            ).fetchone()[0]
            total = conn.execute("SELECT COUNT(*) FROM learning_facts").fetchone()[0]
            for text, url in candidates:
                key = self.secrets.blind("learning-fact", url + "\n" + text)
                exists = conn.execute("SELECT 1 FROM learning_facts WHERE id=?", (key,)).fetchone()
                if own >= MAX_CONTRIBUTIONS or (not exists and total >= MAX_FACTS):
                    continue
                if not exists:
                    conn.execute(
                        "INSERT INTO learning_facts VALUES (?, ?, ?, ?, ?)",
                        (
                            key,
                            self.secrets.seal(text, "learning-text:" + key),
                            self.secrets.seal(url, "learning-source:" + key),
                            now,
                            now + LIFETIME,
                        ),
                    )
                    conn.executemany(
                        "INSERT INTO learning_terms VALUES (?, ?)",
                        [
                            (self.secrets.blind("learning-term", word), key)
                            for word in sorted(words(text))[:80]
                        ],
                    )
                    total += 1
                added = conn.execute(
                    "INSERT OR IGNORE INTO learning_contributions VALUES (?, ?)", (self.owner, key)
                ).rowcount
                count += added
                own += added
        return count

    def recall(self, question: str) -> list[dict[str, str]]:
        terms = sorted(words(question[:8000]))[:24]
        if not terms:
            return []
        hashes = [self.secrets.blind("learning-term", word) for word in terms]
        with self.connect() as conn:
            self._expire(conn)
            rows = conn.execute(
                "SELECT f.id,f.text,f.source FROM learning_terms t "
                "JOIN learning_facts f ON f.id=t.fact WHERE t.term IN ("
                + ",".join("?" for _ in hashes)
                + ") AND f.expires>? "
                "GROUP BY f.id ORDER BY COUNT(*) DESC,f.created DESC,f.id LIMIT 3",
                (*hashes, time.time()),
            ).fetchall()
        result = []
        for key, sealed, source in rows:
            # Revalidate after decrypting, including rows replicated from peers.
            text = self.secrets.open(sealed, "learning-text:" + key)
            url = self.secrets.open(source, "learning-source:" + key)
            if (
                safe_excerpt(text)
                and public_source(url)
                and secrets.compare_digest(
                    key, self.secrets.blind("learning-fact", url + "\n" + text)
                )
            ):
                result.append({"text": text, "source": url})
        return result
