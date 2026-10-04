"""Account-scoped, opt-in research excerpts with a fixed 48-hour lifetime.

No generated answers or private chat facts are stored. Public biographies are
allowed here, never in the shared learning store. All reads enforce expiry.
"""

from __future__ import annotations

import re
import secrets
import threading
import time
import unicodedata
from urllib.parse import unquote, urlsplit

from aquaticy.injection import clean_text, suspicious
from aquaticy.learning import _INSTRUCTIONS, words

LIFETIME = 2 * 86400
MAX_OWN = 100
MAX_TOTAL = 2000
MAX_CONTEXT_POINTS = 12
MAX_CONTEXT_CHARS = 3200
SCHEMA = """
CREATE TABLE IF NOT EXISTS research_facts (
    owner TEXT NOT NULL, id TEXT NOT NULL, text TEXT NOT NULL, source TEXT NOT NULL,
    created REAL NOT NULL, expires REAL NOT NULL, PRIMARY KEY(owner,id));
CREATE TABLE IF NOT EXISTS research_terms (
    owner TEXT NOT NULL, term TEXT NOT NULL, fact TEXT NOT NULL,
    PRIMARY KEY(owner,term,fact));
CREATE INDEX IF NOT EXISTS research_expiry ON research_facts(expires);
CREATE INDEX IF NOT EXISTS research_created ON research_facts(created);
CREATE INDEX IF NOT EXISTS research_terms_fact ON research_terms(owner,fact);
"""
# Names and ordinary public biographical dates are permitted; contacts, private
# claims, secrets and sensitive personal categories are deliberately excluded.
_PRIVATE = re.compile(
    r"@|https?://|www\.|\b\d{5,}\b|\b(?:ich|mein\w*|unser\w*|dein\w*|du|"
    r"we|our|your|you|my|passwor\w*|secret\w*|token\w*|api.?key|email|"
    r"e-mail|adresse|address|telefon\w*|phone|konto\w*|account\w*|wohn\w*|"
    r"patient\w*|diagnos\w*|krank\w*|disease\w*|health|gesund\w*|"
    r"religio\w*|politisch\w*|political|partei\w*|party|sex\w*|"
    r"ethni\w*|rass\w*|race|straft\w*|criminal|verurteilt|convicted)\b",
    re.IGNORECASE,
)


def source_url(url: str) -> str:
    """Only HTTPS Wikipedia mainspace articles, including biographies."""
    try:
        p = urlsplit(url)
        title = unicodedata.normalize("NFKC", unquote(p.path)[6:]) if (
            p.path.startswith("/wiki/")) else ""
        if (p.scheme != "https" or p.netloc not in {"de.wikipedia.org", "en.wikipedia.org"}
                or p.query or p.fragment or not title or len(title) > 180
                or any(c in title for c in ":/\\@?#") or title in {".", ".."}
                or "%" in title or any(unicodedata.category(c).startswith("C") for c in title)):
            return ""
        return url
    except ValueError:
        return ""


def matches_subject(url: str, query: set[str]) -> bool:
    title = unquote(urlsplit(url).path[6:]).split("(")[0].replace("_", " ").strip()
    tokens = words(title)
    last = words(title.split()[-1]) if title else set()
    return bool(tokens and (tokens <= query or last & query))


def safe_text(text: str, private: set[str] | None = None) -> bool:
    if not 60 <= len(text) <= 400 or clean_text(text) != text or suspicious(text):
        return False
    normalized = unicodedata.normalize("NFKC", text)
    if _PRIVATE.search(normalized) or _INSTRUCTIONS.search(normalized):
        return False
    if (re.search(r"\b[A-Za-z0-9_/-]{32,}\b", normalized)
            or any(unicodedata.category(c).startswith("C") for c in text)):
        return False
    return not any(unicodedata.normalize("NFKC", p).casefold() in normalized.casefold()
                   for p in private or () if len(p) >= 3)


def sentences(body: str) -> list[str]:
    """Keep dates, initials, decimal values and common abbreviations intact.

    Only existing source sentences are used. No generated summaries, clause
    chopping or ellipses that could discard a qualification or negation.
    """
    if "\ue000" in body[:48000]:
        return []  # Never reinterpret a source-supplied control/private-use marker.
    def protect(match):
        return match[0].replace(".", "\ue000")
    protected = re.sub(
        r"\b(?:[A-ZÄÖÜ]|Dr|Prof|Mr|Mrs|Ms|bzw|ca|vgl|z|B|d|h)\.(?=\s)",
        protect, body[:48000],
    )
    protected = re.sub(
        r"\b(?:[12]?\d|3[01])\.(?=\s*(?:Januar|Februar|März|April|Mai|Juni|Juli|"
        r"August|September|Oktober|November|Dezember|January|February|March|May|June|"
        r"July|October|December)\b)", protect, protected,
    )
    return [part.replace("\ue000", ".")
            for part in re.split(r"(?<=[.!?])\s+|\n+", protected)[:300]]


class ResearchCache:
    def __init__(self, store):
        self.store = store
        with store.connect() as conn:
            conn.executescript(SCHEMA)

    @staticmethod
    def prune(conn, now: float) -> None:
        conn.execute("DELETE FROM research_facts WHERE expires<=? OR created<=?",
                     (now, now - LIFETIME))
        conn.execute("DELETE FROM research_terms WHERE NOT EXISTS "
                     "(SELECT 1 FROM research_facts f WHERE f.owner=research_terms.owner "
                     "AND f.id=research_terms.fact)")

    def erase(self, conn) -> None:
        conn.execute("DELETE FROM research_facts WHERE owner=?", (self.store.owner,))
        conn.execute("DELETE FROM research_terms WHERE owner=?", (self.store.owner,))

    def sweep(self) -> float:
        """Delete expired material and return the next maintenance delay."""
        with self.store.connect() as conn:
            now = time.time()
            if conn.execute("SELECT 1 FROM research_facts WHERE expires<=? OR created<=? LIMIT 1",
                            (now, now - LIFETIME)).fetchone():
                conn.execute("BEGIN IMMEDIATE")
                self.prune(conn, now)
            row = conn.execute("SELECT MIN(MIN(expires,created+?)) FROM research_facts",
                               (LIFETIME,)).fetchone()
        return min(60.0, max(0.01, row[0] - time.time())) if row[0] else 60.0

    def learn(self, ticket, question, answer, pages, private=None) -> int:
        if (not ticket or _PRIVATE.search(unicodedata.normalize("NFKC", question))
                or suspicious(question) or suspicious(answer)):
            return 0
        query, used = words(question[:8000]), words(answer[:30000])
        candidates = []
        seen = set()
        for url, body in pages[:6]:
            if not source_url(url) or suspicious(body):
                continue
            # The title must match a nontrivial query token: avoids accumulating
            # unrelated people merely mentioned in a researched article.
            if not matches_subject(url, query):
                continue
            if len(words(body[:48000]) & used) < 3:
                continue  # The successful answer must actually concern this source.
            for sentence in sentences(body):
                if clean_text(sentence) != sentence:
                    continue
                text = re.sub(r"^[-•*]\s+", "", " ".join(sentence.split()))
                if safe_text(text, private) and (text, url) not in seen:
                    candidates.append((text, url))
                    seen.add((text, url))
                if len(candidates) >= MAX_OWN:
                    break
            if len(candidates) >= MAX_OWN:
                break
        if not candidates:
            return 0
        store = self.store
        count = 0
        with store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if not secrets.compare_digest(ticket, store.ticket(conn)):
                return 0
            if store.account_id and not conn.execute("SELECT 1 FROM users WHERE id=?",
                                                     (store.account_id,)).fetchone():
                return 0
            now = time.time()
            self.prune(conn, now)
            own = conn.execute("SELECT COUNT(*) FROM research_facts WHERE owner=?",
                               (store.owner,)).fetchone()[0]
            total = conn.execute("SELECT COUNT(*) FROM research_facts").fetchone()[0]
            for text, url in candidates:
                key = store.secrets.blind("research-fact", store.owner + "\n" + url + "\n" + text)
                if own >= MAX_OWN or total >= MAX_TOTAL:
                    break
                if conn.execute("SELECT 1 FROM research_facts WHERE owner=? AND id=?",
                                (store.owner, key)).fetchone():
                    continue  # Repeated questions do not extend the original deadline.
                conn.execute("INSERT INTO research_facts VALUES (?,?,?,?,?,?)",
                             (store.owner, key, store.secrets.seal("- " + text,
                                                                  "research-text:" + key),
                              store.secrets.seal(url, "research-source:" + key),
                              now, now + LIFETIME))
                conn.executemany("INSERT INTO research_terms VALUES (?,?,?)",
                                 [(store.owner, store.secrets.blind("research-term", word), key)
                                  for word in sorted(words(text) | words(
                                      unquote(urlsplit(url).path[6:]).replace("_", " ")))[:80]])
                own += 1
                total += 1
                count += 1
        return count

    def recall(self, question: str) -> list[dict[str, str]]:
        store = self.store
        terms = sorted(words(question[:8000]))[:24]
        if not terms:
            return []
        with store.connect() as conn:
            if not store.ticket(conn):
                return []
            now = time.time()
            if conn.execute("SELECT 1 FROM research_facts WHERE expires<=? OR created<=? LIMIT 1",
                            (now, now - LIFETIME)).fetchone():
                conn.execute("BEGIN IMMEDIATE")
                self.prune(conn, now)
            hashes = [store.secrets.blind("research-term", w) for w in terms]
            rows = conn.execute(
                "SELECT f.id,f.text,f.source,f.created,f.expires FROM research_terms t "
                "JOIN research_facts f ON f.owner=t.owner AND f.id=t.fact "
                "WHERE t.owner=? AND t.term IN (" + ",".join("?" for _ in hashes) + ") "
                "AND f.expires>? AND f.created+?>? GROUP BY f.id "
                "ORDER BY COUNT(*) DESC,f.created DESC,f.id LIMIT ?",
                (store.owner, *hashes, now, LIFETIME, now, MAX_OWN)).fetchall()
        result = []
        characters = 0
        for key, sealed, source, created, expires in rows:
            text = store.secrets.open(sealed, "research-text:" + key)
            url = store.secrets.open(source, "research-source:" + key)
            # Old Terra rows keep their identifiers and original expiry. New
            # rows store the bullet marker; its removal must still authenticate.
            valid = secrets.compare_digest(key, store.secrets.blind(
                "research-fact", store.owner + "\n" + url + "\n" + text))
            if not valid and text.startswith("- "):
                text = text[2:]
                valid = secrets.compare_digest(key, store.secrets.blind(
                    "research-fact", store.owner + "\n" + url + "\n" + text))
            if (min(expires, created + LIFETIME) > time.time() and safe_text(text)
                    and source_url(url) and matches_subject(url, set(terms))
                    and valid):
                bullet = "- " + re.sub(r"^[-•*]\s+", "", text)
                if characters + len(bullet) > MAX_CONTEXT_CHARS:
                    continue
                result.append({"text": bullet, "source": url})
                characters += len(bullet)
                if len(result) >= MAX_CONTEXT_POINTS:
                    break
        return result


def start_cleanup(cache: ResearchCache):
    """One stoppable maintenance thread per running web server."""
    stop = threading.Event()

    def run():
        while not stop.is_set():
            try:
                delay = cache.sweep()
            except Exception:
                delay = 5.0  # Expiry is still enforced by every read on failure.
            stop.wait(delay)

    worker = threading.Thread(target=run, daemon=True, name="aquaticy-research-cleanup")
    worker.start()
    return stop, worker
