"""Offline lookup benchmark at the research cache's global/owner limits.

Run: .venv/bin/python tools/benchmark_research_terra.py
Uses a temporary encrypted database; no user data or network requests.
"""

from __future__ import annotations

import json
import statistics
import tempfile
import time
from pathlib import Path

from aquaticy.learning import Learning, words
from aquaticy.legal import LEGAL_VERSION
from aquaticy.research import LIFETIME, MAX_CONTEXT_POINTS, MAX_OWN, MAX_TOTAL

SOURCE = "https://de.wikipedia.org/wiki/Albert_Einstein"
FACT = ("Albert Einstein war ein Physiker, dessen Arbeiten zur Relativitätstheorie "
        "und zum photoelektrischen Effekt die moderne Physik maßgeblich beeinflussten.")


def main():
    with tempfile.TemporaryDirectory(prefix="aquaticy-terra-benchmark-") as directory:
        store = Learning(Path(directory))
        store.set_consent(True, LEGAL_VERSION)
        now = time.time()
        with store.connect() as conn:
            for index in range(MAX_TOTAL):
                owner = store.owner if index < MAX_OWN else store.secrets.blind(
                    "learning-owner", "benchmark-" + str(index // MAX_OWN))
                text = FACT + " Beleg " + str(index) + "."
                key = store.secrets.blind("research-fact", owner + "\n" + SOURCE + "\n" + text)
                conn.execute("INSERT INTO research_facts VALUES (?,?,?,?,?,?)",
                             (owner, key, store.secrets.seal("- " + text, "research-text:" + key),
                              store.secrets.seal(SOURCE, "research-source:" + key),
                              now, now + LIFETIME))
                conn.executemany("INSERT INTO research_terms VALUES (?,?,?)",
                                 [(owner, store.secrets.blind("research-term", word), key)
                                  for word in sorted(words(text))[:80]])
        original = store.secrets.open
        decryptions = []

        def decrypt(value, aad):
            decryptions.append(aad)
            return original(value, aad)

        store.secrets.open = decrypt
        timings = []
        for _ in range(100):
            decryptions.clear()
            start = time.perf_counter()
            found = store.research.recall("Was erforschte Albert Einstein?")
            timings.append((time.perf_counter() - start) * 1000)
            assert len(found) == MAX_CONTEXT_POINTS
            assert len(decryptions) == 2 * MAX_CONTEXT_POINTS
        print(json.dumps({"global_facts": MAX_TOTAL, "account_facts": MAX_OWN,
                          "samples": len(timings), "median_ms": statistics.median(timings),
                          "returned_facts": len(found), "decryptions_per_lookup": len(decryptions),
                          "database_bytes": store.path.stat().st_size}, indent=2))


if __name__ == "__main__":
    main()
