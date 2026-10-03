#!/usr/bin/env python3
"""Offline-Vergleich von Chat-Liste und -Suche auf denselben verschluesselten Daten.

Vom Repository aus: PYTHONPATH=. .venv/bin/python tools/benchmark_luna.py
Vergleicht den Arbeitsstand mit 9.6.5, ohne Anbieter oder private Daten.
Sieben Laufzeitmessungen (Median), separat tracemalloc fuer Python-Speicher.
"""

import argparse
import gc
import importlib.util
import json
import statistics
import subprocess
import sys
import tempfile
import time
import tracemalloc
from functools import partial
from pathlib import Path

from aquaticy.cache import Cache


def benchmark(baseline_ref: str) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        legacy_path = root / "legacy_cache.py"
        legacy_path.write_text(
            subprocess.check_output(["git", "show", f"{baseline_ref}:aquaticy/cache.py"], text=True)
        )
        spec = importlib.util.spec_from_file_location("legacy_cache", legacy_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        current = Cache(root / "data" / "cache.sqlite3")
        rows = []
        for chat in range(500):
            for turn in range(4):
                rows.append(
                    (
                        str(chat),
                        chat * 4 + turn,
                        current._seal(f"Frage {chat}/{turn}", "history.question"),
                        current._seal("Stichwort " + "Inhalt " * 1800, "history.answer"),
                        current._seal("{}", "history.meta"),
                    )
                )
        with current._connect() as conn:
            conn.executemany(
                "INSERT INTO history "
                "(session_id,created_at,question,answer,meta) VALUES (?,?,?,?,?)",
                rows,
            )
        rows.clear()
        legacy = module.Cache(current.db_path)
        results = {}
        for label, cache in [(baseline_ref, legacy), ("Arbeitsstand", current)]:
            results[label] = {}
            for operation, invoke in [
                ("Liste", partial(cache.recent_chats, 40)),
                ("Suche_Treffer", partial(cache.search_chats, "Stichwort", 40)),
                ("Suche_ohne_Treffer", partial(cache.search_chats, "Nichtvorhanden", 40)),
            ]:
                samples = []
                for _ in range(7):
                    start = time.perf_counter()
                    result = invoke()
                    samples.append(time.perf_counter() - start)
                gc.collect()
                tracemalloc.start()
                invoke()
                _, peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                results[label][operation] = {
                    "median_ms": round(statistics.median(samples) * 1000, 3),
                    "peak_python_mib": round(peak / 1024**2, 3),
                    "treffer": len(result),
                }
        print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-ref", default="8b4dae0")
    benchmark(parser.parse_args().baseline_ref)
