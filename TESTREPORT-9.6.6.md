# Prüfbericht: 9.6.6 Luna

Stand: 3. Oktober 2026. Ausgangspunkt: `8b4dae0` ([9.6.5 Luna](TESTREPORT-9.6.5.md)).

## Übernahme des Arbeitsstands

Arbeitsbaum und Index waren sauber. Der lokale Branch `work` und der entfernte
Branch `Aquaticy-ai` zeigten auf `8b4dae0`. Auch im lokalen Reflog, unter
unerreichbaren Git-Objekten und in den verfügbaren Arbeitsverzeichnissen war
kein übernehmbarer Stand für 9.6.6 vorhanden. Änderungen aus einem anderen,
nicht erhaltenen Chat-Arbeitsbereich lassen sich hier nicht rekonstruieren.
Die bestehenden Änderungen von 9.6.5 bleiben erhalten.

## Geschwindigkeit

- Die Chat-Liste holt Zusammenfassungen, erste Frage, eigenen Titel und
  Ungelesen-Status mit einer SQL-Abfrage. Zuvor waren es bei 40 Chats
  82 Abfragen über zwei Verbindungen.
- Die Chat-Suche prüft die neuesten Chats zuerst, liest Fragen und Antworten
  schrittweise und endet am Trefferlimit. Sie lädt den gesamten Verlauf
  nicht mehr mit `fetchall` in den Python-Speicher. Titel, Fragen und Antworten,
  die älteste passende Fundstelle, Reihenfolge, Anzahl der Austausche und
  Ungelesen-Status bleiben berücksichtigt. Eine Suche ohne Treffer muss
  weiterhin alle Texte prüfen.
- Recherchehelfer, die dasselbe Cache-Objekt verwenden, warten bei gleichzeitigem
  Abruf derselben Seite auf dessen erste Befüllung. Danach verwenden sie das
  gespeicherte Ergebnis. Unterschiedliche Seiten und Profil-Caches blockieren
  sich nicht. Fehler geben die Sperre wieder frei; nicht gespeicherte Ergebnisse
  können wie bisher erneut abgerufen werden.
- Rechtsrahmen, Ai-guard, Schutz vor dem Abfluss privater Angaben,
  Prompt-Injection-Schutz, Netguard, robots.txt, Domain-Drossel,
  Gegenprüfungen, Kontingente, Modellwahl und Recherchebudgets bleiben aktiv.
  Jeder Werkzeugaufruf geht weiterhin durch seinen eigenen Prüf- und Buchungsweg.
  Der zweite Seitenzugriff wird gemäß der bestehenden Cache-Buchung behandelt.

Der reproduzierbare Offline-Benchmark in `tools/benchmark_luna.py` verwendet
500 erfundene Chats mit je vier verschlüsselten Austauschen und Antworten mit
rund 12.600 Zeichen. Verglichen werden dieselben Daten mit dem Cache-Code aus
`8b4dae0`. Laufzeiten sind der Median aus sieben Aufrufen; die Spitzenwerte
für Python-Speicher werden separat mit `tracemalloc` gemessen. Sie umfassen
nicht den gesamten Prozess oder SQLite-Speicher. Gemessen nach Abschluss
der Gesamtsuite:

| Ablauf | 9.6.5 (ms) | 9.6.6 (ms) | Python-Spitze 9.6.5 / 9.6.6 (MiB) |
|---|---:|---:|---:|
| Chat-Liste | 2.585 | 1.773 | 0.027 / 0.020 |
| Suche mit 40 Treffern | 65.520 | 7.627 | 39.266 / 0.171 |
| Suche ohne Treffer | 184.808 | 193.471 | 33.058 / 0.111 |

Die Suche mit vielen Treffern ist in diesem Fall rund 8,6-mal schneller.
Ohne Treffer ist die Laufzeit in diesem Messlauf rund 5 % höher, bei deutlich
geringerem Python-Speicherbedarf. Die Änderung beschleunigt also nicht
pauschal jeden Suchfall.

Das ist eine Messung dieser lokalen Abläufe, keine Zusage für die Gesamtdauer
echter Recherchen. Modellanbieter, Netz, Hardware und Ratenlimits beeinflussen
diese weiterhin. Das Zusammenführen doppelter Abrufe ist zusätzlich mit
synchronisierten Threads und einem echten Profil-Cache geprüft.

## Bestätigte Fehler und Datenschutz

- Suchbegriffe in Cache-Labels sowie Rechercheergebnisse lagen bislang im
  Klartext. Beide Spalten werden jetzt mit dem vorhandenen AES-GCM-Verfahren
  und dem jeweiligen Profilschlüssel verschlüsselt. Kopierte Werte aus einem
  anderen Profil oder einer anderen Spalte werden nicht akzeptiert; ein
  beschädigter Cache-Wert führt zum erneuten Abruf.
- Bestehende Cache-Einträge werden einmalig in begrenzten Gruppen migriert.
  Gleichzeitiges Öffnen desselben Profils serialisiert auch WAL-Einrichtung
  und Bereinigung und reserviert den Schreiber vor dem Lesen der Altwerte.
  Andere Profile bleiben unabhängig. Leere beschädigte Altwerte bleiben
  Cache-Misses und halten die Migration nicht auf. Der zusätzliche Verschlüsselungsbedarf zählt beim Schreiben und
  Migrieren zum bestehenden Speicherdeckel. Ohne Platz entfällt nur der
  ersetzbare Cache-Eintrag; Uploads werden dafür nicht gelöscht.
- Ein bloßes Überschreiben der Altwerte ließ nachweislich Klartextreste in
  SQLite-Overflow-Seiten zurück. Die Migration verdichtet deshalb die
  Datenbank einmalig und leert das WAL. Bei unterbrochener Bereinigung bleibt
  ein Marker für den nächsten Versuch. Tests prüfen auch die Bytes der Datei,
  große Altwerte, paralleles Öffnen und Wiederaufnahme der Bereinigung.
  Ein alter Suchbegriff, der selbst mit `enc2:` beginnt, wird ebenfalls
  verschlüsselt; das Präfix allein gilt nicht als Verschlüsselungsnachweis.
  Vorhandene externe Sicherungen werden nicht nachträglich verändert.
  Cache-Arten, Zeitangaben und gehashte Cache-Kennungen bleiben Metadaten.
- Nach einem neuen, geöffneten oder per `/clear` geleerten Chat konnte eine
  wiederverwendete Sitzung noch den Lauf des vorherigen Chats liefern.
  Der Laufpuffer wird beim Wechsel der Gesprächskennung nun verworfen.
  Laufende Hintergrundchats behalten ihre eigenen Puffer und Agenten.
- Nach Änderung der SearXNG-Adresse konnten Suchergebnisse der vorherigen
  Instanz aus dem Cache kommen. Die Instanzadresse gehört jetzt zum Cache-Key.
- Die Suche erkannte `STRASSE` in `Straße`, zeigte dazu aber keine Fundstelle.
  Die Fundstelle verwendet jetzt dieselbe Unicode-Faltung und berücksichtigt
  dabei die Position im Originaltext.
- Der Docker-Start erkannte die konkrete Meldung über fehlende Dateisystemquoten
  nicht und brach ab, obwohl es dafür bereits einen überwachten Fallback gibt.
  Die Meldung wird jetzt erkannt. Alle übrigen Containergrenzen bleiben gleich;
  der vorhandene Speicherwächter (Messung während Befehlen alle drei Sekunden)
  und die Schreibsperre bei Überschreitung bleiben aktiv. Andere Docker-Fehler führen weiterhin zum Abbruch. Beide echten
  Sandbox-Tests prüfen Schreibbarkeit, Netzsperre, unveränderliches
  Wurzeldateisystem und Pfadschutz.
- Der Testhelfer für den vollständigen Browser-Rundgang erkennt nun ebenso
  wie der Rundgang selbst den System-Chromium. Die Prüfung wird dadurch in
  dieser Umgebung auch innerhalb der Gesamtsuite ausgeführt.

Die Cache-Verschlüsselung schützt gespeicherte Daten; externe Such- und
Modellanbieter erhalten weiterhin die für den jeweiligen Auftrag notwendigen
Eingaben. Die erstmalige Migration braucht zusätzlichen Speicher für SQLite
und kann das erste Öffnen eines großen Profils verzögern.

## Validierung

- Erster Gesamtlauf auf dem vor den Korrekturen geladenen Python-Stand:
  **4.137 bestanden, 15 übersprungen**, 595,73 Sekunden.
- Gezielte Cache-, Werkzeug- und Verschlüsselungstests vor weiteren
  Korrekturen: **181 bestanden**.
- Gezielte Tests für 9.6.5 und 9.6.6 einschließlich Chromium:
  **19 bestanden** auf dem damaligen Stand.
- Migration unter Parallelität: zehn Durchläufe mit je acht gleichzeitigen
  Profilöffnungen bestanden.
- Abschließende Cache-, Werkzeug- und Verschlüsselungs-Nachtests:
  **201 bestanden**; einschließlich des zuletzt ergänzten Tests für ein
  wörtliches `enc2:`-Präfix in einem alten Suchbegriff.
- Nachtests für Cache-Migration, Sandbox und neue Regressionen:
  **138 bestanden**, einschließlich beider echten Docker-Sandbox-Tests.
- Vollständiger Browser-Rundgang: **402 Prüfungen, 0 Beanstandungen**,
  keine JavaScript- oder Konsolenfehler; Dienste und Modellantworten simuliert.
- Abschließende Gesamtsuite: **4.159 bestanden, 12 übersprungen, keine Fehler**
  in 796,26 Sekunden. Der vollständige Browser-Rundgang läuft jetzt auch
  innerhalb dieser Suite. Zwei Warnungen betreffen Pydantics Unterstützung
  des `ReadOnly`-Typhinweises. Elf ausgelassene Tests benötigen Desktop-/
  Add-on-Abbilder; eine DNS-Rebinding-Kontrollanfrage wird vom Cloud-Proxy
  gesperrt. Beide Docker-Sandbox-Tests werden tatsächlich ausgeführt und bestehen.
- Zusätzlicher Vergleich mit 9.6.5 auf gemischten Verläufen: 24 Suchfälle
  und die Chat-Liste liefern identische Ergebnisse.
- Ruff und `git diff --check`: erfolgreich.
- Installierte Abhängigkeiten: **90 Pakete kompatibel**.
- `pip-audit` über PyPI: **89 externe Pakete, keine bekannten
  Sicherheitsmeldungen**; das editierbar installierte eigene Paket wird
  vom Abhängigkeitsaudit ausgelassen und im Code/Testlauf geprüft.
- Quellarchiv und Wheel erfolgreich gebaut; Wheel enthält den Python-Code,
  die Weboberfläche und die Sicherheitsselektoren in Version 9.6.6.
- CLI zeigt `aquaticy 9.6.6 Luna`; Paket, README und Browser-Fallback sind
  auf denselben Versionsstand gesetzt.

Ein Zwischenlauf fand den neu ergänzten Test auf SQLite-Klartextreste als
Fehler (559 weitere Tests bestanden). Dieser Fund wurde durch die vollständige
Bereinigung behoben und mit allen neuen Regressionstests nachgeprüft. Weitere Nachtests
fanden die konkurrierende WAL-Einrichtung und den Docker-Quotenfehler; beide
sind korrigiert und vor der letzten Gesamtsuite gezielt nachgeprüft.

```bash
LITELLM_LOCAL_MODEL_COST_MAP=True .venv/bin/pytest -q --tb=short -ra
LITELLM_LOCAL_MODEL_COST_MAP=True .venv/bin/pytest tests/test_v966.py -q
LITELLM_LOCAL_MODEL_COST_MAP=True .venv/bin/python -u tools/rundgang.py
PYTHONPATH=. .venv/bin/python tools/benchmark_luna.py
.venv/bin/ruff check .
git diff --check
uv pip check --python .venv/bin/python
uvx pip-audit --path .venv/lib/python3.12/site-packages --skip-editable \
  --vulnerability-service pypi --format json
LITELLM_LOCAL_MODEL_COST_MAP=True .venv/bin/aquaticy --version
```

Live-Aufrufe echter Modellanbieter und bezahlte Rechercheaufrufe sind nicht
Teil dieser Prüfung. Die nicht verfügbaren Desktop-/Add-on-Integrationen und die vom
Cloud-Proxy blockierte DNS-Rebinding-Kontrollanfrage werden ausdrücklich als
nicht live validiert ausgewiesen.
