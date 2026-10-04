# Prüfbericht: 9.6.7 Terra

Stand: 2026-10-04. Grundlage: die bereits gepushte 9.6.7 Luna (`8f696df`).
Branch: `Aquaticy-ai`.

## Ergänzung

Ein kontogetrennter Recherchecache ergänzt das vorhandene gemeinsame Wissen.
Bei aktueller, freiwilliger Zustimmung unter Einstellungen → Gemeinsames Lernen
übernimmt er höchstens drei kurze Originalauszüge aus tatsächlich gelesenen
öffentlichen Wikipedia-Artikeln pro erfolgreichem Chat. Biografien sind hier
erlaubt, im gemeinsamen Wissen weiterhin ausgeschlossen. Maximal 100 Fakten pro
Konto und 2.000 insgesamt; keine neuen Abhängigkeiten und keine weiteren
Modellaufrufe für Auswahl oder Abruf.

Es werden weder Fragen noch vollständige Antworten kopiert. Der aktuelle
Fragebezug und Wortüberschneidungen mit der geprüften Antwort wählen passende
Quellensätze aus. Ein neuer Chat bekommt höchstens drei passende Fakten samt
Quelle als ergänzendes, ausdrücklich unvertrauenswürdiges Recherchematerial
außerhalb des Systemprompts. Die Anweisung verlangt eine neue Antwort auf die
aktuelle Frage, Nachrecherche fehlender Informationen und Prüfung wichtiger oder
aktueller Angaben. Es handelt sich um Recherchekontext, kein Modelltraining.
Die tatsächliche Antwortformulierung bleibt Aufgabe des ausgewählten Modells.

## Datenschutz und Sicherheit

- Der neue Cache ist ausschließlich dem beitragenden Konto zugänglich. Ein
  anderes Konto erhält dessen Personeninformationen auch mit eigener Zustimmung
  nicht. Der gemeinsame Speicher behält seine bisherige engere Quellenpolitik.
- AES-GCM schützt Texte und Quellen; Konto, Suchbegriffe und Faktenkennungen
  werden mit zweckgetrennten Schlüssel-Hashes indexiert. Die Faktenkennung
  bindet Konto, Text und URL zusammen. Entschlüsselung und Quellenprüfung
  wiederholen sich beim Abruf.
- Nur exakte HTTPS-Artikeladressen auf `de.wikipedia.org` und
  `en.wikipedia.org`; keine Zugangsdaten, Ports, Abfragen, Fragmente,
  Namensräume, Pfadtraversierung oder verschleierten Steuerzeichen. Sowohl
  ursprüngliche als auch endgültige Adresse müssen zugelassen sein.
- Kontakte, erkennbare Geheimnisse, private Angaben, bekannte private Begriffe,
  sensible Personenangaben, Anweisungen und verdächtige Quellentexte werden
  ausgeschlossen. Unicode-Normalisierung erfasst unter anderem verschleierte
  E-Mail-Zeichen und HTML. Diese Filter sind konservativ und können weder jede
  sensible Angabe erkennen noch Vollständigkeit garantieren; deshalb bleiben
  Personeninformationen im eigenen Konto und werden nicht gemeinsam geteilt.
- Übernahmen erfolgen erst nach unveränderter Sicherheitsprüfung der Antwort.
  Abbruch, Fehler oder Sicherheitsrücknahme verhindern das Speichern. Der
  Einwilligungsstand zu Beginn des Chats und eine erneute Prüfung unter der
  Schreibsperre verhindern Übernahmen nach zwischenzeitlichem Widerruf oder
  Kontoentfernung. Neu zustimmen legitimiert keinen alten Chatschritt.
- Datenschutzerklärung und Einwilligung wurden auf `2026-10-04.2` aktualisiert.
  Die freiwillige Zustimmung nennt beide Speicher ausdrücklich. Vorherige
  Lern-Zustimmungen aktivieren die Erweiterung nicht. Deutsche und englische
  Bedienungstexte sowie der Status mit Anzahl eigener Cache-Fakten sind ergänzt.
- Authentifizierung, Origin-Prüfungen, Kontosperren, SSRF-Regeln, Tool-Gates,
  Antwortprüfung, Maskierung, Streaming-Sicherheitsrücknahmen und Sandbox-Regeln
  bleiben bestehen. Es gibt keine öffentliche Schreibschnittstelle für
  ungeprüfte Fakten.

## Feste Frist und Löschung

Ein Auszug ist ab seiner ersten Übernahme höchstens 172.800 Sekunden nutzbar.
Doppelte Übernahmen verlängern die Frist nicht. Jeder Abruf prüft sowohl die
gespeicherte Ablaufzeit als auch `created + 48 Stunden`; eine verlängerte
Ablaufspalte allein verlängert die Nutzung nicht. Abgelaufene Einträge und ihre
Suchindizes werden gelöscht. Ein eigener, stoppbarer Wartungsfaden bereinigt den
Cache auch ohne neue Chats und plant die nächste Ablaufzeit ein. Bei einem
ausgeschalteten Prozess erfolgt die physische Bereinigung beim nächsten Start;
kein Abruf verwendet abgelaufene Fakten. Betriebssystemplanung oder
Datenbanksperren können die physische Bereinigung verzögern.

Widerruf, „Alle Daten löschen“ und „Konto löschen“ entfernen auch diesen Cache.
Der bestehende authentifizierte Server-Verbund repliziert ihn für dasselbe Konto;
andere Konten bleiben ausgeschlossen. Löschungen gelten auf einem anderen Server
nach dessen erfolgreichem Abgleich. Bereits erzeugte Antworten, Sicherungen und
das verschlüsselte Verbund-Änderungsprotokoll behalten ihre eigenen Fristen. Die
48-Stunden-Frist bezieht sich auf den aktiven Recherchecache, nicht auf diese
separaten Datenbestände.

## Prüfung

- 38 neue gezielte Tests bestanden: Kontotrennung, Verschlüsselung,
  Namenszuordnung, feste Frist mit Grenzzeitpunkt, Indexlöschung, manipulierte
  Ablaufzeit und verschlüsselte Spalten, Widerruf, Konto-/Datenlöschung,
  konkurrierende Übernahmen, Größenlimits, sensible Inhalte, Unicode,
  Quellenpolitik, Weiterleitungen, Turn-Reset, Abbruch/Fehler/Antwortprüfung,
  automatisches Aufräumen ohne Chat und sauberer Fadenstopp. Ein tatsächlicher
  Agent-Chat recherchiert; ein frischer Agent-Chat verwendet die Fakten für
  eine andere Antwort. Modell und externe Quelle sind dabei simuliert.
- Zusammen mit der Luna-Lern- und Streaming-Prüfung: 76 Tests bestanden.
- Weitere bestehende Versions-, Datenschutz-, Schlüssel- und Browserprüfungen:
  147 Tests bestanden. Überschneidungen mit der vorigen Gruppe sind enthalten.
- Ein zusätzlicher lokaler Verbundversuch mit zwei Konten bestätigt Abruf für
  dasselbe Konto auf einem zweiten Server, Ausschluss des anderen Kontos und
  vollständige Entfernung nach repliziertem Widerruf.
- Vollständige Testsuite (`pytest -q -ra`): **4.236 bestanden, 12 übersprungen,
  keine Fehler**, in **832,62 Sekunden**. Elf Tests benötigen hier nicht
  vorhandene Desktop-/Add-on-Abbilder; bei einem DNS-Rebinding-Test blockiert
  der Cloud-Proxy bereits die ungeschützte Kontrollanfrage. Der vollständige
  Browser-Rundgang sowie die verfügbaren Docker-Sandbox-Prüfungen sind enthalten.
  Zwei unveränderte Warnungen stammen von Pydantics Behandlung eines
  `ReadOnly`-Feldes einer eingebundenen Fremdbibliothek.
- Ruff und `git diff --check`: bestanden. CLI: `aquaticy 9.6.7 Terra`.
- `uv pip check`: 90 Pakete kompatibel. `pip-audit` mit PyPI: 89 Fremdpakete,
  keine bekannten Schwachstellen. Das lokale Projekt ist wie üblich aus der
  Fremdpaketprüfung ausgenommen.
- `uv build`: Wheel und Quellarchiv erfolgreich erstellt. Alle **64**
  ausgelieferten Programmdateien stimmen bytegenau mit dem Arbeitsstand überein;
  `research.py` und Paketversion `9.6.7` sind enthalten. Das Quellarchiv enthält
  außerdem die Terra-Tests, den neuen Benchmark und diesen Prüfbericht.

## Aufwand

`tools/benchmark_research_terra.py` füllt eine temporäre verschlüsselte Datenbank
bis zum globalen Limit von 2.000 Fakten, davon 100 im eigenen Konto. Bei 100
Abrufen: Median **0,884 ms**, drei Fakten und genau sechs Entschlüsselungen je
Abruf, Datenbank rund 22 MB. Die Suche verwendet den kontobezogenen Hash-Index;
andere Konten werden nicht entschlüsselt. Laufzeitmessungen gelten für diese
Testumgebung und diesen lokalen Abruf.

Die bestehende Streaming-Optimierung bleibt erhalten. Ein erneuter Offline-Test
mit 1.000 gleichzeitig eintreffenden Textstücken und 20.800 Zeichen liefert
identisches finales HTML: bisheriges vollständiges Rendern pro Stück 374,3 ms,
gebündeltes Rendern 0,8 ms (je Median aus sieben Läufen). Das misst einen
Textburst, keine allgemeine Modell- oder Netzwerkbeschleunigung.
