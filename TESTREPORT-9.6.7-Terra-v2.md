# Prüfbericht: 9.6.7 Terra v2

Stand: 2026-10-04. Grundlage ist die gepushte 9.6.7 Terra (`61767b5`) auf
`Aquaticy-ai`. Paketversion bleibt `9.6.7`; der sichtbare Name lautet
`9.6.7 Terra v2`. Frühere Prüfberichte bleiben erhalten.

## Stichpunkte und Abdeckung

Der kontoeigene Recherchecache speichert neue zulässige Quellenaussagen als
einzelne Stichpunkte (`- Aussage`) mit ihrer öffentlichen Quelle. Es werden
Originalaussagen verwendet, keine generierten Zusammenfassungen, vollständigen
Antworten oder privaten Chattexte. Der gemeinsame Wissensspeicher behält seine
bisherige engere Quellenpolitik ohne Biografien.

Die Auswahl ist nicht mehr auf die ersten drei Sätze und Aussagen mit mehrfacher
Wortüberschneidung mit der ersten Antwort begrenzt. Stattdessen wird zunächst
geprüft, dass Artikelthema und Frage zusammenpassen und die geprüfte Antwort
inhaltliche Wortüberschneidungen mit dem gelesenen Artikel hat. Anschließend
werden die zulässigen Originalaussagen dieses Artikels geprüft und übernommen,
auch Aussagen, die in der ersten Antwort fehlen oder das Thema nur mit einem
Pronomen fortführen. Doppelte Punkte derselben Quelle werden aussortiert.

„Alle Informationen“ ist durch die vorhandenen Datenschutzfilter und Grenzen
beschränkt: höchstens sechs gelesene öffentliche Wikipedia-Artikel, je die
ersten 48.000 Zeichen beziehungsweise 300 Satzabschnitte, maximal 100 Punkte pro
Konto und 2.000 insgesamt. Es werden ausschließlich Originalaussagen von
60 bis 400 Zeichen übernommen. Kürzere oder längere Abschnitte, unzulässige
Quellen und gefilterte Inhalte werden ausgelassen; unbegrenzte oder semantisch
garantierte Vollständigkeit wird nicht behauptet. Lange Aussagen werden nicht
abgeschnitten: das könnte Einschränkungen oder Verneinungen entfernen.

Die Suchindizes enthalten zusätzlich die Wörter des Artikelthemas. Damit sind
auch Punkte wie „Er erhielt …“ über den Namen der Person auffindbar. Der Abruf
gewichtet die Fragebegriffe und ergänzt höchstens zwölf passende Punkte mit
zusammen höchstens 3.200 Zeichen einschließlich Stichpunktmarkierungen. Die
Quelle gehört zu jedem Punkt. Der Modellkontext verlangt weiterhin eine neue
Antwort, passende Faktenergänzung und Prüfung wichtiger oder aktueller Angaben;
es gibt keine Wiederholung einer gespeicherten Antwort und kein Modelltraining.

## Bestätigter Fehler und Kompatibilität

Die bisherige Satzzerlegung teilte Datumsangaben wie `14. März` und gängige
Abkürzungen wie `Dr.` oder `z. B.` auf. Dadurch konnten Angaben unvollständig
werden oder durch die Mindestlänge aus der Auswahl fallen. Die neue Zerlegung
hält Datumsangaben, Initialen, Abkürzungen und Dezimalwerte zusammen. Eine
Jahreszahl am Satzende verbindet nicht versehentlich den nächsten Satz.
Ein aus dem Quellentext eingeschleuster interner Platzhalter wird abgewiesen.

Bestehende Terra-Einträge werden beim Abruf ebenfalls als Stichpunkte geliefert,
behalten ihre Faktenkennung und ihre ursprüngliche Ablaufzeit. Der Vergleich
der entschlüsselten Aussage mit ihrer Schlüssel-Hash-Kennung unterstützt das
alte Format und das neue Stichpunktformat. Ein erneutes Übernehmen desselben
Fakts verlängert weiterhin keine Frist. Alte Einträge werden nicht pauschal
umgeschrieben oder neu datiert.

## Schutzregeln und Bedienung

Die Kontotrennung, AES-GCM-Verschlüsselung, zweckgetrennten Schlüssel-Hashes,
Quellenprüfung vor und nach Weiterleitung, private Begriffe, Geheimnis- und
Kontaktfilter, Ausschluss sensibler Personenangaben und Anweisungsprüfung
bleiben bestehen. Die konservativen Filter sind keine Garantie für sämtliche
Grenzfälle; Personeninformationen bleiben ausschließlich im eigenen Konto.
Die ursprüngliche Antwortprüfung erfolgt vor jeder Übernahme. Fehler, Abbruch,
Sicherheitsrücknahme, Widerruf und Kontoentfernung verhindern weitere Übernahmen.

Die feste Nutzungsfrist von 48 Stunden, Prüfung jeder Leseoperation,
automatische Bereinigung im laufenden Webserver, Löschung der Suchindizes und
Entfernung bei Widerruf beziehungsweise Daten-/Kontolöschung bleiben erhalten.
Bei ausgeschaltetem Server erfolgt die physische Bereinigung beim nächsten
Start. Bestehende Chatverläufe, Sicherungen und Verbund-Änderungsprotokolle
haben ihre eigenen Fristen; Löschungen auf anderen Servern gelten nach einem
erfolgreichen Abgleich.

Datenschutzerklärung und freiwillige Zustimmung beschreiben Stichpunkte und die
größere Auswahl; Rechtsversion `2026-10-04.3`. Vorherige Lern-Zustimmungen
aktivieren die erweiterte Übernahme nicht automatisch. Deutsche und englische
Bedienungstexte nennen das Stichpunktformat. Versionsanzeige, CLI, README und
Versionsprüfungen verwenden `9.6.7 Terra v2`.

## Prüfungen

- 11 neue Prüfungen: mehr als drei Fakten, nicht in der ersten Antwort enthaltene
  Aussagen, Pronomen ohne wiederholten Personennamen, Sachartikel, Verneinungen,
  Stichpunktformat im verschlüsselten Speicher, Kompatibilität mit Terra,
  ursprüngliche Ablaufzeit, Datum/Abkürzung/Dezimalwert, Jahreszahl am Satzende,
  Platzhalterabwehr, Inhaltsfilter, Speicher- und Kontextgrenzen.
- Zusammen mit den bestehenden Terra-, Luna- und Datenschutzprüfungen:
  **90 Tests bestanden**.
- Vollständige Testsuite (`pytest -q -ra`): **4.247 bestanden, 12 übersprungen,
  keine Fehler**, in **829,68 Sekunden**. Elf Prüfungen benötigen hier nicht
  vorhandene Desktop-/Add-on-Abbilder; eine DNS-Rebinding-Kontrollanfrage wird
  bereits vom Cloud-Proxy blockiert. Der vollständige Browser-Rundgang und die
  verfügbaren Docker-Sandbox-Prüfungen sind enthalten. Zwei unveränderte
  Pydantic-Warnungen betreffen ein `ReadOnly`-Feld einer Fremdbibliothek.
- Ruff und `git diff --check`: bestanden. CLI: `aquaticy 9.6.7 Terra v2`.
- `uv pip check`: 90 Pakete kompatibel. `pip-audit` mit PyPI: 89 Fremdpakete,
  keine bekannten Schwachstellen. Keine neuen Abhängigkeiten. Das lokale Projekt
  ist aus der Fremdpaketprüfung ausgenommen.
- `uv build`: Wheel und Quellarchiv erfolgreich erstellt. Alle **64**
  ausgelieferten Programmdateien stimmen bytegenau mit dem Arbeitsstand überein.
  Das Quellarchiv enthält die v2-Tests, den aktualisierten Benchmark und diesen
  Prüfbericht. Die Paketmetadaten verwenden weiterhin Version `9.6.7`.

## Aufwand

Der aktualisierte Offline-Benchmark `tools/benchmark_research_terra.py` füllt
eine temporäre verschlüsselte Datenbank mit 2.000 Punkten, davon 100 im eigenen
Konto. Bei 100 Abrufen beträgt der Median **2,226 ms**; je Abruf werden zwölf
Punkte mit 24 Entschlüsselungen geliefert. Datenbankgröße rund 22 MB. Terra
lieferte in der vorherigen Messung drei Punkte; die größere Ausgabe in v2 hat
entsprechend mehr lokalen Aufwand. Modell- und Netzlaufzeiten sind in dieser
Messung nicht enthalten. Es gibt keine zusätzlichen Modell- oder Netzaufrufe
für die Stichpunktauswahl. Die bestehenden Streaming-Optimierungen bleiben
unverändert enthalten.
