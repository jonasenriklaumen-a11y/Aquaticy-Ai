# Prüfbericht: 9.6.8 Luna

Stand: 2026-10-05. Grundlage ist die gepushte **9.6.7 Terra v2**
(`1acc31c`) auf `Aquaticy-ai`. Der Ausgangsstand war sauber; die begonnenen
Änderungen früherer Fassungen waren dort bereits enthalten. Paketversion und
sichtbarer Name lauten jetzt `9.6.8` beziehungsweise `9.6.8 Luna`.

## Umfang

Die **59 Python-Module mit 45.936 Quellzeilen** wurden mit Ruff, Syntaxprüfung und Bandit untersucht;
die Suche nach Ein- und Ausgabepfaden, Dateizugriffen, SQL, Prozessaufrufen,
Deserialisierung und Netzwerkgrenzen umfasste alle Programmdateien. Vertieft
geprüft wurden Anmeldung und Kontotrennung, Verschlüsselung, Schlüsseldateien,
HTTP/CSRF, Serververbund, Quellenabruf, Exporte, fremde Produktdaten, freiwilliges
Lernen, Recherchefristen und die Verarbeitung von Sicherheitsurteilen.
Auch die Container-Konfiguration, Startskripte und Desktop-Helfer wurden geprüft.
Die Browser- und Sandbox-Prüfungen ergänzen diese Quellcodeprüfung.

Dies ist eine Prüfung auf nachvollziehbare Fehler und bekannte Schwachstellen,
keine Garantie, dass jede denkbare Lücke ausgeschlossen ist. Externe Dienste
und Modelle werden in den automatisierten Prüfungen überwiegend durch
kontrollierte Antworten ersetzt; echte Kundendaten werden nicht verwendet.

## Bestätigte Fehler und Korrekturen

- **Beschädigter Hauptschlüssel:** Eine bereits vorhandene leere `data.key`
  konnte als leerer Hauptschlüssel weiterverwendet und im Arbeitsspeicher
  zwischengespeichert werden. Der neue gemeinsame Lader prüft den tatsächlich
  gelesenen Schlüssel und bricht bei unzureichender Länge ab. Ein fehlgeschlagener
  Leseversuch wird nicht zwischengespeichert.
- **Ungewollter Schlüsselwechsel:** Zu kurze `auth.key`, Schlüsselbund-Geheimnisse
  und `memory.salt` sowie leere `memory.key` wurden still ersetzt. Das konnte
  Anmeldungen beziehungsweise vorhandene verschlüsselte Daten unzugänglich
  machen. Beschädigte Dateien bleiben nun unverändert erhalten und werden
  abgewiesen; Fernet-Schlüssel werden zusätzlich auf ihr Format geprüft.
- **Parallele Schlüsselerstellung:** Mehrere Prozesse konnten unterschiedliche
  Geheimnisse erzeugen oder einen noch unvollständig geschriebenen Schlüssel
  lesen. Neue Schlüssel werden in einer geschützten temporären Datei vollständig
  geschrieben und synchronisiert, anschließend ohne Überschreiben eines anderen
  Erstellers veröffentlicht. Auf Dateisystemen ohne Hardlinks serialisiert eine
  kleine SQLite-Sperrdatei die atomare Veröffentlichung. Sie enthält kein
  Schlüsselmaterial und bleibt zur Wiederverwendung bestehen. Fehlgeschlagene
  temporäre Dateien werden aufgeräumt. Gültige alte Schlüssel werden beibehalten.
- **Unicode-Passwörter:** Passwortänderungen mit Umlauten scheiterten am Vergleich
  zweier Unicode-Zeichenketten. Der konstante Vergleich erfolgt nun auf UTF-8-Bytes.
  Nicht kodierbare Unicode-Werte werden kontrolliert abgewiesen. Bei der Anmeldung
  bleibt die ausgleichende Argon2id-Arbeit auch für solche ungültigen Werte erhalten.
  Die Passwortgrenzen werden vor einer Kodierung geprüft.
- **Fehlerhafte HTTP-Eingaben:** Ein syntaktisch ungültiger Origin führte zu einem
  Serverfehler; ein ungültiges absolutes Anfrageziel konnte die Verarbeitung vor
  dem Fehlerauffangnetz abbrechen. Jetzt erfolgen kontrollierte Antworten mit
  Status 403 beziehungsweise 400 und den bestehenden Sicherheitskopfzeilen.
- **Vertrauliche Fehlerprotokolle:** Die Fehlerzeile enthielt den vollständigen
  Anfragepfad und den Ausnahmetext. Damit konnten URL-Zugangstokens oder vertrauliche
  Inhalte aus Ausnahmen ins Terminal geraten. Weiterhin protokolliert werden
  HTTP-Methode und Fehlerklasse; Pfad, Query und Ausnahmeinhalt werden ausgelassen.
  Die kontrollierte Fehlerantwort und die Erreichbarkeit des Servers bleiben.
- **Übermäßig verschachtelte Fremddaten:** Rekursive Produkt-JSON-LD-Daten führten
  reproduzierbar zu `RecursionError` und verhinderten die Erkennung eines gültigen
  Produkts derselben Seite. Stark verschachtelte Modellurteile konnten ebenfalls
  bei der Umwandlung ihres Rückmeldungstextes scheitern. HTTP, Verbundnachrichten,
  lokale Servererkennung, Produkt-JSON-LD und die betreffenden Sicherheitsparser
  verwenden jetzt eine gemeinsame Grenze von **64 JSON-Containern** vor dem
  eigentlichen Dekodieren. Die Grenze gilt unabhängig von Python-Version und
  Rekursionslimit. Fehlerhafte Quelldaten werden übersprungen; unlesbare
  Sicherheitsurteile bleiben unklar und erteilen keine neue Freigabe. Klammern
  und maskierte Anführungszeichen innerhalb von Text zählen nicht als Container.
  UTF-8, BOM, UTF-16 und UTF-32 bleiben unterstützt.
- **Rechner:** `0**-1` und andere negative Potenzen von null erzeugten einen
  ungefangenen Rechenfehler. Nun wird wie bei anderen Divisionen durch null
  `CalcError` zurückgegeben; AST-Positivliste und Exponentengrenzen bleiben.
- **Recherchezuordnung:** Bei einer ausdrücklich mit üblicher Großschreibung
  genannten anderen Person mit gleichem Nachnamen, etwa **Mileva Einstein** statt
  **Albert Einstein**, konnten fremde Fakten desselben Kontos ergänzt werden.
  Die Namensprüfung greift jetzt beim Lernen und Abrufen. Die Nachfrage nur mit
  Nachnamen bleibt möglich. Es handelt sich um eine konservative Textheuristik,
  keine vollständige semantische Personenauflösung.

- **Container-LAN-Schalter:** `aquaticy-box --lan` setzte nur eine von Compose
  nicht mehr ausgewertete Variable. Nun wird der vorhandene Zusatz
  `compose.host.yaml` tatsächlich bei Start, Build und Einrichtung ausgewählt.
  Die Argumente bleiben getrennt und maskiert; ohne `--lan` gilt das Standardnetz.

Bei beschädigten Schlüsseldateien ist die ursprüngliche Datei aus einer
Sicherung wiederherzustellen. Ein automatisch erzeugter Ersatz kann bereits
verschlüsselte Daten oder mit dem ursprünglichen Pfeffer erzeugte Passwort-Hashes
nicht wieder lesbar machen. Das Release rotiert gültige Schlüssel nicht und
ändert weder Verschlüsselungsformate noch die vorhandene Migration alter Daten.

## Schutzmaßnahmen und Funktionen

Argon2id-Parameter, konstante Geheimnisvergleiche, Sitzungsschutz und Widerruf
anderer Sitzungen, IP-/Gerätebindung, Kontotrennung, AES-GCM/Fernet,
zweckgebundene Schlüsselableitung und authentifizierte Verschlüsselung bleiben.
Ebenso erhalten bleiben CSRF-/Origin-Prüfung, CSP, Maskierung, SSRF-/Weiterleitungs-
und DNS-Prüfungen, Größen-/Zeit-/Kontingentgrenzen, Sandbox-Isolation,
Home-Assistant-Freigaben, Rechtsprüfung und Ai-guard.

Gemeinsames Quellenwissen, kontoeigene Recherche-Stichpunkte, freiwillige aktuelle
Zustimmung, private Inhaltsfilter, feste 48-Stunden-Frist und Löschung bei Widerruf
oder Kontoentfernung bleiben enthalten. Es werden keine privaten Chattexte für
andere Konten freigegeben und keine Modellgewichte trainiert. Die bestehenden
Streaming- und Suchoptimierungen bleiben erhalten. Die Verarbeitung wird nicht
um neue Datenzwecke erweitert; die aktuelle Lern-Zustimmung bleibt gültig.

## Einordnung automatischer Befunde

Bandit meldet **110 Hinweise**: 88 niedrig, 21 mittel und einen hohen Hinweis.
Die SQL-Hinweise betreffen gebundene Werte beziehungsweise feste oder maskierte
Schema-/Tabellennamen. Die XML-Feed-Verarbeitung weist DTD und Entitäten bereits
über den Parser ab, einschließlich anderer Zeichenkodierungen. Hinweise auf
LAN-Bindung und Sandbox-Verzeichnisse entsprechen den bestehenden Funktionen.
Es wurden keine Prüfregeln oder Fundstellen pauschal unterdrückt.

Der verbleibende hohe Hinweis betrifft `verify=False` bei der **Titel-Erkennung
privater IPv4-Geräte**. Dort werden bewusst auch Geräte mit selbstsignierten
Zertifikaten erkannt. Der Aufruf überträgt keine Anmeldedaten, folgt keinen
Weiterleitungen, verwendet keinen Umgebungsproxy und hat Größen-/Zeitgrenzen.
Diese bestehende Funktion bleibt; der gelesene Gerätename ist kein verifizierter
Identitätsnachweis. Die Zertifikatsprüfung für normale Quellen, APIs und
Zugangsdaten wird nicht abgeschaltet.

Drei SHA-1-Anwendungen im Serververbund erzeugen ausschließlich unveränderte
Trigger-/Dateinamen, keine Signaturen oder Authentifikatoren. Sie sind nun
explizit als `usedforsecurity=False` gekennzeichnet, damit Python sie auch in
entsprechend konfigurierten FIPS-Umgebungen als Namensbildung verwenden kann.
Die eigentliche Verbundauthentifikation und Verschlüsselung bleiben unverändert.

## Prüfungen

- **41 neue Regressionstests** prüfen beschädigte und vorhandene Schlüssel,
  Wiederherstellung, acht gleichzeitig erstellende Threads und sechs unabhängige
  Prozesse, jeweils mit und ohne Hardlinks, temporäre Dateibereinigung, Unicode-
  Passwörter und Sitzungswiderruf, konstante Ersatzarbeit, Potenzen von null,
  fehlerhafte HTTP-Ziele und Origin, JSON-Tiefe/Zeichenkodierungen/Maskierungen,
  vertrauliche Fehlerprotokolle, Erkennung des nächsten gültigen Verbundpakets,
  fehlerhafte authentifizierte Nachrichten, Produkt- und Sicherheitsparser sowie
  unterschiedliche Personen mit gleichem Nachnamen.
- Gezielte Durchläufe: **249** bestehende Konten-/Verschlüsselungs-/Sicherheitstests,
  **105** Schlüssel-/Verbund-/Recherchetests, **164** Eingabe-/Produkt-/Kontentests
  und **220** Tests der Sicherheitsparser und zugehörigen Funktionen bestanden.
  Diese Durchläufe überschneiden sich; die Zahlen sind nicht zu addieren.
- Vollständige Suite (`pytest -q -ra`): **4.288 bestanden, 12 übersprungen,
  keine Fehler**, in **833,86 Sekunden**. Der Browser-Rundgang und die verfügbaren
  Docker-Sandbox-Prüfungen sind enthalten. Elf weitere Prüfungen benötigen nicht
  vorhandene Desktop-/Add-on-Abbilder; eine DNS-Rebinding-Kontrollanfrage wird
  bereits vom Cloud-Proxy blockiert. Zwei unveränderte Pydantic-Warnungen betreffen
  ein `ReadOnly`-Feld einer Fremdbibliothek. Ausgeführt unter Linux/Python 3.12;
  der Hardlink-Ersatz wurde zusätzlich simuliert, echte Windows-/FAT-Systeme
  waren nicht verfügbar.
- Ruff für Programmcode, Tests und Werkzeuge, AST- und Bytecode-Prüfung aller
  59 Python-Module sowie `git diff --check`: bestanden. Startskripte und
  Desktop-Helfer: Syntaxprüfung bestanden. Fünf simulierte Docker-Aufrufe prüfen
  Standardstart, LAN-Start, Build, LAN-Build und LAN-Einrichtung einschließlich
  eines Arguments mit Leerzeichen.
- CLI: `aquaticy 9.6.8 Luna`. `uv pip check`: **90 Pakete kompatibel**.
  `pip-audit` mit PyPI: **89 Fremdpakete, keine bekannten Schwachstellen**.
  Keine neuen Paketabhängigkeiten; das lokale Projekt ist aus der Fremdpaket-
  Schwachstellenprüfung ausgenommen.
- `uv build`: Wheel und Quellarchiv erfolgreich erstellt. Alle **65 ausgelieferten
  Programmdateien** stimmen bytegenau mit dem Arbeitsstand überein. Paketmetadaten:
  `9.6.8`. Das Quellarchiv enthält den neuen JSON-Lader, die Regressionstests,
  den korrigierten Starter und diesen abgeschlossenen Prüfbericht.

## Lokaler Aufwand

Der bestehende Offline-Recherchebenchmark (`tools/benchmark_research_terra.py`)
verwendet 2.000 globale und 100 kontoeigene Fakten. Bei 100 Abrufen liegt der
Median bei **2,269 ms**, mit zwölf Punkten und 24 Entschlüsselungen je Abruf;
Datenbankgröße **22.056.960 Bytes**. Der neue JSON-Lader benötigt in einem
separaten lokalen Durchlauf etwa **0,048 ms** für 4 KB und **3,144 ms** für
256 KB Textdaten. Es entstehen keine zusätzlichen Modell- oder Netzaufrufe.
Diese Messungen liefen parallel zu den Tests und sind keine garantierten
Laufzeiten auf anderen Rechnern.
