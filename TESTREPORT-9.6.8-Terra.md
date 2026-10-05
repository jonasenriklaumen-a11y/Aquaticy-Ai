# Prüfbericht: 9.6.8 Terra

Stand: 2026-10-05. Grundlage ist die gepushte **9.6.8 Luna**
(`5c28b42`) auf `Aquaticy-ai`. Der Ausgangsstand war sauber; die zuvor
begonnenen Änderungen waren darin enthalten. Paketversion: **9.6.8**;
sichtbarer Release-Name: **9.6.8 Terra**. Der Luna-Prüfbericht bleibt erhalten.

## Umfang und Vorgehen

Alle **59 Python-Module mit 46.041 Quellzeilen** wurden erneut mit Ruff,
Syntaxprüfung und Bandit untersucht. Die vertiefte Prüfung betraf insbesondere
Anmeldung, Passwortmigration und Sitzungswiderruf bei konkurrierenden Zugriffen,
Netzwerkweiterleitungen, Schlüsseldateien, fremde JSON-Daten sowie die bestehenden
Konten-, Datenschutz-, Recherche-, Browser- und Sandbox-Funktionen.
Bestätigte Fehler wurden zunächst reproduziert und anschließend mit zusätzlichen
Regressionstests abgesichert. Die vollständige Suite prüft auch die übrigen
Funktionen; Tests wurden nicht entfernt oder Sicherheitsregeln unterdrückt.

Diese Prüfung weist nachvollziehbare Fehler und bekannte Paketlücken nach;
sie garantiert nicht, dass jede denkbare Schwachstelle ausgeschlossen ist.
Externe Dienste und Modelle werden überwiegend durch kontrollierte Antworten
ersetzt. Echte Kundendaten wurden nicht verwendet.

## Bestätigte Fehler und Korrekturen

- **Anmeldung während eines Passwortwechsels:** Ein bereits geprüftes altes
  Passwort konnte nach dessen Änderung noch eine neue Sitzung erzeugen.
  Konten erhalten jetzt intern einen kontogebundenen HMAC-Nachweis der geprüften
  Passwortversion. Die Sitzungserstellung vergleicht diesen Nachweis innerhalb
  einer SQLite-Schreibtransaktion mit dem aktuellen Datensatz. Veraltete oder
  gelöschte Konten werden abgewiesen. Der Nachweis ist kein Passwort-Hash und
  erscheint weder in öffentlichen Kontoantworten noch in der Konto-Darstellung.
  Der HTTP-Anmeldeweg antwortet kontrolliert mit 401; bei diesem Fehler werden
  weder ein Sitzungscookie noch ein neuer Nutzer-Scheduler erzeugt.
- **Konkurrierende Passwortänderungen und Teilfehler:** Passwortprüfung und
  Aktualisierung waren getrennt; der Sitzungswiderruf folgte in einer weiteren
  Transaktion. Jetzt werden die geprüfte Passwortversion erneut verglichen,
  das Passwort aktualisiert und andere Sitzungen innerhalb derselben
  Schreibtransaktion widerrufen. Ein Fehler beim Widerruf rollt auch die
  Passwortänderung zurück. Eine ausdrücklich beibehaltene Sitzung bleibt gültig.
  Teure neue Passwortberechnungen erfolgen vor dem Erwerb der Schreibsperre.
- **Migration alter Passwort-Hashes:** Die automatische Umstellung eines alten
  scrypt-Hashes konnte einen gleichzeitig gesetzten neuen Hash überschreiben.
  Die Aktualisierung erfolgt jetzt nur, solange Hash und Salt noch dem geprüften
  Datensatz entsprechen. Hat ein anderer Anmeldevorgang dasselbe Passwort bereits
  migriert, wird der aktuelle Hash erneut geprüft: Beide gültigen Anmeldungen
  bleiben möglich; eine echte Passwortänderung gewinnt.
- **Zugangsdaten bei Weiterleitungen:** Der manuelle, SSRF-geschützte Abruf
  übernahm Client- beziehungsweise Anfrage-Header bei einem Wechsel zu einem
  anderen Ursprung erneut. Jetzt werden Authorization, Proxy-Authorization,
  Cookie und die unterstützten API-Schlüssel-Header entfernt; Client-Auth und
  Zugangsdaten in der URL werden nicht weitergereicht. Das gilt auch bei
  HTTPS-Abstieg und Portwechsel und bleibt für die restliche Kette wirksam.
  Gleichursprüngliche Weiterleitungen und der normale HTTP-zu-HTTPS-Aufstieg
  derselben Domain behalten die Authentifikation. Explizit für das Ziel gültige
  Cookie-Jar-Einträge bleiben unterstützt; rohe beziehungsweise ungebundene
  Cookies werden nicht übertragen. Bei HTTPS-Abstieg werden alle Cookies
  zurückgehalten. DNS-, SSRF-, Größen-, Zeit- und Weiterleitungsgrenzen bleiben.
- **Windows-Hardlink-Fehler:** Der bestehende atomare Schlüssellader erkannte
  bestimmte Windows-Fehler für fehlende Hardlink-Unterstützung beziehungsweise
  fehlende Berechtigungen nicht. Die Fehlercodes 1, 50 und 1314 aktivieren nun
  ebenfalls den vorhandenen SQLite-geschützten Ersatzweg. Andere E/A-Fehler
  werden weiterhin abgewiesen; vorhandene Geheimnisse werden nicht ersetzt.
- **Ungültige Unicode-Kontofelder:** Nicht kodierbare Surrogatzeichen in
  E-Mail-Adresse oder Nutzername konnten bis zur Schlüsselableitung oder
  Datenbank gelangen und Serverfehler erzeugen. Sie werden nun vor diesen
  Schritten kontrolliert abgewiesen. Gültige Unicode-Zeichen bleiben erlaubt.
- **Weitere unbeschränkte Modell-JSON-Pfade:** Tool-Argumente, Verlaufskorrektur
  und Rechercheplanung verwenden jetzt ebenfalls den vorhandenen JSON-Lader
  mit maximal 64 Container-Ebenen. Ein zusätzlicher begrenzter Ein-Wert-Decoder
  erhält die Unterstützung mehrerer aneinandergehängter Tool-Aufrufe und bereits
  gültiger Präfixe. Maskierte Anführungszeichen und Klammern in Text zählen nicht
  als Verschachtelung. Unlesbare Werte führen zu den bestehenden kontrollierten
  Rückfällen; sie erzeugen keine neue Sicherheitsfreigabe.

## Erhaltene Funktionen und Datenschutz

Argon2id-Parameter und Ersatzarbeit, konstante Geheimnisvergleiche,
Geräte-/IP-Bindung, Kontotrennung, Sitzungswiderruf, Verschlüsselung und
Schlüsselmigration bleiben bestehen. Ebenso erhalten bleiben CSRF-/Origin-
Prüfung, CSP, SSRF/DNS-Schutz, Streaming, Suche, Kontingente, Sandbox,
Home-Assistant-Freigaben, Rechtsprüfung und Ai-guard.

Das freiwillige gemeinsame Quellenwissen und die kontoeigenen Recherche-
Stichpunkte bleiben enthalten. Die Recherche-Stichpunkte verfallen weiterhin
nach höchstens 48 Stunden; Widerruf und Kontoentfernung löschen die zugehörigen
Daten. Private Chattexte werden nicht für andere Konten freigegeben, und es
werden keine Modellgewichte trainiert. Die Verarbeitung erhält keinen neuen
Datenzweck; die vorhandene Lern-Zustimmung und Rechtsversion bleiben unverändert.
Die Korrekturen erzeugen keine zusätzlichen Modell- oder Netzaufrufe und senken
weder Verschlüsselungs- noch Passwortparameter.

## Automatische Befunde und Grenzen

Bandit meldet **111 Hinweise**: **89 niedrig, 21 mittel, einen hohen**;
37.203 Zeilen wurden dabei ausgewertet. SQL-Hinweise betreffen gebundene Werte
beziehungsweise feste oder maskierte Schema-/Tabellennamen. Die XML-Feed-
Verarbeitung weist DTD und Entitäten bereits ab. Hinweise auf LAN-Bindung und
Sandbox-Verzeichnisse entsprechen bestehenden Funktionen. Kein Befund wurde
pauschal durch eine neue Unterdrückungsregel ausgeblendet.

Der hohe Hinweis betrifft die bestehende Titel-Erkennung privater IPv4-Geräte
mit `verify=False`, damit selbstsignierte Geräte erkannt werden können. Der
Aufruf überträgt keine Anmeldedaten, folgt keinen Weiterleitungen, verwendet
keinen Umgebungsproxy und hat Größen-/Zeitgrenzen. Der erkannte Gerätename
ist kein verifizierter Identitätsnachweis. Normale Quellen und APIs behalten
ihre Zertifikatsprüfung. Diese verbleibende Einschränkung ist unverändert.

## Prüfungen

- **31 neue Regressionstests bestanden** in 3,28 Sekunden. Sie prüfen
  konkurrierende Änderungen über unabhängige AuthStore-Verbindungen, alte
  Passwortmigration, zwei parallele gültige Altanmeldungen, Transaktionsabbruch,
  kontogebundene Nachweise, einen echten HTTP-Anmeldeablauf während eines
  Passwortwechsels, ungültiges Unicode, simulierte Windows-Fehler,
  Herkunftswechsel mit verschiedenen Authentifikationswegen, Cookie-Zuordnung,
  HTTPS-Abstieg, SSRF-Abbruch und begrenzte Modellargumente einschließlich
  aneinandergehängter gültiger Tool-Aufrufe.
- Ergänzende Konten-/Netzwerk-/Schlüssel-Regressionen: **381 bestanden,
  eine übersprungen**, zwei unveränderte Warnungen; die gezielten Durchläufe
  überschneiden sich und ihre Zahlen sind nicht zu addieren.
- Vollständige Suite (`pytest -q -ra`): **4.319 bestanden, 12 übersprungen,
  keine Fehler**, in **866,79 Sekunden**. Browser-Rundgang und verfügbare
  Docker-Sandbox-Prüfungen sind enthalten. Elf weitere Tests benötigen nicht
  vorhandene Desktop-/Add-on-Abbilder; die Kontrollanfrage einer DNS-Rebinding-
  Prüfung wird bereits vom Cloud-Proxy blockiert. Zwei unveränderte Pydantic-
  Warnungen betreffen ein `ReadOnly`-Feld einer Fremdbibliothek.
- Ruff für Programmcode, Tests und Werkzeuge, AST-/Bytecode-Prüfung aller
  59 Python-Module und `git diff --check`: bestanden.
- Zusätzlich stimmen 5.000 mit festem Zufalls-Seed erzeugte JSON-Werte mit
  dem Standardparser überein, einschließlich maskierter Zeichen und Endpositionen
  beim Lesen aus einem größeren Text. CLI: `aquaticy 9.6.8 Terra`.
- `uv pip check`: **90 Pakete kompatibel**. `pip-audit` mit PyPI:
  **89 Fremdpakete, keine bekannten Schwachstellen**. Keine neuen Abhängigkeiten;
  das lokale Projekt ist aus der Fremdpaket-Schwachstellenprüfung ausgenommen.
- `uv build`: Wheel und Quellarchiv erfolgreich erstellt. Alle **65 ausgelieferten
  Programmdateien** stimmen bytegenau mit dem Arbeitsstand überein. Paketmetadaten:
  `9.6.8`; Codename: `Terra`. Das Quellarchiv enthält die neuen Regressionstests,
  die aktuelle README und diesen abgeschlossenen Bericht.

Die Windows-Fehler wurden unter Linux/Python 3.12 simuliert; echte Windows-/FAT-
Systeme standen nicht zur Verfügung. Externe reale Modellantworten sind damit
nicht vollständig abgedeckt.

## Lokale Effizienzprüfung

Der bestehende Offline-Recherchebenchmark (`tools/benchmark_research_terra.py`)
mit 2.000 globalen und 100 kontoeigenen Fakten ergab bei 100 Abrufen einen
Median von **4,221 ms**, zwölf Punkten und 24 Entschlüsselungen je Abruf;
Datenbankgröße **22.122.496 Bytes**. Die Messung lief parallel zur vollständigen
Testsuite. Sie ist keine garantierte Laufzeit und wegen unterschiedlicher Last
kein kontrollierter Geschwindigkeitsvergleich mit dem Luna-Durchlauf.
Die begrenzte Rechercheauswahl und vorhandenen Streaming-Optimierungen bleiben.
Neue Passwort-Hashes werden außerdem außerhalb der AuthStore-Sperre berechnet,
auch bei der Migration alter Hashes. Andere Kontenzugriffe müssen dadurch nicht
auf diese rechenintensive Arbeit unter derselben Prozesssperre warten. Die
entscheidenden Vergleiche und Änderungen bleiben transaktional geschützt;
die Rechenkosten von Argon2id werden nicht reduziert.
