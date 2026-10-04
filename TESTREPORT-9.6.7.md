# Prüfbericht: 9.6.7 Luna

Stand: 4. Oktober 2026. Grundlage ist der bereits gepushte Stand 9.6.6 Luna
(`6cef7a5`) auf `Aquaticy-ai`. Seine Änderungen an Cache, Verschlüsselung,
Chatwechseln, parallelen Abrufen und Sandbox bleiben enthalten.

## Web-Leistung

Die Weboberfläche verarbeitete die gesamte bis dahin eingetroffene Antwort
bei jedem Streaming-Textstück erneut als Markdown und ersetzte ihr HTML.
Bei gebündelt eintreffenden Daten verursachte dies viele unnötige DOM- und
Scroll-Aktualisierungen. Jetzt werden diese Aktualisierungen pro
Bildschirmaktualisierung zusammengeführt. Der Textpuffer enthält weiterhin
jeden Teil in seiner ursprünglichen Reihenfolge. Abschluss, Abbruch,
Verbindungsende, Chatwechsel, Zwischennachricht und Sicherheitsrücknahme
leeren beziehungsweise beenden vorgemerkte Aktualisierungen passend.

Offline-Messung mit System-Chromium, sieben Wiederholungen, Median:

| Fall | Vorher | 9.6.7 |
|---|---:|---:|
| Block aus 1.000 Textstücken, 20.800 Zeichen | 250,3 ms | 0,7 ms |
| Markdown-Verarbeitungen einschließlich Abschluss | 1.001 | 1 |

Das fertige HTML war identisch. Die Messung benutzt den tatsächlichen
Markdown-Parser und den neuen Renderer, ohne Modellaufrufe oder Netzverkehr.
Reproduzierbar mit `.venv/bin/python tools/benchmark_streaming_luna.py`.
Der Gewinn betrifft gebündelte Streaming-Daten; einzeln langsam eintreffende
Teile und die Dauer externer Modellaufrufe werden dadurch nicht entsprechend
schneller. Im Browser wird normalerweise höchstens einmal pro Frame gemalt;
ein Abschluss wird sofort dargestellt, auch bei einem Hintergrund-Tab.

## Gemeinsames Lernen

Das neue Lernen ist ein gemeinsamer Quellen-Wissensspeicher, kein Training
der Modellgewichte. Eine gesonderte, standardmäßig ausgeschaltete Einwilligung
steht im Einstieg und unter Einstellungen → Gemeinsames Lernen. Bestehende
Datenschutz-Zustimmungen schalten die Funktion nicht ein. Die Rechtstextversion
ist `2026-10-04.1`; für zukünftige Änderungen muss die Übernahme neu erlaubt
werden. Die bisherige Website bleibt ohne diese freiwillige Zustimmung nutzbar.

- Der Agent prüft die Einwilligung zu Beginn eines Chatschritts und erneut
  beim Speichern unter der Datenbank-Schreibsperre. Eine neue Zustimmung
  während eines laufenden Chats gilt erst für den nächsten Chatschritt.
  Widerruf und erneute Zustimmung erzeugen eine andere Kennung; ein alter
  Lauf kann dadurch auch nach erneuter Zustimmung nichts mehr veröffentlichen.
- Nur erfolgreich über den bestehenden Seitenabruf gelesene Originaltexte
  ausgewählter HTTPS-Wikipedia-Sachartikel sind zugelassen. Sowohl angefragte
  als auch endgültige Adresse müssen passen. Zugangsdaten, zusätzliche Ports,
  Query-Parameter, Fragmente, andere Domains, Biografien und Nutzerseiten sind
  ausgeschlossen. Es gibt keine zusätzlichen Netzwerk- oder Modellaufrufe
  für das Übernehmen eines Auszugs.
- Kurze Original-Sätze werden nach Themenüberschneidung mit der aktuellen
  Frage und der fertigen Antwort gewählt. Private Fragen, Antworten, Uploads,
  Erinnerungen und Modell-Paraphrasen werden nicht in diesem Speicher abgelegt.
  Konservative Prüfungen schließen unter anderem persönliche Formulierungen,
  wahrscheinliche vollständige Namen, E-Mail-Adressen, lange Kennungen,
  bekannte private Angaben und erkennbare Anweisungen aus. Unicode-Normalisierung,
  unsichtbare Zeichen und bestehende Injection-Prüfungen sind berücksichtigt.
- Zurückgezogene, fehlgeschlagene und abgebrochene Antworten tragen nichts bei.
  Das Übernehmen läuft nach der vorhandenen Antwortprüfung. Die bestehenden
  Rechts- und Werkzeugprüfungen, SSRF- und Abflusssperren, Bestätigungen,
  Nutzungsgrenzen und Schutzregeln werden weiter ausgeführt.
- Spätere passende Fragen aller Konten dieser Installation erhalten höchstens
  drei Auszüge mit öffentlicher Quellenadresse, ausdrücklich als fremde Daten
  außerhalb des Systemprompts. Das gilt auch für den AI Council. Der bestehende
  Schutz nach fremden Inhalten wird aktiviert und im Chatverlauf vermerkt.
  Wichtige Angaben müssen erneut geprüft werden.
- Texte und Quellen sind mit AES-GCM verschlüsselt, auch im bestehenden
  verschlüsselten Server-Verbund. Der Suchindex enthält Schlüssel-Hashes.
  Kontozuordnungen für Widerruf enthalten ebenfalls Schlüssel-Hashes. Sie sind
  pseudonyme Verwaltungsdaten; vollständige Anonymität wird nicht behauptet.
- Ausschalten entfernt die eigenen Beitragszuordnungen und Auszüge ohne weitere
  unabhängige Beiträge. Daten- und Kontolöschung tun dies in derselben
  Datenbanktransaktion. Ein gelöschtes Konto kann keine neue Zustimmung erteilen.
  Gesperrte Konten können widerrufen, aber nicht neu aktivieren. Ihre Anmeldung
  allein aktiviert das Lernen ebenfalls nicht.
- Höchstens drei Übernahmen je Chatschritt, sechs für die Auswahl berücksichtigte gelesene
  Seiten, 200 Beiträge je Konto und 2.000 verschiedene Auszüge insgesamt.
  Bei vollem Speicher werden weitere Übernahmen ausgelassen. Auszüge verfallen
  nach 30 Tagen und werden beim nächsten Zugriff bereinigt. Der Verbund
  synchronisiert Einwilligung, Wissensdaten und Löschungen über seine vorhandene,
  authentifizierte Datenbankreplikation. Sicherungen und das vorhandene
  Änderungsprotokoll unterliegen weiterhin ihren Aufbewahrungsfristen.

Eine lokale Belastungsmessung mit 2.000 vorbereiteten, verschlüsselten Auszügen
und stark überlappenden Suchbegriffen ergab über 25 Aufrufe einen Median von
22,5 ms. Nur drei Treffer wurden zurückgegeben und dafür sechs Spalten
entschlüsselt, nicht der gesamte Wissensbestand. Die vorbereitete Datenbank
belegte rund 12 MB einschließlich der gehashten Suchindizes. Das ist eine
lokale Messung, kein allgemeines Laufzeitversprechen.

Die Funktion übernimmt absichtlich kein beliebiges Nutzerwissen aus privaten
Chats. Derzeit unterstützt sie nur die im Code überprüfbare Sachartikel-Auswahl
zu Mathematik, Naturwissenschaften und Informatik. Andere Chats tragen nichts
bei; Recherche ausschließlich durch Helfer liefert keine Übernahme, wenn der
Hauptagent selbst keine zugelassene Seite liest. Der Abruf sucht nach
gemeinsamen Wörtern und ist keine semantische oder automatische Übersetzungssuche.
Öffentliche Quellen und die Auswahl nach Themenwörtern können Fehler enthalten;
die Filter sind kein universelles Anonymisierungs- oder Wahrheitsbeweisverfahren.
Bereits erzeugte Antworten anderer Konten werden durch Widerruf nicht verändert.

## Bestätigte zusätzliche Fehler

- `/api/consent` wertete bisher auch `"false"` als wahr aus. Jetzt gilt allein
  der echte JSON-Wert `true` als Zustimmung. Herkunftsprüfung und sichere
  Cookie-Eigenschaften bleiben bestehen.
- Die Datenschutzseite nannte an einer Stelle scrypt, obwohl neue Passwörter
  bereits mit Argon2id verarbeitet werden. Der Text ist korrigiert; die
  kompatible Migration alter Passwort-Hashes bleibt erhalten.
- Einwilligung und sofort wirksamer Lern-Schalter haben unterschiedliche,
  passende Bedienelemente. Statusmeldungen sind für assistive Technik
  ausgezeichnet. Die neuen Bedienhinweise sind auch auf Englisch vorhanden.

## Validierung

- 38 neue Tests bestanden im gezielten Lauf: Einwilligung und Versionierung,
  Verschlüsselung, Index, Quellen- und Unicode-Regeln, private Angaben,
  Antwortprüfung, Abbruch, Limits, parallele Übernahme, Widerruf, Ablauf,
  Daten- und Kontolöschung, HTTP-Anmeldung, Herkunft und Server-Verbund.
- Echte Agenten mit simuliertem Modell prüfen den vollständigen Weg von
  Seitenabruf und Einwilligung über Übernahme bis zur nächsten Antwort eines
  anderen Kontos. Erst während eines Chats erteilte Zustimmung wird dabei
  ausdrücklich als zu spät für diesen Chatschritt geprüft.
- Chromium prüft die Bedienelemente, 1.000 gebündelte Streaming-Teile,
  Maskierung von HTML, Markdown, vollständigen Abschluss, Abbruch vorgemerkter
  Aktualisierungen und eine echte SSE-Sicherheitsrücknahme ohne Wiedererscheinen
  des zurückgezogenen Textes. Keine JavaScript-Fehler in diesen Prüfungen.
- Ein breiter Zwischenlauf bestand mit 806 Tests; eine alte UI-Prüfung musste
  die zusätzliche freiwillige Einwilligung berücksichtigen. Der sofort
  wirksame Schalter wurde entsprechend der bestehenden UI-Regel angepasst.
- Ein weiterer Gesamtlauf bestand mit 4.194 Tests; vier Test-Aufbauten
  erreichten das über mehrere Tests hinweg angesammelte Anmeldelimit.
  Die allgemeine Test-Isolation setzt nun auch diesen Zähler mit den gleichen
  acht Versuchen je Minute zurück. Die Produktionsgrenze bleibt unverändert.
  Der gemeinsame Folgelauf für 9.6.5–9.6.7 bestand mit **66 Tests**. Der
  Server-Testhelfer räumt jetzt auch bei einem Fehler vor dem Teststart auf.
- Abschließende vollständige Gesamtsuite: **4.198 bestanden, 12 übersprungen,
  keine Fehler**, in **848,09 Sekunden**. Der vollständige Browser-Rundgang
  ist enthalten. Beide echten Docker-Sandbox-Tests wurden ausgeführt.
  Elf ausgelassene Tests benötigen Desktop-/Add-on-Abbilder, eine
  DNS-Rebinding-Kontrollanfrage wird durch den Cloud-Proxy blockiert.
  Zwei Warnungen betreffen Pydantics Unterstützung des `ReadOnly`-Typhinweises.
- Ruff für `aquaticy`, `tests` und `tools` sowie `git diff --check` bestanden.
- `uv pip check`: 90 Pakete kompatibel. Keine neuen Abhängigkeiten.
- `pip-audit` mit PyPI: 89 Fremdpakete geprüft, keine bekannten Schwachstellen;
  die editierbare Aquaticy-Installation ist entsprechend als nicht geprüft markiert.
- Wheel und Quelldistribution wurden erfolgreich gebaut. Alle 63 enthaltenen
  Laufzeitdateien stimmen bytegenau mit dem finalen Arbeitsstand überein;
  Prüfbericht und neue Tests sind im Quellarchiv enthalten. CLI und
  installierte Paketmetadaten melden **9.6.7 Luna** beziehungsweise **9.6.7**.

Die Tests verwenden für externe Modellanbieter und öffentliche Webseiten
simulierte Antworten. Eine vollständige Prüfung echter Anbieterzugänge ist
damit nicht verbunden. Die oben genannten ausgelassenen Integrationen sind
entsprechend keine bestandenen Live-Prüfungen.
