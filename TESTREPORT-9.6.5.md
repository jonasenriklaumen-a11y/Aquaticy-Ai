# Prüfbericht: 9.6.5 Luna

Stand: 2. Oktober 2026. Baut auf [9.6.4 Aqua](TESTREPORT-9.6.4-Aqua.md) auf.

## Schnellere Recherche im Normalmodus

- Geplante Recherchen werden im Normalmodus nur noch bis auf drei statt sechs
  Teilaufgaben aufgefüllt. Alle tatsächlich vom Planer gelieferten Teilfragen
  bleiben erhalten. Das spart zusätzliche Agenten- und Modellrunden,
  insbesondere bei lokalen Modellen und begrenzten Anbieterraten.
- Zusammenhängende Gruppen ausschließlich lesender Werkzeugaufrufe laufen
  auch dann parallel, wenn die Modellrunde zusätzlich einen schreibenden
  Aufruf enthält. Vor jedem Schreiben wird auf alle vorherigen Leseaufrufe
  gewartet; anschließend beginnt erst die nächste Gruppe. Antwortzuordnung
  und Reihenfolge bleiben erhalten.
- Beide Änderungen gelten ausschließlich für den Arbeitsmodus `normal`.
  Der Pro-Modus und der Code-Modus behalten ihre bisherige Recherchelogik,
  Werkzeugsortierung, Budgets, Modellwahl und Zeitlimits. Die Denktiefe und
  die gewünschte Gegenprüfung werden nicht geändert.

Ein kontrollierter Vergleich mit vier simulierten Lesezugriffen und einem
dazwischenliegenden Schreibzugriff ergab ca. **0,061 Sekunden im Normalmodus**
gegen **0,120/0,121 Sekunden in Pro/Code**. Die Tests prüfen zusätzlich die
tatsächliche gleichzeitige Ausführung und die Schreibgrenze. Das ist ein
Vergleich dieses Ablaufs, kein Versprechen einer halbierten Gesamtdauer:
echte Geschwindigkeit hängt auch von Modell, Hardware, Suchanbieter,
Quellen und Ratenbegrenzungen ab.

## Chatwechsel während einer Recherche

Die bisherige Sperre galt für das ganze Konto und einen gemeinsamen Agenten.
Der Browser lehnte zusätzlich jeden Chatwechsel während einer Antwort ab.
Jetzt behalten Hintergrundchats ihren eigenen Agenten, Laufpuffer, Abbruch
und Rückfragen. Neue Chats werden unabhängig gestartet; gespeicherte Chats
können während einer Recherche geöffnet und weitergeführt werden.

Der Browser nennt den gewählten Chat bei Chat-Anfragen ausdrücklich mit
`X-Aquaticy-Chat`. Dadurch sind auch Anfragen aus unterschiedlichen Tabs
ihrem Chat zugeordnet. Der Server akzeptiert ausschließlich Chats, die zur
angemeldeten Sitzung beziehungsweise ihrem eigenen Profil gehören.

Beim Wechsel endet nur die Anzeige der alten Antwort. Die Recherche läuft
weiter; beim Zurückkehren wird der Lauf erneut gelesen. Einträge noch laufender
Chats erscheinen bereits vor der ersten fertigen Antwort in der Seitenleiste.
Entwürfe und noch nicht gesendete Anhänge bleiben während des Chatwechsels
im Browser erhalten. Ein Neuladen der Seite setzt diese lokalen Entwürfe zurück.

## Fehler- und Sicherheitsprüfung

- Veraltete Stream-Ereignisse, Fehler und Antworten dürfen nach dem Wechsel
  weder im neuen Chat erscheinen noch dessen Eingabesperre lösen.
- Der Stop-Knopf stoppt nur den im Browser ausgewählten Chat.
- Ein fremder oder unbekannter Chat-Header liefert einen Fehler und keine
  fremden Laufdaten.
- Laufende Hintergrundchats dürfen nicht gelöscht werden. Gelöschte, fertige
  Chats werden auch aus dem Agentenspeicher entfernt, damit ihr Kontext nicht
  über einen alten Header wieder benutzt werden kann.
- Beim Löschen eines Kontos werden alle seine Hintergrundagenten angehalten
  und geschlossen. Der Verbund zählt diese Läufe mit und verweigert den
  Profilumzug, solange noch eine Antwort läuft.
- Der Speicher für zusätzliche Chat-Sitzungen ist auf 16 Einträge begrenzt.
  Laufende oder noch abholbare Antworten werden bei der Bereinigung behalten.
- Änderungen an Kontoeinstellungen werden auch den anderen Chat-Agenten
  mitgeteilt; laufende Antworten bauen ihren Agenten danach neu auf.

Die neuen Tests verwenden einen echten HTTP-Server mit getrennten
Chat-Agenten und gezielt angehaltenen Antworten. Zwei Chromium-Szenarien
prüfen das Schreiben in B während A recherchiert, den Abschluss von A im
Hintergrund, die Rückkehr zur laufenden beziehungsweise fertigen Antwort,
erhaltene Entwürfe und eine fehlerfreie JavaScript-Konsole. Modellantworten
und externe Recherchen werden dabei simuliert.

## Validierung

- Neue HTTP-, Chromium- und Reihenfolgetests: **8 bestanden**.
- Gezielte Agenten- und Verbund-Nachtests: **248 bestanden**.
- Feature-Rundgang über HTTP für Normal-, Pro- und Ultra-Konten: **9 bestanden**.
  Der Testhelfer unterscheidet jetzt die neue Chat-Kennung im SSE-Transport
  von fachlichen Antwort- und Sicherheitsereignissen. Der erste Gesamtlauf
  hatte drei Fehler wegen seiner bisherigen Annahme, das erste Ereignis sei
  bereits ein Antwortfehler; die eigentlichen Sicherheitsprüfungen bleiben
  erhalten und bestehen nach der Anpassung.
- Ruff, `git diff --check`, CLI-Versionsanzeige und lokaler
  Abhängigkeitsabgleich: erfolgreich, 90 Pakete kompatibel.
- Vollständiger Browser-Rundgang: **402 Prüfungen, keine Beanstandungen**,
  keine JavaScript- oder Konsolenfehler. Die Testattrappe wurde dabei auf
  getrennte Chat-Kennungen und eigene Agenten umgestellt; der erste Versuch
  mit ihrer bisherigen gemeinsamen Kennung konnte den neuen Ablauf nicht
  korrekt nachbilden und wurde nach der Anpassung vollständig wiederholt.
- Abschließende Gesamtsuite: **4.137 bestanden, 15 übersprungen, keine Fehler**
  in 538,29 Sekunden. Zwei Warnungen betreffen Pydantics Unterstützung des
  `ReadOnly`-Typhinweises. 13 übersprungene Tests benötigen Docker-Dienste oder
  vorbereitete Images. Ein älterer Browser-Testhelfer erkennt den vorhandenen
  System-Browser nicht; dessen kompletter Rundgang wurde separat ausgeführt.
  Der DNS-Rebinding-Browsertest kann seine ungeschützte Kontrollanfrage wegen
  einer Cloud-Proxy-Sperre nicht ausführen und bleibt hier nicht validiert.

```bash
LITELLM_LOCAL_MODEL_COST_MAP=True .venv/bin/pytest -q --tb=short -ra
LITELLM_LOCAL_MODEL_COST_MAP=True .venv/bin/python -u tools/rundgang.py
LITELLM_LOCAL_MODEL_COST_MAP=True .venv/bin/pytest tests/test_v965.py -q -s
.venv/bin/ruff check .
git diff --check
uv pip check --python .venv/bin/python
.venv/bin/aquaticy --version
```

Echte Modellanbieter, bezahlte Rechercheaufrufe und nicht verfügbare
Docker-Integrationen sind nicht Teil dieser Live-Prüfung. Der Browser-Rundgang
verwendet ebenfalls simulierte Dienste. Parallel laufende Chats teilen sich
weiterhin die vorhandene Hardware, das Kontingent und die Ratenlimits eines
Kontos; die Trennung der Chats hebt diese Grenzen nicht auf.
