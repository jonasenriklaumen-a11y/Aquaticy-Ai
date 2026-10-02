# Aquaticy AI 9.6.5 Luna

**Aquaticy** recherchiert für dich. Du stellst eine Frage, Aquaticy sucht im Web, liest die
passenden Seiten und fasst das Ergebnis zusammen — mit Quelle an jeder Angabe. Es läuft im
Terminal, im Browser und auf dem Handy.

```
$ aquaticy

> Finde mir gute Cafés in Mönchengladbach mit WLAN

  [Suche] cafés mönchengladbach
  [Suche] café mönchengladbach wlan arbeiten
  [Lese]  4 Seiten...

  Ich habe 6 Cafés gefunden, die zu deiner Anfrage passen:

  1. Café Nordwand — Hindenburgstr. 12
     WLAN ausdrücklich erwähnt, Steckdosen an den Fensterplätzen.
     Quelle: die gelesene Café-Seite
  ...

> davon nur die, die sonntags offen haben
```

---

## Inhalt

- [Was Aquaticy kann](#was-aquaticy-kann)
- [Quickstart](#quickstart)
- [Prüfbericht zu 9.6.5 Luna](TESTREPORT-9.6.5.md)
- [Installation im Detail](#installation-im-detail)
- [Benutzung im Terminal](#benutzung-im-terminal)
- [Die Weboberfläche](#die-weboberfläche)
- [Konten: Normal, Pro und Ultra](#konten-normal-pro-und-ultra)
- [Add-ons](#add-ons)
- [Virtual machine und User mode](#virtual-machine-und-user-mode)
- [Speicher](#speicher)
- [Aufträge](#aufträge)
- [Gmail und Kalender](#gmail-und-kalender)
- [Zuhause: Heimnetz, Home Assistant, Lager](#zuhause-heimnetz-home-assistant-lager)
- [Sicherheit, Rechts-Leitplanken und Ai-guard](#sicherheit-rechts-leitplanken-und-ai-guard)
- [Modelle und Anbieter](#modelle-und-anbieter)
- [Suche](#suche)
- [Im Container](#im-container)
- [Konfiguration](#konfiguration)
- [Server-Verbund](#server-verbund-seit-961)
- [Konten verwalten (Betreiber)](#konten-verwalten-betreiber)
- [Entwicklung](#entwicklung)
- [Lizenz](#lizenz)

---

## Was Aquaticy kann

**Recherche**
- Sucht selbst im Web, liest die Seiten und nennt zu jeder Angabe die Quelle.
- Merkt sich den Gesprächsverlauf: Nachfragen wie „nur die mit 4+ Sternen“ funktionieren.
- Fragt selbst nach, wenn etwas Entscheidendes offen ist (Budget, Ort, was gemeint ist).
- **Strukturieren:** zerlegt große Fragen in Teilfragen und schickt für jede einen eigenen
  Helfer los — im Pro-Modus bis zu 50 gleichzeitig.
- **Gegenprüfen:** prüft Ergebnisse auf anderen Seiten nach.
- **Bilder als Eingabe:** Foto anhängen, Aquaticy erkennt, was darauf ist, und sucht danach.
- **Öffentliche Webcams und Satellitenbilder** auf Wunsch einbeziehen.
- Funktioniert auch ohne Internetsuche — dann aus eigenem Wissen, mit Hinweis, wo es veraltet
  sein könnte.
- **Sofortantworten ohne Modell:** Einfache Nachrichten wie „Hallo“, „Danke“, „Wie geht’s?“,
  „Wer bist du?“ oder „Wer hat dich erschaffen?“ beantwortet Aquaticy sofort und kostenlos —
  mit vielen wechselnden Formulierungen (bei den häufigen je 25), zufällig gewählt und Wort für
  Wort ausgegeben wie vom Modell. Alles, was Suche oder Nachdenken braucht, geht wie gewohnt an
  das Modell.

**Arbeitsweisen**
- **Normal** — ein ganz normales Gespräch, gesucht wird, wenn es nötig ist. Seit 9.6.1 deutlich
  schneller: jeder Helfer hat eine Frist und fasst danach zusammen, was er gefunden hat (mit
  Quellen), statt die ganze Antwort aufzuhalten.
  Seit 9.6.5 mit weniger zusätzlichen Teilaufgaben und parallel gebündelten
  Leseabfragen; die Recherche im Pro-Modus bleibt unverändert.
- **Pro** — für große Fragen: das stärkste Modell und bis zu 50 Helfer. Dauert bewusst länger —
  wegen der höheren Genauigkeit (steht auch unter dem Eingabefeld). Der Master plant
  schon, während die Rechtsprüfung läuft — losgeschickt wird erst nach dem OK.
- **Code** — schreibt Code statt langer Texte und probiert ihn in einer abgeschotteten
  **virtual machine** wirklich aus. Die virtual machine fährt schon hoch, während das Modell nachdenkt.

**Oberfläche**
- Terminal-Chat, Weboberfläche im Browser, Zugriff vom Handy im eigenen Netz.
- **Design:** Hell, Dunkel oder wie das System; Standard (grün), Schlicht (schwarz-weiß) oder
  ein selbst erstelltes Design mit eigenen Farben für Akzent, Hintergrund und Seitenleiste.
- **Sprache:** Deutsch oder Englisch — Oberfläche und Antworten wechseln sofort.
- Slash-Befehle wie `/max` leuchten beim Tippen im Akzentton, damit man sie sofort erkennt.
- Chats durchsuchen, umbenennen, exportieren (HTML, Markdown, CSV).

**Extras**
- **Add-ons:** GitHub, Wetter, RSS-Feeds, Tagesschau, Wikipedia, Währungsrechner, Feiertage,
  WhatsApp Web, Signal, Telegram Web, Blender.
- **Speicher:** merkt sich auf Wunsch, was länger gilt — verschlüsselt, jederzeit einsehbar.
- **Aufträge:** regelmäßig recherchieren, Preise, Webcams oder Satellitenbilder beobachten.
- **Gmail und Kalender:** Termine und Mails lesen, auf Wunsch Termine anlegen und
  Mail-Entwürfe schreiben (verschickt wird nie etwas).
- **Zuhause** (Ultra): Geräte im Heimnetz finden, Home Assistant, Lagerverwaltung.
- **KI-Bilder** erstellen lassen.
- **Modell automatisch wählen:** für jede Nachricht das passende Modell.

**Sicherheit**
- Rechts-Leitplanken nach Grundgesetz und BGB, Ai-guard gegen Missbrauch.
- Keine Bezahlschranken, Logins oder Captchas umgehen; `robots.txt` wird beachtet.
- Konten sauber getrennt, Zugangsdaten verschlüsselt, Schutz vor Mehrfachkonten per Anhaltspunkten.
- XSS-Schutz: strenge Content-Security-Policy (Skripte nur mit Einmal-Schlüssel je Seite),
  alles Fremde wird maskiert; PHP- und JSP-Dateien lassen sich nicht hochladen, und
  angebliche Bilder müssen echte Bilder sein.

---

## Quickstart

```bash
# 1. Installieren (aus diesem Repo)
git clone --branch Aquaticy-ai --single-branch https://github.com/jonasenriklaumen-a11y/Aquaticy-Ai.git
cd Aquaticy-Ai
uv tool install --force --reinstall .
aquaticy --version            # 9.6.5 Luna

# 2. Einrichten — fragt nach Modell und Schlüssel und testet beide
aquaticy setup

# 3. Loslegen — im Terminal …
aquaticy

# … oder im Browser (öffnet sich von selbst)
aquaticy web
```

**Voraussetzungen:** Python 3.11 oder neuer und [uv](https://docs.astral.sh/uv/).

**Mindest-Hardware:**

| Betrieb | CPU | RAM | Speicher |
|---|---|---|---|
| Modell in der Cloud (Mistral, NVIDIA, verknüpfte Konten) | 1 Kern | 1 GB | 1 GB |
| + Seiten mit echtem Browser | 2 Kerne | 2 GB | 2 GB |
| + virtual machine (Code-Modus, Add-ons) | 2 Kerne | 4 GB | 10 GB |
| Lokales Modell mit Ollama | 4 Kerne | 8 GB (GPU empfohlen) | 10 GB |

**Aktualisieren** (im Repo-Ordner ausführen):

```bash
cd ~/Aquaticy-Ai
git switch Aquaticy-ai
git pull --ff-only origin Aquaticy-ai
uv tool install --force --reinstall .
aquaticy --version
```

Die Installation liest den Code aus dem aktuellen Repo-Ordner. Ein bereits installiertes
`aquaticy` aktualisiert sich durch `git pull` allein nicht: der letzte `uv`-Befehl
installiert die neue Fassung erneut. Wenn du GitHubs [Download ZIP](https://github.com/jonasenriklaumen-a11y/Aquaticy-Ai/archive/refs/heads/Aquaticy-ai.zip)
verwendest, lade das ZIP neu herunter, entpacke es und führe
`uv tool install --force --reinstall .` im entpackten Ordner aus. Ein altes ZIP
oder ein anderer Ordner enthält weiterhin den alten Code.

`aquaticy setup` fragt genau zwei Dinge:

| Was | Woher | Pflicht? |
|---|---|---|
| KI-Anbieter + Schlüssel | [Mistral](https://console.mistral.ai/api-keys/) · [NVIDIA NIM](https://build.nvidia.com/) · oder lokal mit [Ollama](https://ollama.com), ganz ohne Schlüssel | ja |
| Suchmaschine | Nichts — die offene Suche ist Standard und braucht weder Schlüssel noch Konto. | nein |

Beides wird sofort getestet, bevor die Einstellungen gespeichert werden
(`~/.config/aquaticy/.env`, nur für dich lesbar).

Eine einzelne Frage ohne Chat:

```bash
aquaticy "welche Bahnstrecken in NRW sind gerade gesperrt?"
```

---

## Installation im Detail

### Linux und macOS

Wie im Quickstart. Zum Entwickeln stattdessen:

```bash
uv venv && uv pip install -c constraints.txt -e ".[browser,dev]"
uv run aquaticy
```

### Windows (PowerShell)

```powershell
# uv installieren, falls noch nicht vorhanden
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"

git clone --branch Aquaticy-ai `
  https://github.com/jonasenriklaumen-a11y/Aquaticy-Ai.git
cd Aquaticy-Ai
uv tool install --force --reinstall .
uv tool update-shell        # danach PowerShell neu öffnen

aquaticy install-model      # holt Ollama per winget und lädt die Modelle
```

- Ohne winget: Installer von [ollama.com/download](https://ollama.com/download) laden und
  `aquaticy install-model` erneut starten.
- Pfade in Anführungszeichen: `aquaticy --image "C:\Users\du\Bilder\foto.jpg"`
- Pfeiltasten-Verlauf im Chat: `pip install pyreadline3`

### Ganz ohne Schlüssel: lokales Modell

```bash
aquaticy install-model
```

Der Befehl sucht Ollama (und fragt, bevor er etwas installiert), startet es, schlägt anhand
von Arbeitsspeicher und Grafikkarte ein passendes Modell vor, lädt es und prüft an einem echten
Aufruf, ob es Werkzeuge bedienen kann. Nur ein Modell, das den Test besteht, wird eingetragen.
Auf Wunsch richtet er zusätzlich ein Modell für Bilder ein.

```bash
aquaticy install-model --model qwen2.5:14b                    # nur Text
aquaticy install-model --vision-model llava:7b                # Text + Bild
aquaticy install-model --vision-only --vision-model llava:7b  # nur Bild nachrüsten
aquaticy install-model --yes                                  # ohne Rückfragen
```

**Ein Modell für alles** (Suche und Bilder):

| Modell | ca. Größe | ab VRAM |
|---|---|---|
| `qwen3-vl:4b` | 3,3 GB | 6 GB |
| `gemma4:e4b` | 3,5 GB | 6 GB |
| `qwen3-vl:8b` | 6,1 GB | 12 GB |
| `gemma4:12b` | 6,6 GB | 10 GB |
| `gemma4:26b` | 16,0 GB | 24 GB |

**Nur Recherche:** `qwen2.5:3b`, `qwen2.5:7b`, `llama3.1:8b`, `qwen3:8b`, `qwen2.5:14b`.
**Nur Bilder:** `moondream`, `gemma3:4b`, `llava:7b`, `minicpm-v`, `gemma3:12b`.

> Das Modell-Kürzel muss `ollama_chat/` lauten, nicht `ollama/` — nur so kommen Werkzeuge
> durch. `aquaticy install-model` schreibt es automatisch richtig.

Wird der Grafikspeicher knapp (`model runner has unexpectedly stopped`), bietet Aquaticy von
selbst ein kleineres Modell an. Von Hand: `ollama ps`, `ollama stop <modell>`.

### Seiten mit echtem Browser laden

Für Seiten, die ihren Inhalt erst per JavaScript nachladen:

```bash
aquaticy install-browser
```

---

## Benutzung im Terminal

### Slash-Befehle

| Befehl | Wirkung |
|---|---|
| `/max <frage>` | im Pro-Modus mit allen Helfern recherchieren |
| `/location <ort>` | Ortsfilter setzen (ohne Ort: aufheben) |
| `/model <name>` | Modell wechseln, z. B. `mistral/mistral-large-latest` |
| `/image <pfad>` | Bild beschreiben lassen und damit weitersuchen |
| `/export html\|md\|csv` | Recherche dieser Sitzung speichern |
| `/history` | frühere Recherchen anzeigen |
| `/notes` | Merkzettel anzeigen |
| `/notes delete <nr>` / `/notes clear` | Notiz oder alle Notizen löschen (Website) |
| `/clear` | Gespräch neu beginnen |
| `/memory` / `/forget` | Langzeitspeicher anzeigen oder leeren |
| `/uploads` / `/uploads clear` | Hochgeladene Dateien anzeigen oder löschen |
| `/help` | Übersicht |
| `/quit` / `/exit` / `/q` | Terminal beenden (auch <kbd>Strg</kbd>+<kbd>D</kbd>); im Browser Fenster schließen |

### Optionen

```bash
aquaticy --location "Mönchengladbach" --lang de   # Ortsfilter vorgeben
aquaticy --model mistral/mistral-large-latest     # Modell für diese Sitzung
aquaticy --image foto.jpg                         # Bild als Ausgangspunkt
aquaticy --max-calls 30                           # mehr Suchen je Frage erlauben
aquaticy --no-stream                              # Antwort am Stück statt fließend
aquaticy --download-images                        # Bilder beim Export mitspeichern
```

### Alle Befehle

```bash
aquaticy setup                  # Ersteinrichtung
aquaticy config                 # aktive Einstellungen prüfen
aquaticy web                    # Weboberfläche starten
aquaticy web --lan              # auch vom Handy im eigenen Netz erreichbar
aquaticy search "cafés köln"    # nur suchen, ohne KI
aquaticy fetch https://…        # nur eine Seite lesen, ohne KI
aquaticy history                # vergangene Recherchen
aquaticy export html -n 3       # letzte 3 Recherchen exportieren
aquaticy notes                  # Merkzettel anzeigen (--delete N löscht)
aquaticy cache                  # Zwischenspeicher anzeigen (--clear leert ihn)
aquaticy install-model          # lokales Modell einrichten
aquaticy install-browser        # echten Browser für schwierige Seiten
aquaticy google                 # Gmail und Kalender verbinden (--aendern: auch schreiben)
aquaticy connect-ha             # Home Assistant verbinden
aquaticy lan                    # Geräte im eigenen Netz anzeigen
aquaticy sandbox                # zeigt, wie abgeschottet Aquaticy gerade läuft
aquaticy cluster                # Server-Verbund: Anfrage zum Verbinden mit yes/no beantworten
aquaticy list                   # Konten mit Adress-Kürzel (#…), Geräteanzahl, Nutzung und Ai-guard-Stand
aquaticy remove "name"         # Konto samt Sitzungen, Verbrauch und privaten Daten löschen (fragt nach; --yes ohne Rückfrage)
aquaticy ban "name"             # Konto, IP-Adresse oder Adress-Kürzel ("#1a2b3c4d") sperren
aquaticy unban "name"           # wieder freigeben
aquaticy aiguard "Satz"         # zeigt, wie Ai-guard einen Satz einstuft (sperrt niemanden)
aquaticy pro-code               # Code für neue Pro-Konten
aquaticy ultra-code             # Code für neue Ultra-Konten
aquaticy version
```

---

## Die Weboberfläche

```bash
aquaticy web          # öffnet sich im Browser
aquaticy web --lan    # zeigt alle Adressen, unter denen es im Heimnetz erreichbar ist
```

**Chat.** Links die letzten Chats (durchsuchbar), in der Mitte das Gespräch, unten die
Eingabe mit den drei Arbeitsweisen Normal, Pro und Code. Dateien und Bilder hängst du mit 📎 an.
Ein vollständig geschriebener Slash-Befehl leuchtet im Akzentton; der Text dahinter bleibt normal.
Oben links steht das **Logo** (seit 9.6.0), darunter „Aquaticy“, daneben die Version; im
Browser-Tab steht nur das Logo.

**Chatwechsel während einer Recherche (seit 9.6.5).** Du kannst einen anderen
Chat öffnen oder einen neuen anfangen und dort schreiben. Die erste Recherche
läuft im Hintergrund weiter. Beim Zurückwechseln siehst du ihren aktuellen
Stand oder die fertige Antwort. Der Stop-Knopf gilt nur für den offenen Chat;
ungesendete Entwürfe bleiben beim Wechsel erhalten.

**Neuer Chat (seit 9.6.0).** Jeder neue Chat begrüßt dich mit einem anderen Satz — „Guten
Morgen, Anna. Wobei kann ich dir helfen?“ ist einer von über 50 je Modus (Normal, Pro und Code
haben eigene) — und darunter stehen drei zufällige Vorschläge, ebenfalls aus über 50 je Modus.

**Während Aquaticy arbeitet (seit 9.6.0)** stehen statt einer langen Schrittliste nur wenige
Zeilen da, zum Beispiel:

```
🅰 Denken
   „Ich suche jetzt nach den neuesten Nachrichten.“   ← Zwischennachricht
🅰 Websuche
🅰 Denken
Hier sind die neuesten Nachrichten …                    ← die richtige Antwort
```

- Links neben der laufenden Zeile bewegt sich das **Logo** (ein Lichtbogen kreist, das A schwebt),
  solange Aquaticy daran arbeitet. Wer weniger Bewegung eingestellt hat, sieht es ruhig.
- Die **Zwischennachricht** verschwindet, sobald die richtige Antwort da ist.
- Ein **Klick** auf eine Zeile klappt auf, was darin passiert ist — bei „Denken“ die Gedanken,
  bei „Websuche“ Suchanfragen und gelesene Seiten.
- Im **Code-Modus** heißt „Denken“ wie bei Claude: *Noodling*, *Aquaticing*, *Pondering*,
  *Schlepping*, *Booping* und über 45 weitere Wörter, die sich abwechseln.
- Fehler, Sperren und Abbrüche bleiben immer offen sichtbar.

**Interne Versionen.** Eine interne oder Test-Fassung trägt das im Namen („9.6.0 Spark
Intern“), und unten mittig unter der Eingabe steht ein gelber Hinweis.

**Modellauswahl** (unten, links neben dem Senden-Knopf; das Menü öffnet sich nach oben):
- Oben die **Modelle** zur Wahl.
- **🎨 Bilderstellung** (seit 9.5.34): wer das wählt, landet sofort im Standard-Modus, und
  Aquaticy nimmt selbst ein Modell, das Bilder erstellen kann (NVIDIA FLUX oder Mistral, je nach
  Schlüssel). Ohne passenden Schlüssel sagt es, was einzutragen ist. Ein zweiter Klick, ein
  anderes Modell oder ein anderer Modus beendet die Bilderstellung.
- **⚡ Aufwand** öffnet ein kleines Fenster: **Denktiefe** Low / Medium / High und die Zahl der
  **Helfer** (Modus Normal und Code 1–12, Modus Pro 1–50).
- **⚙ Weitere Einstellungen** öffnet ein zweites kleines Fenster: **Im Web suchen**,
  **Öffentliche Webcams & Satellitenbilder**, **Denken** (mitlesen, wie Aquaticy überlegt),
  **Strukturieren**, **Gegenprüfen** — und im Code-Modus **Code wirklich ausprobieren** in der
  virtual machine.

**Einstellungen (seit 9.6.0)** speichern sich selbst: Schalter sofort, Textfelder beim
Verlassen des Feldes (oder mit Enter). Oben im Fenster erscheint dann kurz ein kleines
„Gespeichert“ in der Farbe deines Designs; einen Speichern-Knopf gibt es nicht mehr, „‹ Zurück“
steht oben links. Die Schalter zeigen ihren Zustand über Füllung und Rand (ohne „I/O“).

**Design** (links unten): Hell, Dunkel oder wie das System. Dazu:
- **Standard** — das grüne Papier.
- **Schlicht** — alles weiß mit schwarzer Schrift und schwarzen Knöpfen; im Dunkelmodus
  genau umgekehrt.
- **Design selber erstellen** — wähle die Farbe für den **Akzent** (alles, was bei Standard
  grün ist, z. B. blau, pink oder rot), den **Hintergrund** und die **Seitenleiste** links.
  Die Schrift passt sich automatisch an, damit sie lesbar bleibt. Das Design wird an deinem
  Konto gespeichert und gilt auf jedem Gerät.
- **Schriftgröße** — Klein, Normal oder Groß; gilt sofort für die ganze Oberfläche und wird am
  Konto gespeichert.
- **Sprache** — Deutsch oder English. Knöpfe, Fenster, Hinweise und Platzhalter wechseln sofort,
  ohne Neuladen, und Aquaticy antwortet in der gewählten Sprache. Was im Chat steht (deine
  Fragen, die Antworten, Chat-Titel), bleibt, wie es geschrieben wurde. Auch die Sprache wird
  am Konto gespeichert.

**Einstellungen** — Schalter gelten sofort (mit kurzer Bestätigung „Gespeichert“), Textfelder nach
„Speichern“. Funktionen nur für Ultra sind mit 🔒 gekennzeichnet; ein Klick erklärt, warum.
- **Konto** — Name, E-Mail, Kontotyp, Nutzung, Abmelden. Darunter **Sicherheit**: deine Geräte
  und deine letzte Adresse (nur du siehst sie), **Passwort ändern**, **Überall sonst abmelden**.
  Und **Daten und Konto löschen**: „Alle Daten löschen“ (Chats, Bilder, Uploads, Erinnerungen,
  Aufträge, Einstellungen, eigene Schlüssel, Google, Geräte — das Konto bleibt) oder „Konto
  löschen“ (alles samt Konto; mit Passwort und dem Wort LÖSCHEN). Meldet sich jemand von einem
  unbekannten Gerät an, steht beim nächsten Besuch ein Hinweis oben im Chat.
- **Modell** — Hauptmodell, Bild-Modell, Helfer-Modell, Code-Modell, eigene Adresse.
- **Eigene Modelle** — erscheint erst, wenn du oben ein eigenes Modell oder einen eigenen
  Schlüssel einträgst, und zeigt genau diese. Schlüssel werden verschlüsselt gespeichert und
  nie an den Browser zurückgegeben.
- **virtual machine** — Größe, User mode, Add-ons, Login-Apps.
- **Speicher**, **Mitlesen**, **Auslastung** (nur Ultra), **Nutzung**, **Aufträge**,
  **Gmail & Kalender**, **Zuhause & Netz** (Ultra), **Suche**, **Ort & Sprache**,
  **Helfer & Grenzen**, **Dev settings**.

**Merkzettel** — was sich Aquaticy über dich gemerkt hat; jede Zeile einzeln löschbar.

**Bedienung.** Rückfragen und Hinweise erscheinen in Aquaticys eigenem Fenster statt in
Browser-Dialogen. Nach einem Fehler holt „↻ Erneut versuchen“ dieselbe Frage noch einmal. Vor
der ersten Nachricht steht, was Aquaticy kann und was nicht. Schalter zeigen ihren Zustand
nicht nur über die Farbe („I“/„O“), der Tastatur-Fokus ist überall sichtbar, und am Handy sind
Senden und Stopp mindestens 44 px groß. Im Dunkelmodus nutzt auch „Schlicht“ fast-schwarz
(#121212) statt reinem Schwarz.

---

## Konten: Normal, Pro und Ultra

Wer die Weboberfläche öffnet, legt zuerst ein Konto an. Jedes Konto hat eigene Chats,
Einstellungen, Speicher und Schlüssel.

**Mehrfachkonten (seit 9.5.31): Anhaltspunkte statt „ein Konto pro IP-Adresse“.** Zwei Menschen
im selben Haushalt teilen sich die Adresse — das allein sperrt nicht mehr. Aquaticy zählt Punkte
gegen jedes vorhandene Konto; ab **3 Punkten** wird kein neues Konto angelegt, ab 1,5 steht ein
Hinweis im Terminal.

| Anhaltspunkt | Punkte |
|---|---|
| dasselbe Gerät (zufällige Geräte-Kennung im Cookie `aquaticy_device`) | 3 |
| gleiche Hardware **und** gleicher Browser | 1,5 |
| gleiche Hardware | 1 |
| gleicher Browser | 0,5 |
| dieselbe IP-Adresse (Anlege- oder zuletzt genutzte) | 1 |
| sehr ähnliche E-Mail-Adresse (`max.muster@…` / `maxmuster7@…`) | 1 |

Beispiele: selbe Adresse + selber Browser = 1,5 → geht durch. Zwei gleiche Handys im selben WLAN
= 2,5 → geht durch. Dasselbe Handy (Kennung) = 3 → gesperrt. Selbe Adresse + ähnliche E-Mail +
gleiche Hardware = 3 → gesperrt. Der eigene Rechner (Loopback) zählt nicht als gleiche Adresse.
Gespeichert werden je Konto höchstens 20 Geräte: die Kennung nur als Hash, Hardware und Browser
(„Windows · 16 Kerne · 8 GB · 2560x1440 · NVIDIA …“, „Chrome 126, de-DE“) **verschlüsselt**,
verglichen wird über Schlüssel-Hashes. Der Betreiber sieht davon nichts — nur die Anzahl der
Geräte und die Adresse als Kürzel („#1a2b3c4d“). Kein Canvas- oder Audio-Fingerabdruck. Mit
dem Konto werden auch die Geräte gelöscht.

**Verschlüsselung (seit 9.5.32).** Chats (Fragen, Antworten, Chatnamen, Notizen), Uploads,
Fotos und Bilder, IP-Adressen, Geräte und E-Mail-Adressen liegen mit AES-256-GCM verschlüsselt,
jedes Konto mit eigenem Schlüssel (abgeleitet aus `data.key` neben der Kontendatenbank).
Passwörter: Argon2id (64 MiB, 3 Durchläufe) mit Salz und geheimem Serverwert (`auth.key`);
alte Hashes werden bei der nächsten Anmeldung umgeschrieben. Bestehende Daten werden beim
ersten Start automatisch verschlüsselt. Wichtig für Betreiber: `data.key` und `auth.key` nie
zusammen mit den Daten sichern — und ohne sie sind die Daten nicht mehr lesbar. Ehrlich dazu:
Der Server braucht den Schlüssel, um mit Chats zu arbeiten; wer den Server selbst kontrolliert,
könnte entschlüsseln. Geschützt ist gegen gestohlene Datenbanken und Sicherungen, gegen andere
Konten und gegen das Hineinsehen in Dateien.

| | Normal | Pro | Ultra |
|---|---|---|---|
| Recherche, Chat, Code-Modus, Add-ons ohne virtual machine | ✔ | ✔ | ✔ |
| Nutzung je 5-Stunden-Sitzung | 300.000 Token | 533.333 Token | unbegrenzt |
| Nutzung je Woche | 2 Mio. Token | 4 Mio. Token | unbegrenzt |
| Auslastungsanzeige | – | – | ✔ |
| Heimnetz, Home Assistant, Lagerverwaltung | – | – | ✔ |
| User mode, virtual machine „Plus“, virtual-machine-Add-ons | – | – | ✔ |
| Internet für die virtual machine (Code-Modus) | – | – | ✔ |
| Eigene Adressen für Modell und Suche | – | – | ✔ |
| Rechts-Leitplanken abschaltbar | – | – | ✔ |
| Ai-guard | sperrt | sperrt | warnt nur |
| Code zum Anlegen | – | 9 Zeichen | 14 Zeichen |

**Codes.** Beim ersten Start erzeugt Aquaticy zwei geheime Codes und zeigt sie im Terminal:
- den **Pro-Code** (9 Zeichen) — später mit `aquaticy pro-code`, vorgeben mit
  `AQUATICY_PRO_CODE`;
- den **Ultra-Code** (14 Zeichen, mit Buchstaben, Ziffern und Sonderzeichen, unabhängig vom
  Pro-Code) — später mit `aquaticy ultra-code`, vorgeben mit `AQUATICY_ULTRA_CODE`.

**Nutzung.** Die Sitzung beginnt mit deiner ersten Nachricht und läuft fünf Stunden, die Woche
beginnt zur Uhrzeit deiner Kontoerstellung. Angezeigt wird beides in Prozent (*Einstellungen →
Nutzung*, ab 80 % auch als Hinweis). Gezählt wird nur auf dem Server — wer Chats löscht, löscht
nicht seinen Verbrauch. Anfragen über **eigene Schlüssel** zählen nicht gegen das Limit.

---

## Add-ons

*Einstellungen → virtual machine → 🧩 Add-ons.* Jedes Add-on lässt sich installieren, an- und
ausschalten und wieder entfernen; aus dem Chat heraus lässt sich nichts davon ändern. Anmelden
musst du dich immer selbst — Aquaticy kennt keine Passwörter. Unter jedem Add-on stellst du ein,
was Aquaticy damit darf (**Rechte**).

### KI-Konten: Claude, ChatGPT, Gemini (seit 9.6.1)

*Add-ons → KI-Konten.* Verknüpfen geht in drei Schritten (seit 9.6.2):

1. **„Mit Google“, „Mit Apple“ oder „Mit E-Mail“** öffnet die Seite des Anbieters — dort
   meldest du dich an, wie du es gewohnt bist (Claude: Google oder E-Mail; ChatGPT: Google,
   Apple oder E-Mail; Gemini: Google).
2. Dort einen **API-Schlüssel erstellen** und kopieren.
3. In Aquaticy auf **„Einfügen“** — Aquaticy erkennt am Schlüssel selbst, ob er von Claude,
   ChatGPT oder Gemini ist. (Ohne HTTPS erlaubt der Browser die Zwischenablage nicht; dann
   einfach ins Feld einfügen.)

Danach liest Aquaticy selbst aus:

- **Modelle**, die dein Konto freigeschaltet hat — sie stehen in der Modellauswahl im Normal-,
  Pro- und Code-Modus wie alle anderen.
- **Stufe (Tier)** und **freie Tokens** im laufenden Zeitfenster (Claude und ChatGPT; dafür
  geht eine winzige Anfrage mit einem Token raus). Google gibt beides nicht über die
  Schnittstelle heraus — das steht dann so da.

Der Schlüssel liegt verschlüsselt im Schlüsselbund deines Kontos, geht nur an den Anbieter
und ist jederzeit beim Anbieter widerrufbar. **Warum nicht direkt „Mit Google bei ChatGPT
anmelden“?** Diese Anmeldung gilt nur für die Website des Anbieters selbst — sie gibt keinem
anderen Programm Zugriff, und die Abos (ChatGPT Plus, Claude Pro) gelten ohnehin nur in deren
eigenen Apps. Der API-Schlüssel ist der vorgesehene Weg für Programme wie Aquaticy; Aquaticy
kennt dein Passwort nie.

**AI Council** (*Einstellungen → Dev settings*): mit mindestens zwei verknüpften Konten
arbeiten die Modelle zusammen. Zwei lösen die Aufgabe (z. B. Claude und ChatGPT), eines prüft
auf Fehler (Gemini, wenn verknüpft), und Aquaticy ist mit seinem Hauptmodell der **Richter**:
es entscheidet, ob die Lösung trägt, oder schickt Einwände und die Lösungen der anderen zum
Nachbessern und Ausdiskutieren zurück (bis zu drei Runden). Im Council laufen keine Agenten.

### Programme und Dienste

| Add-on | Was es kann | Anmeldung |
|---|---|---|
| 🐙 GitHub | Repos, Issues, Pull Requests und Dateien lesen (nie schreiben) | Token |
| 🌦️ Wetter | Wetter und 7-Tage-Vorhersage (Open-Meteo) | keine |
| 📰 RSS-Feeds | deine eigenen Nachrichtenquellen zusammenfassen | Feed-Adressen |
| 🗞️ Tagesschau | aktuelle Meldungen nach Thema oder als Suche | keine |
| 📚 Wikipedia | Begriffe nachschlagen, Kurzfassung mit Link (Deutsch/Englisch) | keine |
| 💱 Währungsrechner | Tageskurse der EZB für gut 30 Währungen | keine |
| 📅 Feiertage | gesetzliche Feiertage weltweit, auch je Bundesland | keine |
| 💬 WhatsApp Web | Chats lesen, Antworten vorbereiten — senden nur nach deinem Ja | QR-Code |
| 🔵 Signal | wie WhatsApp, mit Signal Desktop | QR-Code |
| ✈️ Telegram Web | Kanäle und Gruppen lesen, Antworten vorbereiten | QR-Code |
| 🧊 Blender | 3D-Modelle bauen und rendern in der virtual machine | keine |

WhatsApp, Signal, Telegram und Blender laufen in der virtual machine und brauchen den User mode
(Ultra). Die Tagesschau ist nur für den privaten Gebrauch; Aquaticy hält die erlaubten 60
Abrufe pro Stunde ein.

---

## Virtual machine und User mode

> Früher hieß die virtual machine „Werkstatt“ — seit 9.5.30 durchgehend **virtual machine**.

Die **virtual machine** ist ein abgeschotteter Rechner, in dem Aquaticy Code wirklich ausführt:

| Größe | Kerne | Arbeitsspeicher | Platte |
|---|---|---|---|
| Normal | 1 | 1 GB | 4 GB |
| Plus (Ultra) | 4 | 6 GB | 20 GB |

- Kein root; die Platte ist hart begrenzt.
- **Netz je Tarif (seit 9.6.0):** **Normal und Pro** haben in der virtual machine **gar kein
  Netz** — weder Internet noch das lokale Netz; Rechnen, Code ausführen und Dateien bearbeiten
  geht trotzdem. Mit Internet sind private Adressbereiche, Router, Home Assistant und der eigene
  Rechner gesperrt; lässt sich die Sperre nicht setzen, startet die Maschine gar nicht. **Ultra** stellt
  das Internet selbst ein (seit 9.5.31) und kann mit dem Schalter **Auch ins lokale Netz** die
  Sperre ganz wegnehmen — dann erreicht die Maschine Internet **und** Heimnetz. Das Modell kann
  beides nicht umschalten. Es braucht das Desktop-Abbild (unten).
- Angehängte Dateien liegen unter `eingang`, alles Erstellte kannst du herunterladen.
- 20 Minuten nach der letzten Nachricht wird die virtual machine samt Inhalt gelöscht.

Der **User mode** (Ultra) macht aus der virtual machine einen kleinen Desktop mit Internet: Aquaticy
sieht den Bildschirm, klickt, tippt und nutzt Browser, Office oder Bildbearbeitung — wie ein
Mensch. Das Heimnetz bleibt gesperrt. Absenden, Kaufen und Löschen nur nach deinem Ja;
Passwörter, Zahlungsdaten, Captchas und „Alle akzeptieren“ fasst Aquaticy nie an. Bei
**Login-Apps** meldest du dich selbst an: Was du dort tippst, landet nur in der App.

Einmalig nötig (Betreiber):

```bash
docker build -f docker/workshop-desktop.Dockerfile -t aquaticy-werkstatt-desktop:local .
```

---

## Speicher

Mit eingeschaltetem Speicher merkt sich Aquaticy, was länger gilt — Wohnort, Vorlieben,
laufende Vorhaben. Nur Text, verschlüsselt, höchstens 400 MB für alles im Konto zusammen.
Unter **„Was weißt du über mich?“** siehst du jeden Eintrag und kannst ihn einzeln oder alle
auf einmal löschen.

---

## Aufträge

*Einstellungen → Aufträge.* Aquaticy bleibt für dich dran:

- **regelmäßig recherchieren** — täglich, stündlich, wöchentlich;
- **Kamera, Satellit oder Straße beobachten** — z. B. „ein oranges Flugzeug ist sichtbar“;
- **Preis beobachten**;
- **Bild hochladen und danach suchen**, bis ein Angebot auftaucht.

Tritt ein, worauf du wartest, bekommst du einen neuen Chat — mit Bild und Uhrzeit. Nur
öffentliche Quellen, keine privaten Kameras, keine Anmeldungen.

---

## Gmail und Kalender

Aquaticy kann Termine und Mails lesen und — wenn du „Ändern erlaubt“ einschaltest — Termine
anlegen und ändern und Mail-**Entwürfe** schreiben. **Verschickt wird nie eine Mail, gelöscht
wird nichts**; diese Rechte holt Aquaticy bei Google gar nicht erst.

### Einrichten — einmal, etwa fünf Minuten

1. Auf [console.cloud.google.com](https://console.cloud.google.com/) ein neues Projekt anlegen.
2. **APIs und Dienste → Bibliothek:** „Gmail API“ und „Google Calendar API“ aktivieren.
3. **OAuth-Zustimmungsbildschirm:** Nutzertyp „Extern“, dich selbst als Testnutzer eintragen.
4. **Anmeldedaten → OAuth-Client-ID**, Typ **Desktop-App**, Weiterleitung
   `http://localhost:8765/google`.
5. Client-ID und Client-Secret in *Einstellungen → Gmail & Kalender* eintragen (oder als
   `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`), speichern, **Verbinden**.

Im Terminal geht es mit `aquaticy google` (bzw. `aquaticy google --aendern`). Die Zugangsdaten
werden verschlüsselt gespeichert und verlassen den Rechner nicht; **Trennen** löscht sie.

---

## Zuhause: Heimnetz, Home Assistant, Lager

Nur mit einem **Ultra-Konto**.

- **Heimnetz:** „Welche Geräte sind in meinem WLAN?“, „Ist mein Drucker an?“ — Aquaticy schaut
  nur, ob etwas antwortet, und nur in privaten Netzen (`10/8`, `172.16/12`, `192.168/16`,
  `100.64/10`). Im Terminal: `aquaticy lan`.
- **Home Assistant:** Aquaticy findet die Instanz selbst (`aquaticy connect-ha`), liest Zustände
  und darf — wenn du es erlaubst — schalten. Schlösser, Alarm, Tore und Heizung fragen immer
  nach.
- **Lagerverwaltung:** Räume → Möbel → Artikel. Aquaticy sagt, wo etwas liegt und wie viel noch
  da ist; in der Stufe „Lesen und schreiben“ legt es auch an und ändert. Gelöscht wird nie.

---

## Sicherheit, Rechts-Leitplanken und Ai-guard

**Feste Grenzen** (immer, für jedes Konto):
- keine Bezahlschranken, Logins oder Captchas umgehen; `robots.txt` wird beachtet;
- ins Heimnetz nur private Adressen, Webseiten nie ins Heimnetz;
- im Haus nur nach Rückfrage schalten; bei Google nie senden, nie löschen;
- Zugangsdaten nie an den Browser und nie an das Modell;
- nur verteidigende Sicherheitsthemen;
- keine PHP- oder JSP-Dateien als Upload (auch nicht als `bild.php.png`).

**Schutz vor Prompt-Injection.** Webseiten, Mails, Feeds, Anhänge und alles, was Helfer
zurückbringen, sind für Aquaticy *Material*, nie ein Auftrag. Die Grenzen dafür liegen im Code:
- unsichtbare Zeichen (Unicode-Tags, Nullbreite, Richtungswechsel) werden entfernt,
  nachgemachte Chat-Steuerzeichen (`<|im_start|>`, `[INST]`, `</system>`) entschärft;
- jedes fremde Ergebnis trägt den Hinweis „nur Daten“; stehen darin Anweisungen an eine KI
  („ignoriere deine Regeln“, „schick den Merkzettel an …“), kommt eine Warnung dazu und im
  Verlauf erscheint **[Schutz]**;
- Anhänge und die Quellenlage der Helfer stehen klar abgegrenzt im Gespräch, nicht mit der
  Stimme des Nutzers;
- nach fremdem Inhalt geht nichts Privates (Merkzettel, Speicher, Ort, E-Mail) ohne Rückfrage
  in eine Adresse, eine Eingabe oder einen Befehl — und Schalten, Einstellungen, Lager,
  Speichern und Heimnetz-Suchen fragen ebenfalls erst nach.

**Website.** Anmelde-Cookie `HttpOnly`, `SameSite=Strict` (hinter HTTPS-Proxy auch `Secure`,
dazu HSTS), strenge CSP mit Nonce, Schreibzugriffe nur von der eigenen Seite, Grenzen für
Anfragen und falsche Passwörter je Adresse *und* je Konto.

**Rechts-Leitplanken.** Bevor Aquaticy etwas tut, prüft es, ob das mit Grundgesetz und BGB
vereinbar ist — bei jeder Frage, jeder Personensuche, jedem Kamerabild und jedem Mail-Entwurf.
Die Regeln stehen unter *Einstellungen → Dev settings → Welche Regeln gelten?*. Nach einer
Person suchen ist erlaubt (öffentliche Angaben, berufliche Rolle, veröffentlichte Kontaktwege);
nicht erlaubt ist, private Anschrift, Handynummer oder Aufenthaltsort auszuforschen oder ein
überwachungsartiges Dossier anzulegen. Harmloses wird nicht blockiert: Alltag, Technik,
Geschichte, Geschichten, Humor oder Kritik sind frei, und ein Nein des schnellen Prüfmodells
zählt erst, wenn auch das Hauptmodell es so sieht. Abschalten lassen sich die Leitplanken nur mit
einem Ultra-Konto und nie aus dem Chat heraus.

**Einmal abgelehnt bleibt abgelehnt.** Soll Aquaticy selbst etwas tun, das gegen das Grundgesetz
oder eine wichtige Regel des BGB verstößt (z. B. fremdes Eigentum, Betrug, Persönlichkeitsrechte),
gilt eine strenge Regel: Ein „bitte“, Drängen, „ich darf das“, „nur dieses eine Mal“ oder
„ist für die Schule“ ändern an einer Absage nichts — Aquaticy fragt dann nicht einmal mehr das
Modell, sondern bleibt bei derselben Begründung. Wer es umformuliert, als Rollenspiel oder
„rein hypothetisch“ versucht, wird mit dem Vermerk der Absage erneut geprüft. Eine neue,
erlaubte Frage oder ein neuer Chat heben das auf.

**Ai-guard** läuft auf jedem Konto und entscheidet nach **Art und Schwere**, was passiert:

| Art | Was passiert |
|---|---|
| Beleidigung, leicht | nur **dieser Chat** wird gesperrt — neue Chats gehen |
| Beleidigung, mittel bis schwer | Bann für 1 Tag, 7 Tage oder für immer |
| Schadsoftware bauen/installieren (auch in der virtual machine) | sofort Bann, 4 Tage bis für immer |
| Angriffshilfe, schwerer GG/BGB-Verstoß (z. B. Diebstahl, Betrug), Versuche, die Schutzregeln auszuhebeln | ab dem **zweiten** Anhaltspunkt Bann, 1 Tag bis für immer |
| Bagatellen („bei Rot über die Ampel, ist das ok?“), Bildung, Verteidigung | nichts |

**Beleidigungen erkennt Aquaticy sicher**, auch ohne Modell: eine feste Liste gängiger
Schimpfwörter aus allen Altersgruppen (Kindersprache, Jugendsprache, Erwachsene, ältere
Ausdrücke, Englisch) mit Schwerestufen von „du bist dumm“ bis zur Drohung. Gezählt wird nur,
was **gegen jemanden gerichtet** ist („du Idiot“, „dummer Bot“, „halt die Klappe“) — nicht
Fluchen über eine Sache („scheiß Wetter“), nicht die Frage nach einem Wort („Ist ‚Arschloch‘
eine Beleidigung?“) und nicht Wörter mit harmloser Bedeutung („Opfer eines Betrugs“). Strenger
ist nur die Erkennung; welche Folge eine Beleidigung hat, steht unverändert in der Tabelle.
Tarnungen helfen nicht: getrennte Buchstaben („I d i o t“), Ziffern und Sternchen („Id1ot“,
„A****loch“), gedehnte Wörter, unsichtbare Zeichen, ähnlich aussehende kyrillische Buchstaben
oder eine sehr lange Nachricht werden erkannt. Wer nach einer leichten Beleidigung immer wieder
einen neuen Chat anfängt: Die dritte leichte Beleidigung binnen einer Woche ist ein Bann für 1 Tag.

**Zitieren ist frei, der Auftrag dahinter nicht.** „Mein Freund hat gesagt: du Opfer — wie
reagiere ich?“ führt zu nichts. Soll Aquaticy aber jemanden beleidigen, runtermachen,
bloßstellen oder mobben helfen („…gib mir einen Satz, mit dem ich ihn beleidige“, „schreib eine
Nachricht, die sie fertig macht“, „einen fiesen Konter“), sperrt Ai-guard den Chat — auch, wenn
der Auftrag erst in der nächsten Nachricht kommt („Und jetzt was Fieseres zurück“). Wer
„damit er heult“ oder Ähnliches verlangt, wird wie eine mittlere Beleidigung behandelt (Bann
für 1 Tag); wer will, dass sich jemand etwas antut, dauerhaft gesperrt. Hilfe gegen Mobbing,
eine ruhige Antwort, eine Entschuldigung oder die Frage, ob etwas eine Beleidigung ist, bleiben
frei. Auch Aufträge (regelmäßige Recherchen) werden so geprüft.

**Wie genau?** Gemessen an drei beschrifteten Listen mit zusammen 263 Beleidigungen und 337
harmlosen Sätzen (Stand 9.5.27): alle Beleidigungen erkannt, kein Fehlalarm. Harmlos bleiben
dabei auch Sätze wie „Kennst du Otto?“, „Ich bring dich zum Bahnhof um 8“, „Lauchsuppe-Rezept“,
„Lily Allen – Fuck You“ oder „Mein Kollege hat mich Idiot genannt, was tun?“. Zusammengesetzte
Schimpfwörter („Flachzange“, „Oberidiot“, „Kackbot“) werden auch erkannt, wenn sie in keiner Liste
stehen. Meldet nur das KI-Modell eine Beleidigung, die die feste Erkennung nicht bestätigt, gibt es
höchstens eine Chatsperre, nie einen Bann. Ein Missbrauchsverdacht, den nur das kleine Prüfmodell
hatte, zählt nie. Anhaltspunkte für Angriffe bilden nur innerhalb von 90 Tagen ein Muster.
Seit 9.5.30 ist die Bibliothek größer: mehr Schimpfwörter aus allen Altersgruppen (Recherche zur
Jugendsprache und zu Abkürzungen wie „stfu“ oder „kys“) und mehr StGB-Delikte (Diebstahl, Betrug,
Erpressung, Nötigung, Körperverletzung, Sachbeschädigung, Nachstellen u. a.). Die Schwere richtet
sich nach der Absicht: beiläufig, ernst gemeint, konkret mit Ziel, besonders gefährlich.

**Getarnte Beleidigungen (9.5.32).** Vor der Erkennung macht Ai-guard Tarnungen rückgängig:
unsichtbare Zeichen, fremde Buchstaben, die gleich aussehen, Leetspeak („1d10t“), Buchstaben mit
Leerzeichen, Punkten oder Emojis dazwischen („d🙂u🙂m🙂m“), Akzente („dúmm“), gedehnte und
verdoppelte Buchstaben („duuu biiist“, „verpiiiss dich“), Sternchen („Kn*llkopf“, „A****loch“)
und zusammengeklebte Anrede („du_1d10t“). Gemessen an 1.816 getarnten Varianten der
Korpus-Beleidigungen: **99,8 % erkannt**, bei **0 Fehlalarmen** in 421 harmlosen Sätzen —
darunter solche, die wie Tarnung aussehen (Emojis, „z.B.“, „2*3“, Namen mit Akzent). Ein ganz
ausgesterntes Wort („d****r“) ist ohne Zusammenhang mehrdeutig; das beurteilt das Modell.

**Mehr Wörter, Ketten und Drohungen (9.5.33).** Rund 90 weitere Schimpfwörter auf Deutsch und
Englisch, von leicht („Schnarchnase“, „Wichtigtuer“, „coward“) bis grob („Drecksau“, „scum“).
**Ketten:** Eine Nachricht nur aus Schimpfwörtern („Idiot Trottel Depp“, „you stupid useless
idiot“) zählt als Beleidigung, auch ohne Satz drumherum; ab **drei verschiedenen** Schimpfwörtern
in einer beleidigenden Nachricht steigt die Schwere um eine Stufe — höchstens bis „grob“ (Bann für
7 Tage). Für immer gesperrt wird dadurch niemand; das bleibt Drohungen vorbehalten. Dasselbe Wort
dreimal ist keine Kette, und Tiernamen in einer Frage zum Bauernhof auch nicht. **Drohungen**
(§ 241 StGB) werden jetzt auch über Kommas hinweg erkannt: „ich weiß, wo du wohnst“ ist grob,
ausgesprochene Gewalt („ich polier dir die Fresse“, „I'll smash your face“) sperrt dauerhaft.
Mehrdeutiges wie „Ich finde dich!“ (Versteckspiel) zählt bewusst nicht. **Rechtliches:** Ai-guard
ordnet mehr Straftaten richtig ein — Verleumdung, üble Nachrede, Freiheitsberaubung,
Menschenhandel, sexueller Missbrauch, Doxxing, Swatting, Cybermobbing, Steuerhinterziehung,
Bestechung, Drogenhandel, Geldfälschung, Unfallflucht, Tierquälerei, Volksverhetzung, Meineid
(auch englisch) als Rechtsbruch; Terror, Anschläge, Vergiftung und Computersabotage als Angriff.
Beim Nachprüfen mit Wortlisten (je 50.000 häufige deutsche und englische Wörter) sind Fehlalarme
aufgefallen und behoben: „deep“, „Asien“, „Meme“, „Creeper“, „Superbot“, „flicker“ oder
„Hundeschnauze“ gelten nicht mehr als Beleidigung.

**Geprüft wie ein Angreifer und wie ein Nutzer (9.6.0).** Drei Prüfer haben die App angegriffen,
jede Funktion im Browser ausprobiert und Netguard und Ai-guard durchgesehen; alles Bestätigte ist
behoben und hat einen Test:
- **Netguard:** eine „Zip-Bombe“ (389 KB, die zu 400 MB werden) belegt nicht mehr 149 MB, sondern
  wenige MB — gepackte Antworten werden Stück für Stück und gedeckelt ausgepackt, angefragt wird
  nur noch gzip/deflate. Ein Server, der die Kopfzeilen Byte für Byte tröpfeln lässt, hält einen
  Abruf nicht mehr über die Gesamtfrist hinaus fest. `fec0::/10` (veraltetes internes IPv6) ist
  gesperrt, NAT64-Adressen (`64:ff9b::/96`) werden nach ihrer IPv4-Adresse beurteilt. Ein
  `AQUATICY_PROXY`, der nicht `http://` ist, führt nicht mehr still am Proxy vorbei, sondern
  stoppt den Abruf. Ändert sich httpx so, dass der Schutz nicht greifen kann, startet kein Client.
- **Ai-guard, weniger Fehlalarme:** „die Präsentation für meinen Chef fertig machen“, „meinen
  Freund in Minecraft fertig machen“, „damit meine Oma vor Freude weint“, „mock the database in
  my coworker's test“ oder „Kann man jemanden wegen ‚Halt die Fresse‘ anzeigen?“ zählen nicht
  mehr — im Prüfsatz von 309 harmlosen Sätzen von 13 auf 1 Fehlalarm. Person und Verb müssen
  jetzt direkt zusammenstehen; „fertig machen“ allein ist nur noch eine Chatsperre, kein Bann.
- **Ai-guard, mehr Treffer:** „Ich zünde dein Haus an“, „I'm going to hurt you“, „you should
  die“, „Stirb“, „Du wirst es bereuen“, behindertenfeindliche Beschimpfungen und „Du bist nicht
  schlau, sondern ein Idiot“ werden erkannt (verpasst: von 17 auf 6 von 87).
- **Ai-guard, Sperren:** eine automatische Sperre ersetzt nie eine längere (vorher machte eine
  Beleidigung aus „für immer“ einen Tag); wiederholte schwere Beleidigungen werden länger
  gesperrt (7 Tage → 30 Tage → für immer); beide Prüfwege zählen Anhaltspunkte gleich.
- **Antwortprüfung:** Rohrbombe, Schusswaffe, Rizin, Sarin, Erpressungstrojaner, Keylogger im
  Code und Entmenschlichung gehen jetzt zum Modell; bei langen Antworten sieht es die Stellen um
  jedes Stichwort statt nur den Anfang. Dialoge („**Tom:** …“) und berichtete Drohungen
  („soll gedroht haben: …“) werden nicht mehr zurückgezogen. Lange Zeichenketten ohne Leerzeichen
  (base64) brauchen keine 1,7 Sekunden Prüfzeit mehr.
- **Webserver:** Fehlertexte gehen immer durch den Schlüsselfilter (vorher nicht bei 500ern);
  die Speichern-Meldung verrät keinen Serverpfad mehr; `HEAD /logo.png` geht; das Logo zählt
  nicht zum Anfragen-Limit.
- **Oberfläche:** Nach dem kleinen schnellen Modell lässt sich das große wieder wählen; das
  Modellmenü bleibt auf kleinen Bildschirmen im Bild, ist per Tastatur erreichbar (Fokus springt
  hinein, Pfeiltasten, Escape zurück) und die kleinen Fenster halten den Fokus; „Überall sonst
  abmelden“ fragt nach.

**Unabhängig geprüft (9.5.34).** Vier Prüfer ohne Vorwissen über den Code haben Webserver,
Agent, Netz und Ai-guard durchgesehen und jeden Fund ausprobiert; alles Bestätigte ist behoben
und hat einen Test. Die wichtigsten Punkte:
- **Ai-guard:** Alltagssätze wie „Ich bringe dich um 8 Uhr zur Schule“, „Shut up and take my
  money“, „Du kannst mich mal anrufen“, „Nobody thinks you are stupid“, „Im Spiel bist du die
  Ratte“ oder „Übersetze: Du bist ein Idiot“ zählen nicht mehr; Drohungen über Kommas zählen nur
  noch am Ende der Nachricht. Neu erkannt werden „Klappe!“, „Du bist Müll“, „You're the dumbest“.
  Eine lange Nachricht mit vielen Sternchen braucht keine 38 Sekunden mehr. Alte Anhaltspunkte
  (älter als 90 Tage) bilden auch über den zweiten Prüfweg kein Muster mehr.
- **robots.txt nach RFC 9309:** die längste passende Regel gilt, `*` und `$` werden verstanden,
  und bei einem Serverfehler wird nichts abgerufen. Ein Overlay, das nach Bezahlschranke oder
  Anmeldung aussieht, wird nie entfernt.
- **Datenschutz:** Home-Assistant-Token und Google-Client-Geheimnis liegen jetzt verschlüsselt im
  Schlüsselbund statt in der `.env`. Ein laufender Chat schreibt nach „Konto löschen“ nichts
  mehr zurück. Der Schutz vor dem Weitergeben privater Angaben prüft auch Rechnernamen
  („0176….example“), und unsichtbare Trennzeichen verstecken keine Anweisungen mehr.
- **Sicherheit:** kein Ausbruch aus Links in der Oberfläche; „nur öffentliche Repos“ bei GitHub
  lässt sich nicht mehr mit `../..` umgehen; UTF-16-Feeds mit DTD werden abgelehnt; jeder Abruf
  hat eine Gesamtfrist; wer ein gesperrtes Konto löscht, kann von derselben Adresse aus nicht
  sofort ein neues anlegen.
- **Kleinere Fehler:** Einstellungen speichern hängt nicht mehr während einer Antwort, der
  400-MB-Deckel hält auch bei schnellen Schreibfolgen und löscht keine Uploads mehr, wenn es
  nichts nützt, Preiswächter lesen „bis 17 Zoll unter 80 Euro“ richtig, `aquaticy export` nimmt
  die Produkte mit, Orte wie „Zahnarzt“ oder „Parkhaus“ werden richtig gesucht.

**Antworten werden mitgeprüft (seit 9.5.34).** Ai-guard schaut auch auf das, was Aquaticy
selbst schreibt — milder als bei deinen Nachrichten: niemand wird deswegen gesperrt. Beschimpft
oder bedroht eine Antwort den Nutzer, oder halten bei Stichworten (Schadsoftware, Waffen,
Selbstverletzung, Hass, Sexuelles …) das schnelle Modell und die feste Erkennung sie für
eindeutig unangemessen, wird sie zurückgezogen. Stattdessen steht: „Dabei kann ich nicht
helfen.“ Zitate, Erklärungen, Geschichte, Bildung und Prävention bleiben frei; fällt das Modell
aus, gilt die Antwort als in Ordnung. Auch aus dem Verlauf wird sie genommen, damit sie nicht
im Kontext der nächsten Frage steht.

**Sicherheit im Code-Modus (9.5.30).** Fragt ein **Normal- oder Pro-Konto** im Code-Modus mit
laufender virtual machine nach etwas in Richtung **Cybersecurity, Hacking oder Schadsoftware**,
schaltet Aquaticy automatisch zurück in den **Normal-Modus** — die virtual machine ist damit aus —
und schreibt kurz in den Chat, warum. So bekommt man kein Werkzeug in die Hand, mit dem sich in
dieser Richtung etwas ausführen ließe; die Frage selbst wird im Normal-Modus weiter beantwortet
(soweit die Rechts-Leitplanken sie erlauben). **Ultra-Konten** behalten die virtual machine.
Gewöhnliches Programmieren („REST-API bauen“, „IndexError beheben“) löst das nicht aus.

Bei einem Bann bleibt der Chat, in dem es passiert ist, dauerhaft gesperrt. Der **Wächter der virtual machine**
prüft, was in der virtual machine gebaut, installiert oder ausgeführt werden soll, und stoppt
Schadsoftware, bevor sie läuft. Ein gesperrtes Konto kann sich anmelden, aber nichts mehr tun —
weder schreiben noch virtual machine, Add-ons, Aufträge, Befehle oder Einstellungen; nur abmelden, das
Design ändern und die eigenen Chats ansehen. Auch Aufträge und Antworten auf Rückfragen prüft
Ai-guard wie den Chat. Oben links unter der Versionsnummer steht ein rotes **Info** mit Dauer, Grund und was man tun kann.
Ultra-Konten werden nur im Terminal gewarnt. Die Daten dienen ausschließlich dem Missbrauchsschutz.

```bash
aquaticy ban "name"            # Konto dauerhaft sperren
aquaticy ban "name" --tage 7   # Konto für 7 Tage sperren
aquaticy ban 203.0.113.7       # IP-Adresse sperren
aquaticy unban "name"          # wieder freigeben (auch Chatsperren)
aquaticy list                  # Konten mit Adress-Kürzel, Geräteanzahl und Ai-guard-Stand
aquaticy aiguard "du Idiot"    # Stufe und Folge eines Satzes testen -- ohne Vermerk
aquaticy aiguard --konto "name"  # die letzten Vorfälle eines Kontos
```

---

## Server-Verbund (seit 9.6.1)

*Einstellungen → Dev settings → Server-Verbund* (nur **Ultra**). Bis zu **10 Server**, auf
denen Aquaticy läuft, arbeiten zusammen:

- **Eine Datenbank, auf jedem Server vollständig.** Konten, Sitzungen und Ai-guard werden
  Zeile für Zeile gespiegelt, die Profilordner (Chats, Speicher, Aufträge) vom zuständigen
  Server auf alle anderen. Anmelden geht an jedem Server.
- **Lastausgleich.** Jedes Konto hat einen Heimserver; der Master teilt neue und länger
  untätige Konten dem Server mit der geringsten Auslastung zu. Kommt eine Anfrage woanders
  an, wird sie verschlüsselt an den Heimserver weitergereicht. Aufträge laufen nur dort.
- **Master** ist der Server, der eingeladen hat.

**Verbinden:** auf allen Servern `aquaticy web --lan` starten und den Schalter einschalten.
Die anderen Server im lokalen Netz erscheinen dann in der Liste (oder IP-Adresse eintragen) →
**Verbinden**. Auf dem anderen Server fragt das Terminal `Annehmen? [yes/no]`; bei `yes`
zeigt er einen sechsstelligen Code, den du auf dem Master eingibst. Läuft der Server ohne
Terminal (Container im Hintergrund): `docker compose exec aquaticy aquaticy cluster`.

**Gut zu wissen:** Der neue Server übernimmt die Daten des Verbunds und startet einmal neu;
seine bisherigen Daten werden unter `cluster/backup-<Zeit>` gesichert, nicht gelöscht.
Zwischen den Servern ist alles mit AES-GCM verschlüsselt; der Schlüssel entsteht per
X25519-Schlüsseltausch und wird gewechselt, wenn ein Server entfernt wird. Das Finden läuft
per UDP-Rundruf auf Port 8766 (`AQUATICY_CLUSTER_PORT`) — im Container dafür
`compose.host.yaml` (Host-Netz) nutzen. Fällt der Master aus, arbeiten die anderen mit der
letzten Zuteilung weiter.

---

## Modelle und Anbieter

Aquaticy ist auf **Mistral**, **NVIDIA NIM** und lokale Modelle mit **Ollama** eingerichtet.

| Anbieter | Kürzel | Schlüssel |
|---|---|---|
| [Mistral](https://console.mistral.ai/api-keys/) | `mistral/` | `MISTRAL_API_KEY` |
| [NVIDIA NIM](https://build.nvidia.com/) | `nvidia_nim/` | `NVIDIA_NIM_API_KEY` |
| Ollama (lokal) | `ollama_chat/` | — |

Je Anbieter wählt Aquaticy selbst das passende Modell:

| Aufgabe | Mistral | NVIDIA NIM |
|---|---|---|
| Recherche und Antwort | `mistral-large-latest` | `meta/llama-3.3-70b-instruct` |
| Helfer, Planung | `mistral-small-latest` | `meta/llama-3.1-8b-instruct` |
| Code-Modus | `codestral-latest` | `qwen/qwen2.5-coder-32b-instruct` |

```bash
aquaticy --model mistral/mistral-large-latest
aquaticy --model nvidia_nim/meta/llama-3.3-70b-instruct
aquaticy --model ollama_chat/qwen2.5:7b
```

- Das Modell muss **Werkzeuge aufrufen** können (Tool-Calling), sonst kann es nicht suchen.
- Fehlt das Anbieter-Kürzel, ergänzt Aquaticy es beim Speichern.
- Jeder andere LiteLLM-Anbieter geht über `AQUATICY_MODEL=anbieter/modell` und
  `AQUATICY_API_KEY`.
- Aquaticy hält die Anfragegrenzen der Anbieter selbst ein (NVIDIA 40/Minute, Mistral 240/Minute
  im kostenlosen Tarif) — anpassbar mit `AQUATICY_RPM` und `AQUATICY_PARALLEL_CALLS`.
- In der Weboberfläche kann jedes Konto eigene Modelle und Schlüssel eintragen; sie gelten nur
  dort und zählen nicht gegen das Limit.

---

## Suche

Standard ist eine **offene Metasuche** über mehrere Suchdienste — ohne Schlüssel, ohne Konto.
Jede Frage wird auf mehrere Arten formuliert, das findet mehr (`AQUATICY_SEARCH_VARIANTS`).

| Suchmaschine | Einstellung | Schlüssel |
|---|---|---|
| Offene Suche | `duckduckgo` | — |
| Eigener [SearXNG](https://docs.searxng.org/)-Server | `searxng` + `AQUATICY_SEARXNG_URL` | — |
| [Brave Search](https://brave.com/search/api/) | `brave` | `BRAVE_API_KEY` |
| [Tavily](https://tavily.com/) | `tavily` | `TAVILY_API_KEY` |

Alles auf dem eigenen Rechner — lokales Modell plus eigener Suchserver:

```bash
docker compose --profile searxng up -d searxng
echo 'AQUATICY_SEARCH_BACKEND=searxng' >> .env
```

Vor dem ersten Start in `docker/searxng/settings.yml` den `secret_key` ersetzen
(`openssl rand -hex 32`).

---

## Im Container

```bash
./aquaticy-box --setup            # einmalig: fragt Modell und Schlüssel ab
./aquaticy-box                    # Chat
./aquaticy-box "deine Frage"      # einzelne Recherche
```

Oder mit Compose:

```bash
docker compose run --rm aquaticy
docker compose build aquaticy                                # mit Chromium (Standard)
AQUATICY_IMAGE_TARGET=slim docker compose build aquaticy     # ohne Chromium, ~700 MB kleiner
```

Nach einem `git pull` oder einem neuen ZIP muss auch das Container-Image neu gebaut
werden: `docker compose build aquaticy`. Ein bereits laufender Web-Container
braucht danach einen Neustart mit `docker compose up -d --force-recreate aquaticy`.

Der Container trennt das Dateisystem vom Rechner; ins Internet darf Aquaticy weiterhin, sonst
könnte es nicht recherchieren. Noch strenger abgeschottet: `compose.sandbox.yaml`
(`aquaticy sandbox` zeigt, was offen steht).

---

## Konfiguration

Alle Werte stehen in der `.env` (Vorlage: [`.env.example`](.env.example)). In der Weboberfläche
setzt du die meisten unter *Einstellungen*.

| Variable | Bedeutung | Standard |
|---|---|---|
| `AQUATICY_MODEL` | Hauptmodell (`anbieter/name`) | `mistral/mistral-large-latest` |
| `AQUATICY_VISION_MODEL` | Modell für Bilder | wie `AQUATICY_MODEL` |
| `AQUATICY_SUBAGENT_MODEL` | Modell der Helfer | das schnelle kleine des Anbieters |
| `AQUATICY_CODE_MODEL` | Modell für den Code-Modus | das stärkste erreichbare |
| `AQUATICY_API_BASE` | eigene Adresse (Ollama, eigene NIM, Proxy) | — |
| `AQUATICY_API_KEY` | Schlüssel für andere Anbieter | — |
| `AQUATICY_AUTO_MODEL` | Modell je Nachricht automatisch wählen | `false` |
| `AQUATICY_SEARCH_BACKEND` | `duckduckgo`, `searxng`, `brave`, `tavily` | `duckduckgo` |
| `AQUATICY_SEARCH_ENGINES` | Suchdienste der offenen Suche einschränken | alle |
| `AQUATICY_SEARCH_VARIANTS` | Formulierungen je Suche (`1` = aus) | `3` |
| `AQUATICY_SEARXNG_URL` | Adresse des SearXNG-Servers | — |
| `AQUATICY_LOCATION` | Standard-Ort | — |
| `AQUATICY_LANG` / `AQUATICY_COUNTRY` | Sprache / Land der Suche | `de` / `de` |
| `AQUATICY_MAX_TOOL_CALLS` | Suchen und Seitenaufrufe je Frage | `20` |
| `AQUATICY_SUBAGENTS_AUTO` | große Fragen automatisch aufteilen | `true` |
| `AQUATICY_SUBAGENT_BUDGET` | Suchen je Helfer | `6` |
| `AQUATICY_SUBAGENT_PARALLEL` | Helfer gleichzeitig (`0` = automatisch) | lokal `2` |
| `AQUATICY_PLANNER_TIMEOUT` | Zeit fürs Aufteilen einer Frage (s) | `20` |
| `AQUATICY_CONTEXT_TOKENS` | Gesprächsgedächtnis lokaler Modelle | `16384` |
| `AQUATICY_RPM` | Anfragen pro Minute an den Anbieter | NVIDIA `40`, Mistral `240` |
| `AQUATICY_PARALLEL_CALLS` | gleichzeitige Anfragen | NVIDIA `4`, Mistral `8` |
| `AQUATICY_FETCH_TIMEOUT` | Wartezeit je Seite (s) | `15` |
| `AQUATICY_CACHE_TTL_HOURS` | Gültigkeit des Zwischenspeichers | `24` |
| `AQUATICY_ENABLE_PLAYWRIGHT` | echten Browser für schwierige Seiten | `true` |
| `AQUATICY_MEMORY` | Speicher an | `true` |
| `AQUATICY_LEGAL_GUARD` | Rechts-Leitplanken (abschaltbar nur mit Ultra) | `true` |
| `AQUATICY_VM_SIZE` | virtual machine: `normal` oder `plus` (Ultra) | `normal` |
| `AQUATICY_VM_IMAGE` | Abbild der virtual machine | `python:3.12-slim` |
| `AQUATICY_VM_USER_MODE` | User mode (Ultra) | `false` |
| `AQUATICY_VM_INTERNET` | Internet für die virtual machine im Code-Modus (nur Ultra; Normal und Pro haben dort kein Netz) | `false` |
| `AQUATICY_VM_LAN` | virtual machine auch ins lokale Netz, ohne Sperre (nur Ultra) | `false` |
| `AQUATICY_ANSWER_CHECK` | Ai-guard prüft auch die Antworten von Aquaticy (nur der Betreiber stellt es ab) | `true` |
| `AQUATICY_VM_DESKTOP_IMAGE` | Abbild für den User mode | `aquaticy-werkstatt-desktop:local` |
| `AQUATICY_VM_IDLE_MINUTES` | virtual machine löschen nach Minuten Ruhe | `20` |
| `AQUATICY_GITHUB_TOKEN` | Token des GitHub-Add-ons | — |
| `AQUATICY_GOOGLE` / `AQUATICY_GOOGLE_WRITE` | Gmail und Kalender lesen / ändern | `false` |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | eigene Google-Anwendung | — |
| `AQUATICY_HA_URL` / `AQUATICY_HA_CONTROL` | Home Assistant / schalten erlaubt (Ultra) | — / `false` |
| `AQUATICY_LAN_ENABLED` / `AQUATICY_LAN_SUBNET` | Heimnetz ansehen (Ultra) | `true` / automatisch |
| `AQUATICY_STORAGE_URL` / `AQUATICY_STORAGE_ACCESS` | Lagerverwaltung: Adresse / `off`, `read`, `write` (Ultra) | — / `read` |
| `AQUATICY_PRO_CODE` | Code für neue Pro-Konten | zufällig |
| `AQUATICY_ULTRA_CODE` | Code für neue Ultra-Konten (14 Zeichen) | zufällig |
| `MISTRAL_API_KEY`, `NVIDIA_NIM_API_KEY`, `BRAVE_API_KEY`, `TAVILY_API_KEY` | Schlüssel der Anbieter | — |

Daten liegen unter `~/.aquaticy/` (Konten in `accounts.sqlite3`, je Konto ein eigener Ordner
unter `users/`), die Einstellungen unter `~/.config/aquaticy/.env`.

---

## Konten verwalten (Betreiber)

```bash
aquaticy list                  # alle Konten: Typ, Adress-Kürzel (#…), Geräte, Nutzung, Speicher, Ai-guard
aquaticy pro-code              # Code für neue Pro-Konten anzeigen
aquaticy ultra-code            # Code für neue Ultra-Konten anzeigen
aquaticy ban "name"            # Konto sperren (auch per IP-Adresse)
aquaticy unban "name"          # Sperre aufheben, Anhaltspunkte zurücksetzen
```

---

## Entwicklung

```bash
git clone --branch Aquaticy-ai --single-branch https://github.com/jonasenriklaumen-a11y/Aquaticy-Ai.git
cd Aquaticy-Ai
uv venv && uv pip install -c constraints.txt -e ".[browser,dev]"

uv run pytest          # alle Tests; Netz und Modelle sind gestellt
uv run ruff check .    # Stilprüfung

python tools/rundgang.py            # bedient die Weboberfläche wie ein Mensch
python tools/rundgang.py --bilder   # dabei Bildschirmfotos ablegen
```

---

## Lizenz

MIT — der volle Text steht in [`LICENSE`](LICENSE).
