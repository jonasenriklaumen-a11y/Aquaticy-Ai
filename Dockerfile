# syntax=docker/dockerfile:1
#
# aquaticy im Container: isoliert vom System, aber mit vollem Netzzugang.
#
#   docker build -t aquaticy .                     # mit Browser-Fallback (Default)
#   docker build -t aquaticy --target slim .       # ohne Browser, ~700 MB kleiner
#
# Der Container schraenkt das Netz bewusst NICHT ein -- aquaticy muss frei
# suchen und Seiten lesen koennen. Isoliert wird das Dateisystem: der
# Container sieht nur /data (Cache und Verlauf) und /work (Exporte).

# ---------------------------------------------------------------------------
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    AQUATICY_DATA_DIR=/data \
    PLAYWRIGHT_BROWSERS_PATH=/browsers \
    TERM=xterm-256color \
    HOME=/tmp

# tini raeumt Zombie-Prozesse auf und leitet Strg+C sauber weiter.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*

# /data und /work sind fuer jede UID beschreibbar. Das erlaubt es,
# den Container unter der UID des Host-Nutzers laufen zu lassen -- sonst
# gehoerten die Exporte unter Linux dem falschen Benutzer.
RUN useradd --create-home --uid 1000 aquaticy \
    && mkdir -p /data /work /browsers \
    && chown -R aquaticy:aquaticy /data /work /browsers \
    && chmod 0777 /data /work

WORKDIR /app
COPY pyproject.toml README.md constraints.txt ./
COPY aquaticy ./aquaticy
# Genau die getesteten Versionen (constraints.txt, seit 9.5.15).
RUN pip install --no-cache-dir -c constraints.txt .

# ---------------------------------------------------------------------------
# Ohne Browser -- Cookie-Stufen 1 und 2 reichen fuer die allermeisten Seiten.
FROM base AS slim

USER aquaticy
WORKDIR /work
ENTRYPOINT ["/usr/bin/tini", "--", "aquaticy"]
CMD []

# ---------------------------------------------------------------------------
# Mit Chromium fuer den JavaScript-Fallback (Stufe 3).
FROM base AS browser

RUN pip install --no-cache-dir -c constraints.txt playwright \
    && playwright install --with-deps chromium \
    && chmod -R a+rX /browsers \
    && rm -rf /var/lib/apt/lists/* /root/.cache

# Chromium versucht immer zuerst MIT seiner eigenen Sandbox (seit 9.5.15).
# Im Container fehlen ihr meist die Benutzer-Namensraeume -- sie zu erlauben
# hiesse, den Container zu schwaechen. Dann, und nur dann, darf er ohne
# starten; die Isolation uebernimmt der Container (Benutzer ohne Rechte,
# siehe README: --cap-drop ALL, no-new-privileges).
ENV AQUATICY_BROWSER_NO_SANDBOX=1 \
    AQUATICY_ENABLE_PLAYWRIGHT=true

USER aquaticy
WORKDIR /work
ENTRYPOINT ["/usr/bin/tini", "--", "aquaticy"]
CMD []

# ---------------------------------------------------------------------------
# Die aeussere Kiste: die Weboberflaeche laeuft eingeschlossen, und DARIN
# macht die Werkstatt noch einmal eine eigene Kiste auf.
#
#   docker build -t aquaticy:web --target web .
#
# Warum Podman drinnen und nicht der Docker-Sockel des Wirts: der Sockel
# waere der uebliche Kurzweg -- und er hebt die ganze aeussere Wand auf.
# Wer ihn erreicht, startet auf dem Wirt einen Container mit dessen
# Wurzelverzeichnis und ist damit root. Die Werkstatt bekommt deshalb eine
# eigene, wurzellose Laufzeit im Inneren.
FROM browser AS web

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends podman uidmap fuse-overlayfs \
    && rm -rf /var/lib/apt/lists/*

# Podman wurzellos in einem Container: ohne zusaetzliche Rechte gibt es
# keine Kennungsbereiche (`newuidmap` braucht Datei-Faehigkeiten, die
# `no-new-privileges` gerade verhindert). Mit dem vfs-Treiber und
# `ignore_chown_errors` geht es trotzdem -- langsamer, aber ohne dass die
# Kiste dafuer aufgemacht werden muesste.
RUN mkdir -p /etc/containers \
    && printf '%s\n' \
        '[storage]' \
        'driver = "vfs"' \
        'runroot = "/tmp/containers"' \
        'graphroot = "/home/aquaticy/.local/share/containers/storage"' \
        '[storage.options]' \
        'ignore_chown_errors = "true"' \
        > /etc/containers/storage.conf \
    && printf '%s\n' \
        '[engine]' \
        'cgroup_manager = "cgroupfs"' \
        'events_logger = "file"' \
        > /etc/containers/containers.conf \
    && printf '%s\n' 'unqualified-search-registries = ["docker.io"]' \
        > /etc/containers/registries.conf \
    && echo 'aquaticy:100000:65536' > /etc/subuid \
    && echo 'aquaticy:100000:65536' > /etc/subgid \
    && mkdir -p /home/aquaticy/.local/share/containers \
    && chown -R aquaticy:aquaticy /home/aquaticy

ENV HOME=/home/aquaticy \
    AQUATICY_VM_RUNTIME=podman \
    AQUATICY_SANDBOXED=1

USER aquaticy
WORKDIR /work
EXPOSE 8765
# Nur an alle Schnittstellen IN der Kiste -- nach draussen bindet erst
# Compose, und zwar auf 127.0.0.1.
ENTRYPOINT ["/usr/bin/tini", "--", "aquaticy", "web", "--host", "0.0.0.0"]
CMD []
