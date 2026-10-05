"""Bound nesting before decoding JSON received over the network."""

from __future__ import annotations

import json
import re
from typing import Any

MAX_DEPTH = 64
_STRUCTURE = re.compile(r'\\.|"|[\[\]{}]')


class JsonDepthError(ValueError):
    """A request exceeds the bounded JSON container depth."""


def loads(raw: bytes | str) -> Any:
    """Keep standard JSON syntax and encodings, with a fixed depth ceiling.

    Escaped quotes and brackets in strings are data. Check before decoding so
    neither Python's recursion limit nor a third-party change to it controls
    the amount of nesting a network peer can submit.
    """
    text = raw.decode(json.detect_encoding(raw), "surrogatepass") if isinstance(raw, bytes) else raw
    quoted = False
    depth = 0
    for match in _STRUCTURE.finditer(text):
        token = match.group()
        if token == '"':
            quoted = not quoted
        elif not quoted:
            if token in ("[", "{"):
                depth += 1
                if depth > MAX_DEPTH:
                    raise JsonDepthError("Die Anfrage ist zu stark verschachtelt.")
            elif token in ("]", "}"):
                depth -= 1
    return json.loads(text)
