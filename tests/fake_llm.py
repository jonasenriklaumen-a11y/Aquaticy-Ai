"""Ein kleiner OpenAI-kompatibler Modellserver fuer den Ende-zu-Ende-Test.

- Rechtspruefer (response_format "urteil"): zulaessig, ausser "VERBOTEN" steht in der Frage.
- Normale Fragen: mit "rechne" zuerst ein Werkzeugaufruf calculate(6*7), dann die Antwort.
- Streaming (SSE) und usage wie beim echten Anbieter. Jede Anfrage wird protokolliert.
"""

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

#: Was angefragt wurde -- zum Nachsehen im Test.
ANFRAGEN: list[str] = []


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        msgs = body.get("messages") or []
        ANFRAGEN.append(
            json.dumps(
                {
                    "model": body.get("model"),
                    "stream": bool(body.get("stream")),
                    "rf": (body.get("response_format") or {}).get("json_schema", {}).get("name"),
                    "tools": len(body.get("tools") or []),
                    "auth": self.headers.get("Authorization", "")[:12],
                }
            )
            + "\n"
        )
        rf = (body.get("response_format") or {}).get("json_schema", {}).get("name")
        letzte = max((i for i, m in enumerate(msgs) if m.get("role") == "user"), default=-1)
        user = str(msgs[letzte].get("content")) if letzte >= 0 else ""
        tool_done = any(m.get("role") == "tool" for m in msgs[letzte + 1 :])
        tool_calls = None
        if rf == "urteil":
            text = json.dumps(
                {
                    "zulaessig": "VERBOTEN" not in user,
                    "regel": "persoenlichkeitsrecht",
                    "grund": "Testurteil",
                }
            )
        elif "stelle formulierungen" in user.lower() and body.get("tools") and not tool_done:
            text = ""
            tool_calls = [
                {
                    "id": "call_s",
                    "type": "function",
                    "function": {
                        "name": "change_setting",
                        "arguments": json.dumps({"setting": "formulierungen", "value": "2"}),
                    },
                }
            ]
        elif "werkstatt" in user.lower() and body.get("tools") and not tool_done:
            text = ""
            tool_calls = [
                {
                    "id": "call_w",
                    "type": "function",
                    "function": {
                        "name": "vm_run",
                        "arguments": json.dumps({"command": "echo hallo-aus-der-werkstatt; id -u"}),
                    },
                }
            ]
        elif "rechne" in user.lower() and body.get("tools") and not tool_done:
            text = ""
            tool_calls = [
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {
                        "name": "calculate",
                        "arguments": json.dumps({"expression": "6*7"}),
                    },
                }
            ]
        else:
            ergebnis = next(
                (m.get("content") for m in reversed(msgs) if m.get("role") == "tool"), ""
            )
            text = "Die Antwort ist 42." + (
                " (Werkzeug: " + str(ergebnis)[:60] + ")" if ergebnis else ""
            )
        usage = {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}
        if body.get("stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()

            def send(obj):
                self.wfile.write(b"data: " + json.dumps(obj).encode() + b"\n\n")
                self.wfile.flush()

            base = {
                "id": "x",
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": body.get("model"),
            }
            if tool_calls:
                tc = dict(tool_calls[0])
                tc["index"] = 0
                send(
                    {
                        **base,
                        "choices": [
                            {
                                "index": 0,
                                "delta": {"role": "assistant", "tool_calls": [tc]},
                                "finish_reason": None,
                            }
                        ],
                    }
                )
                send(
                    {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}
                )
            else:
                for stueck in text.split(" "):
                    send(
                        {
                            **base,
                            "choices": [
                                {
                                    "index": 0,
                                    "delta": {"content": stueck + " "},
                                    "finish_reason": None,
                                }
                            ],
                        }
                    )
                send({**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
            send({**base, "choices": [], "usage": usage})
            self.wfile.write(b"data: [DONE]\n\n")
            return
        msg = {"role": "assistant", "content": text or None}
        if tool_calls:
            msg["tool_calls"] = tool_calls
        out = {
            "id": "x",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": body.get("model"),
            "choices": [
                {
                    "index": 0,
                    "message": msg,
                    "finish_reason": "tool_calls" if tool_calls else "stop",
                }
            ],
            "usage": usage,
        }
        data = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        data = json.dumps({"data": [{"id": "fake-modell", "object": "model"}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def starte() -> tuple[ThreadingHTTPServer, int]:
    """Startet den Server im Hintergrund. Returns: (Server, Port)."""
    import threading

    server = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]
