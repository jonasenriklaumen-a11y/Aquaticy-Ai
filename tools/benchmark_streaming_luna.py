"""Offline Chromium benchmark of a burst of 1,000 answer chunks.

Run: .venv/bin/python tools/benchmark_streaming_luna.py
Uses the actual Markdown parser and stream renderer from webui.html.
No application accounts, external requests or model calls are required.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from playwright.sync_api import sync_playwright


def main() -> None:
    ui = (Path(__file__).resolve().parents[1] / "aquaticy" / "webui.html").read_text()
    markdown = ui[ui.index("const esc ="):ui.index("/* ---------- Nachrichten")]
    renderer = ui[ui.index("function streamRenderer("):ui.index("async function verfolge(")]
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=shutil.which("chromium"))
        try:
            page = browser.new_page()
            page.set_content('<div id="answer"></div>')
            page.add_script_tag(content="function scroll(){}\n" + markdown + renderer)
            result = page.evaluate("""() => {
              const pieces = Array.from({length:1000}, (_, i) =>
                i % 10 === 0
                  ? '\\n- **Photosynthese** wandelt Lichtenergie um.\\n' : 'chemische Energie ');
              const bubble = document.querySelector('#answer');
              const samples = {previous:[], current:[]};
              let equal = true;
              for(let run=0;run<7;run++){
                let text = '', begin = performance.now();
                for(const piece of pieces){
                  text += piece; bubble.innerHTML = md(text) + '<span class="cursor"></span>';
                }
                bubble.innerHTML = md(text);
                samples.previous.push(performance.now()-begin);
                const expected = bubble.innerHTML;
                text = ''; begin = performance.now();
                const render = streamRenderer(bubble, () => text, () => true);
                for(const piece of pieces){ text += piece; render.schedule(); }
                render.flush();
                samples.current.push(performance.now()-begin);
                equal = equal && bubble.innerHTML === expected;
              }
              const median = values => [...values].sort((a,b) => a-b)[3];
              return {chunks:pieces.length, answer_characters:pieces.join('').length,
                previous_median_ms:median(samples.previous),
                current_median_ms:median(samples.current), identical_final_html:equal,
                previous_markdown_renders:1001, current_markdown_renders:1};
            }""")
            if not result["identical_final_html"]:
                raise AssertionError("Final answer changed")
            print(json.dumps(result, indent=2))
        finally:
            browser.close()


if __name__ == "__main__":
    main()
