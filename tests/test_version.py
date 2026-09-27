"""Die angezeigte Version muss zu dem installierbaren Paket passen."""

import tomllib
from pathlib import Path

import aquaticy

ROOT = Path(__file__).resolve().parents[1]


def test_release_version_is_consistent() -> None:
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    label = aquaticy.VERSION_LABEL

    assert metadata["project"]["version"] == aquaticy.__version__
    assert (ROOT / "README.md").read_text(encoding="utf-8").startswith(
        f"# Aquaticy AI {label}\n"
    )
    assert f'window.__AQUATICY_VERSION__ || "{label}"' in (
        ROOT / "aquaticy" / "webui.html"
    ).read_text(encoding="utf-8")
