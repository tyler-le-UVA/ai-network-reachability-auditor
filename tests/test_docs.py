"""Keep the README honest: every local file or image it links to must exist."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"

LINK = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)\)")


def local_links(text):
    for target in LINK.findall(text):
        if target.startswith(("http://", "https://", "#", "mailto:")):
            continue
        yield target.split("#", 1)[0]


def test_readme_exists_with_diagram():
    text = README.read_text()
    assert text.startswith("# ")
    assert "```mermaid" in text


def test_every_local_link_in_readme_exists():
    missing = [t for t in local_links(README.read_text()) if not (ROOT / t).exists()]
    assert not missing, f"README links to files that don't exist: {missing}"
