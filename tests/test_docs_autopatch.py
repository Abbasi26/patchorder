"""Keep docs/windows-autopatch.md honest: its example is real demo output and its sources are Microsoft's."""

import re
from pathlib import Path

from patchorder.cli import main

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "windows-autopatch.md"


def _example_line() -> str:
    block = re.search(r"```text\n(.+?)\n```", DOC.read_text(encoding="utf-8"), re.S)
    assert block is not None
    return block.group(1).strip()


def test_autopatch_doc_example_matches_demo_output(capsys):
    assert main(["demo"]) == 0
    assert _example_line() in capsys.readouterr().out


def test_autopatch_doc_cites_only_microsoft_sources():
    text = DOC.read_text(encoding="utf-8")
    urls = re.findall(r"<(https://[^>]+)>", text.split("## Sources", 1)[1])
    assert len(urls) == 3
    for url in urls:
        assert url.startswith(("https://learn.microsoft.com/", "https://techcommunity.microsoft.com/")), url


def test_readme_links_autopatch_doc():
    assert "docs/windows-autopatch.md" in (ROOT / "README.md").read_text(encoding="utf-8")
