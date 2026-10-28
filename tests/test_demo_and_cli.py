import json
import urllib.request
from pathlib import Path
from dataclasses import replace

import pytest

from patchorder.cli import main
from patchorder.engine import run_demo
from patchorder.llm import cve_texts, preview_json

ROOT = Path(__file__).resolve().parents[1]


def test_demo_briefing_answers_the_question():
    report = run_demo()
    by_asset = {}
    for finding in report.findings:
        by_asset.setdefault(finding.asset_id, []).append(finding)
    assert by_asset["edge-proxy"][0].cve_id == "CVE-2023-44487"
    assert by_asset["edge-proxy"][0].kev
    assert by_asset["edge-proxy"][0].points > by_asset["tls-library"][0].points
    assert "3.0.13" in by_asset["tls-library"][0].fixed_hint
    assert "FIXTURE-SA-2024-0001" in by_asset["tls-library"][0].fixed_hint
    assert "not an official" in by_asset["tls-library"][0].fixed_hint
    assert any(part.points == 5 for part in by_asset["tls-library"][0].parts)
    assert by_asset["file-servers"][0].cve_id == "CVE-2024-38063"
    assert "10.0.20348.2655" in by_asset["file-servers"][0].fixed_hint
    assert by_asset["analyst-laptops"][0].cve_id == "CVE-2024-38063"
    assert "10.0.22631.4037" in by_asset["analyst-laptops"][0].fixed_hint
    assert by_asset["bastion-ssh"][0].cve_id == "CVE-2024-6387"
    assert "edge-current" not in by_asset
    assert "file-servers-patched" not in by_asset
    assert "bastion-fixed" not in by_asset
    assert "server-name-only" not in by_asset
    assert "custom-connector" not in by_asset
    assert report.new_cve_ids == ["CVE-2023-44487", "CVE-2024-38063"]
    kinds = {(note.asset_id, note.kind) for note in report.notes}
    assert ("edge-current", "not_affected") in kinds
    assert ("file-servers-patched", "not_affected") in kinds
    assert ("bastion-fixed", "not_affected") in kinds
    assert ("server-name-only", "not_decided") in kinds
    assert ("custom-connector", "unresolved") in kinds
    # Score lines are the formula, not a hidden weight.
    blob = " ".join(part.text for part in by_asset["edge-proxy"][0].parts)
    assert "CISA KEV" in blob
    assert "EPSS" in blob
    assert "CVSS" in blob
    assert "internet" in blob
    assert "12 hosts" in blob


def test_demo_command_writes_nothing_and_stays_offline(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["demo"]) == 0
    assert list(tmp_path.iterdir()) == []
    out = capsys.readouterr().out
    assert "exploited in the wild" in out
    assert "Patch nginx 1.25.2 on 12 internet-facing hosts" in out
    assert "New since last run" in out
    assert "CVE-2023-44487" in out
    assert "10.0.22631.4037" in out
    assert "Harbor Connector" in out or "custom-connector" in out
    assert "read-only" in out
    assert "Priority formula" in out


def test_demo_html_and_json(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    html_path = tmp_path / "brief.html"
    assert main(["demo", "--format", "html", "--output", str(html_path)]) == 0
    html = html_path.read_text(encoding="utf-8")
    assert "<h1>patchorder briefing</h1>" in html
    assert "CVE-2023-44487" in html
    assert "<script>" not in html
    assert main(["demo", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["tool"] == "patchorder"
    assert payload["read_only"] is True
    assert payload["top_actions"][0]["cve_id"] == "CVE-2023-44487"
    assert "exploited in the wild" in payload["top_actions"][0]["text"]


def test_llm_preview_contains_cve_text_only(capsys):
    report = run_demo()
    texts = cve_texts(report.findings)
    body = preview_json(texts, "local-model")
    assert "CVE-2023-44487" in body
    for forbidden in ("edge-proxy", "Harbor Workshop", "platform", "10.0.20348.2400", "custom-connector"):
        assert forbidden not in body
    assert main(["demo", "--llm-preview"]) == 0
    out = capsys.readouterr().out
    preview = out.split("```json", 1)[1].split("```", 1)[0]
    assert "edge-proxy" not in preview
    assert "CVE-2024-38063" in preview


def test_resolve_is_preview_until_write(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    inventory = ROOT / "examples" / "inventory.yaml"
    lock = tmp_path / "inventory.lock.yaml"
    assert main(["resolve", "-i", str(inventory), "-o", str(lock), "--non-interactive", "--offline", "--no-discover-cpes"]) == 0
    assert not lock.exists()
    err = capsys.readouterr().err
    assert "not written" in err
    assert main(
        [
            "resolve",
            "-i",
            str(inventory),
            "-o",
            str(lock),
            "--non-interactive",
            "--offline",
            "--no-discover-cpes",
            "--write",
            "--accept",
            "edge-proxy=cpe:2.3:a:f5:nginx",
        ]
    ) == 0
    text = lock.read_text(encoding="utf-8")
    assert "cpe:2.3:a:f5:nginx" in text
    assert "edge-proxy" in text


def test_offline_scan_without_cache_exits_3(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    inventory = tmp_path / "inventory.yaml"
    inventory.write_text(
        "schema: patchorder.inventory/v1\n"
        "name: Example\n"
        "assets:\n"
        "  - id: edge\n"
        "    product: nginx\n"
        "    vendor: F5\n"
        "    version: \"1.25.2\"\n"
        "    count: 1\n"
        "    owner: ops\n"
        "    exposure: internet\n",
        encoding="utf-8",
    )
    lock = tmp_path / "inventory.lock.yaml"
    lock.write_text(
        "schema: patchorder.lock/v1\nentries:\n  edge:\n    cpe: cpe:2.3:a:f5:nginx\n    pinned: true\n",
        encoding="utf-8",
    )
    code = main(["scan", "-i", str(inventory), "-l", str(lock), "--offline", "--no-discover-cpes", "--format", "json"])
    captured = capsys.readouterr()
    assert code == 3
    assert "offline mode" in captured.out + captured.err


@pytest.mark.parametrize("filename", ["inventory.yaml", "inventory.lock.yaml"])
def test_examples_match_the_packaged_demo(filename: str) -> None:
    demo = ROOT / "src" / "patchorder" / "data" / "demo" / filename
    example = ROOT / "examples" / filename
    assert demo.read_text(encoding="utf-8") == example.read_text(encoding="utf-8")


def test_demo_epss_source_preserves_fixture_dates():
    report = run_demo()
    assert [source for source in report.sources if source.startswith("FIRST EPSS:")] == [
        "FIRST EPSS: bundled scores. Not a live query."
    ]

    payload = json.loads(
        (ROOT / "src" / "patchorder" / "data" / "demo" / "epss.json").read_text(
            encoding="utf-8"
        )
    )
    dates = {item["cve"]: item["date"] for item in payload["data"]}
    scored = [finding for finding in report.findings if finding.epss is not None]
    assert scored
    for finding in scored:
        assert finding.epss_date == dates[finding.cve_id]


@pytest.mark.parametrize(
    "args",
    [
        ["demo"],
        ["demo", "--format", "html"],
        ["demo", "--format", "json"],
        ["demo", "--llm-preview"],
    ],
    ids=["markdown", "html", "json", "llm-preview"],
)
@pytest.mark.parametrize("write_output", [False, True], ids=["stdout", "file"])
def test_demo_attempts_no_http_and_writes_only_requested_output(
    args, write_output, tmp_path, monkeypatch, capsys
):
    attempts = []

    def reject_http(*call_args, **call_kwargs):
        # Record first because application error handling may catch the exception.
        attempts.append((call_args, call_kwargs))
        raise AssertionError("demo attempted HTTP")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(urllib.request, "urlopen", reject_http)
    output = tmp_path / "reports" / "briefing.txt"
    command = args + ["--output", str(output)] if write_output else args

    assert main(command) == 0
    assert attempts == []
    captured = capsys.readouterr()
    if write_output:
        assert captured.out == ""
        assert "CVE-2023-44487" in output.read_text(encoding="utf-8")
        assert set(tmp_path.rglob("*")) == {output.parent, output}
    else:
        assert "CVE-2023-44487" in captured.out
        assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("length", [1199, 1200, 1201])
def test_llm_description_cap_includes_truncation_marker(length):
    description = " \n" + "é" * length + "\n "
    finding = replace(run_demo().findings[0], description=description)

    texts = cve_texts([finding])

    expected = "é" * length if length <= 1200 else "é" * 1197 + "..."
    assert texts == [(finding.cve_id, expected)]
    assert len(texts[0][1]) <= 1200
    assert finding.description == description
