import csv
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

from patchorder.cache import cache_key
from patchorder.csvout import COLUMNS


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "offline-scan-example.yml"
README = ROOT / "README.md"
EXAMPLE = ROOT / "examples" / "offline-scan"
SHA = re.compile(r"^[0-9a-f]{40}$")
SCAN_COMMAND = (
    "python -m patchorder scan -i examples/offline-scan/inventory.yaml "
    "-l examples/offline-scan/inventory.lock.yaml --offline --no-discover-cpes --pinned-only "
    "--cache-dir examples/offline-scan/cache --format csv --output .tmp/offline-findings.csv"
)


def _scan(cache: Path, output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "patchorder",
            "scan",
            "-i",
            str(EXAMPLE / "inventory.yaml"),
            "-l",
            str(EXAMPLE / "inventory.lock.yaml"),
            "--offline",
            "--no-discover-cpes",
            "--pinned-only",
            "--cache-dir",
            str(cache),
            "--format",
            "csv",
            "--output",
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_workflow_is_manual_and_actions_are_hardened():
    text = WORKFLOW.read_text(encoding="utf-8")
    workflow = yaml.load(text, Loader=yaml.BaseLoader)

    assert set(workflow["on"]) == {"workflow_dispatch"}
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["scan"]
    assert job["timeout-minutes"] == "10"

    action_steps = [step for step in job["steps"] if "uses" in step]
    assert len(action_steps) == 3
    for step in action_steps:
        _action, revision = step["uses"].split("@", 1)
        assert SHA.fullmatch(revision)
        assert re.search(rf"uses: {re.escape(step['uses'])} # v\d", text)

    checkout = action_steps[0]
    assert checkout["uses"].startswith("actions/checkout@")
    assert checkout["with"]["persist-credentials"] == "false"
    upload = action_steps[-1]
    assert upload["with"] == {
        "name": "offline-scan-findings",
        "path": ".tmp/offline-findings.csv",
        "if-no-files-found": "error",
        "retention-days": "7",
    }
    scan = next(step["run"] for step in job["steps"] if step.get("name") == "Create offline CSV briefing")
    assert SCAN_COMMAND in scan
    assert SCAN_COMMAND in README.read_text(encoding="utf-8")
    for flag in ("--offline", "--no-discover-cpes", "--pinned-only", "--format csv"):
        assert flag in scan


def test_checked_in_cache_names_match_their_urls():
    entries = sorted((EXAMPLE / "cache").glob("*.json"))
    assert len(entries) == 4
    for entry in entries:
        payload = json.loads(entry.read_text(encoding="utf-8"))
        assert entry.stem == cache_key(payload["url"])


def test_documented_offline_scan_writes_expected_csv(tmp_path):
    output = tmp_path / "offline-findings.csv"
    result = _scan(EXAMPLE / "cache", output)

    assert result.returncode == 0, result.stderr
    with output.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert tuple(rows[0]) == COLUMNS
    assert [(row["asset_id"], row["cve_id"]) for row in rows] == [
        ("example-edge-proxy", "CVE-2023-44487")
    ]


def test_missing_required_cache_entry_has_no_network_fallback(tmp_path):
    cache = tmp_path / "cache"
    shutil.copytree(EXAMPLE / "cache", cache)
    (cache / "2389ec1e1bbfecb218d267abdca1dc30acfc73d7e591b35a21d97fff1c9c40b8.json").unlink()

    result = _scan(cache, tmp_path / "missing.csv")

    assert result.returncode == 3
    assert (tmp_path / "missing.csv").read_text(encoding="utf-8").splitlines() == [",".join(COLUMNS)]
