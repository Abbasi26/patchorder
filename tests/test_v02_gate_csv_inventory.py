import csv
import io
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from patchorder.cli import main
from patchorder.csvout import COLUMNS, render_csv
from patchorder.engine import run_demo
from patchorder.errors import PatchorderError
from patchorder.gate import evaluate_gates, parse_gate
from patchorder.inventory import load_inventory
from patchorder.inventorytools import check_inventory, csv_to_inventory

ROOT = Path(__file__).resolve().parents[1]


def test_parse_gate():
    assert parse_gate("KEV").kind == "kev"
    gate = parse_gate("priority:70")
    assert gate.kind == "priority" and gate.threshold == 70 and gate.label() == "priority:70"
    for bad in ("priority:x", "priority:200", "critical"):
        with pytest.raises(PatchorderError):
            parse_gate(bad)


def test_parse_epss_gate():
    gate = parse_gate("epss:0.5")
    assert gate.kind == "epss" and gate.threshold == 0.5 and gate.label() == "epss:0.5"
    assert parse_gate("epss:0").threshold == 0.0
    assert parse_gate("epss:1").threshold == 1.0
    for bad in ("epss:x", "epss:1.5", "epss:-0.1", "epss"):
        with pytest.raises(PatchorderError):
            parse_gate(bad)


def test_gates_on_demo():
    report = run_demo()
    assert evaluate_gates(report, [parse_gate("kev")])[0].startswith("--fail-on kev: 1 finding(s) (edge-proxy:CVE-2023-44487")
    assert evaluate_gates(report, [parse_gate("priority:95")]) == []
    assert len(evaluate_gates(report, [parse_gate("priority:40"), parse_gate("internet")])) == 2
    assert "3 finding(s)" in evaluate_gates(report, [parse_gate("new")])[0]
    with pytest.raises(PatchorderError):
        evaluate_gates(replace(report, new_cve_ids=None), [parse_gate("new")])


def test_epss_gate_on_demo():
    report = run_demo()
    assert len(evaluate_gates(report, [parse_gate("epss:0.5")])) == 1
    hits = evaluate_gates(report, [parse_gate("epss:0.5")])[0]
    assert "finding(s)" in hits
    assert "CVE-2023-44487" in hits and "CVE-2024-6387" in hits
    assert evaluate_gates(report, [parse_gate("epss:1.0")]) == []
    assert evaluate_gates(report, [parse_gate("epss:0.99999")]) != []
    assert evaluate_gates(report, [parse_gate("epss:0.04")]) != []
    assert evaluate_gates(report, [parse_gate("epss:0.9999999")]) == []


def test_epss_gate_skips_missing_epss():
    report = run_demo()
    finding = replace(report.findings[0], epss=None)
    rep = replace(report, findings=[finding])
    assert evaluate_gates(rep, [parse_gate("epss:0.5")]) == []


def test_cli_gate_exit_codes(capsys):
    assert main(["demo", "--fail-on", "priority:95"]) == 0
    assert "gate: passed" in capsys.readouterr().err
    assert main(["demo", "--fail-on", "kev"]) == 4
    captured = capsys.readouterr()
    assert "gate: --fail-on kev" in captured.err
    assert "CVE-2023-44487" in captured.out  # the briefing is still printed
    assert main(["demo", "--fail-on", "nonsense"]) == 2


def test_scan_fail_on_new_needs_state(capsys):
    code = main(["scan", "-i", str(ROOT / "examples/inventory.yaml"), "--offline", "--fail-on", "new"])
    assert code == 2
    assert "needs --state" in capsys.readouterr().err


def test_csv_output_sorted_and_complete():
    text = render_csv(run_demo())
    rows = list(csv.DictReader(io.StringIO(text)))
    assert tuple(rows[0].keys()) == COLUMNS
    assert rows[0]["cve_id"] == "CVE-2023-44487" and rows[0]["kev"] == "yes"
    priorities = [float(row["priority"]) for row in rows]
    assert priorities == sorted(priorities, reverse=True)
    assert {row["new_since_last_run"] for row in rows} <= {"yes", "no"}


def test_csv_neutralizes_formulas():
    report = run_demo()
    finding = replace(report.findings[0], owner="=HYPERLINK(\"http://x.test\")", product="+cmd")
    text = render_csv(replace(report, findings=[finding], new_cve_ids=None))
    row = next(csv.DictReader(io.StringIO(text)))
    assert row["owner"].startswith("'=") and row["product"] == "'+cmd"
    assert row["new_since_last_run"] == ""


def test_cli_csv_to_file(tmp_path):
    out = tmp_path / "findings.csv"
    assert main(["demo", "--format", "csv", "--output", str(out)]) == 0
    assert out.read_text(encoding="utf-8").startswith("priority,asset_id,")


def test_inventory_check_example():
    notes = check_inventory(ROOT / "examples/inventory.yaml")
    by_id = {note.asset_id: note for note in notes}
    assert "not a Windows build" in by_id["server-name-only"].text
    assert "no CPE candidate" in by_id["custom-connector"].text
    assert "edge-proxy" not in by_id


def test_inventory_check_duplicates_orphan_pins_and_strict(tmp_path, capsys):
    inv = tmp_path / "inv.yaml"
    inv.write_text(
        "schema: patchorder.inventory/v1\nname: t\nassets:\n"
        "  - {id: a, product: Example Thing, version: \"1.0\", count: 0, owner: o, exposure: internal}\n"
        "  - {id: b, product: Example Thing, version: \"1.0\", count: 2, owner: o, exposure: internal}\n",
        encoding="utf-8",
    )
    (tmp_path / "inv.lock.yaml").write_text(
        "schema: patchorder.lock/v1\nentries:\n  gone:\n    cpe: cpe:2.3:a:example:thing\n    pinned: true\n    origin: user\n",
        encoding="utf-8",
    )
    texts = [(n.level, n.asset_id, n.text) for n in check_inventory(inv)]
    assert ("warning", "gone", "lock file pins an id that is not in the inventory") in texts
    assert any(asset == "b" and "same product and version" in text for _, asset, text in texts)
    assert any(asset == "a" and "count is 0" in text for _, asset, text in texts)
    assert main(["inventory", "check", str(inv)]) == 0
    assert main(["inventory", "check", str(inv), "--strict"]) == 4


def test_inventory_check_bad_file_is_an_error(tmp_path):
    inv = tmp_path / "inv.yaml"
    inv.write_text("assets:\n  - {product: x, version: 1.10, count: 1, owner: o, exposure: internal}\n", encoding="utf-8")
    assert main(["inventory", "check", str(inv)]) == 1


def test_csv_import_round_trips(tmp_path):
    text = "Software;Version;Hosts;Team;Exposed;Vendor\nnginx;1.10;3;web;yes;F5\nOpenSSH;9.6;;;;\n"
    yaml_text = csv_to_inventory(text, "Imported", default_owner="ops")
    data = yaml.safe_load(yaml_text)
    assert data["assets"][0]["version"] == "1.10"
    assert data["assets"][0]["exposure"] == "internet" and data["assets"][0]["vendor"] == "F5"
    assert data["assets"][1] == {"product": "OpenSSH", "version": "9.6", "count": 1, "owner": "ops", "exposure": "internal"}
    path = tmp_path / "inv.yaml"
    path.write_text(yaml_text, encoding="utf-8")
    inventory = load_inventory(path)
    assert [a.version for a in inventory.assets] == ["1.10", "9.6"]


@pytest.mark.parametrize(
    "text, message",
    [
        ("product,count\nx,1\n", "`version` column"),
        ("product,version,count\nx,1.0,many\n", "not a whole number"),
        ("product,version,exposure\nx,1.0,somewhere\n", "must be internet or internal"),
        ("product,version\n", "no data rows"),
    ],
)
def test_csv_import_errors(text, message):
    with pytest.raises(PatchorderError, match=message):
        csv_to_inventory(text, "t")


def test_cli_from_csv_writes_only_with_output(tmp_path, capsys):
    src = tmp_path / "hosts.csv"
    src.write_text("product,version,owner\nnginx,1.27.2,web\n", encoding="utf-8")
    assert main(["inventory", "from-csv", str(src)]) == 0
    assert 'name: "hosts"' in capsys.readouterr().out
    assert list(tmp_path.iterdir()) == [src]
    out = tmp_path / "inventory.yaml"
    assert main(["inventory", "from-csv", str(src), "--output", str(out)]) == 0
    assert load_inventory(out).assets[0].version == "1.27.2"
