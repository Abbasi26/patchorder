"""KEV dueDate handling and the fictional Ivanti Connect Secure demo rows."""

from __future__ import annotations

import csv
import io
import json

from patchorder.briefing import render_json, render_markdown
from patchorder.cpe import with_version
from patchorder.csvout import render_csv
from patchorder.engine import run_demo
from patchorder.gate import evaluate_gates, parse_gate
from patchorder.records import from_nvd_cve, parse_kev
from patchorder.report import overdue_days
from patchorder.versions import split_portable_update


def _by_asset(report):
    found = {}
    for finding in report.findings:
        found.setdefault(finding.asset_id, {})[finding.cve_id] = finding
    return found


def test_release_suffix_is_split_like_a_cpe_update():
    assert split_portable_update("22.8R2.4") == ("22.8", "r2.4")
    assert split_portable_update("22.8r2") == ("22.8", "r2")
    assert split_portable_update("9.8p1") == ("9.8", "p1")
    assert split_portable_update("1.1.1w") == ("1.1.1w", None)
    assert split_portable_update("25.1.1.3") == ("25.1.1.3", None)
    assert with_version("cpe:2.3:a:ivanti:connect_secure", "22.8R2.4") == (
        "cpe:2.3:a:ivanti:connect_secure:22.8:*:*:*:*:*:*:*"
    )


def test_overdue_days():
    assert overdue_days("2026-11-02", "2026-11-03") == 1
    assert overdue_days("2026-10-16", "2026-11-03T07:00:00+00:00") == 18
    assert overdue_days("2026-11-13", "2026-11-03") == 0
    assert overdue_days("2026-11-03", "2026-11-03") == 0
    assert overdue_days(None, "2026-11-03") is None
    assert overdue_days("not a date", "2026-11-03") is None


def test_kev_and_nvd_due_dates_are_parsed():
    kev = parse_kev({"count": 1, "vulnerabilities": [{"cveID": "CVE-2026-104935", "dueDate": "2026-10-16"}]})
    assert kev.entries["CVE-2026-104935"].due_date == "2026-10-16"
    record = from_nvd_cve({"id": "CVE-2026-104935", "cisaExploitAdd": "2026-10-13", "cisaActionDue": "2026-10-16"})
    assert record.cisa_action_due == "2026-10-16"


def test_demo_vpn_rows_match_by_release_and_carry_due_dates():
    report = run_demo(as_of="2026-11-03")
    found = _by_asset(report)
    gateway = found["vpn-gateway"]
    assert set(gateway) == {"CVE-2026-104935", "CVE-2026-111357"}
    assert gateway["CVE-2026-104935"].kev_due_date == "2026-10-16"
    assert gateway["CVE-2026-104935"].kev_overdue_days == 18
    assert gateway["CVE-2026-111357"].kev_due_date == "2026-11-02"
    assert gateway["CVE-2026-111357"].kev_overdue_days == 1
    # NVD lists 22.8 r2.5 for CVE-2026-111357 only, so the lab row has one finding.
    assert set(found["vpn-gateway-lab"]) == {"CVE-2026-111357"}
    kinds = {(note.asset_id, note.kind) for note in report.notes if "CVE-2026-104935" in note.text}
    assert ("vpn-gateway-lab", "not_affected") in kinds
    # The due date does not change points.
    assert all("due" not in part.text for part in gateway["CVE-2026-104935"].parts)


def test_kev_overdue_gate_depends_on_the_as_of_day():
    early = run_demo(as_of="2026-10-20")
    line = evaluate_gates(early, [parse_gate("kev-overdue")])[0]
    assert line.startswith("--fail-on kev-overdue: 2 finding(s)")
    assert "vpn-gateway:CVE-2026-104935" in line
    assert "CVE-2026-111357" not in line
    late = run_demo(as_of="2026-11-03")
    assert "4 finding(s)" in evaluate_gates(late, [parse_gate("kev-overdue")])[0]


def test_due_dates_in_markdown_json_and_csv():
    report = run_demo(as_of="2026-11-03")
    markdown = render_markdown(report)
    assert "KEV due date 2026-10-16 passed 18 days before 2026-11-03" in markdown
    assert "KEV due date 2026-11-02 passed 1 day before 2026-11-03" in markdown
    payload = json.loads(render_json(report))
    assert payload["as_of"] == "2026-11-03"
    row = next(f for f in payload["findings"] if f["asset_id"] == "vpn-gateway" and f["cve_id"] == "CVE-2026-104935")
    assert row["kev_due_date"] == "2026-10-16"
    assert row["kev_overdue_days"] == 18
    rows = list(csv.DictReader(io.StringIO(render_csv(report))))
    lab = next(r for r in rows if r["asset_id"] == "vpn-gateway-lab")
    assert lab["kev_due_date"] == "2026-11-02"
    assert lab["kev_overdue_days"] == "1"
    plain = next(r for r in rows if r["kev"] == "no")
    assert plain["kev_due_date"] == ""
    assert plain["kev_overdue_days"] == ""
