import csv
import io

import pytest

from patchorder.cli import main
from patchorder.csvout import COLUMNS, parse_columns, render_csv
from patchorder.engine import run_demo
from patchorder.errors import PatchorderError


def _rows(text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text)))


def test_default_is_every_column_unchanged():
    report = run_demo()
    assert parse_columns(None) == COLUMNS
    assert parse_columns("  ") == COLUMNS
    assert render_csv(report) == render_csv(report, COLUMNS)


def test_selected_columns_keep_the_given_order():
    report = run_demo()
    full = list(csv.DictReader(io.StringIO(render_csv(report))))
    rows = _rows(render_csv(report, parse_columns("cve_id, priority,owner")))
    assert rows[0] == ["cve_id", "priority", "owner"]
    assert len(rows) - 1 == len(full)
    assert rows[1] == [full[0]["cve_id"], full[0]["priority"], full[0]["owner"]]


def test_unknown_and_duplicate_columns_are_usage_errors():
    with pytest.raises(PatchorderError) as unknown:
        parse_columns("cve_id,score")
    assert unknown.value.code == 2 and "score" in str(unknown.value) and "kev_due_date" in str(unknown.value)
    with pytest.raises(PatchorderError) as twice:
        parse_columns("cve_id,kev,cve_id")
    assert twice.value.code == 2 and "cve_id" in str(twice.value)


def test_cli_columns(capsys):
    assert main(["demo", "--format", "csv", "--columns", "asset_id,cve_id,kev"]) == 0
    rows = _rows(capsys.readouterr().out)
    assert rows[0] == ["asset_id", "cve_id", "kev"]
    assert all(len(row) == 3 for row in rows)
    assert ["edge-proxy", "CVE-2023-44487", "yes"] in rows


def test_cli_columns_needs_csv_and_valid_names(capsys):
    assert main(["demo", "--columns", "cve_id"]) == 2
    assert "--format csv" in capsys.readouterr().err
    assert main(["demo", "--format", "csv", "--columns", "nope"]) == 2
