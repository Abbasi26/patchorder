"""One CSV row per finding, for spreadsheets and ticket imports."""

from __future__ import annotations

import csv
import io

from patchorder.errors import PatchorderError
from patchorder.report import Report

COLUMNS = (
    "priority", "asset_id", "product", "vendor", "version", "count", "owner", "exposure",
    "cve_id", "kev", "epss", "cvss", "severity", "fixed_hint", "cpe", "cpe_confirmed", "new_since_last_run",
    "kev_due_date", "kev_overdue_days",
)

_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def _cell(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:.4f}".rstrip("0").rstrip(".")
    text = str(value)
    # Spreadsheet formula injection: CVE text and inventory labels are untrusted input.
    if text.startswith(_FORMULA_START):
        text = "'" + text
    return text


def parse_columns(value: str | None) -> tuple[str, ...]:
    """Validate a comma-separated ``--columns`` value. ``None`` or empty means all columns."""
    if value is None or not value.strip():
        return COLUMNS
    names = [part.strip() for part in value.split(",") if part.strip()]
    unknown = [name for name in names if name not in COLUMNS]
    if unknown:
        raise PatchorderError(f"unknown CSV column(s): {', '.join(unknown)}. Valid: {', '.join(COLUMNS)}", code=2)
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise PatchorderError(f"CSV column(s) listed twice: {', '.join(duplicates)}", code=2)
    return tuple(names)


def render_csv(report: Report, columns: tuple[str, ...] = COLUMNS) -> str:
    new = set(report.new_cve_ids or [])
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(columns)
    for f in sorted(report.findings, key=lambda item: (-item.points, item.asset_id, item.cve_id)):
        row = {
            "priority": _cell(round(f.points, 2)), "asset_id": _cell(f.asset_id), "product": _cell(f.product),
            "vendor": _cell(f.vendor), "version": _cell(f.version), "count": _cell(f.count),
            "owner": _cell(f.owner), "exposure": _cell(f.exposure), "cve_id": _cell(f.cve_id),
            "kev": _cell(f.kev), "epss": _cell(f.epss), "cvss": _cell(f.cvss), "severity": _cell(f.severity),
            "fixed_hint": _cell(f.fixed_hint), "cpe": _cell(f.cpe), "cpe_confirmed": _cell(f.cpe_confirmed),
            "new_since_last_run": _cell(f.cve_id in new) if report.new_cve_ids is not None else "",
            "kev_due_date": _cell(f.kev_due_date), "kev_overdue_days": _cell(f.kev_overdue_days),
        }
        writer.writerow([row[name] for name in columns])
    return buffer.getvalue()
