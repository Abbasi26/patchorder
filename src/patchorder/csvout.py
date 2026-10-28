"""One CSV row per finding, for spreadsheets and ticket imports."""

from __future__ import annotations

import csv
import io

from patchorder.report import Report

COLUMNS = (
    "priority", "asset_id", "product", "vendor", "version", "count", "owner", "exposure",
    "cve_id", "kev", "epss", "cvss", "severity", "fixed_hint", "cpe", "cpe_confirmed", "new_since_last_run",
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


def render_csv(report: Report) -> str:
    new = set(report.new_cve_ids or [])
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(COLUMNS)
    for f in sorted(report.findings, key=lambda item: (-item.points, item.asset_id, item.cve_id)):
        writer.writerow([
            _cell(round(f.points, 2)), _cell(f.asset_id), _cell(f.product), _cell(f.vendor), _cell(f.version),
            _cell(f.count), _cell(f.owner), _cell(f.exposure), _cell(f.cve_id), _cell(f.kev), _cell(f.epss),
            _cell(f.cvss), _cell(f.severity), _cell(f.fixed_hint), _cell(f.cpe), _cell(f.cpe_confirmed),
            _cell(f.cve_id in new) if report.new_cve_ids is not None else "",
        ])
    return buffer.getvalue()
