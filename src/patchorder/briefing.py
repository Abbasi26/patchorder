"""Markdown, HTML, and JSON briefings. Same content, three renderings."""

from __future__ import annotations

import html
import json
from collections import OrderedDict

from patchorder.report import Finding, Report


def _action(finding: Finding, extra: int) -> str:
    where = "internet-facing" if finding.exposure == "internet" else "internal"
    sentence = (
        f"Patch {finding.product} {finding.version} on {finding.count} {where} hosts "
        f"(owner {finding.owner})."
    )
    if finding.kev:
        sentence += f" {finding.cve_id} is listed in CISA KEV (exploited in the wild)."
    else:
        sentence += f" Highest issue: {finding.cve_id}."
    if finding.fixed_hint:
        sentence += " " + finding.fixed_hint
    if not finding.cpe_confirmed:
        sentence += f" CPE {finding.cpe} is not pinned (confidence used, not confirmed)."
    if extra:
        sentence += f" {extra} other CVE{'s' if extra != 1 else ''} also matched this entry."
    return sentence


def _top_actions(report: Report) -> list[tuple[Finding, int]]:
    grouped: OrderedDict[str, list[Finding]] = OrderedDict()
    for finding in report.findings:
        grouped.setdefault(finding.asset_id, []).append(finding)
    ranked = sorted(grouped.values(), key=lambda items: -items[0].points)
    return [(items[0], len(items) - 1) for items in ranked[:10]]


def _md_finding(finding: Finding) -> str:
    severity = finding.severity or "unscored"
    cvss = "n/a" if finding.cvss is None else f"{finding.cvss:.1f}"
    pin = "pinned" if finding.cpe_confirmed else "not pinned"
    lines = [
        f"### {finding.cve_id} — {finding.product} {finding.version} — {finding.points:.2f} points",
        "",
        finding.description.strip() or "(no description in the loaded record)",
        "",
        f"- Entry `{finding.asset_id}`, owner {finding.owner}, {finding.count} hosts, {finding.exposure}",
        f"- CPE `{finding.cpe}` ({pin}), matched via {finding.basis}: {finding.reason}",
        f"- CVSS {cvss} {severity}" + (f" `{finding.vector}`" if finding.vector else ""),
    ]
    if finding.epss is not None:
        lines.append(
            f"- EPSS {finding.epss:.5f}"
            + (f", percentile {finding.epss_percentile:.5f}" if finding.epss_percentile is not None else "")
            + (f", scored {finding.epss_date}" if finding.epss_date else "")
        )
    if finding.kev:
        lines.append(
            f"- CISA KEV: {finding.kev_name or finding.cve_id}"
            + (f", added {finding.kev_date}" if finding.kev_date else "")
        )
    if finding.ransomware:
        lines.append("- Known ransomware campaign use: yes (CISA flag)")
    if finding.fixed_hint:
        lines.append(f"- Fixed-version hint: {finding.fixed_hint}")
    lines.append("- Score:")
    for part in finding.parts:
        lines.append(f"  - {part.text}")
    lines.append("- Links:")
    for label, url in finding.links:
        lines.append(f"  - {label}: {url}")
    return "\n".join(lines)


def render_markdown(report: Report) -> str:
    mode = "demo, no network" if report.mode == "demo" else report.mode
    lines = [
        "# patchorder briefing",
        "",
        f"{report.name}. Generated {report.generated_at}. Mode: {mode}.",
        "",
        "This run is read-only. Nothing was changed on the systems in the inventory.",
        "",
        "## Top actions",
        "",
    ]
    actions = _top_actions(report)
    if not actions:
        lines.append("No affected versions in the records loaded for this run.")
    else:
        for index, (finding, extra) in enumerate(actions, start=1):
            lines.append(f"{index}. {_action(finding, extra)} Priority {finding.points:.2f}.")
            lines.append("")
    lines.append("## New since last run")
    lines.append("")
    if not report.previous_state_loaded:
        lines.append(
            "No previous state was loaded, so nothing is marked new. "
            "Pass --state to compare, and --save-state to record this run."
        )
    elif not report.new_cve_ids:
        lines.append("No affected CVE in this run is new compared with the previous state.")
    else:
        lines.append("Affected CVEs that were not in the previous state:")
        lines.append("")
        for cve_id in report.new_cve_ids:
            assets = [item.asset_id for item in report.findings if item.cve_id == cve_id]
            lines.append(f"- {cve_id} on {', '.join(assets)}")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    if not report.findings:
        lines.append("None.")
    else:
        for finding in report.findings:
            lines.append(_md_finding(finding))
            lines.append("")
    lines.append("## Not affected")
    lines.append("")
    clean = [note for note in report.notes if note.kind == "not_affected"]
    if not clean:
        lines.append("None.")
    else:
        for note in clean:
            lines.append(f"- {note.asset_id}: {note.text}")
    lines.append("")
    lines.append("## Not decided")
    lines.append("")
    undecided = [note for note in report.notes if note.kind == "not_decided"]
    if not undecided:
        lines.append("None. Every checked version was comparable with the loaded ranges.")
    else:
        for note in undecided:
            lines.append(f"- {note.asset_id} ({note.product} {note.version}): {note.text}")
    lines.append("")
    lines.append("## Unresolved products")
    lines.append("")
    unresolved = [note for note in report.notes if note.kind == "unresolved"]
    if not unresolved:
        lines.append("Every entry had a CPE pin or a candidate above the auto-use line.")
    else:
        lines.append("These entries were not queried. Pin a CPE with `patchorder resolve --write`.")
        lines.append("")
        for note in unresolved:
            lines.append(f"- {note.asset_id} ({note.product} {note.version}): {note.text}")
    lines.append("")
    if report.warnings:
        lines.append("## Warnings")
        lines.append("")
        for warning in report.warnings:
            lines.append(f"- {warning}")
        lines.append("")
    if report.llm_summary:
        lines.append("## Optional model summary")
        lines.append("")
        lines.append(
            "The text below came from an OpenAI-compatible endpoint. "
            "The request contained CVE identifiers and description text only, not the inventory."
        )
        lines.append("")
        lines.append(report.llm_summary.strip())
        lines.append("")
    if report.llm_preview:
        lines.append("## LLM request preview (not sent)")
        lines.append("")
        lines.append("This is the body that --llm would POST. It is CVE text only.")
        lines.append("")
        lines.append("```json")
        lines.append(report.llm_preview.rstrip())
        lines.append("```")
        lines.append("")
    lines.append("## Sources for this run")
    lines.append("")
    for source in report.sources:
        lines.append(f"- {source}")
    lines.append("")
    lines.append("## Priority formula")
    lines.append("")
    for line in report.formula:
        lines.append(line if line.startswith("priority") else f"`{line}`")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_html(report: Report) -> str:
    def esc(value: object) -> str:
        return html.escape(str(value), quote=True)

    actions = _top_actions(report)
    action_html = ""
    if not actions:
        action_html = "<p>No affected versions in the records loaded for this run.</p>"
    else:
        items = []
        for finding, extra in actions:
            klass = "kev" if finding.kev else ""
            items.append(f"<li class=\"{klass}\">{esc(_action(finding, extra))} Priority {finding.points:.2f}.</li>")
        action_html = "<ol>" + "".join(items) + "</ol>"
    rows = []
    for finding in report.findings:
        rows.append(
            "<tr>"
            f"<td><code>{esc(finding.cve_id)}</code></td>"
            f"<td>{esc(finding.product)} {esc(finding.version)}<br><code>{esc(finding.cpe)}</code></td>"
            f"<td>{finding.points:.2f}</td>"
            f"<td>{'KEV' if finding.kev else ''}</td>"
            f"<td>{esc(finding.fixed_hint or '')}</td>"
            "</tr>"
        )
    table = (
        "<table><thead><tr><th>CVE</th><th>Installed</th><th>Points</th><th>KEV</th><th>Fixed-version hint</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
        if rows
        else "<p>None.</p>"
    )
    new_block = "<p>No previous state was loaded, so nothing is marked new.</p>"
    if report.previous_state_loaded:
        if report.new_cve_ids:
            lis = "".join(f"<li><code>{esc(cve)}</code></li>" for cve in report.new_cve_ids)
            new_block = f"<ul>{lis}</ul>"
        else:
            new_block = "<p>No affected CVE in this run is new compared with the previous state.</p>"
    notes = []
    for note in report.notes:
        notes.append(f"<li><strong>{esc(note.kind)}</strong> {esc(note.asset_id)}: {esc(note.text)}</li>")
    sources = "".join(f"<li>{esc(source)}</li>" for source in report.sources)
    warnings = ""
    if report.warnings:
        warnings = "<h2>Warnings</h2><ul>" + "".join(f"<li>{esc(item)}</li>" for item in report.warnings) + "</ul>"
    llm = ""
    if report.llm_summary:
        llm = (
            "<h2>Optional model summary</h2>"
            "<p>CVE identifiers and description text only were sent. The inventory was not.</p>"
            f"<pre>{esc(report.llm_summary)}</pre>"
        )
    mode = "demo, no network" if report.mode == "demo" else report.mode
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>patchorder briefing</title>
<style>
body {{ margin: 0; background: #f4f0e6; color: #1c1915; font: 17px/1.5 Palatino, "Iowan Old Style", Georgia, serif; }}
main {{ max-width: 860px; margin: 0 auto; padding: 32px 20px 80px; }}
h1 {{ font-weight: 600; letter-spacing: -0.02em; margin-bottom: 0.2em; }}
h2 {{ margin-top: 1.6em; font-size: 1.25rem; }}
.meta {{ color: #5c564c; }}
.kev {{ color: #8d2a1f; }}
table {{ width: 100%; border-collapse: collapse; font-size: 0.95rem; }}
th, td {{ text-align: left; vertical-align: top; padding: 8px 6px; border-bottom: 1px solid #ddd4c4; }}
code, pre {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.88em; }}
pre {{ white-space: pre-wrap; background: #fffdf8; padding: 12px; }}
a {{ color: #1f4e3d; }}
</style>
</head>
<body>
<main>
<h1>patchorder briefing</h1>
<p class="meta">{esc(report.name)}. Generated {esc(report.generated_at)}. Mode: {esc(mode)}.</p>
<p>This run is read-only. Nothing was changed on the systems in the inventory.</p>
<h2>Top actions</h2>
{action_html}
<h2>New since last run</h2>
{new_block}
<h2>Findings</h2>
{table}
<h2>Other results</h2>
<ul>{''.join(notes) or '<li>None.</li>'}</ul>
{warnings}
{llm}
<h2>Sources for this run</h2>
<ul>{sources}</ul>
</main>
</body>
</html>
"""


def _finding_dict(finding: Finding) -> dict:
    return {
        "asset_id": finding.asset_id,
        "product": finding.product,
        "vendor": finding.vendor,
        "version": finding.version,
        "count": finding.count,
        "owner": finding.owner,
        "exposure": finding.exposure,
        "cpe": finding.cpe,
        "cpe_confirmed": finding.cpe_confirmed,
        "cve_id": finding.cve_id,
        "description": finding.description,
        "cvss": finding.cvss,
        "severity": finding.severity,
        "vector": finding.vector,
        "epss": finding.epss,
        "epss_percentile": finding.epss_percentile,
        "epss_date": finding.epss_date,
        "kev": finding.kev,
        "kev_name": finding.kev_name,
        "kev_date": finding.kev_date,
        "points": finding.points,
        "score": [{"points": part.points, "text": part.text} for part in finding.parts],
        "reason": finding.reason,
        "fixed_hint": finding.fixed_hint,
        "links": [{"label": label, "url": url} for label, url in finding.links],
        "basis": finding.basis,
    }


def render_json(report: Report) -> str:
    actions = [
        {"asset_id": finding.asset_id, "cve_id": finding.cve_id, "points": finding.points, "text": _action(finding, extra)}
        for finding, extra in _top_actions(report)
    ]
    payload = {
        "tool": "patchorder",
        "generated_at": report.generated_at,
        "mode": report.mode,
        "read_only": True,
        "inventory_name": report.name,
        "top_actions": actions,
        "new_since_last_run": report.new_cve_ids,
        "findings": [_finding_dict(item) for item in report.findings],
        "notes": [
            {"asset_id": note.asset_id, "kind": note.kind, "product": note.product, "version": note.version, "text": note.text}
            for note in report.notes
        ],
        "warnings": report.warnings,
        "sources": report.sources,
        "formula": list(report.formula),
        "llm_summary": report.llm_summary,
    }
    return json.dumps(payload, indent=2) + "\n"


def render(report: Report, fmt: str) -> str:
    if fmt == "html":
        return render_html(report)
    if fmt == "json":
        return render_json(report)
    if fmt == "md":
        return render_markdown(report)
    raise ValueError(fmt)
