# Changelog

## Unreleased

- KEV due dates: each KEV finding carries `kev_due_date` (KEV `dueDate`, or NVD `cisaActionDue` when no KEV file is loaded) and `kev_overdue_days` relative to the run's UTC date. Shown in Markdown, HTML, JSON (`as_of`) and as two new trailing CSV columns. Points are unchanged.
- `--fail-on kev-overdue`: exit 4 when a KEV finding is past its due date.
- Ivanti-style release strings (`22.8R2.4`) are split into CPE version `22.8` and update `r2.4`.
- Demo: fictional VPN gateway rows on Ivanti Connect Secure 22.8R2.4 and 22.8R2.5 with recorded NVD, KEV (catalog 2026.10.30) and EPSS data for CVE-2026-104935 and CVE-2026-111357.

## 0.2.0 - 2026-10-28

- `--fail-on kev|new|internet|priority:N` on `scan` and `demo` (repeatable). Exit 4 when a gate matches; the briefing is still printed.
- `--format csv`: one row per finding, sorted by priority, with spreadsheet formula injection neutralized.
- `patchorder inventory check`: offline lint for rows a scan cannot decide, duplicates, zero counts, and orphaned lock pins. `--strict` exits 4 on warnings.
- `patchorder inventory from-csv`: CSV export to inventory YAML with quoted versions and common header aliases.
- CI on Python 3.11 to 3.13 with demo gate and inventory check smoke steps.
- ROADMAP.md, issue forms, and a pull request template.
- Renamed the project from `patchwindow` to `patchorder`: package, CLI, environment variables, files and docs. Entries below use the old name.

## 0.1.0 - 2026-10-21

- First release.
- Inventory YAML, CPE candidates with a confidence score, and a lock file.
- Interactive and non-interactive `resolve`.
- Local version matching for NVD ranges, CVE List 5 version blocks, OpenSSH `p` suffixes, OpenSSL letter suffixes, and Windows builds such as `10.0.22631.4037`.
- Priority points from the loaded CISA KEV catalog, EPSS, CVSS, exposure, host count, and version-specific CSAF hits, with the arithmetic printed on every finding.
- Briefings in Markdown, HTML, and JSON, including top actions, what is new since the last state file, fixed-version hints, and source links.
- Disk cache, per-host spacing, and `--offline`. `demo` uses bundled fixtures and does not use the network.
- Optional OpenAI-compatible summary that is off unless `--llm` is passed and that sends CVE identifiers and description text only.
