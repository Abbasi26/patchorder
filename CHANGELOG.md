# Changelog

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
