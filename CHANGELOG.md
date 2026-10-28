# Changelog

## Unreleased

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
