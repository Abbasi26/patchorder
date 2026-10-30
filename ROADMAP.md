# Roadmap

patchorder answers one question: which public CVEs apply to the versions you run, and what to patch first. It stays local, read-only by default, and honest about what it cannot decide. Open an issue before a large change.

## v0.2 (this release)

- `--fail-on kev|new|internet|priority:N` exit-code gates for CI and scheduled jobs.
- `--format csv` for spreadsheets and ticket imports.
- `inventory check` (offline lint) and `inventory from-csv` (import).

## Next

- SARIF output, so findings show up in code-scanning views.
- A maintained, shareable CPE alias table and pin sharing between teams.
- Windows KB article to build mapping.
- Incremental CERT-Bund CSAF through the ROLIE changes feed instead of downloaded files.

## Later

- CycloneDX and SPDX input.
- RPM, Debian, and Maven version schemes.
- More than the first page of Vulnerability-Lookup `cpesearch`, and more than `--max-pages` of NVD.

## Good first issues

- `inventory from-csv`: accept an `id` column alias such as `hostname_group` or `asset`.
- `inventory check --json` for editors and CI.
- Add five CPE aliases for common products to the starter table, each with a test.
- `--fail-on epss:N` (any finding with an EPSS probability at or above the value). Done in v0.2.
- `--format csv`: an option to pick the columns.
- An example GitHub Actions workflow that runs `scan --offline` against a committed cache and uploads the CSV.
