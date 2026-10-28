# SPEC — patchorder (GitHub repo: patchorder)

Restored from Cursor cloud-agent transcript.

## Original task prompt

Build v0.1 of **patchorder**, an agentless open-source tool that answers "which CVEs actually affect MY systems, and what do I do first?" from a simple inventory file. Follow ALL rules in uploads/gemeinsame_regeln.md. The prior-art research is in uploads/stand_der_technik.md (section B): CIRCL Vulnerability-Lookup already aggregates many sources (NVD, CISA KEV, EPSS, CERT-Bund CSAF), and OpenCVE and CVE_Prioritizer cover subscriptions and scoring. The real gap is the last mile: mapping a human-written inventory (product + version) to correct CPEs/product ids and deciding per version whether you are affected. Build on public APIs (Vulnerability-Lookup, NVD 2.0, KEV JSON, EPSS API, BSI/CERT-Bund CSAF) instead of rebuilding a database.

v0.1 scope (Python 3.11+ CLI):
- `inventory.yaml` format: product, vendor, version, count, owner and exposure (internet/internal), with examples. The resolver maps entries to CPE candidates with a confidence score, lets the user pin the correct CPE in a lock file, and offers an interactive `patchorder resolve`.
- Version-range matching (affected/fixed), handling vendor build formats such as Windows builds 10.0.22631.xxxx where feasible.
- Prioritization combining KEV listing, EPSS, CVSS, exposure and count, with a transparent score explanation.
- Daily briefing in Markdown/HTML/JSON:
  - top actions ("patch X on N hosts, exploited in the wild")
  - new since last run
  - fixed-version hints
  - links to sources
- Local caching, rate-limit-friendly behaviour and offline mode. `patchorder demo` runs on bundled cached fixtures with no network.
- Optional LLM summary hook that is OFF by default, works with any OpenAI-compatible endpoint, and sends only CVE texts, never inventory data. Document this clearly.
- pytest with recorded fixtures; no live network in CI.
