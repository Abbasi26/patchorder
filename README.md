# patchorder

[![CI](https://github.com/Abbasi26/patchorder/actions/workflows/ci.yml/badge.svg)](https://github.com/Abbasi26/patchorder/actions/workflows/ci.yml)

Which public CVEs apply to the versions in a local inventory, and what to patch first.

You keep a short YAML file: product, vendor, version, how many hosts, who owns them, and whether they face the internet. patchorder maps each row to CPE candidates, you pin the right one, and it decides affected / not affected / not decided from the published version ranges. The briefing ranks the work. It does not scan a network and it does not install updates.

## The problem

A vulnerability feed can tell you that something named nginx is having a bad week. It cannot tell you that twelve internet-facing proxies on 1.25.2 are in the vulnerable range and the three you already moved to 1.27.2 are not. [Vulnerability-Lookup](https://vulnerability.circl.lu/) returns every CVE for a vendor and product, on purpose, and leaves the version filter to the client. [OpenCVE](https://www.opencve.io/) subscribes you to a product. [CVE_Prioritizer](https://github.com/TURROKS/CVE_Prioritizer) scores a CVE list you already have. None of them starts from "Windows Server 2022, build 10.0.20348.2400, eight internal hosts."

That last step is this tool. The fictional Harbor Workshop inventory, run offline, opens with:

```text
Patch nginx 1.25.2 on 12 internet-facing hosts (owner platform). CVE-2023-44487 is listed in CISA KEV (exploited in the wild). NVD marks versions through 1.25.2 as affected (versionEndIncluding). Move to a release newer than 1.25.2. Priority 91.86.

Patch OpenSSH 9.6 on 2 internal hosts (owner ops). Highest issue: CVE-2024-6387. NVD marks versions through 9.8 as affected (versionEndIncluding). Move to a release newer than 9.8. Priority 45.88.

Patch Windows 11 23H2 10.0.22631.3593 on 15 internal hosts (owner it). Highest issue: CVE-2024-38063. Update to 10.0.22631.4037 or later (NVD versionEndExcluding). Priority 43.25.
```

The same run says nginx 1.27.2 is outside that range, Windows Server 2022 build 10.0.20348.2655 is the fixed build for CVE-2024-38063, and OpenSSH 9.8p1 sorts after the NVD bound 9.8. A row whose version is the marketing name `2022` is reported as not decided, because comparing the number 2022 with `10.0.20348.2655` would be a false "not affected."

## Quickstart

Python 3.11 or newer.

```bash
python -m pip install -e .
python -m patchorder demo
```

`demo` reads bundled fixtures recorded on 2026-10-21 and does not use the network. Add `--format html` or `--format json`. `--output briefing.md` is the explicit way to write a file. With no `--output`, nothing is written.

```bash
python -m patchorder demo --format html --output briefing.html
python -m patchorder demo --llm-preview
```

`--llm-preview` prints the request body and does not send it. The body is CVE identifiers and description text only.

## Real usage

Copy `examples/inventory.yaml`. Quote versions. YAML will read an unquoted `1.10` as `1.1`.

```yaml
schema: patchorder.inventory/v1
name: Harbor Workshop (fictional)
assets:
  - id: edge-proxy
    product: nginx
    vendor: F5
    version: "1.25.2"
    count: 12
    owner: platform
    exposure: internet
```

`exposure` is `internet` or `internal`. `count` is a non-negative integer. `owner` is a label for the briefing, not an account.

See the candidates, then pin the CPE you mean. Pinning is a write, so it requires `--write`. The proposed lock file is printed first.

```bash
python -m patchorder resolve -i inventory.yaml --offline --no-discover-cpes
python -m patchorder resolve -i inventory.yaml --write --accept edge-proxy=cpe:2.3:a:f5:nginx
```

In a terminal, `resolve` asks you to pick a number. A lock file looks like this:

```yaml
schema: patchorder.lock/v1
entries:
  edge-proxy:
    cpe: cpe:2.3:a:f5:nginx
    pinned: true
    origin: user
```

The lock stores vendor and product, not the version. The version stays in the inventory and is compared on every run.

```bash
python -m patchorder scan -i inventory.yaml -l inventory.lock.yaml --format md
python -m patchorder scan -i inventory.yaml --state previous.json --save-state .patchorder/state.json
python -m patchorder scan -i inventory.yaml --offline
python -m patchorder scan -i inventory.yaml --csaf ./advisories --pinned-only
```

A live scan calls, per pinned product version:

- NVD CVE API 2.0 `cpeName` (version-aware candidate list)
- Vulnerability-Lookup `cpesearch` for one page (not version-aware; filtered locally)
- the CISA KEV JSON catalog, once
- the FIRST EPSS API, in batches of 100

Responses are cached under `.patchorder/cache`. NVD requests are spaced 6.5 seconds apart (5 requests per 30 seconds without a key). Vulnerability-Lookup requests are spaced 3.5 seconds apart (anonymous limit 20 per minute). Set `NVD_API_KEY` to raise the NVD limit. The key is not written into the cache. `--refresh` ignores cache age. `--offline` uses the cache only and exits 3 when a chosen CPE has no cached vulnerability records.

NVD returns matches oldest-first, at most 2000 per page. `--max-pages` defaults to 2, which covers a product version with up to 4000 matching CVEs (a current Windows Server 2022 build is in that range). Above that, the run keeps the oldest page, the newest page, and every match NVD marks `hasKev`, and the briefing says the middle was not loaded.

CPE discovery (`resolve` and unpinned rows during `scan`) also queries the NVD CPE dictionary. `--no-discover-cpes` keeps the local alias table only. A candidate at or above 0.85 is used and labeled unconfirmed. Below that, the row is not queried. `--pinned-only` queries pins and nothing else.

`--csaf` reads CSAF 2.0 files you already have (one file or a directory of JSON). CERT-Bund publishes those documents at <https://wid.cert-bund.de/.well-known/csaf/>. patchorder does not download that feed: the WID index is tens of megabytes. `--csaf-provider` fetches only the small provider-metadata document and prints the TLP:WHITE feed URLs. A CSAF product id adds priority points only when the document names the installed version. A product name with no version is a mention, not an "affected" decision.

`python -m patchorder sources` lists the endpoints and does not contact them.

### Priority points

Every finding prints its arithmetic. The maximum is 105.

| Signal | Points |
| --- | --- |
| CVE is in the CISA KEV catalog loaded for this run | 40, else 0 |
| EPSS probability | probability × 25, else 0 |
| CVSS base score | score / 10 × 20, else 0 |
| Exposure | 10 internet, 4 internal |
| Host count | min(5, log10(count + 1) / log10(1001) × 5) |
| Loaded CSAF document marks this exact version known_affected | 5, else 0 |

"Not listed" means not listed in the catalog loaded for this run. The demo catalog is one recorded KEV entry out of the published count, so that the offline briefing can show a real exploited-in-the-wild hit. A live scan loads the catalog file it fetched.

### Optional LLM summary

Off unless you pass `--llm`. Any OpenAI-compatible `POST /chat/completions` endpoint works, including a local one.

```bash
export PATCHORDER_LLM_BASE_URL=http://127.0.0.1:11434/v1
export PATCHORDER_LLM_MODEL=llama3.1
export PATCHORDER_LLM_API_KEY=   # optional; do not put the key in the URL
python -m patchorder scan -i inventory.yaml --llm-preview
python -m patchorder scan -i inventory.yaml --llm
```

The JSON body contains CVE identifiers and description text, capped at 20 CVEs and 1200 characters each. It does not contain the inventory. `--llm-preview` prints the body and does not send it. `demo` refuses `--llm` for the same reason: demo mode does not call an endpoint. If the endpoint fails, the local briefing is still produced and the failure is a warning.

### Version matching

The local matcher is the source of the affected / not affected / not decided line. NVD and Vulnerability-Lookup only supply candidate records.

- NVD `versionStartIncluding` / `versionStartExcluding` / `versionEndIncluding` / `versionEndExcluding`
- An exact CPE version, including an update field such as OpenSSH `8.5` update `p1`
- CVE List 5 `versions` blocks (`lessThan`, `lessThanOrEqual`, `status`, `defaultStatus`) when the record has no NVD configuration. Configurations win when both exist
- Windows builds `10.0.<build>.<ubr>` and `6.*`. `10.0.22631.3593` is before `10.0.22631.4037`. The marketing name `2022` is not compared with a build
- OpenSSH `9.8p1` sorts after `9.8`. OpenSSL `1.1.1w` sorts before `1.1.1x`
- A build such as `10.0.22631.3593` on a row that only says "Windows 11" suggests `windows_11_23h2` and does not auto-use it. Build 26100 is offered as both Windows 11 24H2 and Windows Server 2025
- A negated CPE node, or an AND configuration that also requires a product this row does not name, is not decided

The alias table is a starter set (nginx, NGINX Plus, OpenSSL, Apache HTTP Server, Tomcat, OpenSSH, PHP, curl, PostgreSQL, MySQL, MariaDB, and a handful of Windows releases). It is not a CPE dictionary. Pin the CPE after you have looked at the candidates.

## Required permissions

None. The tool reads a YAML file you wrote and, on a live run, makes outbound HTTPS requests to the public endpoints above. It does not need an agent, administrator rights, or credentials on the systems in the inventory.

Writes happen only when you ask:

| Flag | What it writes |
| --- | --- |
| `--output` | the briefing |
| `--write` on `resolve` | the lock file, after printing it |
| `--save-state` | the CVE ids in this run, so the next run can say what is new |
| cache files | HTTP responses under `--cache-dir` (default `.patchorder/cache`) during a live run |

`demo` writes nothing unless you pass `--output`.

## How this differs from existing tools

Aggregation is a solved problem. The gap is the inventory and the version decision.

| Tool | What it already does | What it does not do |
| --- | --- | --- |
| [Vulnerability-Lookup](https://github.com/vulnerability-lookup/vulnerability-lookup) (CIRCL) | Aggregates NVD, CISA KEV, EPSS, CERT-Bund CSAF, and many other sources. Public API. | No inventory file. `cpesearch` matches vendor and product, not the version. No local briefing. |
| [OpenCVE](https://github.com/opencve/opencve) | Subscriptions and daily reports by vendor and product. | No per-version decision. KEV and EPSS are not the point of the product. |
| [CVE_Prioritizer](https://github.com/TURROKS/CVE_Prioritizer) | Scores a CVE list you already hold, using CVSS, EPSS, and KEV. | No inventory and no version match. |
| [cve-search](https://github.com/cve-search/cve-search) | Local CVE database and CPE search. | You operate the database. No briefing that starts from a human inventory. |
| [osv-scanner](https://github.com/google/osv-scanner) | Lockfiles, containers, and SBOMs. | Not a Windows or appliance inventory. |
| [Greenbone Community Edition](https://github.com/greenbone/openvas-scanner) | Network and authenticated scanning. | The opposite of an inventory file. It needs access to the hosts. |

patchorder does not re-host those datasets. A live run asks the public APIs and caches the answers.

## Tests

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

Pytest blocks sockets. CI runs the same suite on Python 3.11 and 3.12 (`.github/workflows/ci.yml`).

## How to contribute

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Roadmap

Not in 0.1, and not claimed:

- A maintained CPE alias table, and a way to share pins, beyond the starter list
- Windows KB article to build mapping. v0.1 understands `10.0.<build>.<ubr>`, not a KB number
- Incremental CERT-Bund CSAF via the ROLIE changes feed, instead of `--csaf` files you downloaded
- CycloneDX or SPDX input
- RPM, Maven, and Debian version schemes. Semver-like strings, letter suffixes, and Windows builds are what v0.1 compares
- More than the first page of Vulnerability-Lookup `cpesearch`, and more than `--max-pages` of NVD

## Status

Version 0.1.0, early but usable. Python package `patchorder` (CLI `patchorder`). MIT licensed. Every push runs the test suite in GitHub Actions (`.github/workflows/ci.yml`).

## Install

```sh
pip install .
```

## License

MIT. Copyright 2026 Wasaf Abbasi.

## Kurzfassung (Deutsch)

patchorder ist ein lokales Kommandozeilenwerkzeug. Es beantwortet die Frage, welche öffentlichen Schwachstellen die Versionen in einer Inventardatei wirklich betreffen und was zuerst gepatcht werden sollte.

Die Datei nennt Produkt, Hersteller, Version, Anzahl, Besitzer und ob das System aus dem Internet erreichbar ist. Das Werkzeug schlägt CPE-Kandidaten mit einem Vertrauenswert vor. Die richtige CPE wird in einer Lock-Datei festgehalten. Danach entscheidet ein lokaler Versionsvergleich über betroffen, nicht betroffen oder nicht entscheidbar. Windows-Builds wie `10.0.22631.4037` werden als vier Zahlen verglichen. Ein Marketingname wie `2022` reicht dafür nicht.

Die Priorität setzt sich aus CISA KEV, EPSS, CVSS, Erreichbarkeit, Anzahl und einem versionsscharfen CSAF-Treffer zusammen. Jede Zeile zeigt die Rechnung. Das Briefing kommt als Markdown, HTML oder JSON und nennt die nächsten Schritte, neue Funde seit dem letzten Lauf, Hinweise auf behobene Versionen und Links zu den Quellen.

Es wird keine eigene Datenbank aufgebaut. Ein Live-Lauf fragt Vulnerability-Lookup, die NVD-API 2.0, den CISA-KEV-Katalog, die EPSS-API und lokal vorliegende CSAF-Dokumente (CERT-Bund veröffentlicht sie unter <https://wid.cert-bund.de/.well-known/csaf/>). Der vollständige WID-Feed wird nicht heruntergeladen. `patchorder demo` läuft ohne Netz auf mitgelieferten Beispieldaten. Es gibt keine Telemetrie. Das Inventar bleibt auf dem Rechner. Ein optionales LLM ist standardmäßig aus und bekommt nur CVE-Texte, nie das Inventar.
