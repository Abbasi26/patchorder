"""Public endpoints and the live fetch path.

Demo mode does not use this module's network. It loads the files under data/demo.
"""

from __future__ import annotations

import os
from urllib.parse import quote, urlsplit, urlunsplit, parse_qsl, urlencode

from patchorder.cpe import parse_cpe, with_version
from patchorder.errors import PatchorderError
from patchorder.httpclient import HttpClient
from patchorder.models import KevCatalog, Record, Resolution
from patchorder.records import (
    dedupe_records,
    parse_epss,
    parse_kev,
    parse_nvd_cpe_hits,
    parse_nvd_cve_page,
    parse_vulnerability_lookup,
)
from patchorder.versions import version_is_comparable

NVD_CVES = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPES = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
VULNLOOKUP = "https://vulnerability.circl.lu"
EPSS = "https://api.first.org/data/v1/epss"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CSAF_PROVIDER = "https://wid.cert-bund.de/.well-known/csaf/provider-metadata.json"

ENDPOINTS = (
    ("NVD CVE API 2.0", NVD_CVES),
    ("NVD CPE API 2.0", NVD_CPES),
    ("Vulnerability-Lookup", VULNLOOKUP + "/api/vulnerability/cpesearch/"),
    ("FIRST EPSS", EPSS),
    ("CISA KEV", KEV),
    ("CERT-Bund CSAF provider metadata", CSAF_PROVIDER),
)


def _with_api_key(url: str) -> str:
    key = os.environ.get("NVD_API_KEY", "").strip()
    if not key or urlsplit(url).netloc != "services.nvd.nist.gov":
        return url
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query.append(("apiKey", key))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


# NVD's maximum page size. Results are ordered by publish date, oldest first.
NVD_PAGE_SIZE = 2000


def nvd_cve_url(
    cpe_base: str,
    version: str,
    start: int = 0,
    per_page: int = NVD_PAGE_SIZE,
    has_kev: bool = False,
) -> str:
    name = with_version(cpe_base, version)
    kev = "&hasKev" if has_kev else ""
    return (
        f"{NVD_CVES}?cpeName={quote(name, safe='')}"
        f"&resultsPerPage={per_page}&startIndex={start}{kev}"
    )


def nvd_cpe_url(keyword: str) -> str:
    return f"{NVD_CPES}?keywordSearch={quote(keyword)}&resultsPerPage=20"


def vulnlookup_url(cpe_base: str, page: int = 1) -> str:
    return (
        f"{VULNLOOKUP}/api/vulnerability/cpesearch/{quote(cpe_base, safe='')}"
        f"?per_page=20&page={page}"
    )


def epss_url(cve_ids: list[str]) -> str:
    return EPSS + "?cve=" + ",".join(cve_ids)


class LiveFetcher:
    """Pull candidate CVEs, then leave the version decision to the local matcher."""

    def __init__(self, client: HttpClient, max_pages: int = 2) -> None:
        self.client = client
        self.max_pages = max_pages

    def fetch(self, resolutions: list[Resolution]) -> tuple[list[Record], list[str], list[str]]:
        warnings: list[str] = []
        records: list[Record] = []
        queried: list[str] = []
        seen_cpe: set[tuple[str, str]] = set()
        seen_product: set[str] = set()
        for resolution in resolutions:
            if resolution.chosen is None:
                continue
            cpe = resolution.chosen.cpe
            version = resolution.asset.version
            identity = parse_cpe(cpe)
            comparable, _why = version_is_comparable(identity.vendor, identity.product, version)
            if not comparable:
                continue
            key = (cpe, version)
            if key in seen_cpe:
                continue
            seen_cpe.add(key)
            try:
                records.extend(self._nvd_cves(cpe, version, warnings))
                queried.append(f"NVD cpeName {with_version(cpe, version)}")
            except PatchorderError as exc:
                warnings.append(str(exc))
            if cpe not in seen_product:
                seen_product.add(cpe)
                try:
                    extra = self._vulnlookup(cpe, warnings)
                    records.extend(extra)
                    queried.append(f"Vulnerability-Lookup cpesearch {cpe} ({len(extra)} records before version filtering)")
                except PatchorderError as exc:
                    warnings.append(str(exc))
        return dedupe_records(records), warnings, queried

    def _nvd_cves(self, cpe: str, version: str, warnings: list[str]) -> list[Record]:
        """Load NVD matches for one version.

        Pages are oldest-first. When the count fits in ``--max-pages`` pages of
        2000, every match is loaded. When it does not, the oldest page, the
        newest page, and the ``hasKev`` subset are loaded, and a warning says
        the middle was skipped.
        """
        found, total, covered_until, fetched_starts = self._nvd_walk(cpe, version, has_kev=False)
        # Completeness follows the index NVD says it served, not how many
        # records we kept. Rejected CVEs are dropped and must not look like a
        # short page.
        if total <= covered_until or self.max_pages < 1:
            return found
        newest_start = max(0, total - NVD_PAGE_SIZE)
        if newest_start not in fetched_starts:
            newest, _total, _next = self._nvd_page(cpe, version, newest_start, has_kev=False)
            found.extend(newest)
        kev_records, _total, _next = self._nvd_page(cpe, version, 0, has_kev=True)
        found.extend(kev_records)
        warnings.append(
            f"NVD reports {total} CVEs for {cpe} {version}. "
            f"Loaded the oldest page, the newest page, and the hasKev subset "
            f"({len(found)} records before de-duplication). "
            f"Raise --max-pages above {self.max_pages} to walk the middle "
            f"(page size {NVD_PAGE_SIZE})."
        )
        return found

    def _nvd_walk(
        self, cpe: str, version: str, has_kev: bool
    ) -> tuple[list[Record], int, int, set[int]]:
        found: list[Record] = []
        start = 0
        total = 0
        covered_until = 0
        fetched_starts: set[int] = set()
        for _page in range(self.max_pages):
            records, total, next_start = self._nvd_page(cpe, version, start, has_kev)
            fetched_starts.add(start)
            found.extend(records)
            if next_start <= start:
                break
            covered_until = next_start
            if next_start >= total:
                break
            start = next_start
        return found, total, covered_until, fetched_starts

    def _nvd_page(self, cpe: str, version: str, start: int, has_kev: bool) -> tuple[list[Record], int, int]:
        url = _with_api_key(nvd_cve_url(cpe, version, start=start, has_kev=has_kev))
        payload = self.client.get_json(url, "nvd-cve")
        if not payload:
            return [], 0, start
        return parse_nvd_cve_page(payload)

    def _vulnlookup(self, cpe: str, warnings: list[str]) -> list[Record]:
        payload = self.client.get_json(vulnlookup_url(cpe), "vulnlookup")
        if not payload:
            return []
        records = parse_vulnerability_lookup(payload)
        if len(records) >= 20:
            warnings.append(
                f"Vulnerability-Lookup returned a full page for {cpe}. "
                "cpesearch is not version-specific; only the first page is loaded in v0.1, "
                "and the local matcher drops versions that do not apply."
            )
        return records

    def kev(self) -> KevCatalog:
        payload = self.client.get_json(KEV, "kev")
        return parse_kev(payload)

    def epss(self, cve_ids: list[str]) -> dict:
        found = {}
        for offset in range(0, len(cve_ids), 100):
            chunk = cve_ids[offset : offset + 100]
            if not chunk:
                continue
            payload = self.client.get_json(epss_url(chunk), "epss")
            found.update(parse_epss(payload))
        return found

    def cpe_hits(self, keyword: str) -> list[dict]:
        payload = self.client.get_json(nvd_cpe_url(keyword), "nvd-cpe")
        return parse_nvd_cpe_hits(payload)

    def provider_metadata(self) -> dict:
        return self.client.get_json(CSAF_PROVIDER, "csaf-meta")
