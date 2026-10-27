"""Normalize NVD 2.0 CVE objects and CVE List 5 records into one shape.

Vulnerability-Lookup returns either shape: a bare CVE record, a map of source
name to CVE records, or a search envelope of [id, record] pairs. cpesearch is
not version-aware (upstream issue 219); callers filter with the local matcher.
"""

from __future__ import annotations

from patchwindow.models import EpssScore, KevCatalog, KevEntry, Record


def _cvss_from_nvd(metrics: dict) -> tuple[float | None, str | None, str | None]:
    if not isinstance(metrics, dict):
        return None, None, None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        block = metrics.get(key)
        if isinstance(block, list) and block:
            data = block[0].get("cvssData") or {}
            score = data.get("baseScore")
            if isinstance(score, (int, float)):
                return float(score), data.get("baseSeverity"), data.get("vectorString")
    return None, None, None


def _cvss_from_cve5(metrics: object) -> tuple[float | None, str | None, str | None]:
    if not isinstance(metrics, list):
        return None, None, None
    for item in metrics:
        if not isinstance(item, dict):
            continue
        for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0"):
            data = item.get(key)
            if isinstance(data, dict) and isinstance(data.get("baseScore"), (int, float)):
                return float(data["baseScore"]), data.get("baseSeverity"), data.get("vectorString")
    return None, None, None


def _description(items: object) -> str:
    if not isinstance(items, list):
        return ""
    english = ""
    fallback = ""
    for item in items:
        if not isinstance(item, dict):
            continue
        value = item.get("value") or ""
        if not isinstance(value, str):
            continue
        if not fallback:
            fallback = value.strip()
        if item.get("lang", "").lower().startswith("en") and value.strip():
            english = value.strip()
            break
    return english or fallback


def _refs(items: object) -> list[str]:
    found: list[str] = []
    if not isinstance(items, list):
        return found
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("url"), str):
            found.append(item["url"])
        elif isinstance(item, str):
            found.append(item)
    return found


def from_nvd_cve(cve: dict, source: str = "nvd") -> Record | None:
    if not isinstance(cve, dict) or not isinstance(cve.get("id"), str):
        return None
    status = str(cve.get("vulnStatus") or "")
    if status.upper().startswith("REJECT"):
        return None
    score, severity, vector = _cvss_from_nvd(cve.get("metrics") or {})
    configurations = cve.get("configurations")
    if not isinstance(configurations, list):
        configurations = []
    return Record(
        cve_id=cve["id"],
        description=_description(cve.get("descriptions")),
        configurations=configurations,
        cve5_affected=[],
        cvss=score,
        severity=severity,
        vector=vector,
        references=_refs(cve.get("references")),
        published=cve.get("published"),
        cisa_exploit_add=cve.get("cisaExploitAdd"),
        cisa_name=cve.get("cisaVulnerabilityName"),
        source=source,
    )


def from_cve5(document: dict, source: str = "cvelist") -> Record | None:
    if not isinstance(document, dict):
        return None
    meta = document.get("cveMetadata") or {}
    cve_id = meta.get("cveId")
    if not isinstance(cve_id, str):
        return None
    if str(meta.get("state") or "").upper() == "REJECTED":
        return None
    containers = document.get("containers") or {}
    cna = containers.get("cna") if isinstance(containers, dict) else None
    if not isinstance(cna, dict):
        cna = {}
    affected = cna.get("affected")
    if not isinstance(affected, list):
        affected = []
    score, severity, vector = _cvss_from_cve5(cna.get("metrics"))
    return Record(
        cve_id=cve_id,
        description=_description(cna.get("descriptions")),
        configurations=[],
        cve5_affected=affected,
        cvss=score,
        severity=severity,
        vector=vector,
        references=_refs(cna.get("references")),
        published=meta.get("datePublished"),
        source=source,
    )


def _from_any(document: dict, source: str) -> Record | None:
    if "cveMetadata" in document:
        return from_cve5(document, source=source)
    if "id" in document and "descriptions" in document:
        return from_nvd_cve(document, source=source)
    return None


def parse_nvd_cve_page(payload: dict) -> tuple[list[Record], int, int]:
    """Return records, totalResults, and the next start index."""
    vulns = payload.get("vulnerabilities") or []
    records: list[Record] = []
    for item in vulns:
        if isinstance(item, dict) and isinstance(item.get("cve"), dict):
            record = from_nvd_cve(item["cve"])
            if record:
                records.append(record)
    total = int(payload.get("totalResults") or len(records))
    start = int(payload.get("startIndex") or 0)
    per_page = int(payload.get("resultsPerPage") or len(records) or 0)
    return records, total, start + per_page


def parse_vulnerability_lookup(payload: object) -> list[Record]:
    """Accept the three envelopes Vulnerability-Lookup uses."""
    records: list[Record] = []
    if isinstance(payload, dict) and "cveMetadata" in payload:
        record = from_cve5(payload, source="vulnerability-lookup")
        return [record] if record else []
    if isinstance(payload, dict) and isinstance(payload.get("results"), dict):
        payload = payload["results"]
    if isinstance(payload, dict):
        # {"nvd": [record, ...]} or {"nvd": [[id, record], ...]}
        for source, items in payload.items():
            if source in {"metadata", "total_count", "page_size", "page"}:
                continue
            if not isinstance(items, list):
                continue
            for item in items:
                document = item
                if isinstance(item, list) and len(item) >= 2 and isinstance(item[1], dict):
                    document = item[1]
                if isinstance(document, dict):
                    record = _from_any(document, source=f"vulnerability-lookup:{source}")
                    if record:
                        records.append(record)
        return records
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                record = _from_any(item, source="vulnerability-lookup")
                if record:
                    records.append(record)
    return records


def parse_nvd_cpe_hits(payload: dict) -> list[dict]:
    hits: list[dict] = []
    for item in payload.get("products") or []:
        cpe = item.get("cpe") if isinstance(item, dict) else None
        if not isinstance(cpe, dict) or not isinstance(cpe.get("cpeName"), str):
            continue
        titles = cpe.get("titles") or []
        title = ""
        if titles and isinstance(titles[0], dict):
            title = str(titles[0].get("title") or "")
        deprecated_by = ""
        by = cpe.get("deprecatedBy") or []
        if by and isinstance(by[0], dict):
            deprecated_by = str(by[0].get("cpeName") or "")
        hits.append(
            {
                "cpe": cpe["cpeName"],
                "title": title,
                "deprecated": bool(cpe.get("deprecated")),
                "deprecated_by": deprecated_by,
            }
        )
    return hits


def parse_epss(payload: dict) -> dict[str, EpssScore]:
    found: dict[str, EpssScore] = {}
    for item in payload.get("data") or []:
        if not isinstance(item, dict) or not isinstance(item.get("cve"), str):
            continue
        try:
            probability = float(item["epss"])
        except (KeyError, TypeError, ValueError):
            continue
        percentile = None
        if item.get("percentile") is not None:
            percentile = float(item["percentile"])
        found[item["cve"]] = EpssScore(item["cve"], probability, percentile, item.get("date"))
    return found


def parse_kev(payload: dict) -> KevCatalog:
    entries: dict[str, KevEntry] = {}
    for item in payload.get("vulnerabilities") or []:
        if not isinstance(item, dict) or not isinstance(item.get("cveID"), str):
            continue
        entries[item["cveID"]] = KevEntry(
            cve_id=item["cveID"],
            name=str(item.get("vulnerabilityName") or ""),
            date_added=item.get("dateAdded"),
            short_description=str(item.get("shortDescription") or ""),
            ransomware=item.get("knownRansomwareCampaignUse"),
        )
    published = payload.get("count")
    note = ""
    loaded = len(entries)
    if isinstance(published, int) and published != loaded:
        noun = "entry" if loaded == 1 else "entries"
        note = (
            f"{loaded} {noun} loaded; the published catalog count is {published}. "
            "A smaller file is a fixture subset, not the live catalog."
        )
    return KevCatalog(
        title=str(payload.get("title") or "CISA Known Exploited Vulnerabilities"),
        catalog_version=str(payload.get("catalogVersion") or ""),
        date_released=payload.get("dateReleased"),
        published_count=published if isinstance(published, int) else None,
        entries=entries,
        note=note,
    )


def dedupe_records(records: list[Record]) -> list[Record]:
    """Prefer a record that carries NVD configurations when the same CVE arrives twice."""
    chosen: dict[str, Record] = {}
    for record in records:
        current = chosen.get(record.cve_id)
        if current is None:
            chosen[record.cve_id] = record
            continue
        if not current.configurations and record.configurations:
            chosen[record.cve_id] = record
    return list(chosen.values())
