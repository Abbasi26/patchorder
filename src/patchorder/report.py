"""Assemble a briefing from inventory rows, records, and the local matcher."""

from __future__ import annotations

from dataclasses import dataclass, field

from patchorder.csaf import CsafAdvisory, CsafHit, hits_for
from patchorder.matching import Observation, evaluate
from patchorder.models import KevCatalog, Record, Resolution
from patchorder.prioritize import FORMULA_LINES, ScorePart, score


@dataclass
class Finding:
    asset_id: str
    product: str
    vendor: str
    version: str
    count: int
    owner: str
    exposure: str
    cpe: str
    cpe_confirmed: bool
    cve_id: str
    description: str
    cvss: float | None
    severity: str | None
    vector: str | None
    epss: float | None
    epss_percentile: float | None
    epss_date: str | None
    kev: bool
    kev_name: str | None
    kev_date: str | None
    ransomware: str | None
    points: float
    parts: list[ScorePart]
    reason: str
    fixed_hint: str | None
    links: list[tuple[str, str]]
    csaf: list[CsafHit]
    published: str | None
    basis: str


@dataclass
class AssetNote:
    asset_id: str
    product: str
    version: str
    cpe: str | None
    kind: str
    text: str


@dataclass
class Report:
    name: str
    generated_at: str
    mode: str
    read_only: bool
    findings: list[Finding]
    notes: list[AssetNote]
    new_cve_ids: list[str] | None
    previous_state_loaded: bool
    warnings: list[str]
    sources: list[str]
    formula: tuple[str, ...] = field(default_factory=lambda: FORMULA_LINES)
    llm_summary: str | None = None
    llm_preview: str | None = None


def _links(cve_id: str, references: list[str], csaf_hits: list[CsafHit], kev: bool) -> list[tuple[str, str]]:
    links = [
        ("NVD", f"https://nvd.nist.gov/vuln/detail/{cve_id}"),
        ("Vulnerability-Lookup", f"https://vulnerability.circl.lu/vuln/{cve_id}"),
        ("EPSS", f"https://api.first.org/data/v1/epss?cve={cve_id}"),
    ]
    if kev:
        links.append(("CISA KEV catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"))
    for url in references[:3]:
        links.append(("reference", url))
    for hit in csaf_hits:
        if hit.url:
            links.append((hit.advisory_id, hit.url))
    return links


def _fixed_hint(observation: Observation, csaf_hits: list[CsafHit]) -> str | None:
    pieces: list[str] = []
    if observation.fixed_hint:
        pieces.append(observation.fixed_hint)
    for hit in csaf_hits:
        if hit.remediation and hit.known_affected:
            label = "official CSAF" if hit.official else "CSAF fixture, not an official CERT-Bund advisory"
            pieces.append(f"{hit.advisory_id} ({label}): {hit.remediation}")
    if not pieces:
        return None
    return " ".join(pieces)


def assemble(
    *,
    name: str,
    generated_at: str,
    mode: str,
    resolutions: list[Resolution],
    records: list[Record],
    kev: KevCatalog | None,
    epss: dict,
    advisories: list[CsafAdvisory],
    previous_ids: set[str] | None,
    warnings: list[str],
    sources: list[str],
) -> Report:
    findings: list[Finding] = []
    notes: list[AssetNote] = []
    for resolution in resolutions:
        asset = resolution.asset
        if resolution.chosen is None:
            shown = ", ".join(f"{item.cpe} ({item.confidence:.2f})" for item in resolution.candidates[:3])
            text = resolution.hint or "No CPE was confident enough to query."
            if shown:
                text = f"{text} Closest: {shown}."
            notes.append(
                AssetNote(asset.id, asset.product, asset.version, None, "unresolved", text.strip())
            )
            continue
        cpe = resolution.chosen.cpe
        saw_product = False
        for record in records:
            observation = evaluate(record, cpe, asset.version, asset.vendor, asset.product)
            if observation.verdict == "not_affected" and not observation.product_mentioned:
                continue
            if not observation.product_mentioned and observation.verdict != "affected":
                continue
            saw_product = True
            csaf_hits = hits_for(advisories, record.cve_id, cpe, asset.version, asset.product)
            if observation.verdict == "affected":
                kev_entry = kev.entries.get(record.cve_id) if kev else None
                kev_flag = kev_entry is not None or bool(record.cisa_exploit_add)
                if kev_entry is not None:
                    kev_detail = f" (added {kev_entry.date_added})" if kev_entry.date_added else ""
                    kev_name = kev_entry.name
                    kev_date = kev_entry.date_added
                    ransomware = kev_entry.ransomware
                elif record.cisa_exploit_add:
                    kev_detail = f" (NVD cisaExploitAdd {record.cisa_exploit_add}; KEV catalog file not loaded)"
                    kev_name = record.cisa_name
                    kev_date = record.cisa_exploit_add
                    ransomware = None
                else:
                    kev_detail = ""
                    kev_name = None
                    kev_date = None
                    ransomware = None
                epss_score = epss.get(record.cve_id)
                exact = any(hit.known_affected and hit.version_specific for hit in csaf_hits)
                csaf_detail = ", ".join(hit.advisory_id for hit in csaf_hits if hit.known_affected) or ""
                points, parts = score(
                    kev=kev_flag,
                    kev_detail=kev_detail,
                    epss=None if epss_score is None else epss_score.probability,
                    cvss=record.cvss,
                    exposure=asset.exposure,
                    count=asset.count,
                    csaf_exact=exact,
                    csaf_detail=csaf_detail,
                )
                findings.append(
                    Finding(
                        asset_id=asset.id,
                        product=asset.product,
                        vendor=asset.vendor,
                        version=asset.version,
                        count=asset.count,
                        owner=asset.owner,
                        exposure=asset.exposure,
                        cpe=cpe,
                        cpe_confirmed=resolution.confirmed,
                        cve_id=record.cve_id,
                        description=record.description,
                        cvss=record.cvss,
                        severity=record.severity,
                        vector=record.vector,
                        epss=None if epss_score is None else epss_score.probability,
                        epss_percentile=None if epss_score is None else epss_score.percentile,
                        epss_date=None if epss_score is None else epss_score.date,
                        kev=kev_flag,
                        kev_name=kev_name,
                        kev_date=kev_date,
                        ransomware=ransomware if ransomware and ransomware.lower() == "known" else None,
                        points=points,
                        parts=parts,
                        reason=observation.reason,
                        fixed_hint=_fixed_hint(observation, csaf_hits),
                        links=_links(record.cve_id, record.references, csaf_hits, kev_flag),
                        csaf=csaf_hits,
                        published=record.published,
                        basis=observation.basis,
                    )
                )
            elif observation.verdict == "not_decided":
                notes.append(
                    AssetNote(
                        asset.id,
                        asset.product,
                        asset.version,
                        cpe,
                        "not_decided",
                        f"{record.cve_id}: {observation.reason}",
                    )
                )
            else:
                notes.append(
                    AssetNote(
                        asset.id,
                        asset.product,
                        asset.version,
                        cpe,
                        "not_affected",
                        f"{record.cve_id} does not affect {asset.product} {asset.version}. {observation.reason}",
                    )
                )
        if not saw_product:
            notes.append(
                AssetNote(
                    asset.id,
                    asset.product,
                    asset.version,
                    cpe,
                    "not_affected",
                    "No loaded CVE names this CPE.",
                )
            )
    findings.sort(key=lambda item: (-item.points, item.cve_id, item.asset_id))
    if previous_ids is None:
        new_ids = None
    else:
        new_ids = sorted({item.cve_id for item in findings if item.cve_id not in previous_ids})
    return Report(
        name=name,
        generated_at=generated_at,
        mode=mode,
        read_only=True,
        findings=findings,
        notes=notes,
        new_cve_ids=new_ids,
        previous_state_loaded=previous_ids is not None,
        warnings=warnings,
        sources=sources,
    )
