"""Demo bundle and the live scan that shares the same briefing assembler."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from patchorder.csaf import load_csaf_path
from patchorder.inventory import load_inventory
from patchorder.lockfile import load_lock, load_state
from patchorder.models import Inventory, Resolution
from patchorder.records import dedupe_records, from_nvd_cve, parse_epss, parse_kev
from patchorder.report import Report, assemble
from patchorder.resolver import resolve_asset
from patchorder.sources import CSAF_PROVIDER, LiveFetcher

DEMO_ROOT = Path(__file__).resolve().parent / "data" / "demo"
RECORDED = "2026-10-21"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _load_nvd_dir(path: Path) -> list:
    records = []
    for item in sorted(path.glob("*.json")):
        payload = json.loads(item.read_text(encoding="utf-8"))
        for wrapped in payload.get("vulnerabilities") or []:
            record = from_nvd_cve(wrapped.get("cve") or {})
            if record:
                records.append(record)
    return records


def run_demo() -> Report:
    root = DEMO_ROOT
    inventory = load_inventory(root / "inventory.yaml")
    lock = load_lock(root / "inventory.lock.yaml")
    previous = load_state(root / "state-previous.json")
    resolutions = [resolve_asset(asset, lock.get(asset.id)) for asset in inventory.assets]
    records = dedupe_records(_load_nvd_dir(root / "nvd"))
    kev = parse_kev(json.loads((root / "kev.json").read_text(encoding="utf-8")))
    epss = parse_epss(json.loads((root / "epss.json").read_text(encoding="utf-8")))
    advisories = load_csaf_path(root / "csaf")
    sources = [
        f"NVD CVE API 2.0: {len(records)} records bundled as fixtures recorded {RECORDED}, "
        "reduced to the CPE matches this demo decides. Not a live query.",
        f"CISA KEV: catalog {kev.catalog_version}. {kev.note or str(len(kev.entries)) + ' entries loaded'}".strip(),
        "FIRST EPSS: bundled scores. Not a live query.",
        "Vulnerability-Lookup: not queried in demo mode. Live scans call cpesearch and then filter versions locally.",
        f"CSAF: {len(advisories)} fictional local documents. "
        "EXAMPLE-SA-2024-0099 (Example CERT) names PHP without a version and does not match this inventory. "
        "FIXTURE-SA-2024-0001 marks OpenSSL 3.0.12 known_affected. "
        f"Live scans may request provider metadata from {CSAF_PROVIDER}. That response is not bundled.",
    ]
    return assemble(
        name=inventory.name,
        generated_at=utc_now(),
        mode="demo",
        resolutions=resolutions,
        records=records,
        kev=kev,
        epss=epss,
        advisories=advisories,
        previous_ids=previous,
        warnings=[],
        sources=sources,
    )


def resolve_inventory(
    inventory: Inventory,
    lock: dict,
    dictionary_by_asset: dict[str, list[dict]] | None = None,
) -> list[Resolution]:
    dictionary_by_asset = dictionary_by_asset or {}
    return [
        resolve_asset(asset, lock.get(asset.id), dictionary_by_asset.get(asset.id))
        for asset in inventory.assets
    ]


def run_with_records(
    inventory: Inventory,
    resolutions: list[Resolution],
    records,
    kev,
    epss,
    advisories,
    previous_ids,
    *,
    mode: str,
    warnings: list[str],
    sources: list[str],
) -> Report:
    return assemble(
        name=inventory.name,
        generated_at=utc_now(),
        mode=mode,
        resolutions=resolutions,
        records=dedupe_records(records),
        kev=kev,
        epss=epss,
        advisories=advisories,
        previous_ids=previous_ids,
        warnings=warnings,
        sources=sources,
    )


def live_scan(
    inventory: Inventory,
    resolutions: list[Resolution],
    fetcher: LiveFetcher,
    advisories,
    previous_ids,
    *,
    pinned_only: bool,
    extra_sources: list[str] | None = None,
) -> Report:
    from patchorder.resolver import AUTO_USE_CONFIDENCE

    adjusted: list[Resolution] = []
    for resolution in resolutions:
        if pinned_only and not resolution.confirmed:
            resolution.chosen = None
            resolution.hint = resolution.hint or (
                f"pinned-only is set, so a candidate below or above {AUTO_USE_CONFIDENCE:.2f} "
                "is not queried until you pin it."
            )
        adjusted.append(resolution)
    records, warnings, queried = fetcher.fetch(adjusted)
    try:
        kev = fetcher.kev()
    except Exception as exc:
        from patchorder.errors import PatchorderError

        if isinstance(exc, PatchorderError):
            warnings.append(str(exc))
        else:
            warnings.append(f"KEV catalog was not loaded: {exc}")
        kev = None
    cve_ids = [record.cve_id for record in records]
    epss = {}
    if cve_ids:
        try:
            epss = fetcher.epss(cve_ids)
        except Exception as exc:
            from patchorder.errors import PatchorderError

            if isinstance(exc, PatchorderError):
                warnings.append(str(exc))
            else:
                warnings.append(f"EPSS was not loaded: {exc}")
    sources = [
        "Live read of public APIs. Inventory stays on this machine.",
        *queried,
        f"CISA KEV entries loaded: {0 if kev is None else len(kev.entries)}.",
        f"EPSS scores loaded: {len(epss)}.",
        f"CSAF documents loaded from disk: {len(advisories)}. The full CERT-Bund feed is not downloaded "
        f"(the WID index is tens of megabytes). Provider metadata: {CSAF_PROVIDER}",
    ]
    if extra_sources:
        sources.extend(extra_sources)
    if kev is not None and kev.note:
        sources.append(kev.note)
    return run_with_records(
        inventory,
        adjusted,
        records,
        kev,
        epss,
        advisories,
        previous_ids,
        mode="live",
        warnings=warnings,
        sources=sources,
    )

