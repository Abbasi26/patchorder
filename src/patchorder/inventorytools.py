"""Inventory helpers that never touch the network: lint a YAML inventory, import a CSV export."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass
from pathlib import Path


from patchorder.cpe import parse_cpe
from patchorder.engine import resolve_inventory
from patchorder.errors import PatchorderError
from patchorder.inventory import load_inventory
from patchorder.lockfile import default_lock_path, load_lock
from patchorder.versions import version_is_comparable

FIELDS = ("id", "product", "vendor", "version", "count", "owner", "exposure")
_HEADER_ALIASES = {
    "name": "product", "software": "product", "application": "product",
    "manufacturer": "vendor", "publisher": "vendor",
    "hosts": "count", "devices": "count", "installs": "count",
    "team": "owner", "responsible": "owner",
    "exposed": "exposure", "network": "exposure",
}


@dataclass
class InventoryNote:
    level: str  # "error", "warning", "info"
    asset_id: str
    text: str


def check_inventory(path: Path, lock_path: Path | None = None) -> list[InventoryNote]:
    """Load the inventory (errors raise) and report what a scan would not be able to decide."""
    inventory = load_inventory(path)
    lock_path = lock_path or default_lock_path(path)
    lock = load_lock(lock_path if lock_path.exists() else None)
    notes: list[InventoryNote] = []
    for asset_id in sorted(set(lock) - {a.id for a in inventory.assets}):
        notes.append(InventoryNote("warning", asset_id, "lock file pins an id that is not in the inventory"))
    seen: dict[tuple[str, str, str], str] = {}
    for resolution in resolve_inventory(inventory, lock, {}):
        asset = resolution.asset
        key = (asset.vendor.lower(), asset.product.lower(), asset.version)
        if key in seen:
            notes.append(InventoryNote("info", asset.id, f"same product and version as `{seen[key]}`; consider one row with a higher count"))
        else:
            seen[key] = asset.id
        if asset.count == 0:
            notes.append(InventoryNote("info", asset.id, "count is 0; findings will rank low"))
        chosen = resolution.chosen
        if chosen is None:
            notes.append(InventoryNote("warning", asset.id, "no CPE candidate offline; pin one with `resolve --accept` or the row is skipped"))
            continue
        if not resolution.confirmed:
            notes.append(InventoryNote("warning", asset.id, f"CPE {chosen.cpe} is a guess ({chosen.confidence:.2f}), not pinned"))
        try:
            identity = parse_cpe(chosen.cpe)
        except PatchorderError:
            continue
        ok, reason = version_is_comparable(identity.vendor, identity.product, asset.version)
        if not ok:
            notes.append(InventoryNote("warning", asset.id, f"{reason}; every CVE for this row will be 'not decided'"))
    return notes


def _normalize_header(name: str) -> str:
    key = name.strip().lower().replace(" ", "_")
    return _HEADER_ALIASES.get(key, key)


def csv_to_inventory(text: str, name: str, default_owner: str = "unassigned", default_exposure: str = "internal") -> str:
    """Turn a CSV export into inventory YAML with every version quoted."""
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    if not reader.fieldnames:
        raise PatchorderError("CSV has no header row")
    headers = {raw: _normalize_header(raw) for raw in reader.fieldnames}
    for required in ("product", "version"):
        if required not in headers.values():
            raise PatchorderError(f"CSV needs a `{required}` column (found: {', '.join(reader.fieldnames)})")
    assets = []
    for line, row in enumerate(reader, start=2):
        item = {headers[k]: (v or "").strip() for k, v in row.items() if k is not None and headers.get(k) in FIELDS}
        if not any(item.values()):
            continue
        if not item.get("product") or not item.get("version"):
            raise PatchorderError(f"CSV line {line}: product and version are required")
        count_text = item.get("count") or "1"
        try:
            count = int(count_text)
        except ValueError as exc:
            raise PatchorderError(f"CSV line {line}: count {count_text!r} is not a whole number") from exc
        exposure = (item.get("exposure") or default_exposure).lower()
        if exposure in {"yes", "true", "external", "public", "dmz"}:
            exposure = "internet"
        elif exposure in {"no", "false", "private", "lan"}:
            exposure = "internal"
        if exposure not in {"internet", "internal"}:
            raise PatchorderError(f"CSV line {line}: exposure {exposure!r} must be internet or internal")
        asset = {}
        if item.get("id"):
            asset["id"] = item["id"]
        asset["product"] = item["product"]
        if item.get("vendor"):
            asset["vendor"] = item["vendor"]
        asset["version"] = item["version"]
        asset["count"] = count
        asset["owner"] = item.get("owner") or default_owner
        asset["exposure"] = exposure
        assets.append(asset)
    if not assets:
        raise PatchorderError("CSV has no data rows")

    # Every string is written as a JSON string, which is a valid double-quoted YAML scalar,
    # so versions such as 1.10 stay strings.
    lines = [
        "# Generated by patchorder inventory from-csv. Review before use.",
        "schema: patchorder.inventory/v1",
        f"name: {json.dumps(name, ensure_ascii=False)}",
        "assets:",
    ]
    for asset in assets:
        first = True
        for key, value in asset.items():
            rendered = str(value) if isinstance(value, int) else json.dumps(value, ensure_ascii=False)
            lines.append(f"  {'- ' if first else '  '}{key}: {rendered}")
            first = False
    return "\n".join(lines) + "\n"
