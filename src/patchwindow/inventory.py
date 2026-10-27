"""Load inventory.yaml. Versions must be quoted strings so 1.10 does not become 1.1."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from patchwindow.errors import PatchwindowError
from patchwindow.models import Asset, Inventory

_EXPOSURES = {"internet": "internet", "internal": "internal"}
_SLUG = re.compile(r"[^a-z0-9]+")


def _require_mapping(data: object, path: Path) -> dict:
    if not isinstance(data, dict):
        raise PatchwindowError(f"{path}: inventory file must be a mapping")
    return data


def _string(value: object, label: str) -> str:
    if isinstance(value, bool) or value is None:
        raise PatchwindowError(f"{label} is missing")
    if isinstance(value, float):
        raise PatchwindowError(
            f"{label} was read as the number {value}. Quote versions in YAML "
            '(version: "1.25.2"). An unquoted 1.10 would be read as 1.1.'
        )
    if isinstance(value, int):
        return str(value)
    if not isinstance(value, str) or not value.strip():
        raise PatchwindowError(f"{label} must be a string")
    text = value.strip()
    if len(text) > 80:
        raise PatchwindowError(f"{label} is longer than 80 characters")
    return text


def _slug(vendor: str, product: str, version: str, used: set[str]) -> str:
    raw = "-".join(part for part in (vendor, product, version) if part)
    slug = _SLUG.sub("-", raw.lower()).strip("-") or "asset"
    base = slug
    number = 2
    while slug in used:
        slug = f"{base}-{number}"
        number += 1
    used.add(slug)
    return slug


def load_inventory(path: Path) -> Inventory:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PatchwindowError(f"cannot read inventory {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise PatchwindowError(f"{path} is not valid YAML: {exc}") from exc
    mapping = _require_mapping(data, path)
    schema = mapping.get("schema")
    if schema is not None and schema != "patchwindow.inventory/v1":
        raise PatchwindowError(f"{path}: unsupported schema {schema!r}")
    name = mapping.get("name") or path.stem
    if not isinstance(name, str):
        raise PatchwindowError(f"{path}: name must be a string")
    assets = mapping.get("assets")
    if not isinstance(assets, list) or not assets:
        raise PatchwindowError(f"{path}: assets must be a non-empty list")
    used: set[str] = set()
    loaded: list[Asset] = []
    for index, raw in enumerate(assets, start=1):
        if not isinstance(raw, dict):
            raise PatchwindowError(f"{path}: asset {index} must be a mapping")
        where = f"{path} asset {index}"
        product = _string(raw.get("product"), f"{where} product")
        vendor = raw.get("vendor", "")
        if vendor is None:
            vendor = ""
        if isinstance(vendor, float):
            raise PatchwindowError(f"{where} vendor must be a string")
        if not isinstance(vendor, str):
            raise PatchwindowError(f"{where} vendor must be a string")
        vendor = vendor.strip()
        version = _string(raw.get("version"), f"{where} version")
        count = raw.get("count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise PatchwindowError(f"{where} count must be a non-negative integer")
        owner = raw.get("owner")
        if not isinstance(owner, str) or not owner.strip():
            raise PatchwindowError(f"{where} owner must be a string")
        exposure_raw = raw.get("exposure")
        if not isinstance(exposure_raw, str):
            raise PatchwindowError(f"{where} exposure must be internet or internal")
        exposure = _EXPOSURES.get(exposure_raw.strip().lower())
        if exposure is None:
            raise PatchwindowError(f"{where} exposure must be internet or internal")
        asset_id = raw.get("id")
        if asset_id is None or asset_id == "":
            asset_id = _slug(vendor, product, version, used)
        elif not isinstance(asset_id, str):
            raise PatchwindowError(f"{where} id must be a string")
        else:
            asset_id = asset_id.strip()
            if asset_id in used:
                raise PatchwindowError(f"{where} duplicates id {asset_id}")
            used.add(asset_id)
        loaded.append(
            Asset(
                id=asset_id,
                product=product,
                vendor=vendor,
                version=version,
                count=count,
                owner=owner.strip(),
                exposure=exposure,
            )
        )
    return Inventory(name=name.strip(), assets=loaded, source=str(path))
