"""CPE pins. Writing a lock file is explicit; reading one never changes it."""

from __future__ import annotations

from pathlib import Path

import yaml

from patchwindow.cpe import canonical_base
from patchwindow.errors import PatchwindowError
from patchwindow.models import LockEntry


def default_lock_path(inventory_path: Path) -> Path:
    name = inventory_path.name
    if name.endswith(".yaml"):
        return inventory_path.with_name(name[: -len(".yaml")] + ".lock.yaml")
    if name.endswith(".yml"):
        return inventory_path.with_name(name[: -len(".yml")] + ".lock.yaml")
    return inventory_path.with_name(name + ".lock.yaml")


def load_lock(path: Path | None) -> dict[str, LockEntry]:
    if path is None or not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PatchwindowError(f"cannot read lock file {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise PatchwindowError(f"{path} is not valid YAML: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise PatchwindowError(f"{path}: lock file must be a mapping")
    schema = data.get("schema")
    if schema is not None and schema != "patchwindow.lock/v1":
        raise PatchwindowError(f"{path}: unsupported schema {schema!r}")
    entries = data.get("entries") or {}
    if not isinstance(entries, dict):
        raise PatchwindowError(f"{path}: entries must be a mapping")
    loaded: dict[str, LockEntry] = {}
    for asset_id, raw in entries.items():
        if not isinstance(raw, dict) or not isinstance(raw.get("cpe"), str):
            raise PatchwindowError(f"{path}: entry {asset_id} needs a cpe string")
        pinned = raw.get("pinned", True)
        if not isinstance(pinned, bool):
            raise PatchwindowError(f"{path}: entry {asset_id} pinned must be true or false")
        note = raw.get("note") or ""
        if not isinstance(note, str):
            raise PatchwindowError(f"{path}: entry {asset_id} note must be a string")
        loaded[str(asset_id)] = LockEntry(
            cpe=canonical_base(raw["cpe"]),
            pinned=pinned,
            confidence=1.0 if pinned else 0.0,
            origin=str(raw.get("origin") or "user"),
            note=note,
        )
    return loaded


def dump_lock(entries: dict[str, LockEntry]) -> str:
    body = {
        "schema": "patchwindow.lock/v1",
        "entries": {
            asset_id: {
                "cpe": entry.cpe,
                "pinned": True,
                "confidence": 1.0,
                "origin": entry.origin or "user",
                "note": entry.note,
            }
            for asset_id, entry in entries.items()
            if entry.pinned
        },
    }
    return yaml.safe_dump(body, sort_keys=False, allow_unicode=True)


def load_state(path: Path | None) -> set[str] | None:
    """Return CVE ids from a previous run, or None when no baseline was given."""
    if path is None:
        return None
    if not path.exists():
        raise PatchwindowError(f"state file not found: {path}")
    import json

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PatchwindowError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("cve_ids"), list):
        raise PatchwindowError(f"{path}: expected cve_ids list")
    return {str(item) for item in data["cve_ids"]}


def dump_state(cve_ids: list[str], generated_at: str) -> str:
    import json

    return json.dumps(
        {
            "schema": "patchwindow.state/v1",
            "generated_at": generated_at,
            "cve_ids": sorted(set(cve_ids)),
        },
        indent=2,
    ) + "\n"
