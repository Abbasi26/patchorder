"""Turn one inventory row into CPE candidates, and remember which one was pinned."""

from __future__ import annotations

import re

from patchwindow.aliases import BUILD_FAMILY, alias_candidates
from patchwindow.cpe import canonical_base
from patchwindow.models import Asset, Candidate, LockEntry, Resolution
from patchwindow.normalize import tokens

# At or above this, scan will use the CPE and label the result unconfirmed.
# Below it, scan refuses to guess. Pinning is the only way to mark it confirmed.
AUTO_USE_CONFIDENCE = 0.85

_BUILD = re.compile(r"\b10\.\d+\.(\d+)\.\d+\b")
_WINDOWSISH = re.compile(r"windows|microsoft", re.IGNORECASE)


def _windows_build(asset: Asset) -> int | None:
    match = _BUILD.search(asset.version)
    if not match:
        return None
    return int(match.group(1))


def _looks_like_windows(asset: Asset) -> bool:
    return bool(_WINDOWSISH.search(asset.product) or _WINDOWSISH.search(asset.vendor))


def apply_build_hints(asset: Asset, candidates: list[Candidate]) -> list[Candidate]:
    """Use 10.0.<build>.<ubr> to confirm or contradict a Windows CPE."""
    if not _looks_like_windows(asset):
        return candidates
    build = _windows_build(asset)
    if build is None:
        if not candidates and tokens(asset.product)[:1] == ["windows"]:
            return candidates
        return candidates
    families = BUILD_FAMILY.get(build)
    if not families:
        return candidates
    updated: list[Candidate] = []
    family_products = {item[0] for item in families}
    for candidate in candidates:
        product = candidate.cpe.rsplit(":", 1)[-1]
        if product in family_products:
            note = f"{candidate.note} Build {build} agrees with this product.".strip()
            updated.append(Candidate(candidate.cpe, candidate.confidence, candidate.origin, note))
            continue
        if product.startswith("windows_"):
            names = ", ".join(item[1] for item in families)
            note = (
                f"{candidate.note} Build {build} belongs to {names}, which disagrees with this CPE."
            ).strip()
            updated.append(
                Candidate(candidate.cpe, min(candidate.confidence, 0.55), candidate.origin, note)
            )
            continue
        updated.append(candidate)
    known = {item.cpe for item in updated}
    ambiguous = len(families) > 1
    named = [item for item in candidates if item.cpe.rsplit(":", 1)[-1].startswith("windows_")]
    windows_still_confident = any(
        item.confidence >= AUTO_USE_CONFIDENCE and item.cpe.rsplit(":", 1)[-1].startswith("windows_")
        for item in updated
    )
    for product, label in families:
        cpe = f"cpe:2.3:o:microsoft:{product}"
        if cpe in known:
            continue
        if ambiguous:
            confidence = 0.62
            note = (
                f"Build {build} is shared by more than one Windows edition ({label}). "
                "Pin the edition you actually run."
            )
        else:
            confidence = 0.82
            note = f"Inferred {label} from build {build}. Pin it if this is the right edition."
        # Keep a confident, agreeing alias. Otherwise offer the build-family CPE.
        if not named or not windows_still_confident:
            updated.append(Candidate(cpe, confidence, "build", note))
    return _dedupe(updated)


def _dedupe(candidates: list[Candidate]) -> list[Candidate]:
    best: dict[str, Candidate] = {}
    for candidate in candidates:
        current = best.get(candidate.cpe)
        if current is None or candidate.confidence > current.confidence:
            best[candidate.cpe] = candidate
        elif current is not None and candidate.confidence == current.confidence and candidate.note not in current.note:
            best[candidate.cpe] = Candidate(
                current.cpe,
                current.confidence,
                current.origin,
                f"{current.note} {candidate.note}".strip(),
            )
    ordered = sorted(best.values(), key=lambda item: (-item.confidence, item.cpe))
    return [item for item in ordered if item.confidence >= 0.3]


def dictionary_candidates(asset: Asset, hits: list[dict]) -> list[Candidate]:
    """Score NVD CPE API hits. `hits` are dicts with cpe, title, deprecated."""
    product_tokens = tokens(asset.product)
    vendor_tokens = set(tokens(asset.vendor))
    scored: list[Candidate] = []
    for hit in hits:
        try:
            base = canonical_base(hit["cpe"])
        except Exception:
            continue
        identity_tokens = tokens(base.replace(":", " ").replace("_", " "))
        title_tokens = tokens(hit.get("title") or "")
        vendor = base.split(":")[3]
        product = base.split(":")[4].replace("_", " ")
        product_equal = tokens(product) == product_tokens
        vendor_ok = bool(vendor_tokens) and (vendor in vendor_tokens or bool(vendor_tokens & set(title_tokens)))
        if product_equal and vendor_ok:
            confidence = 0.88
            note = "NVD CPE dictionary title matches the product and vendor"
        elif product_equal:
            confidence = 0.74
            note = "NVD CPE dictionary product matches; vendor was not confirmed"
        elif product_tokens and set(product_tokens) <= set(tokens(product)) | set(title_tokens) | set(identity_tokens):
            confidence = 0.5
            note = "NVD CPE dictionary keyword overlap"
        else:
            continue
        if hit.get("deprecated"):
            confidence = round(max(0.3, confidence - 0.25), 2)
            replacement = hit.get("deprecated_by") or ""
            note = f"deprecated NVD CPE. {note}. Replacement: {replacement}".strip()
        scored.append(Candidate(base, confidence, "nvd-cpe", note))
    return scored


def resolve_asset(
    asset: Asset,
    lock_entry: LockEntry | None = None,
    dictionary_hits: list[dict] | None = None,
) -> Resolution:
    if lock_entry is not None and lock_entry.pinned:
        chosen = Candidate(
            cpe=lock_entry.cpe,
            confidence=1.0,
            origin="lock",
            note=lock_entry.note or "Pinned in the lock file.",
        )
        return Resolution(asset=asset, candidates=[chosen], chosen=chosen, confirmed=True, hint="")
    candidates = alias_candidates(asset)
    if dictionary_hits:
        candidates.extend(dictionary_candidates(asset, dictionary_hits))
    candidates = apply_build_hints(asset, candidates)
    candidates = _dedupe(candidates)
    hint = ""
    if not candidates and _looks_like_windows(asset):
        hint = (
            "Name the Windows release (for example Windows 11 23H2 or Windows Server 2022) "
            "or a build such as 10.0.22631.3593, then pin the CPE."
        )
    elif not candidates:
        hint = "No alias or dictionary hit. Pin a CPE yourself, or run resolve with CPE discovery online."
    chosen = None
    confirmed = False
    if candidates and candidates[0].confidence >= AUTO_USE_CONFIDENCE:
        chosen = candidates[0]
    return Resolution(asset=asset, candidates=candidates, chosen=chosen, confirmed=confirmed, hint=hint)


def format_candidates(resolution: Resolution) -> str:
    asset = resolution.asset
    lines = [
        f"{asset.id}: {asset.vendor + ' ' if asset.vendor else ''}{asset.product} {asset.version} "
        f"({asset.count} hosts, {asset.exposure}, owner {asset.owner})"
    ]
    if resolution.confirmed and resolution.chosen:
        lines.append(f"  pinned  {resolution.chosen.cpe}  {resolution.chosen.note}")
        return "\n".join(lines)
    if not resolution.candidates:
        lines.append(f"  no CPE candidate. {resolution.hint}")
        return "\n".join(lines)
    for index, candidate in enumerate(resolution.candidates, start=1):
        lines.append(
            f"  {index}) {candidate.cpe}  confidence {candidate.confidence:.2f}  "
            f"[{candidate.origin}] {candidate.note}"
        )
    if resolution.hint:
        lines.append(f"  {resolution.hint}")
    return "\n".join(lines)
