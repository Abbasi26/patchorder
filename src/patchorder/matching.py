"""Decide whether one installed version is inside a published affected range.

NVD configurations win over CVE List 5 `affected` blocks when both exist.
Vulnerability-Lookup's cpesearch returns every version of a product; this module
is the filter that service deliberately leaves to the client.
"""

from __future__ import annotations

from dataclasses import dataclass

from patchorder.cpe import CpeIdentity, parse_cpe
from patchorder.models import Record
from patchorder.normalize import phrase_in, tokens
from patchorder.versions import (
    compare_versions,
    in_bounds,
    is_windows_product,
    split_portable_update,
    version_is_comparable,
)


@dataclass
class Observation:
    cve_id: str
    verdict: str
    product_mentioned: bool
    reason: str
    fixed_hint: str | None
    basis: str


def _wildcard(value: str) -> bool:
    return value in {"*", "-", ""}


def _describe_match(match: dict, identity: CpeIdentity) -> str:
    version = identity.version
    update = identity.update
    start = match.get("versionStartIncluding") or match.get("versionStartExcluding")
    if not _wildcard(version):
        extra = "" if _wildcard(update) else f" update {update}"
        return f"exact {version}{extra}"
    parts: list[str] = []
    if match.get("versionStartIncluding"):
        parts.append(f"from {match['versionStartIncluding']} including")
    elif match.get("versionStartExcluding"):
        parts.append(f"after {match['versionStartExcluding']}")
    if match.get("versionEndIncluding"):
        parts.append(f"through {match['versionEndIncluding']} including")
    elif match.get("versionEndExcluding"):
        parts.append(f"before {match['versionEndExcluding']}")
    if not parts:
        return "any version"
    if start and not any(p.startswith("from") or p.startswith("after") for p in parts):
        pass
    return " ".join(parts)


def _hint_for_match(match: dict, identity: CpeIdentity) -> str | None:
    if match.get("versionEndExcluding"):
        end = match["versionEndExcluding"]
        return f"Update to {end} or later (NVD versionEndExcluding)."
    if match.get("versionEndIncluding"):
        end = match["versionEndIncluding"]
        return (
            f"NVD marks versions through {end} as affected (versionEndIncluding). "
            f"Move to a release newer than {end}."
        )
    if not _wildcard(identity.version):
        shown = identity.version if _wildcard(identity.update) else f"{identity.version} {identity.update}"
        return (
            f"NVD lists {shown} as a vulnerable version and does not state a fixed release "
            "on this CPE match."
        )
    return None


def _exact_version_match(identity: CpeIdentity, installed: str) -> bool:
    numeric, portable = split_portable_update(installed)
    if _wildcard(identity.version):
        return False
    if compare_versions(numeric if portable else installed, identity.version) != 0:
        return False
    if _wildcard(identity.update):
        if identity.update == "-" and portable:
            return False
        return True
    installed_update = portable or "-"
    return installed_update == identity.update


def _range_match(match: dict, installed: str) -> bool:
    start = match.get("versionStartIncluding") or match.get("versionStartExcluding")
    end = match.get("versionEndIncluding") or match.get("versionEndExcluding")
    if not start and not end:
        return True
    return in_bounds(
        installed,
        match.get("versionStartIncluding") or match.get("versionStartExcluding"),
        "versionStartExcluding" not in match or bool(match.get("versionStartIncluding")),
        match.get("versionEndIncluding") or match.get("versionEndExcluding"),
        "versionEndIncluding" in match,
    )


def _eval_configs(record: Record, identity_wanted: CpeIdentity, version: str) -> Observation:
    comparable, why = version_is_comparable(identity_wanted.vendor, identity_wanted.product, version)
    affected_reason = ""
    affected_hint: str | None = None
    mentioned = False
    exclusions: list[str] = []
    undecided: list[str] = []

    for config in record.configurations:
        if not isinstance(config, dict):
            continue
        nodes = config.get("nodes") or []
        if any(isinstance(node, dict) and node.get("negate") for node in nodes):
            # A negated node changes the meaning of the whole configuration.
            if _config_mentions(nodes, identity_wanted):
                mentioned = True
                undecided.append("a negated CPE node is not evaluated in v0.1")
            continue
        node_results = [_eval_node(node, identity_wanted, version, comparable, why) for node in nodes if isinstance(node, dict)]
        mentions = [item for item in node_results if item[0] != "absent"]
        others = [item for item in node_results if item[0] == "absent"]
        if not mentions:
            continue
        mentioned = True
        operator = str(config.get("operator") or "AND").upper()
        if operator == "AND" and others and any(item[0] == "affected" for item in mentions):
            undecided.append("configuration also requires another product this entry does not name")
            continue
        for verdict, reason, hint in mentions:
            if verdict == "affected" and not affected_reason:
                affected_reason = reason
                affected_hint = hint
            elif verdict == "not_decided" and reason:
                undecided.append(reason)
            elif verdict == "not_affected" and reason:
                exclusions.append(reason)

    if affected_reason:
        return Observation(record.cve_id, "affected", True, affected_reason, affected_hint, "nvd")
    if undecided:
        return Observation(record.cve_id, "not_decided", True, undecided[0], None, "nvd")
    if mentioned:
        detail = "; ".join(dict.fromkeys(exclusions)) or "no vulnerable range includes this version"
        return Observation(
            record.cve_id,
            "not_affected",
            True,
            f"{version} is not inside a vulnerable range for {identity_wanted.base} ({detail})",
            None,
            "nvd",
        )
    return Observation(
        record.cve_id,
        "not_affected",
        False,
        f"{identity_wanted.base} is not a vulnerable CPE in this CVE",
        None,
        "nvd",
    )


def _config_mentions(nodes: list, identity_wanted: CpeIdentity) -> bool:
    for node in nodes:
        if not isinstance(node, dict):
            continue
        for match in node.get("cpeMatch") or []:
            if not isinstance(match, dict) or not match.get("vulnerable", False):
                continue
            try:
                parsed = parse_cpe(str(match.get("criteria") or ""))
            except Exception:
                continue
            if parsed.same_product(identity_wanted):
                return True
    return False


def _eval_node(
    node: dict,
    identity_wanted: CpeIdentity,
    version: str,
    comparable: bool,
    why: str,
) -> tuple[str, str, str | None]:
    operator = str(node.get("operator") or "OR").upper()
    relevant: list[dict] = []
    saw_other = False
    for match in node.get("cpeMatch") or []:
        if not isinstance(match, dict):
            continue
        try:
            parsed = parse_cpe(str(match.get("criteria") or ""))
        except Exception:
            continue
        if not match.get("vulnerable", False):
            if not parsed.same_product(identity_wanted):
                saw_other = True
            continue
        if not parsed.same_product(identity_wanted):
            saw_other = True
            continue
        relevant.append(match)
    if not relevant:
        return "absent", "", None
    if operator == "AND" and saw_other:
        return "not_decided", "CPE node uses AND with other products; this entry is only one product", None
    decisions = [_decide_match(match, version, comparable, why) for match in relevant]
    for verdict, reason, hint in decisions:
        if verdict == "affected":
            return verdict, reason, hint
    for verdict, reason, hint in decisions:
        if verdict == "not_decided":
            return verdict, reason, hint
    reasons = [reason for verdict, reason, _hint in decisions if verdict == "not_affected" and reason]
    return "not_affected", "; ".join(dict.fromkeys(reasons)), None


def _decide_match(match: dict, version: str, comparable: bool, why: str) -> tuple[str, str, str | None]:
    try:
        identity = parse_cpe(str(match.get("criteria") or ""))
    except Exception:
        return "not_decided", "CPE criteria could not be parsed", None
    described = _describe_match(match, identity)
    if not comparable:
        return "not_decided", why, None
    wildcard_version = _wildcard(identity.version)
    if not wildcard_version:
        if _exact_version_match(identity, version):
            return (
                "affected",
                f"exact NVD CPE match {identity.base} {described}",
                _hint_for_match(match, identity),
            )
        return "not_affected", described, None
    if _range_match(match, version):
        return (
            "affected",
            f"inside NVD range {described} ({identity.base})",
            _hint_for_match(match, identity),
        )
    return "not_affected", described, None


def _names_match(wanted: CpeIdentity, asset_vendor: str, asset_product: str, rec_vendor: object, rec_product: object) -> bool:
    if not isinstance(rec_product, str) or not rec_product.strip():
        return False
    rec_p = tokens(rec_product)
    cpe_p = tokens(wanted.product.replace("_", " "))
    asset_p = tokens(asset_product)
    product_ok = rec_p == cpe_p or rec_p == asset_p
    if not product_ok and len(cpe_p) >= 2 and phrase_in(rec_p, cpe_p):
        product_ok = True
    if not product_ok and len(asset_p) >= 2 and phrase_in(rec_p, asset_p):
        product_ok = True
    if not product_ok:
        return False
    if not isinstance(rec_vendor, str) or not rec_vendor.strip():
        return True
    rec_v = tokens(rec_vendor)
    cpe_v = tokens(wanted.vendor)
    asset_v = tokens(asset_vendor)
    if cpe_v and (set(cpe_v) & set(rec_v) or phrase_in(rec_v, cpe_v)):
        return True
    if asset_v and set(asset_v) & set(rec_v):
        return True
    return False


def _cve5_block_matches(installed: str, block: dict) -> bool:
    start = str(block.get("version") or "")
    if start.lower() in {"n/a", "na", "unspecified", "-"}:
        return False
    end = block.get("lessThan")
    end_eq = block.get("lessThanOrEqual")
    if isinstance(end, str) and end == "*":
        end = None
    if start in {"*", ""} and not end and not end_eq:
        return True
    if start and start not in {"*"} and compare_versions(installed, start) < 0:
        return False
    if isinstance(end, str) and end and compare_versions(installed, end) >= 0:
        return False
    if isinstance(end_eq, str) and end_eq and compare_versions(installed, end_eq) > 0:
        return False
    if not end and not end_eq and start not in {"*", ""}:
        return compare_versions(installed, start) == 0
    return True


def _eval_cve5(record: Record, wanted: CpeIdentity, version: str, asset_vendor: str, asset_product: str) -> Observation:
    comparable, why = version_is_comparable(wanted.vendor, wanted.product, version)
    mentioned = False
    affected_hint = None
    affected = False
    undecided = False
    ranges: list[str] = []
    for item in record.cve5_affected:
        if not isinstance(item, dict):
            continue
        if not _names_match(wanted, asset_vendor, asset_product, item.get("vendor"), item.get("product")):
            continue
        mentioned = True
        default_status = str(item.get("defaultStatus") or "unknown").lower()
        hit_affected = False
        hit_unaffected = False
        for block in item.get("versions") or []:
            if not isinstance(block, dict):
                continue
            status = str(block.get("status") or "affected").lower()
            described = _describe_cve5(block)
            ranges.append(described)
            if not comparable:
                undecided = True
                continue
            if not _cve5_block_matches(version, block):
                continue
            if status == "unaffected":
                hit_unaffected = True
            elif status == "affected":
                hit_affected = True
                if isinstance(block.get("lessThan"), str) and block["lessThan"] not in {"*", ""}:
                    affected_hint = f"Update to {block['lessThan']} or later (CVE record lessThan)."
                elif isinstance(block.get("lessThanOrEqual"), str):
                    affected_hint = (
                        f"CVE record marks versions through {block['lessThanOrEqual']} as affected "
                        "(lessThanOrEqual)."
                    )
        if hit_affected and not hit_unaffected:
            affected = True
        elif not comparable:
            undecided = True
        elif default_status == "affected" and not hit_unaffected:
            affected = True
    if not mentioned:
        return Observation(record.cve_id, "not_affected", False, "product name is not in the CVE affected list", None, "cve5")
    if affected:
        return Observation(
            record.cve_id,
            "affected",
            True,
            "inside a CVE affected version block (" + "; ".join(dict.fromkeys(ranges)) + ")",
            affected_hint,
            "cve5",
        )
    if undecided:
        return Observation(record.cve_id, "not_decided", True, why or "version could not be compared", None, "cve5")
    return Observation(
        record.cve_id,
        "not_affected",
        True,
        f"{version} is outside the CVE affected ranges ({'; '.join(dict.fromkeys(ranges)) or 'defaultStatus unaffected'})",
        None,
        "cve5",
    )


def _describe_cve5(block: dict) -> str:
    start = block.get("version") or "*"
    if block.get("lessThan"):
        return f"{start} <= v < {block['lessThan']}"
    if block.get("lessThanOrEqual"):
        return f"{start} <= v <= {block['lessThanOrEqual']}"
    return f"exact {start}"


def evaluate(record: Record, cpe_base: str, version: str, asset_vendor: str, asset_product: str) -> Observation:
    wanted = parse_cpe(cpe_base)
    if record.configurations:
        return _eval_configs(record, wanted, version)
    if record.cve5_affected:
        return _eval_cve5(record, wanted, version, asset_vendor, asset_product)
    return Observation(record.cve_id, "not_decided", False, "no configuration or affected-version data", None, "none")


def windows_product(cpe_base: str) -> bool:
    identity = parse_cpe(cpe_base)
    return is_windows_product(identity.vendor, identity.product)
