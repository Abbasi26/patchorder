"""Read CSAF 2.0 documents, including the CERT-Bund shape.

A product id counts as a version-specific hit only when the document names a
version (a product_version branch or a versioned CPE). CERT-Bund often names
the product and not the version. That is a mention, not proof the installed
build is affected, and it does not add priority points.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from patchwindow.cpe import parse_cpe
from patchwindow.errors import PatchwindowError
from patchwindow.normalize import phrase_in, tokens
from patchwindow.versions import compare_versions


@dataclass
class CsafProduct:
    product_id: str
    name: str
    cpe: str | None
    version: str | None


@dataclass
class CsafVuln:
    cve_id: str
    known_affected: list[str]
    fixed: list[str]
    remediations: list[str]


@dataclass
class CsafAdvisory:
    tracking_id: str
    title: str
    publisher: str
    url: str | None
    official: bool
    products: dict[str, CsafProduct] = field(default_factory=dict)
    vulns: list[CsafVuln] = field(default_factory=list)
    path: str = ""


@dataclass
class CsafHit:
    advisory_id: str
    title: str
    url: str | None
    official: bool
    version_specific: bool
    known_affected: bool
    fixed: bool
    remediation: str | None


def _walk(branch: dict, products: dict[str, CsafProduct], version: str | None) -> None:
    if not isinstance(branch, dict):
        return
    if branch.get("category") == "product_version" and isinstance(branch.get("name"), str):
        version = branch["name"]
    product = branch.get("product")
    if isinstance(product, dict) and isinstance(product.get("product_id"), str):
        helper = product.get("product_identification_helper") or {}
        cpe = helper.get("cpe") if isinstance(helper, dict) else None
        if not isinstance(cpe, str):
            cpe = None
        product_version = version
        if cpe:
            try:
                parsed = parse_cpe(cpe)
            except PatchwindowError:
                parsed = None
            if parsed and parsed.version not in {"*", "-", ""}:
                product_version = parsed.version
        products[product["product_id"]] = CsafProduct(
            product_id=product["product_id"],
            name=str(product.get("name") or ""),
            cpe=cpe,
            version=product_version,
        )
    for child in branch.get("branches") or []:
        _walk(child, products, version)


def load_csaf_document(path: Path) -> CsafAdvisory:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PatchwindowError(f"cannot read CSAF {path}: {exc}") from exc
    if not isinstance(data, dict) or "document" not in data:
        raise PatchwindowError(f"{path} is not a CSAF document")
    document = data.get("document") or {}
    tracking = document.get("tracking") or {}
    publisher = document.get("publisher") or {}
    publisher_name = str(publisher.get("name") or "")
    namespace = str(publisher.get("namespace") or "")
    official = "bsi.bund.de" in namespace or "cert-bund" in publisher_name.lower() or "bsi" in publisher_name.lower()
    url = None
    for ref in document.get("references") or []:
        if isinstance(ref, dict) and ref.get("category") == "self" and isinstance(ref.get("url"), str):
            url = ref["url"]
            break
    products: dict[str, CsafProduct] = {}
    tree = data.get("product_tree") or {}
    for branch in tree.get("branches") or []:
        _walk(branch, products, None)
    vulns: list[CsafVuln] = []
    for item in data.get("vulnerabilities") or []:
        if not isinstance(item, dict):
            continue
        cve_id = item.get("cve")
        if not isinstance(cve_id, str):
            continue
        status = item.get("product_status") or {}
        remediations: list[str] = []
        for rem in item.get("remediations") or []:
            if isinstance(rem, dict) and rem.get("category") == "vendor_fix" and isinstance(rem.get("details"), str):
                remediations.append(rem["details"].strip())
        vulns.append(
            CsafVuln(
                cve_id=cve_id,
                known_affected=[str(x) for x in status.get("known_affected") or []],
                fixed=[str(x) for x in (status.get("fixed") or [])],
                remediations=remediations,
            )
        )
    return CsafAdvisory(
        tracking_id=str(tracking.get("id") or path.stem),
        title=str(document.get("title") or path.stem),
        publisher=publisher_name,
        url=url,
        official=official,
        products=products,
        vulns=vulns,
        path=str(path),
    )


def load_csaf_path(path: Path) -> list[CsafAdvisory]:
    if path.is_file():
        return [load_csaf_document(path)]
    if not path.is_dir():
        raise PatchwindowError(f"CSAF path not found: {path}")
    found: list[CsafAdvisory] = []
    for item in sorted(path.glob("*.json")):
        if item.name == "provider-metadata.json":
            continue
        found.append(load_csaf_document(item))
    return found


def _product_applies(product: CsafProduct, cpe_base: str, version: str, asset_product: str) -> tuple[bool, bool]:
    """Return (applies, version_specific)."""
    wanted = parse_cpe(cpe_base)
    if product.cpe:
        try:
            parsed = parse_cpe(product.cpe)
        except PatchwindowError:
            parsed = None
        if parsed and parsed.same_product(wanted):
            if parsed.version in {"*", "-", ""} and not product.version:
                return True, False
            if parsed.version not in {"*", "-", ""}:
                return compare_versions(version, parsed.version) == 0, True
            if product.version:
                return compare_versions(version, product.version) == 0, True
            return True, False
    product_tokens = tokens(product.name)
    asset_tokens = tokens(asset_product)
    cpe_tokens = tokens(wanted.product.replace("_", " "))
    name_ok = product_tokens == asset_tokens or product_tokens == cpe_tokens
    if not name_ok and asset_tokens and phrase_in(product_tokens, asset_tokens):
        name_ok = True
    if not name_ok:
        return False, False
    if product.version:
        return compare_versions(version, product.version) == 0, True
    return True, False


def hits_for(
    advisories: list[CsafAdvisory],
    cve_id: str,
    cpe_base: str,
    version: str,
    asset_product: str,
) -> list[CsafHit]:
    found: list[CsafHit] = []
    for advisory in advisories:
        for vuln in advisory.vulns:
            if vuln.cve_id != cve_id:
                continue
            version_specific_affected = False
            version_specific_fixed = False
            product_mention = False
            for product_id in vuln.known_affected:
                product = advisory.products.get(product_id)
                if product is None:
                    continue
                applies, specific = _product_applies(product, cpe_base, version, asset_product)
                if not applies:
                    continue
                if specific:
                    version_specific_affected = True
                else:
                    product_mention = True
            for product_id in vuln.fixed:
                product = advisory.products.get(product_id)
                if product is None:
                    continue
                applies, specific = _product_applies(product, cpe_base, version, asset_product)
                if applies and specific:
                    version_specific_fixed = True
            if not (version_specific_affected or version_specific_fixed or product_mention):
                continue
            remediation = vuln.remediations[0] if vuln.remediations else None
            found.append(
                CsafHit(
                    advisory_id=advisory.tracking_id,
                    title=advisory.title,
                    url=advisory.url,
                    official=advisory.official,
                    version_specific=version_specific_affected or version_specific_fixed,
                    known_affected=version_specific_affected and not version_specific_fixed,
                    fixed=version_specific_fixed and not version_specific_affected,
                    remediation=remediation,
                )
            )
    return found
