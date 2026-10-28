import json
from pathlib import Path

import pytest

from patchorder.csaf import hits_for, load_csaf_document, load_csaf_path
from patchorder.errors import PatchorderError
from patchorder.inventory import load_inventory
from patchorder.llm import build_messages, cve_texts
from patchorder.records import parse_kev, parse_nvd_cpe_hits
from patchorder.report import Finding

ROOT = Path(__file__).resolve().parents[1] / "src" / "patchorder" / "data" / "demo"


def test_float_versions_are_rejected(tmp_path):
    path = tmp_path / "inventory.yaml"
    path.write_text(
        "assets:\n  - product: nginx\n    vendor: F5\n    version: 1.10\n    count: 1\n"
        "    owner: ops\n    exposure: internet\n",
        encoding="utf-8",
    )
    with pytest.raises(PatchorderError, match="1.1"):
        load_inventory(path)


def test_exposure_must_be_internet_or_internal(tmp_path):
    path = tmp_path / "inventory.yaml"
    path.write_text(
        "assets:\n  - product: nginx\n    vendor: F5\n    version: \"1.25.2\"\n    count: 1\n"
        "    owner: ops\n    exposure: dmz\n",
        encoding="utf-8",
    )
    with pytest.raises(PatchorderError, match="exposure"):
        load_inventory(path)


def test_demo_csaf_shapes():
    advisories = load_csaf_path(ROOT / "csaf")
    by_id = {item.tracking_id: item for item in advisories}
    example = by_id["EXAMPLE-SA-2024-0099"]
    assert example.official is False
    assert example.publisher == "Example CERT"
    assert "EXAMPLE-PHP" in example.products
    assert any(vuln.cve_id.startswith("CVE-") for vuln in example.vulns)
    fixture = by_id["FIXTURE-SA-2024-0001"]
    assert fixture.official is False
    hits = hits_for(advisories, "CVE-2024-0727", "cpe:2.3:a:openssl:openssl", "3.0.12", "OpenSSL")
    assert len(hits) == 1
    assert hits[0].known_affected
    assert hits[0].version_specific
    assert "3.0.13" in hits[0].remediation
    # The example advisory names PHP without a version, and must not attach to OpenSSL.
    assert hits_for(advisories, "CVE-2099-0001", "cpe:2.3:a:openssl:openssl", "3.0.12", "OpenSSL") == []
    php = hits_for(advisories, "CVE-2099-0001", "cpe:2.3:a:php:php", "8.3.0", "PHP")
    assert php and php[0].version_specific is False
    assert php[0].known_affected is False


def test_provider_metadata_and_kev_subset_and_cpe_dictionary():
    meta = json.loads((ROOT / "csaf" / "provider-metadata.json").read_text(encoding="utf-8"))
    assert meta["role"] == "csaf_trusted_provider"
    assert meta["publisher"]["name"] == "Example CERT"
    assert meta["canonical_url"].startswith("https://example.org/")
    kev = parse_kev(json.loads((ROOT / "kev.json").read_text(encoding="utf-8")))
    assert "CVE-2023-44487" in kev.entries
    assert kev.published_count == 1754
    assert len(kev.entries) == 1
    assert "subset" in kev.note or "published catalog count" in kev.note
    hits = parse_nvd_cpe_hits(json.loads((ROOT / "nvd-cpes-nginx.json").read_text(encoding="utf-8")))
    assert any(item["cpe"].startswith("cpe:2.3:a:f5:nginx:") and not item["deprecated"] for item in hits)
    assert any(item["deprecated"] for item in hits)


def test_llm_builder_cannot_see_inventory_fields():
    finding = Finding(
        asset_id="SENTINEL-ASSET",
        product="SENTINEL-PRODUCT",
        vendor="SENTINEL-VENDOR",
        version="SENTINEL-VERSION",
        count=99,
        owner="SENTINEL-OWNER",
        exposure="internet",
        cpe="cpe:2.3:a:f5:nginx",
        cpe_confirmed=True,
        cve_id="CVE-2024-0001",
        description="A parser crash in a public component.",
        cvss=9.0,
        severity="CRITICAL",
        vector=None,
        epss=0.5,
        epss_percentile=None,
        epss_date=None,
        kev=True,
        kev_name="name",
        kev_date="2024-01-01",
        ransomware=None,
        points=10,
        parts=[],
        reason="range",
        fixed_hint="Update to 1.2.3",
        links=[],
        csaf=[],
        published=None,
        basis="nvd",
    )
    messages = build_messages(cve_texts([finding]))
    blob = json.dumps(messages)
    assert "CVE-2024-0001" in blob
    assert "parser crash" in blob
    for secret in ("SENTINEL-ASSET", "SENTINEL-PRODUCT", "SENTINEL-OWNER", "SENTINEL-VERSION", "1.2.3"):
        assert secret not in blob


def test_single_csaf_file(tmp_path):
    target = tmp_path / "one.json"
    target.write_text((ROOT / "csaf" / "fixture-openssl.json").read_text(encoding="utf-8"), encoding="utf-8")
    loaded = load_csaf_document(target)
    assert loaded.tracking_id == "FIXTURE-SA-2024-0001"
