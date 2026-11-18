"""CVE-2026-114938 (Java4Shell) uses official NVD/CNA data only.

NVD had no CPE configurations when the demo fixture was recorded
(vulnStatus Received, 2026-11-18). The matcher therefore uses the exact
supported versions in the Oracle CNA affected list, and must not invent a
broader range.
"""

from __future__ import annotations

import json
from pathlib import Path

from patchorder.matching import evaluate
from patchorder.records import from_cve5, from_nvd_cve

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "src" / "patchorder" / "data" / "demo" / "nvd" / "CVE-2026-114938.json"
CPE = "cpe:2.3:a:oracle:jdk"


def _demo_record():
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    record = from_nvd_cve(payload["vulnerabilities"][0]["cve"])
    assert record is not None
    return record


def test_nvd_fixture_is_the_official_record_without_invented_configurations():
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    cve = payload["vulnerabilities"][0]["cve"]
    assert cve["id"] == "CVE-2026-114938"
    assert cve["vulnStatus"] == "Received"
    assert cve["sourceIdentifier"] == "secalert_us@oracle.com"
    assert "configurations" not in cve
    record = _demo_record()
    assert record.configurations == []
    assert record.cvss == 8.1
    assert record.severity == "HIGH"
    assert record.vector == "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
    products = {item["product"] for item in record.cve5_affected}
    assert products == {
        "Oracle Java SE",
        "Oracle GraalVM for JDK",
        "Oracle GraalVM Enterprise Edition",
    }
    java_se = next(item for item in record.cve5_affected if item["product"] == "Oracle Java SE")
    assert [entry["version"] for entry in java_se["versions"]] == [
        "8u511b33-perf",
        "17.0.21.0.3",
        "21.0.13.0.3",
        "25.0.5.0.3",
        "27.0.1.0.3",
    ]


def test_official_supported_versions_match_exactly():
    record = _demo_record()
    java = ("Oracle", "Oracle Java SE")
    for version in ("8u511b33-perf", "17.0.21.0.3", "21.0.13.0.3", "25.0.5.0.3", "27.0.1.0.3"):
        hit = evaluate(record, CPE, version, *java)
        assert hit.verdict == "affected", version
        assert hit.basis == "cve5"
        assert hit.fixed_hint is None
    graal = evaluate(record, "cpe:2.3:a:oracle:graalvm_for_jdk", "17.0.21.0.3", "Oracle", "Oracle GraalVM for JDK")
    assert graal.verdict == "affected"
    graal_ee = evaluate(
        record,
        "cpe:2.3:a:oracle:graalvm",
        "21.3.20.0.3",
        "Oracle",
        "Oracle GraalVM Enterprise Edition",
    )
    assert graal_ee.verdict == "affected"


def test_fixed_and_unlisted_java_versions_are_outside_the_cna_list():
    record = _demo_record()
    java = ("Oracle", "Oracle Java SE")
    # Official Oracle fixed builds for this CSPU are not in the affected list.
    for version in ("17.0.21.1", "21.0.13.1", "25.0.5.1", "27.0.1.1", "8u513-perf"):
        miss = evaluate(record, CPE, version, *java)
        assert miss.verdict == "not_affected", version
        assert miss.product_mentioned is True
    # Standard Java 8 / 11 are not in this CVE's CNA list or the OpenJDK matrix.
    assert evaluate(record, CPE, "8u511b33", *java).verdict == "not_affected"
    assert evaluate(record, CPE, "11.0.33.0.3", *java).verdict == "not_affected"
    # Red Hat describes 17.0.6 and later as affected, but that range is not in
    # the official structured record, so the matcher must not invent it.
    earlier = evaluate(record, CPE, "17.0.6", *java)
    assert earlier.verdict == "not_affected"
    assert earlier.reason.startswith("17.0.6 is outside the CVE affected ranges")


def test_other_products_are_not_mentioned():
    record = _demo_record()
    miss = evaluate(record, "cpe:2.3:a:f5:nginx", "1.25.2", "F5", "nginx")
    assert miss.verdict == "not_affected"
    assert miss.product_mentioned is False


def test_nvd_affecteddata_wrapper_is_read_and_configurations_still_win():
    record = from_nvd_cve(
        {
            "id": "CVE-2026-0001",
            "vulnStatus": "Received",
            "descriptions": [{"lang": "en", "value": "Example."}],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseScore": 8.1,
                            "baseSeverity": "HIGH",
                        }
                    }
                ]
            },
            "affected": [
                {
                    "source": "secalert_us@oracle.com",
                    "affectedData": [
                        {
                            "vendor": "Example Corp",
                            "product": "Example Server",
                            "versions": [{"version": "1.0.0", "status": "affected"}],
                        }
                    ],
                }
            ],
        }
    )
    assert record is not None
    assert record.configurations == []
    assert record.cve5_affected[0]["product"] == "Example Server"
    hit = evaluate(record, "cpe:2.3:a:example:server", "1.0.0", "Example Corp", "Example Server")
    assert hit.verdict == "affected"
    assert hit.basis == "cve5"

    record.configurations = [
        {
            "nodes": [
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:example:server:*:*:*:*:*:*:*:*",
                            "versionEndExcluding": "1.0.0",
                        }
                    ],
                }
            ]
        }
    ]
    # 1.0.0 is in the CNA list but outside the NVD range; configurations win.
    overridden = evaluate(record, "cpe:2.3:a:example:server", "1.0.0", "Example Corp", "Example Server")
    assert overridden.verdict == "not_affected"
    assert overridden.basis == "nvd"


def test_cve_org_document_agrees_with_the_nvd_affected_list():
    # Same official versions, different envelope (CVE List 5 / CVE.org).
    document = {
        "cveMetadata": {"cveId": "CVE-2026-114938", "state": "PUBLISHED"},
        "containers": {
            "cna": {
                "affected": [
                    {
                        "vendor": "Oracle Corporation",
                        "product": "Oracle Java SE",
                        "versions": [{"version": "17.0.21.0.3", "status": "affected"}],
                    }
                ],
                "metrics": [
                    {
                        "cvssV3_1": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseScore": 8.1,
                            "baseSeverity": "HIGH",
                        }
                    }
                ],
                "descriptions": [{"lang": "en", "value": "Compiler vulnerability."}],
            }
        },
    }
    record = from_cve5(document)
    assert record is not None
    assert record.cvss == 8.1
    assert evaluate(record, CPE, "17.0.21.0.3", "Oracle", "Oracle Java SE").verdict == "affected"
    assert evaluate(record, CPE, "17.0.21.1", "Oracle", "Oracle Java SE").verdict == "not_affected"
