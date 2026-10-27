import json
from pathlib import Path

from patchwindow.matching import evaluate
from patchwindow.records import from_cve5, from_nvd_cve, parse_vulnerability_lookup

ROOT = Path(__file__).resolve().parents[1] / "src" / "patchwindow" / "data" / "demo"


def _record(cve_id):
    payload = json.loads((ROOT / "nvd" / f"{cve_id}.json").read_text(encoding="utf-8"))
    return from_nvd_cve(payload["vulnerabilities"][0]["cve"])


def test_nginx_range_includes_1_25_2_and_stops_there():
    record = _record("CVE-2023-44487")
    affected = evaluate(record, "cpe:2.3:a:f5:nginx", "1.25.2", "F5", "nginx")
    assert affected.verdict == "affected"
    assert "1.25.2" in (affected.fixed_hint or "")
    assert "newer than 1.25.2" in (affected.fixed_hint or "")
    current = evaluate(record, "cpe:2.3:a:f5:nginx", "1.27.2", "F5", "nginx")
    assert current.verdict == "not_affected"
    ingress = evaluate(record, "cpe:2.3:a:f5:nginx_ingress_controller", "1.25.2", "F5", "nginx ingress")
    assert ingress.verdict == "not_affected"


def test_openssl_fixed_in_3_0_13_and_letter_suffix():
    record = _record("CVE-2024-0727")
    hit = evaluate(record, "cpe:2.3:a:openssl:openssl", "3.0.12", "OpenSSL", "OpenSSL")
    assert hit.verdict == "affected"
    assert "3.0.13" in (hit.fixed_hint or "")
    fixed = evaluate(record, "cpe:2.3:a:openssl:openssl", "3.0.13", "OpenSSL", "OpenSSL")
    assert fixed.verdict == "not_affected"
    assert evaluate(record, "cpe:2.3:a:openssl:openssl", "1.1.1w", "OpenSSL", "OpenSSL").verdict == "affected"
    assert evaluate(record, "cpe:2.3:a:openssl:openssl", "1.1.1x", "OpenSSL", "OpenSSL").verdict == "not_affected"
    assert evaluate(record, "cpe:2.3:a:openssl:openssl", "3.2.0", "OpenSSL", "OpenSSL").verdict == "affected"
    assert evaluate(record, "cpe:2.3:a:openssl:openssl", "3.2.1", "OpenSSL", "OpenSSL").verdict == "not_affected"
    assert evaluate(record, "cpe:2.3:a:openssl:openssl", "3.3.0", "OpenSSL", "OpenSSL").verdict == "not_affected"


def test_windows_build_boundaries():
    record = _record("CVE-2024-38063")
    old = evaluate(record, "cpe:2.3:o:microsoft:windows_server_2022", "10.0.20348.2400", "Microsoft", "Windows Server 2022")
    assert old.verdict == "affected"
    assert "10.0.20348.2655" in (old.fixed_hint or "")
    patched = evaluate(record, "cpe:2.3:o:microsoft:windows_server_2022", "10.0.20348.2655", "Microsoft", "Windows Server 2022")
    assert patched.verdict == "not_affected"
    laptop = evaluate(record, "cpe:2.3:o:microsoft:windows_11_23h2", "10.0.22631.3593", "Microsoft", "Windows 11 23H2")
    assert laptop.verdict == "affected"
    assert "10.0.22631.4037" in (laptop.fixed_hint or "")
    done = evaluate(record, "cpe:2.3:o:microsoft:windows_11_23h2", "10.0.22631.4037", "Microsoft", "Windows 11 23H2")
    assert done.verdict == "not_affected"
    # A Server 2022 build must not inherit the Windows 11 23H2 range.
    crossed = evaluate(record, "cpe:2.3:o:microsoft:windows_server_2022", "10.0.22631.3593", "Microsoft", "Windows Server 2022")
    assert crossed.verdict == "not_affected"
    named = evaluate(record, "cpe:2.3:o:microsoft:windows_server_2022", "2022", "Microsoft", "Windows Server 2022")
    assert named.verdict == "not_decided"
    assert "10.0.22631.4037" in named.reason


def test_openssh_range_and_portable_suffix():
    record = _record("CVE-2024-6387")
    assert evaluate(record, "cpe:2.3:a:openbsd:openssh", "9.6", "OpenBSD", "OpenSSH").verdict == "affected"
    assert evaluate(record, "cpe:2.3:a:openbsd:openssh", "9.8", "OpenBSD", "OpenSSH").verdict == "affected"
    assert evaluate(record, "cpe:2.3:a:openbsd:openssh", "9.8p1", "OpenBSD", "OpenSSH").verdict == "not_affected"
    assert evaluate(record, "cpe:2.3:a:openbsd:openssh", "9.9", "OpenBSD", "OpenSSH").verdict == "not_affected"
    assert evaluate(record, "cpe:2.3:a:openbsd:openssh", "8.5p1", "OpenBSD", "OpenSSH").verdict == "affected"
    assert evaluate(record, "cpe:2.3:a:openbsd:openssh", "4.3", "OpenBSD", "OpenSSH").verdict == "affected"
    assert evaluate(record, "cpe:2.3:a:openbsd:openssh", "4.4", "OpenBSD", "OpenSSH").verdict == "affected"


def test_cve5_record_from_vulnerability_lookup_shape():
    payload = json.loads((ROOT / "vl-cpesearch-openssl.json").read_text(encoding="utf-8"))
    records = parse_vulnerability_lookup(payload)
    assert len(records) == 1
    record = records[0]
    assert record.cve_id == "CVE-2024-0727"
    assert record.cvss == 5.5
    hit = evaluate(record, "cpe:2.3:a:openssl:openssl", "3.0.12", "OpenSSL", "OpenSSL")
    assert hit.verdict == "affected"
    assert hit.basis == "cve5"
    assert "3.0.13" in (hit.fixed_hint or "")
    assert evaluate(record, "cpe:2.3:a:openssl:openssl", "3.0.13", "OpenSSL", "OpenSSL").verdict == "not_affected"


def test_configurations_win_over_a_contradicting_cve5_block():
    record = _record("CVE-2024-0727")
    record.cve5_affected = [
        {
            "vendor": "OpenSSL",
            "product": "OpenSSL",
            "defaultStatus": "affected",
            "versions": [{"version": "0", "lessThan": "99", "status": "affected"}],
        }
    ]
    # 3.0.13 is outside the NVD configuration, so the loose CVE5 block must not override it.
    assert evaluate(record, "cpe:2.3:a:openssl:openssl", "3.0.13", "OpenSSL", "OpenSSL").verdict == "not_affected"


def test_rejected_records_are_dropped():
    assert from_nvd_cve({"id": "CVE-2020-0000", "vulnStatus": "Rejected", "descriptions": []}) is None
    assert from_cve5({"cveMetadata": {"cveId": "CVE-2020-0000", "state": "REJECTED"}, "containers": {}}) is None


def test_and_configuration_with_another_product_is_not_decided():
    record = from_nvd_cve(
        {
            "id": "CVE-2024-0001",
            "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "Example."}],
            "metrics": {},
            "configurations": [
                {
                    "operator": "AND",
                    "nodes": [
                        {
                            "operator": "OR",
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                                    "versionEndExcluding": "2.4.62",
                                }
                            ],
                        },
                        {
                            "operator": "OR",
                            "cpeMatch": [
                                {
                                    "vulnerable": False,
                                    "criteria": "cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*",
                                }
                            ],
                        },
                    ],
                }
            ],
        }
    )
    observation = evaluate(record, "cpe:2.3:a:apache:http_server", "2.4.58", "Apache", "HTTP Server")
    assert observation.verdict == "not_decided"
    assert "another product" in observation.reason
