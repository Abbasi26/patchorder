from dataclasses import replace

from patchorder.engine import run_demo
from patchorder.llm import cve_texts


def test_cve_texts_selects_twenty_unique_cves_by_priority():
    template = run_demo().findings[0]
    findings = [
        replace(
            template,
            asset_id=f"asset-{index}",
            cve_id=f"CVE-2099-{index:04d}",
            description=f"Description {index}",
            points=float(index),
        )
        for index in range(22)
    ]
    findings.append(
        replace(
            findings[-1],
            asset_id="another-asset",
            description="Highest-priority description",
            points=100.0,
        )
    )
    original = [replace(finding) for finding in findings]

    texts = cve_texts(findings)

    assert texts == [
        ("CVE-2099-0021", "Highest-priority description"),
        *[
            (f"CVE-2099-{index:04d}", f"Description {index}")
            for index in range(20, 1, -1)
        ],
    ]
    assert findings == original


# Skipped production changes and additional options; this is test hardening only.
# Tests were not run successfully: the read-only environment has no writable temporary directory.
