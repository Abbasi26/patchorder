"""Starter alias table. This is not a CPE dictionary.

High confidence means "the product phrase and the vendor agree with a CPE we
have seen in NVD configurations". It is still a guess until someone pins it.
"""

from __future__ import annotations

from dataclasses import dataclass

from patchwindow.models import Asset, Candidate
from patchwindow.normalize import normalize, tokens


@dataclass(frozen=True)
class Alias:
    phrases: tuple[str, ...]
    vendor_hints: tuple[str, ...]
    part: str
    vendor: str
    product: str
    note: str
    base_confidence: float = 0.93


def _cpe(alias: Alias) -> str:
    return f"cpe:2.3:{alias.part}:{alias.vendor}:{alias.product}"


ALIASES: tuple[Alias, ...] = (
    Alias(
        ("nginx", "nginx open source"),
        ("f5", "nginx", "igor"),
        "a",
        "f5",
        "nginx",
        "NVD configurations for NGINX Open Source use f5:nginx (CVE-2023-44487 does).",
    ),
    Alias(
        ("nginx plus",),
        ("f5",),
        "a",
        "f5",
        "nginx_plus",
        "NGINX Plus is a different CPE from NGINX Open Source.",
        0.93,
    ),
    Alias(("openssl",), ("openssl",), "a", "openssl", "openssl", "OpenSSL upstream CPE."),
    Alias(
        ("apache http server", "http server", "httpd"),
        ("apache",),
        "a",
        "apache",
        "http_server",
        "Apache HTTP Server, not Tomcat and not nginx.",
    ),
    Alias(("apache tomcat", "tomcat"), ("apache",), "a", "apache", "tomcat", "Apache Tomcat."),
    Alias(("openssh", "sshd"), ("openbsd", "openssh"), "a", "openbsd", "openssh", "OpenSSH from OpenBSD."),
    Alias(("php",), ("php",), "a", "php", "php", "PHP."),
    Alias(("curl",), ("haxx", "curl"), "a", "haxx", "curl", "The CPE vendor for curl is haxx."),
    Alias(("postgresql", "postgres"), ("postgresql",), "a", "postgresql", "postgresql", "PostgreSQL."),
    Alias(("mysql",), ("oracle", "mysql"), "a", "oracle", "mysql", "Oracle MySQL. MariaDB is a different CPE."),
    Alias(("mariadb",), ("mariadb",), "a", "mariadb", "mariadb", "MariaDB."),
    Alias(("windows server 2025",), ("microsoft",), "o", "microsoft", "windows_server_2025", "Windows Server 2025."),
    Alias(
        ("windows server 2022 23h2",),
        ("microsoft",),
        "o",
        "microsoft",
        "windows_server_2022_23h2",
        "Windows Server 2022 23H2 (build family 25398), not the original Server 2022 release.",
    ),
    Alias(
        ("windows server 2022", "server 2022"),
        ("microsoft",),
        "o",
        "microsoft",
        "windows_server_2022",
        "Windows Server 2022 (build family 20348).",
    ),
    Alias(("windows server 2019",), ("microsoft",), "o", "microsoft", "windows_server_2019", "Windows Server 2019."),
    Alias(("windows server 2016",), ("microsoft",), "o", "microsoft", "windows_server_2016", "Windows Server 2016."),
    Alias(("windows 11 24h2",), ("microsoft",), "o", "microsoft", "windows_11_24h2", "Windows 11 24H2 (build family 26100)."),
    Alias(("windows 11 23h2",), ("microsoft",), "o", "microsoft", "windows_11_23h2", "Windows 11 23H2 (build family 22631)."),
    Alias(("windows 11 22h2",), ("microsoft",), "o", "microsoft", "windows_11_22h2", "Windows 11 22H2 (build family 22621)."),
    Alias(("windows 11 21h2",), ("microsoft",), "o", "microsoft", "windows_11_21h2", "Windows 11 21H2 (build family 22000)."),
    Alias(("windows 10 22h2",), ("microsoft",), "o", "microsoft", "windows_10_22h2", "Windows 10 22H2 (build family 19045)."),
    Alias(("windows 10 21h2",), ("microsoft",), "o", "microsoft", "windows_10_21h2", "Windows 10 21H2 (build family 19044)."),
    Alias(("windows 10 1809",), ("microsoft",), "o", "microsoft", "windows_10_1809", "Windows 10 1809 (build family 17763)."),
    Alias(("windows 10 1607",), ("microsoft",), "o", "microsoft", "windows_10_1607", "Windows 10 1607 (build family 14393)."),
    Alias(("windows 10 1507",), ("microsoft",), "o", "microsoft", "windows_10_1507", "Windows 10 1507 (build family 10240)."),
)

# When the primary alias hits, also show this other dictionary name, lower.
ALTERNATES: dict[str, tuple[str, float, str]] = {
    "cpe:2.3:a:f5:nginx": (
        "cpe:2.3:a:nginx:nginx",
        0.25,
        "Older CPE dictionary name nginx:nginx. Prefer f5:nginx when the NVD configuration uses it.",
    )
}

# Third component of 10.0.<build>.<ubr>. 26100 is both Windows 11 24H2 and Server 2025.
BUILD_FAMILY: dict[int, tuple[tuple[str, str], ...]] = {
    10240: (("windows_10_1507", "Windows 10 1507"),),
    14393: (("windows_10_1607", "Windows 10 1607"),),
    17763: (("windows_10_1809", "Windows 10 1809 or Windows Server 2019"),),
    19044: (("windows_10_21h2", "Windows 10 21H2"),),
    19045: (("windows_10_22h2", "Windows 10 22H2"),),
    20348: (("windows_server_2022", "Windows Server 2022"),),
    22000: (("windows_11_21h2", "Windows 11 21H2"),),
    22621: (("windows_11_22h2", "Windows 11 22H2"),),
    22631: (("windows_11_23h2", "Windows 11 23H2"),),
    25398: (("windows_server_2022_23h2", "Windows Server 2022 23H2"),),
    26100: (
        ("windows_11_24h2", "Windows 11 24H2"),
        ("windows_server_2025", "Windows Server 2025"),
    ),
}


def _phrase_tokens(phrase: str) -> list[str]:
    return tokens(phrase)


def matching_aliases(product: str) -> list[Alias]:
    product_tokens = tokens(product)
    hits: list[tuple[int, Alias]] = []
    for alias in ALIASES:
        best = 0
        for phrase in alias.phrases:
            phrase_tokens = _phrase_tokens(phrase)
            width = len(phrase_tokens)
            if width == 0 or width > len(product_tokens):
                continue
            for index in range(len(product_tokens) - width + 1):
                if product_tokens[index : index + width] == phrase_tokens:
                    best = max(best, len(normalize(phrase)))
        if best:
            hits.append((best, alias))
    if not hits:
        return []
    longest = max(item[0] for item in hits)
    # Unique aliases at the winning phrase length, stable order.
    seen: set[str] = set()
    chosen: list[Alias] = []
    for length, alias in hits:
        if length != longest:
            continue
        key = _cpe(alias)
        if key in seen:
            continue
        seen.add(key)
        chosen.append(alias)
    return chosen


def alias_candidates(asset: Asset) -> list[Candidate]:
    found = matching_aliases(asset.product)
    vendor_tokens = set(tokens(asset.vendor))
    candidates: list[Candidate] = []
    for alias in found:
        hints = set(alias.vendor_hints)
        if not asset.vendor.strip():
            confidence = round(alias.base_confidence - 0.15, 2)
            relation = "product phrase matched; vendor is empty, so this stays below the auto-use line"
        elif vendor_tokens & hints or normalize(asset.vendor) in hints:
            confidence = alias.base_confidence
            relation = "product phrase and vendor match this CPE"
        else:
            confidence = round(alias.base_confidence - 0.45, 2)
            relation = "product phrase matched, but the vendor does not match the CPE vendor"
        note = f"{alias.note} {relation}".strip()
        cpe = _cpe(alias)
        candidates.append(Candidate(cpe=cpe, confidence=confidence, origin="alias", note=note))
        alternate = ALTERNATES.get(cpe)
        if alternate and confidence >= 0.5:
            alt_cpe, penalty, alt_note = alternate
            candidates.append(
                Candidate(
                    cpe=alt_cpe,
                    confidence=round(max(0.3, confidence - penalty), 2),
                    origin="alias",
                    note=alt_note,
                )
            )
    return candidates
