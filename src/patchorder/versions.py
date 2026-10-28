"""Version comparison for NVD ranges, CVE version blocks, and vendor build strings.

Windows builds are compared as dotted integers (10.0.22631.4037). An OpenSSH
portable suffix such as 9.8p1 sorts after 9.8. An OpenSSL letter suffix such as
1.1.1w sorts after 1.1.1 and before 1.1.1x. Missing trailing numeric components
compare as zero, so 1.25 and 1.25.0 are equal.
"""

from __future__ import annotations

import re

_TOKEN = re.compile(r"\d+|[A-Za-z]+")
_LEADING_V = re.compile(r"^[vV](?=\d)")
_PORTABLE = re.compile(r"^(.+?)p(\d+)$")
_WINDOWS_BUILD = re.compile(r"^(?:10|6)\.\d+\.\d+(?:\.\d+)?$")

# A Windows product whose NVD ranges are build numbers, not marketing names.
_WINDOWS_PRODUCT = re.compile(r"^windows_")


def version_key(value: str) -> tuple[tuple[int, int | str], ...]:
    text = _LEADING_V.sub("", value.strip())
    parts: list[tuple[int, int | str]] = []
    for token in _TOKEN.findall(text):
        if token.isdigit():
            parts.append((0, int(token)))
        else:
            parts.append((1, token.lower()))
    return tuple(parts)


def compare_versions(left: str, right: str) -> int:
    """Return -1, 0, or 1, like a three-way comparison of version strings."""
    a = version_key(left)
    b = version_key(right)
    pad: tuple[int, int | str] = (0, 0)
    for index in range(max(len(a), len(b))):
        av = a[index] if index < len(a) else pad
        bv = b[index] if index < len(b) else pad
        if av < bv:
            return -1
        if av > bv:
            return 1
    return 0


def split_portable_update(version: str) -> tuple[str, str | None]:
    """Split an OpenSSH-style 9.8p1 into ('9.8', 'p1'). Leave 1.1.1w intact."""
    text = version.strip()
    match = _PORTABLE.fullmatch(text)
    if match and re.search(r"\d", match.group(1)):
        return match.group(1), "p" + match.group(2)
    return text, None


def is_windows_product(vendor: str, product: str) -> bool:
    return vendor == "microsoft" and bool(_WINDOWS_PRODUCT.match(product))


def windows_build_comparable(version: str) -> bool:
    return bool(_WINDOWS_BUILD.fullmatch(version.strip()))


def version_is_comparable(vendor: str, product: str, version: str) -> tuple[bool, str]:
    """Say whether `version` can be compared with ranges for this CPE product.

    Marketing names such as "2022" must not be compared with 10.0.20348.2655.
    That comparison is numerically true and operationally wrong.
    """
    text = version.strip()
    if not text or text.lower() in {"latest", "stable", "n/a", "na", "unknown", "none", "*"}:
        return False, f"version {text!r} is not a concrete release"
    if is_windows_product(vendor, product) and not windows_build_comparable(text):
        return (
            False,
            f"version {text!r} is not a Windows build "
            "(expected 10.0.<build>.<ubr>, for example 10.0.22631.4037)",
        )
    if not version_key(text):
        return False, f"version {text!r} has no comparable components"
    return True, ""


def in_bounds(
    installed: str,
    start: str | None,
    start_including: bool,
    end: str | None,
    end_including: bool,
) -> bool:
    if start:
        order = compare_versions(installed, start)
        if start_including and order < 0:
            return False
        if not start_including and order <= 0:
            return False
    if end:
        order = compare_versions(installed, end)
        if end_including and order > 0:
            return False
        if not end_including and order >= 0:
            return False
    return True
