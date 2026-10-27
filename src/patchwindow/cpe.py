"""Parse CPE 2.3 and CPE 2.2 names. Inventory locks store the vendor and product only."""

from __future__ import annotations

import re

from patchwindow.errors import PatchwindowError

_BASE = re.compile(r"^cpe:2\.3:([aho]):([^:]+):([^:]+)$", re.IGNORECASE)


class CpeIdentity:
    def __init__(self, part: str, vendor: str, product: str, version: str = "*", update: str = "*") -> None:
        self.part = part.lower()
        self.vendor = vendor.lower()
        self.product = product.lower()
        self.version = version
        self.update = update

    @property
    def base(self) -> str:
        return f"cpe:2.3:{self.part}:{self.vendor}:{self.product}"

    def same_product(self, other: CpeIdentity) -> bool:
        return self.part == other.part and self.vendor == other.vendor and self.product == other.product


def _split_cpe23(value: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value):
            buf.append(value[index + 1])
            index += 2
            continue
        if char == ":":
            parts.append("".join(buf))
            buf = []
            index += 1
            continue
        buf.append(char)
        index += 1
    parts.append("".join(buf))
    return parts


def parse_cpe(value: str) -> CpeIdentity:
    text = value.strip()
    if text.lower().startswith("cpe:/"):
        bits = text[5:].split(":")
        if len(bits) < 3 or bits[0].lower() not in {"a", "o", "h"}:
            raise PatchwindowError(f"not a CPE name: {value}")
        version = bits[3] if len(bits) > 3 and bits[3] else "*"
        return CpeIdentity(bits[0], bits[1] or "*", bits[2] or "*", version, "*")
    if text.lower().startswith("cpe:2.3:"):
        bits = _split_cpe23(text)
        # cpe, 2.3, part, vendor, product, version, update, ...
        if len(bits) < 5 or bits[2].lower() not in {"a", "o", "h"}:
            raise PatchwindowError(f"not a CPE 2.3 name: {value}")
        version = bits[5] if len(bits) > 5 and bits[5] else "*"
        update = bits[6] if len(bits) > 6 and bits[6] else "*"
        return CpeIdentity(bits[2], bits[3], bits[4], version, update)
    raise PatchwindowError(f"not a CPE name: {value}")


def canonical_base(value: str) -> str:
    return parse_cpe(value).base


def with_version(base: str, version: str) -> str:
    """CPE name NVD's cpeName parameter can match. Wildcards the update field.

    OpenSSH 9.8p1 is queried as version 9.8. The local matcher still applies the
    p-suffix, so a hit can be dropped and a miss is not invented.
    """
    from patchwindow.versions import split_portable_update

    identity = parse_cpe(base)
    numeric, update = split_portable_update(version)
    queried = numeric if update else version.strip()
    if re.search(r"[\s:]", queried) or not queried:
        raise PatchwindowError(f"cannot put version {version!r} into a CPE name")
    return f"cpe:2.3:{identity.part}:{identity.vendor}:{identity.product}:{queried}:*:*:*:*:*:*:*"
