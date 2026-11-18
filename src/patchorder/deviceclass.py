"""Windows client vs Windows Server as inventory device classes.

The class is optional. When it is set, CPE resolution can tell editions
apart that share a build family (for example 26100 is both Windows 11 24H2
and Windows Server 2025). When it is omitted, a product name that already
says "Windows Server" is treated as a server; a bare "Windows" stays
ambiguous.

Microsoft Intune can manage eligible Windows Server devices only as an
Insider preview (nonproduction, Windows Server vNext build 29621.1000 or
later, Desktop Experience). See:

- https://learn.microsoft.com/en-us/intune/whats-new/
- https://learn.microsoft.com/en-us/intune/solutions/end-to-end-guides/windows-server-endpoints-get-started
"""

from __future__ import annotations

from patchorder.models import Asset
from patchorder.normalize import tokens

WINDOWS = "windows"
WINDOWS_SERVER = "windows-server"

# Minimum build documented for the Intune Windows Server Insider preview.
# The official name is Windows Server vNext; this is not a published NVD CPE.
INTUNE_SERVER_PREVIEW_MIN_BUILD = 29621

_CLIENT_MARKERS = frozenset({"10", "11"})


def infer_device_class(asset: Asset) -> str:
    if asset.device_class:
        return asset.device_class
    product_tokens = tokens(asset.product)
    if "windows" in product_tokens and "server" in product_tokens:
        return WINDOWS_SERVER
    if "windows" in product_tokens and (_CLIENT_MARKERS & set(product_tokens)):
        return WINDOWS
    return ""


def filter_build_families(
    families: tuple[tuple[str, str], ...], device_class: str
) -> tuple[tuple[str, str], ...]:
    if device_class == WINDOWS_SERVER:
        return tuple(item for item in families if item[0].startswith("windows_server_"))
    if device_class == WINDOWS:
        return tuple(
            item
            for item in families
            if item[0].startswith("windows_") and not item[0].startswith("windows_server_")
        )
    return families


def preview_build_hint(build: int, device_class: str) -> str:
    if device_class != WINDOWS_SERVER or build < INTUNE_SERVER_PREVIEW_MIN_BUILD:
        return ""
    return (
        f"Build {build} is at or above {INTUNE_SERVER_PREVIEW_MIN_BUILD}, the minimum "
        "Windows Server vNext build documented for the Intune Windows Server "
        "Insider preview (nonproduction only). No NVD CPE for that preview name "
        "is in the starter table; pin a CPE after you have checked the dictionary. "
        "Do not invent a marketing name such as Windows Server 2028."
    )
