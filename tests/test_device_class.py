from pathlib import Path

import pytest

from patchorder.errors import PatchorderError
from patchorder.inventory import load_inventory
from patchorder.models import Asset
from patchorder.resolver import AUTO_USE_CONFIDENCE, resolve_asset


def _asset(**kwargs):
    base = dict(
        id="a",
        product="Windows",
        vendor="Microsoft",
        version="10.0.26100.1000",
        count=1,
        owner="ops",
        exposure="internal",
    )
    base.update(kwargs)
    return Asset(**base)


def test_ambiguous_26100_stays_ambiguous_without_a_class():
    resolution = resolve_asset(_asset())
    cpes = {item.cpe for item in resolution.candidates}
    assert "cpe:2.3:o:microsoft:windows_11_24h2" in cpes
    assert "cpe:2.3:o:microsoft:windows_server_2025" in cpes
    assert resolution.chosen is None


def test_device_class_windows_server_keeps_only_the_server_edition():
    resolution = resolve_asset(_asset(device_class="windows-server"))
    cpes = {item.cpe for item in resolution.candidates}
    assert cpes == {"cpe:2.3:o:microsoft:windows_server_2025"}
    assert resolution.chosen is None
    assert resolution.candidates[0].confidence < AUTO_USE_CONFIDENCE
    assert "Windows Server 2025" in resolution.candidates[0].note


def test_device_class_windows_keeps_only_the_client_edition():
    resolution = resolve_asset(_asset(device_class="windows"))
    cpes = {item.cpe for item in resolution.candidates}
    assert cpes == {"cpe:2.3:o:microsoft:windows_11_24h2"}
    assert resolution.chosen is None


def test_windows_server_product_name_is_enough_to_drop_the_client_edition():
    resolution = resolve_asset(_asset(product="Windows Server", device_class=""))
    cpes = {item.cpe for item in resolution.candidates}
    assert "cpe:2.3:o:microsoft:windows_server_2025" in cpes
    assert "cpe:2.3:o:microsoft:windows_11_24h2" not in cpes


def test_vnext_preview_build_does_not_invent_a_cpe():
    resolution = resolve_asset(
        _asset(
            product="Windows Server vNext",
            version="10.0.29621.1000",
            device_class="windows-server",
        )
    )
    assert resolution.candidates == []
    assert resolution.chosen is None
    assert "29621" in resolution.hint
    assert "vNext" in resolution.hint
    assert "2028" in resolution.hint


def test_inventory_loads_device_class(tmp_path: Path):
    path = tmp_path / "inventory.yaml"
    path.write_text(
        "\n".join(
            [
                "schema: patchorder.inventory/v1",
                "name: lab",
                "assets:",
                "  - id: srv",
                "    product: Windows Server 2022",
                "    vendor: Microsoft",
                '    version: "10.0.20348.2400"',
                "    count: 2",
                "    owner: windows",
                "    exposure: internal",
                "    device_class: windows-server",
                "",
            ]
        ),
        encoding="utf-8",
    )
    inventory = load_inventory(path)
    assert inventory.assets[0].device_class == "windows-server"


def test_inventory_rejects_an_unknown_device_class(tmp_path: Path):
    path = tmp_path / "inventory.yaml"
    path.write_text(
        "\n".join(
            [
                "schema: patchorder.inventory/v1",
                "name: lab",
                "assets:",
                "  - id: srv",
                "    product: Windows Server 2022",
                "    vendor: Microsoft",
                '    version: "10.0.20348.2400"',
                "    count: 2",
                "    owner: windows",
                "    exposure: internal",
                "    device_class: laptop",
                "",
            ]
        ),
        encoding="utf-8",
    )
    with pytest.raises(PatchorderError, match="device_class"):
        load_inventory(path)
