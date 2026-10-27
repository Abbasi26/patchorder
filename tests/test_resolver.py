from patchwindow.models import Asset, LockEntry
from patchwindow.resolver import AUTO_USE_CONFIDENCE, resolve_asset


def _asset(**kwargs):
    base = dict(id="a", product="nginx", vendor="F5", version="1.25.2", count=1, owner="ops", exposure="internet")
    base.update(kwargs)
    return Asset(**base)


def test_vendor_and_product_beat_the_older_dictionary_name():
    resolution = resolve_asset(_asset())
    assert resolution.chosen is not None
    assert resolution.chosen.cpe == "cpe:2.3:a:f5:nginx"
    assert resolution.chosen.confidence >= AUTO_USE_CONFIDENCE
    assert resolution.confirmed is False
    alternates = [item.cpe for item in resolution.candidates]
    assert "cpe:2.3:a:nginx:nginx" in alternates


def test_missing_vendor_stays_below_the_auto_use_line():
    resolution = resolve_asset(_asset(vendor=""))
    assert resolution.chosen is None
    assert resolution.candidates[0].cpe == "cpe:2.3:a:f5:nginx"
    assert resolution.candidates[0].confidence < AUTO_USE_CONFIDENCE


def test_nginx_plus_is_not_open_source_nginx():
    resolution = resolve_asset(_asset(product="NGINX Plus", vendor="F5", version="r30"))
    assert resolution.chosen.cpe == "cpe:2.3:a:f5:nginx_plus"


def test_windows_11_build_is_inferred_but_not_auto_used():
    resolution = resolve_asset(
        _asset(product="Windows 11", vendor="Microsoft", version="10.0.22631.3593", exposure="internal")
    )
    assert resolution.chosen is None
    assert resolution.candidates[0].cpe == "cpe:2.3:o:microsoft:windows_11_23h2"
    assert "22631" in resolution.candidates[0].note


def test_named_edition_agrees_with_the_build():
    resolution = resolve_asset(
        _asset(product="Windows 11 23H2", vendor="Microsoft", version="10.0.22631.3593", exposure="internal")
    )
    assert resolution.chosen.cpe == "cpe:2.3:o:microsoft:windows_11_23h2"
    assert "agrees" in resolution.chosen.note


def test_build_disagreement_is_not_auto_used():
    resolution = resolve_asset(
        _asset(product="Windows 11 23H2", vendor="Microsoft", version="10.0.22621.3000", exposure="internal")
    )
    assert resolution.chosen is None
    cpes = {item.cpe for item in resolution.candidates}
    assert "cpe:2.3:o:microsoft:windows_11_22h2" in cpes
    named = next(item for item in resolution.candidates if item.cpe.endswith("windows_11_23h2"))
    assert "disagrees" in named.note
    assert named.confidence < AUTO_USE_CONFIDENCE


def test_ambiguous_26100_offers_both_editions():
    resolution = resolve_asset(
        _asset(product="Windows", vendor="Microsoft", version="10.0.26100.1000", exposure="internal")
    )
    cpes = {item.cpe for item in resolution.candidates}
    assert "cpe:2.3:o:microsoft:windows_11_24h2" in cpes
    assert "cpe:2.3:o:microsoft:windows_server_2025" in cpes
    assert resolution.chosen is None


def test_lock_pin_replaces_candidates():
    lock = LockEntry(cpe="cpe:2.3:a:nginx:nginx", pinned=True, note="operator checked this")
    resolution = resolve_asset(_asset(), lock)
    assert resolution.confirmed
    assert resolution.chosen.cpe == "cpe:2.3:a:nginx:nginx"
    assert len(resolution.candidates) == 1


def test_dictionary_hit_merges_with_alias():
    hits = [
        {"cpe": "cpe:2.3:a:f5:nginx:1.25.2:*:*:*:*:*:*:*", "title": "F5 NGINX 1.25.2", "deprecated": False},
        {"cpe": "cpe:2.3:a:igor_sysoev:nginx:0.1.0:*:*:*:*:*:*:*", "title": "Nginx 0.1.0", "deprecated": True, "deprecated_by": "cpe:2.3:a:nginx:nginx:0.1.0:*:*:*:*:*:*:*"},
    ]
    resolution = resolve_asset(_asset(), dictionary_hits=hits)
    top = resolution.candidates[0]
    assert top.cpe == "cpe:2.3:a:f5:nginx"
    assert top.confidence >= 0.93
